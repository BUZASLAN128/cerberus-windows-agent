using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Cerberus.Agent.Core;
using Microsoft.Win32.SafeHandles;

namespace Cerberus.Agent.Core.Tests;

// ServerDataRoot.EnsureProtected changes TokenOwner in the testhost. Capture and restore
// that field only. No privilege is enabled on the process token.
internal sealed class ProcessTokenOwner : IDisposable
{
    private readonly SafeAccessTokenHandle _token;
    private readonly IntPtr _original;
    private readonly int _length;

    private ProcessTokenOwner(SafeAccessTokenHandle token, IntPtr original, int length)
        => (_token, _original, _length) = (token, original, length);

    internal static ProcessTokenOwner Capture()
    {
        if (!OpenProcessToken(new IntPtr(-1), 0x88, out var token))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        IntPtr buffer = IntPtr.Zero;
        try
        {
            if (GetTokenInformation(token, 4, IntPtr.Zero, 0, out var length) ||
                Marshal.GetLastWin32Error() != 122 || length <= IntPtr.Size)
                throw new InvalidOperationException("Cannot size the original testhost token owner.");
            buffer = Marshal.AllocHGlobal(length);
            if (!GetTokenInformation(token, 4, buffer, length, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return new ProcessTokenOwner(token, buffer, length);
        }
        catch
        {
            if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
            token.Dispose();
            throw;
        }
    }

    internal static bool ReadElevation(SafeAccessTokenHandle token)
    {
        var buffer = Marshal.AllocHGlobal(sizeof(int));
        try
        {
            if (!GetTokenInformation(token, 20, buffer, sizeof(int), out _))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return Marshal.ReadInt32(buffer) != 0;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    public void Dispose()
    {
        try
        {
            if (!SetTokenInformation(_token, 4, _original, _length))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            var actual = Marshal.AllocHGlobal(_length);
            try
            {
                if (!GetTokenInformation(_token, 4, actual, _length, out _))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                if (!EqualSid(Marshal.ReadIntPtr(_original), Marshal.ReadIntPtr(actual)))
                    throw new InvalidOperationException("The original testhost token owner was not restored.");
            }
            finally { Marshal.FreeHGlobal(actual); }
        }
        finally
        {
            Marshal.FreeHGlobal(_original);
            _token.Dispose();
        }
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out SafeAccessTokenHandle token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int infoClass, IntPtr data,
        int length, out int required);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetTokenInformation(SafeAccessTokenHandle token, int infoClass, IntPtr data, int length);

    [DllImport("advapi32.dll")]
    private static extern bool EqualSid(IntPtr left, IntPtr right);
}

internal static class StoppedRemovalToken
{
    internal sealed record State(uint? Restore, uint? Backup, uint? Traverse)
    {
        internal bool RestoreEnabled => (Restore.GetValueOrDefault() & 2) != 0;
        internal bool BackupEnabled => (Backup.GetValueOrDefault() & 2) != 0;
    }

    internal static State Snapshot(SafeAccessTokenHandle token)
        => new(Read(token, "SeRestorePrivilege"), Read(token, "SeBackupPrivilege"), Read(token, "SeChangeNotifyPrivilege"));

    internal static void RunAndVerifyRestoreOnly(Action action)
    {
        using var actor = WindowsIdentity.GetCurrent();
        var process = Snapshot(actor.AccessToken);
        AgentUpdateStoragePrivilege.Run(() =>
        {
            using var thread = WindowsIdentity.GetCurrent(ifImpersonating: true);
            Assert.NotNull(thread);
            Assert.Equal(actor.User, thread.User);
            Assert.Equal(TokenImpersonationLevel.Impersonation, thread.ImpersonationLevel);
            var scoped = Snapshot(thread.AccessToken);
            Assert.True(scoped.RestoreEnabled);
            Assert.False(scoped.BackupEnabled);
            Assert.Equal(process.Traverse, scoped.Traverse);
            Assert.Equal(process, Snapshot(actor.AccessToken));
            action();
        });
    }

    internal static void RunAndVerifyBackupOnly(Action readMetadata)
    {
        using var ambient = WindowsIdentity.GetCurrent(ifImpersonating: true);
        Assert.Null(ambient);
        Assert.True(AlreadyElevatedTc1FactAttribute.IsEligible());
        using var actor = WindowsIdentity.GetCurrent();
        var process = Snapshot(actor.AccessToken);
        Assert.False(process.BackupEnabled);

        // TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES.
        if (!DuplicateTokenEx(actor.AccessToken, 0x2e, IntPtr.Zero, 2, 2, out var duplicate))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        using (duplicate)
        {
            try
            {
                if (process.Restore.HasValue) Adjust(duplicate, "SeRestorePrivilege", 0);
                Adjust(duplicate, "SeBackupPrivilege", 2);
                WindowsIdentity.RunImpersonated(duplicate, () =>
                {
                    using var thread = WindowsIdentity.GetCurrent(ifImpersonating: true);
                    Assert.NotNull(thread);
                    Assert.Equal(actor.User, thread.User);
                    Assert.Equal(TokenImpersonationLevel.Impersonation, thread.ImpersonationLevel);
                    var scoped = Snapshot(thread.AccessToken);
                    Assert.True(scoped.BackupEnabled);
                    Assert.False(scoped.RestoreEnabled);
                    Assert.Equal(process.Traverse, scoped.Traverse);
                    Assert.Equal(process, Snapshot(actor.AccessToken));
                    readMetadata();
                });
            }
            finally
            {
                using var remaining = WindowsIdentity.GetCurrent(ifImpersonating: true);
                Assert.Null(remaining);
                Assert.Equal(process, Snapshot(actor.AccessToken));
            }
        }
    }

    private static void Adjust(SafeAccessTokenHandle token, string name, uint attributes)
    {
        if (!LookupPrivilegeValueW(null, name, out var luid))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        var request = new Privileges { Count = 1, Luid = luid, Attributes = attributes };
        var adjusted = AdjustTokenPrivileges(token, false, ref request, 0, IntPtr.Zero, IntPtr.Zero);
        var error = Marshal.GetLastWin32Error();
        if (!adjusted || error != 0) throw new Win32Exception(error);
    }

    private static uint? Read(SafeAccessTokenHandle token, string name)
    {
        if (!LookupPrivilegeValueW(null, name, out var luid))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        if (GetTokenInformation(token, 3, IntPtr.Zero, 0, out var length) ||
            Marshal.GetLastWin32Error() != 122 || length < 4)
            throw new InvalidOperationException("Cannot size TokenPrivileges.");
        var buffer = Marshal.AllocHGlobal(length);
        try
        {
            if (!GetTokenInformation(token, 3, buffer, length, out _))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            var count = Marshal.ReadInt32(buffer);
            if (count < 0 || count > (length - 4) / 12)
                throw new InvalidOperationException("Invalid TokenPrivileges length.");
            for (var index = 0; index < count; index++)
            {
                var offset = 4 + index * 12;
                if (Marshal.ReadInt32(buffer, offset) == luid.Low && Marshal.ReadInt32(buffer, offset + 4) == luid.High)
                    return unchecked((uint)Marshal.ReadInt32(buffer, offset + 8));
            }
            return null;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public int Low;
        public int High;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Privileges
    {
        public uint Count;
        public Luid Luid;
        public uint Attributes;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DuplicateTokenEx(SafeAccessTokenHandle source, uint rights, IntPtr attributes,
        int impersonation, int tokenType, out SafeAccessTokenHandle duplicate);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(SafeAccessTokenHandle token, bool disableAll,
        ref Privileges state, int length, IntPtr previous, IntPtr required);

    [DllImport("advapi32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LookupPrivilegeValueW(string? system, string name, out Luid value);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int infoClass, IntPtr data,
        int length, out int required);
}
