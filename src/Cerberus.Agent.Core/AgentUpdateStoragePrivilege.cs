using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace Cerberus.Agent.Core;

/// <summary>Temporarily enables an existing restore privilege on a private thread token, never the process token.</summary>
[SupportedOSPlatform("windows")]
internal static class AgentUpdateStoragePrivilege
{
    public static void Run(Action action)
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!identity.IsSystem && !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new UnauthorizedAccessException("Protected update storage creation requires elevated authority.");

        // A duplicate token prevents concurrent service work from observing a temporarily enabled process privilege.
        if (!DuplicateTokenEx(identity.AccessToken, 0x0002 | 0x0004 | 0x0008 | 0x0020, IntPtr.Zero, 2, 2, out var scopedToken))
            throw Failure();
        using (scopedToken)
        {
            if (!LookupPrivilegeValue(null, "SeRestorePrivilege", out var luid))
                throw Failure();
            var requested = new TokenPrivileges { Count = 1, Luid = luid, Attributes = 2 };
            if (!AdjustTokenPrivileges(scopedToken, false, ref requested, Marshal.SizeOf<TokenPrivileges>(), out var previous, out _))
                throw Failure();
            var enableError = Marshal.GetLastWin32Error();
            try
            {
                // AdjustTokenPrivileges can return TRUE when the privilege was unavailable (ERROR_NOT_ALL_ASSIGNED).
                if (enableError != 0)
                    throw new InvalidOperationException("Protected update ownership privilege is unavailable.", new Win32Exception(enableError));
                WindowsIdentity.RunImpersonated(scopedToken, action);
            }
            finally
            {
                if (previous.Count != 0 &&
                    (!AdjustTokenPrivileges(scopedToken, false, ref previous, Marshal.SizeOf<TokenPrivileges>(), out _, out _) ||
                     Marshal.GetLastWin32Error() != 0))
                    throw new InvalidOperationException("Protected update ownership privilege restoration failed.");
            }
        }
    }

    private static InvalidOperationException Failure()
        => new("Protected update ownership privilege is unavailable.", new Win32Exception(Marshal.GetLastWin32Error()));

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges { public uint Count; public Luid Luid; public uint Attributes; }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateTokenEx(SafeAccessTokenHandle token, uint access, IntPtr attributes, int impersonationLevel, int tokenType, out SafeAccessTokenHandle duplicate);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValue(string? system, string name, out Luid value);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(SafeAccessTokenHandle token, [MarshalAs(UnmanagedType.Bool)] bool disableAll, ref TokenPrivileges state,
        int bufferLength, out TokenPrivileges previous, out int returnLength);
}
