#if CERBERUS_SERVER_PROFILE
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Cerberus.Agent.Core;

/// <summary>
/// Gate for the server data folder (<c>%ProgramData%\&lt;DataDirName&gt;</c>). A standard user must not be able to
/// pre-create the folder or entries in it (for example a directory named like a file the agent writes later).
/// Trust rule as in <see cref="ProtectedMachineFile"/>: owner SYSTEM or Administrators, no reparse point.
/// </summary>
public static class ServerDataRoot
{
    private const int MaxEntries = 4096;

    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), AgentInstallIdentity.DataDirName);

    /// <summary>
    /// Creates the folder when missing and applies a protected DACL (SYSTEM and Administrators full control,
    /// inherited by children, nothing inherited from the parent). Returns false, changing nothing about an existing
    /// untrusted folder, when the folder or one of its direct entries has an untrusted owner or is a reparse point,
    /// when it is not a directory, or when it cannot be secured. Callers fail closed on false: enroll exits before the
    /// proof is sent, the service stops. Needs an elevated caller. Does not throw for file-system or permission failures.
    /// </summary>
    public static bool EnsureProtected() => EnsureProtected(null);

    /// <inheritdoc cref="EnsureProtected()"/>
    public static bool EnsureProtected(string? path)
    {
        if (!OperatingSystem.IsWindows())
            return true;
        try
        {
            return Ensure(Path.GetFullPath(path ?? DefaultPath));
        }
        catch (Exception ex) when (ProtectedMachineFile.IsFailure(ex))
        {
            return false;
        }
    }

    [SupportedOSPlatform("windows")]
    private static bool Ensure(string path)
    {
        var directory = new DirectoryInfo(path);
        if (File.Exists(path) || (directory.Exists && !IsTrustedDirectory(path)))
            return false;
        if (!directory.Exists)
        {
            directory.Create(Acl());
            // Creation can lose a race to a pre-existing object; never adopt it on name alone.
            if (!IsTrustedDirectory(path))
                return false;
        }
        directory.SetAccessControl(Acl());
        // Entries are vetted on every call: a protected DACL says nothing about who owns a child, and the owner of a
        // planted child can rewrite its DACL. Children this process creates afterwards must pass the same check on
        // the next start, so an elevated caller's default owner is pinned to Administrators (see SetDefaultOwnerAdministrators).
        return EntriesAreTrusted(path) && SetDefaultOwnerAdministrators();
    }

    /// <summary>
    /// New files and folders take the creating token's default owner, which for an elevated administrator can be the
    /// user SID. The service would then refuse its own CLI-written entries. Setting the owner to BUILTIN\Administrators
    /// on the process token fixes every writer at once, with no ownership inferred from a DACL. SYSTEM already owns as
    /// a trusted SID.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static bool SetDefaultOwnerAdministrators()
    {
        using (var identity = WindowsIdentity.GetCurrent())
        {
            if (identity.IsSystem)
                return true;
        }
        var sid = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var bytes = new byte[sid.BinaryLength];
        sid.GetBinaryForm(bytes, 0);
        var info = Marshal.AllocHGlobal(IntPtr.Size + bytes.Length);
        try
        {
            // TOKEN_OWNER { PSID Owner }, with the SID stored right behind the pointer.
            Marshal.WriteIntPtr(info, info + IntPtr.Size);
            Marshal.Copy(bytes, 0, info + IntPtr.Size, bytes.Length);
            if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustDefault, out var token))
                return false;
            try
            {
                return SetTokenInformation(token, TokenOwnerClass, info, IntPtr.Size + bytes.Length);
            }
            finally
            {
                CloseHandle(token);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(info);
        }
    }

    private const uint TokenAdjustDefault = 0x0080;
    private const int TokenOwnerClass = 4;

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetTokenInformation(IntPtr token, int infoClass, IntPtr info, int length);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [SupportedOSPlatform("windows")]
    private static DirectorySecurity Acl()
    {
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        return acl;
    }

    [SupportedOSPlatform("windows")]
    private static bool IsTrustedDirectory(string path)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0 || (attributes & FileAttributes.Directory) == 0)
            return false;
        return IsTrustedOwner(new DirectoryInfo(path).GetAccessControl());
    }

    [SupportedOSPlatform("windows")]
    private static bool EntriesAreTrusted(string path)
    {
        var count = 0;
        foreach (var entry in Directory.EnumerateFileSystemEntries(path))
        {
            if (++count > MaxEntries)
                return false;
            var attributes = File.GetAttributes(entry);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
                return false;
            var security = (attributes & FileAttributes.Directory) != 0
                ? (FileSystemSecurity)new DirectoryInfo(entry).GetAccessControl()
                : new FileInfo(entry).GetAccessControl();
            if (!IsTrustedOwner(security))
                return false;
        }
        return true;
    }

    [SupportedOSPlatform("windows")]
    private static bool IsTrustedOwner(FileSystemSecurity security)
        => security.GetOwner(typeof(SecurityIdentifier)) is SecurityIdentifier { Value: "S-1-5-18" or "S-1-5-32-544" };
}
#endif
