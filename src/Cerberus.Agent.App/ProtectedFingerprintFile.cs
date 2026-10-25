using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App;

/// <summary>
/// The operator-visible key fingerprint file lives in the user-writable product root. It is created
/// owned by SYSTEM/Administrators with full control for them and read for Users, and a file whose
/// owner or DACL is anything else reads as "no fingerprint".
/// </summary>
internal static class ProtectedFingerprintFile
{
    private const FileSystemRights WriteRights = FileSystemRights.WriteData | FileSystemRights.AppendData |
        FileSystemRights.WriteExtendedAttributes | FileSystemRights.WriteAttributes | FileSystemRights.Delete |
        FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;

    public static void Write(string path, string content)
    {
        var acl = new FileSecurity();
        acl.SetAccessRuleProtection(true, false);
        acl.SetOwner(new SecurityIdentifier(AgentUpdateSecurity.IsLocalSystem()
            ? WellKnownSidType.LocalSystemSid : WellKnownSidType.BuiltinAdministratorsSid, null));
        foreach (var sid in new[] { WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid })
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid, null), FileSystemRights.FullControl, AccessControlType.Allow));
        acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
            FileSystemRights.Read, AccessControlType.Allow));
        using var stream = new FileInfo(path).Create(FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None, 4096,
            FileOptions.WriteThrough, acl);
        var bytes = new UTF8Encoding(false).GetBytes(content);
        stream.Write(bytes, 0, bytes.Length);
    }

    /// <summary>First line of a trusted file; null when the file is missing or untrusted.</summary>
    public static string? ReadFirstLine(string path)
    {
        if (File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
            return null;
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (!IsTrusted(stream.GetAccessControl()))
            return null;
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadLine();
    }

    private static bool IsTrusted(FileSecurity security)
    {
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner || !IsAdminOrSystem(owner))
            return false;
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow &&
                (rule.FileSystemRights & WriteRights) != 0 &&
                !IsAdminOrSystem((SecurityIdentifier)rule.IdentityReference))
                return false;
        }
        return true;
    }

    private static bool IsAdminOrSystem(SecurityIdentifier sid)
        => sid.IsWellKnown(WellKnownSidType.LocalSystemSid) || sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid);
}
