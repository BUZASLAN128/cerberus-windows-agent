using Cerberus.Agent.Core;
using Cerberus.Agent.Integrations.Tailscale;
using Cerberus.Agent.Security;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Cerberus.Agent.App;

internal static class TailscaleUpExporter
{
    public static async Task<string?> ExportAsync(CancellationToken ct)
    {
        // Prefer user-scope secrets (no admin/UAC needed). Fall back to machine-scope (service-mode).
        // Note: machine-scope may require elevation if secrets file ACL is SYSTEM-only.
        foreach (var scope in new[] { SecretStoreScope.User, SecretStoreScope.Machine })
        {
            try
            {
                var secrets = new DpapiSecretStore(scope);
                return await ExportAsync(
                    secrets,
                    baseDir: null,
                    applyAcl: scope == SecretStoreScope.Machine,
                    scope: scope,
                    ct: ct);
            }
            catch (FileNotFoundException)
            {
                // try next scope
            }
        }

        return null;
    }

    internal static async Task<string?> ExportAsync(
        ISecretStore secrets,
        string? baseDir,
        bool applyAcl,
        SecretStoreScope scope,
        CancellationToken ct)
    {
        var (_, _, _, _, loginServer, authKey) = await secrets.LoadAsync(ct);

        if (string.IsNullOrWhiteSpace(loginServer) || string.IsNullOrWhiteSpace(authKey))
            return null;

        baseDir ??= Path.Combine(
            scope == SecretStoreScope.User
                ? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
                : Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "CerberusAgent",
            "tailscale");
        Directory.CreateDirectory(baseDir);

        var cmdPath = Path.Combine(baseDir, "tailscale-up.cmd");
        var cmdText = TailscaleUpCommand.Build(loginServer.Trim(), authKey.Trim());
        await File.WriteAllTextAsync(cmdPath, cmdText, ct);
        if (applyAcl)
            LockDownAcl(cmdPath);
        return cmdPath;
    }

    private static void LockDownAcl(string filePath)
    {
        // Best-effort: allow user to read/run the exported cmd. Do not break export if ACL fails.
        try
        {
            var fileInfo = new FileInfo(filePath);
            var fs = new FileSecurity();

            fs.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            try { fs.SetOwner(new NTAccount("SYSTEM")); } catch { }

            fs.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                FileSystemRights.FullControl,
                AccessControlType.Allow));

            fs.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                FileSystemRights.FullControl,
                AccessControlType.Allow));

            var me = WindowsIdentity.GetCurrent().User;
            if (me is not null)
            {
                fs.AddAccessRule(new FileSystemAccessRule(
                    me,
                    FileSystemRights.ReadAndExecute | FileSystemRights.Read | FileSystemRights.Write,
                    AccessControlType.Allow));
            }

            fileInfo.SetAccessControl(fs);
        }
        catch
        {
            // ignored
        }
    }
}
