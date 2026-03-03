using Cerberus.Agent.Core;
using Cerberus.Agent.Security;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Cerberus.Agent.Integrations.Tailscale;

// Legacy-test implementation: verify-only (no install, no `tailscale up`).
// This is safe for environments where Tailscale is managed externally.
public sealed class TailscaleEnsureConnectedHandler : ICommandHandler
{
    public string Type => "tailscale.ensure_connected";

    public async Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
    {
        var (installed, connected, snapshot, err) = await TailscaleStatusProbe.ProbeAsync(
            timeout: TimeSpan.FromSeconds(10),
            ct: ct);

        if (!installed)
        {
            return new CommandResult(
                Status: "FAILED",
                ExitCode: 127,
                Stdout: null,
                Stderr: "Tailscale is not installed (legacy test mode does not install it).",
                PostVerify: new { installed = false, connected = false, error = err });
        }

        if (!connected)
        {
            // Service-mode runs as LocalSystem and uses machine-scope secrets.
            var secrets = new DpapiSecretStore(SecretStoreScope.Machine);
            var (_, _, _, _, loginServer, authKey) = await secrets.LoadAsync(ct);
            if (string.IsNullOrWhiteSpace(loginServer) || string.IsNullOrWhiteSpace(authKey))
            {
                return new CommandResult(
                    Status: "FAILED",
                    ExitCode: 2,
                    Stdout: null,
                    Stderr: "VPN provisioning is not available (missing one-time auth key).",
                    PostVerify: new { installed = true, connected = false, error = err, status = snapshot });
            }

            // Do NOT run `tailscale up` automatically yet. Write the command to a locked-down file.
            var baseDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "CerberusAgent",
                "tailscale");
            Directory.CreateDirectory(baseDir);
            var cmdPath = Path.Combine(baseDir, "tailscale-up.cmd");
            var cmdText = TailscaleUpCommand.Build(loginServer, authKey);
            await File.WriteAllTextAsync(cmdPath, cmdText, ct);
            LockDownAcl(cmdPath);

            return new CommandResult(
                Status: "DONE",
                ExitCode: 0,
                Stdout: null,
                Stderr: null,
                PostVerify: new
                {
                    installed = true,
                    connected = false,
                    status = snapshot,
                    error = err,
                    up_command_written = true,
                    up_command_path = cmdPath,
                });
        }

        return new CommandResult(
            Status: "DONE",
            ExitCode: 0,
            Stdout: null,
            Stderr: null,
            PostVerify: new { installed = true, connected = true, status = snapshot });
    }

    private static void LockDownAcl(string filePath)
    {
        var fileInfo = new FileInfo(filePath);
        var fs = fileInfo.GetAccessControl();

        fs.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        fs.SetOwner(new NTAccount("SYSTEM"));

        fs.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            FileSystemRights.FullControl,
            AccessControlType.Allow));

        fs.AddAccessRule(new FileSystemAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            FileSystemRights.FullControl,
            AccessControlType.Allow));

        fileInfo.SetAccessControl(fs);
    }
}
