using Cerberus.Agent.Core;
using Cerberus.Agent.Security;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;

namespace Cerberus.Agent.Integrations.Tailscale;

// Legacy-test implementation: verify-only (no install, no `tailscale up`).
// This is safe for environments where Tailscale is managed externally.
public sealed class TailscaleEnsureConnectedHandler : ICommandHandler
{
    private readonly Func<CancellationToken, Task<(bool Installed, bool Connected, object? Snapshot, string? Error)>> _probe;
    private readonly Func<ISecretStore> _secretStoreFactory;
    private readonly Func<bool> _allowUpCommandExport;
    private readonly string? _baseDir;
    private readonly bool _applyAcl;

    public TailscaleEnsureConnectedHandler(
        Func<CancellationToken, Task<(bool Installed, bool Connected, object? Snapshot, string? Error)>>? probe = null,
        Func<ISecretStore>? secretStoreFactory = null,
        Func<bool>? allowUpCommandExport = null,
        string? baseDir = null,
        bool applyAcl = true)
    {
        _probe = probe ?? (ct => TailscaleStatusProbe.ProbeAsync(TimeSpan.FromSeconds(10), ct));
        _secretStoreFactory = secretStoreFactory ?? (() => new DpapiSecretStore(SecretStoreScope.Machine));
        _allowUpCommandExport = allowUpCommandExport ?? IsDebugTailscaleUpEnabled;
        _baseDir = baseDir;
        _applyAcl = applyAcl;
    }

    public string Type => "tailscale.ensure_connected";

    public async Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
    {
        var (installed, connected, snapshot, err) = await _probe(ct).ConfigureAwait(false);

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
            if (!_allowUpCommandExport())
            {
                return new CommandResult(
                    Status: "FAILED",
                    ExitCode: 3,
                    Stdout: null,
                    Stderr: "Tailscale activation is disabled. Public agent mode is read-only unless debug lab export is explicitly enabled.",
                    PostVerify: new
                    {
                        installed = true,
                        connected = false,
                        error = err,
                        status = snapshot,
                        up_command_written = false,
                        debug_required = true,
                    });
            }

            // Service-mode runs as LocalSystem and uses machine-scope secrets.
            var secrets = _secretStoreFactory();
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

            // Do NOT run `tailscale up` automatically. Debug export is short-lived and locked down.
            var baseDir = _baseDir ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "CerberusAgent",
                "tailscale");
            Directory.CreateDirectory(baseDir);
            var exportId = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
            var cmdPath = Path.Combine(baseDir, $"tailscale-up-{exportId}.cmd");
            var metadataPath = Path.Combine(baseDir, $"tailscale-up-{exportId}.metadata.json");
            var expiresAt = DateTimeOffset.UtcNow.AddMinutes(10);
            var cmdText = TailscaleUpCommand.Build(loginServer, authKey);
            await File.WriteAllTextAsync(cmdPath, cmdText, ct);
            await File.WriteAllTextAsync(
                metadataPath,
                JsonSerializer.Serialize(new
                {
                    schema_version = "cerberus.tailscale-debug-export.v1",
                    created_at_utc = DateTimeOffset.UtcNow.ToString("O"),
                    expires_at_utc = expiresAt.ToString("O"),
                    command_path = cmdPath,
                    contains_plaintext_authkey = true,
                }),
                ct);
            if (_applyAcl)
            {
                LockDownAcl(cmdPath);
                LockDownAcl(metadataPath);
            }

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
                    expires_at_utc = expiresAt.ToString("O"),
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

    private static bool IsDebugTailscaleUpEnabled()
        => string.Equals(
            Environment.GetEnvironmentVariable("CERBERUS_AGENT_DEBUG_TAILSCALE_UP"),
            "1",
            StringComparison.Ordinal);
}
