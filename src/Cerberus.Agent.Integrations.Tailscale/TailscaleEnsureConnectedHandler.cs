using Cerberus.Agent.Core;
using Cerberus.Agent.Security;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Diagnostics;

namespace Cerberus.Agent.Integrations.Tailscale;

public sealed class TailscaleEnsureConnectedHandler : ICommandHandler
{
    private readonly Func<CancellationToken, Task<(bool Installed, bool Connected, object? Snapshot, string? Error)>> _probe;
    private readonly Func<ISecretStore> _secretStoreFactory;
    private readonly Func<string, string, CancellationToken, Task<TailscaleUpRunResult>> _upRunner;
    private readonly Func<bool> _allowUpCommandExport;
    private readonly Func<bool> _autoConnectEnabled;
    private readonly string? _baseDir;
    private readonly bool _applyAcl;

    public TailscaleEnsureConnectedHandler(
        Func<CancellationToken, Task<(bool Installed, bool Connected, object? Snapshot, string? Error)>>? probe = null,
        Func<ISecretStore>? secretStoreFactory = null,
        Func<string, string, CancellationToken, Task<TailscaleUpRunResult>>? upRunner = null,
        Func<bool>? allowUpCommandExport = null,
        Func<bool>? autoConnectEnabled = null,
        string? baseDir = null,
        bool applyAcl = true)
    {
        _probe = probe ?? (ct => TailscaleStatusProbe.ProbeAsync(TimeSpan.FromSeconds(10), ct));
        _secretStoreFactory = secretStoreFactory ?? (() => new DpapiSecretStore(SecretStoreScope.Machine));
        _upRunner = upRunner ?? RunTailscaleUpAsync;
        _allowUpCommandExport = allowUpCommandExport ?? IsDebugTailscaleUpEnabled;
        _autoConnectEnabled = autoConnectEnabled ?? IsAutoConnectEnabled;
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
                Stderr: "Tailscale is not installed.",
                PostVerify: new { installed = false, connected = false, error = err });
        }

        if (!connected)
        {
            var autoConnectEnabled = _autoConnectEnabled();
            var debugExportEnabled = _allowUpCommandExport();
            if (!autoConnectEnabled && !debugExportEnabled)
            {
                return new CommandResult(
                    Status: "FAILED",
                    ExitCode: 3,
                    Stdout: null,
                    Stderr: "Tailscale activation is disabled and debug export is not enabled.",
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

            if (autoConnectEnabled)
            {
                var up = await _upRunner(loginServer.Trim(), authKey.Trim(), ct).ConfigureAwait(false);
                var (afterInstalled, afterConnected, afterSnapshot, afterErr) = await _probe(ct).ConfigureAwait(false);
                if (up.ExitCode == 0 && afterInstalled && afterConnected)
                {
                    return new CommandResult(
                        Status: "DONE",
                        ExitCode: 0,
                        Stdout: up.Stdout,
                        Stderr: null,
                        PostVerify: new
                        {
                            installed = true,
                            connected = true,
                            status = afterSnapshot,
                            activated = true,
                        });
                }

                return new CommandResult(
                    Status: "FAILED",
                    ExitCode: up.ExitCode == 0 ? 4 : up.ExitCode,
                    Stdout: up.Stdout,
                    Stderr: string.IsNullOrWhiteSpace(up.Stderr)
                        ? "Tailscale activation did not reach connected state."
                        : up.Stderr,
                    PostVerify: new
                    {
                        installed = afterInstalled,
                        connected = afterConnected,
                        status = afterSnapshot,
                        error = afterErr,
                        activated = false,
                    });
            }

            // Debug export is short-lived and locked down.
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
                    contains_plaintext_authkey = false,
                    authkey_source = "CERBERUS_TAILSCALE_AUTHKEY",
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

    private static bool IsAutoConnectEnabled()
        => !string.Equals(
            Environment.GetEnvironmentVariable("CERBERUS_AGENT_TAILSCALE_AUTO_UP"),
            "0",
            StringComparison.Ordinal);

    private static async Task<TailscaleUpRunResult> RunTailscaleUpAsync(
        string loginServer,
        string authKey,
        CancellationToken ct)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo
        {
            FileName = "tailscale",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        process.StartInfo.ArgumentList.Add("up");
        process.StartInfo.ArgumentList.Add($"--login-server={loginServer}");
        process.StartInfo.ArgumentList.Add($"--authkey={authKey}");
        process.StartInfo.ArgumentList.Add("--accept-dns=false");
        process.StartInfo.ArgumentList.Add("--accept-routes=false");

        try
        {
            process.Start();
            var stdoutTask = process.StandardOutput.ReadToEndAsync(ct);
            var stderrTask = process.StandardError.ReadToEndAsync(ct);
            await process.WaitForExitAsync(ct).ConfigureAwait(false);
            return new TailscaleUpRunResult(
                process.ExitCode,
                await stdoutTask.ConfigureAwait(false),
                await stderrTask.ConfigureAwait(false));
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return new TailscaleUpRunResult(127, "", ex.Message);
        }
    }

    public sealed record TailscaleUpRunResult(int ExitCode, string Stdout, string Stderr);
}
