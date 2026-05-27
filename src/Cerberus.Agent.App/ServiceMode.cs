using Cerberus.Agent.Core;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.Integrations.Ad;
using Cerberus.Agent.Integrations.Tailscale;
using Cerberus.Agent.Observability;
using Cerberus.Agent.Security;
using Microsoft.Win32;
using System.Net.Http;
using System.IO;
using System.Text;

namespace Cerberus.Agent.App;

internal static class ServiceMode
{
    public static async Task RunAsync(CancellationToken ct)
    {
        using var log = AgentFileLogger.CreateDefault(alsoConsole: true);
        log.Info("Service mode starting.");

        var secrets = new DpapiSecretStore(SecretStoreScope.Machine);
        var (_, _, privateKeyPem, storedBackendUrl, _, _) = await secrets.LoadAsync(ct);
        var backendUrl = Environment.GetEnvironmentVariable("CERBERUS_BACKEND_URL") ?? storedBackendUrl;

        var baseAddress = new Uri(backendUrl.TrimEnd('/'));
        using var http = new HttpClient { BaseAddress = baseAddress, Timeout = TimeSpan.FromSeconds(30) };
        using var updateHttp = new HttpClient
        {
            BaseAddress = baseAddress,
            Timeout = ReadTimeSpanFromSeconds("CERBERUS_AGENT_UPDATE_TIMEOUT_SECONDS", TimeSpan.FromMinutes(10)),
        };

        var signer = new RequestSigner(privateKeyPem);
        var tokens = new AgentTokenManager(http, secrets);
        var api = new AgentApiClient(http, secrets, tokens, signer);
        var agentVersion = WindowsDeviceInfo.GetAgentVersion();
        var buildId = WindowsDeviceInfo.GetBuildId();
        var buildChannel = WindowsDeviceInfo.GetBuildChannel();
        var metadata = new AgentBuildMetadata(
            AgentVersion: agentVersion,
            BuildId: buildId,
            BuildChannel: buildChannel,
            BootId: Guid.NewGuid().ToString("N"),
            SupportedSchemaVersions: AgentSchemaVersions.All);

        var cachePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "CerberusAgent",
            "idempotency.json");
        var idempotency = new IdempotencyCache(cachePath, maxEntries: 5000, ttl: TimeSpan.FromHours(24));
        var telemetryBuffer = new OfflineTelemetryBuffer(
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "CerberusAgent",
                "telemetry-offline.json"),
            maxEntries: 200,
            maxBytes: 512 * 1024,
            ttl: TimeSpan.FromHours(24));

        var handlers = new List<ICommandHandler>
        {
            new HealthSnapshotHandler(),
            new RdpQuickTestHandler(),
            new TailscaleEnsureConnectedHandler(),
        };
        handlers.AddRange(LocalUserCommandHandlers.CreateDefaultHandlers());

        var dispatcher = new CommandDispatcher(handlers, idempotency);
        var statusProvider = new TailscaleStatusProvider();
        var updateCoordinator = BuildUpdateCoordinator(updateHttp, log);
        var loop = new HeartbeatLoop(
            api,
            dispatcher,
            minDelayOnError: TimeSpan.FromSeconds(10),
            statusProvider: statusProvider,
            adStatusProvider: _ => Task.FromResult<object?>(BuildAdStatus()),
            agentVersion: agentVersion,
            buildId: buildId,
            buildChannel: buildChannel,
            responseHandler: new HeartbeatResponseHandler(
                secrets,
                log,
                updateCoordinator,
                updateFailureReporter: (response, exception, cancel) =>
                    ReportUpdateFailureAsync(api, metadata, response, exception, cancel)),
            telemetryProvider: new WindowsTelemetryCollector(),
            telemetryBuffer: telemetryBuffer,
            log: log,
            commandTimeout: TimeSpan.FromSeconds(120),
            metadata: metadata);

        try
        {
            await loop.RunAsync(ct);
        }
        finally
        {
            log.Info("Service mode stopped.");
        }
    }

    private static IAgentUpdateCoordinator? BuildUpdateCoordinator(HttpClient http, IAgentLogger log)
    {
        var registryConfig = ReadUpdateTrustConfigFromRegistry();
        string publicKey;
        try
        {
            publicKey = ResolveUpdateManifestPublicKey(
                Environment.GetEnvironmentVariable("CERBERUS_AGENT_UPDATE_MANIFEST_PUBLIC_KEY_PEM"),
                Environment.GetEnvironmentVariable("CERBERUS_AGENT_UPDATE_MANIFEST_PUBLIC_KEY_B64"),
                registryConfig.GetValueOrDefault("updateManifestPublicKeyPem"),
                registryConfig.GetValueOrDefault("updateManifestPublicKeyB64"));
        }
        catch (FormatException)
        {
            log.Warn("Agent update trust disabled because the configured manifest public key is not valid base64.");
            return null;
        }

        if (string.IsNullOrWhiteSpace(publicKey))
            return null;

        var channel = WindowsDeviceInfo.GetBuildChannel();
        var prefixSource = Environment.GetEnvironmentVariable("CERBERUS_AGENT_UPDATE_ALLOWED_ARTIFACT_PREFIXES");
        if (string.IsNullOrWhiteSpace(prefixSource))
            registryConfig.TryGetValue("updateAllowedArtifactPrefixes", out prefixSource);
        var prefixes = SplitCsv(prefixSource);
        var stagingRoot = AgentUpdateStager.DefaultStagingRoot;
        var trust = new AgentUpdateTrust(
            ManifestPublicKeyPem: publicKey,
            ExpectedChannel: channel,
            AllowedArtifactPrefixes: prefixes,
            CurrentVersion: WindowsDeviceInfo.GetAgentVersion());
        return new AgentUpdateCoordinator(new AgentUpdateStager(http, trust, stagingRoot, log), log);
    }

    internal static string ResolveUpdateManifestPublicKey(
        string? envPem,
        string? envBase64,
        string? registryPem,
        string? registryBase64)
    {
        if (!string.IsNullOrWhiteSpace(envPem))
            return envPem.Trim();

        var decodedEnv = DecodeUpdateManifestPublicKey(envBase64);
        if (!string.IsNullOrWhiteSpace(decodedEnv))
            return decodedEnv;

        if (!string.IsNullOrWhiteSpace(registryPem))
            return registryPem.Trim();

        return DecodeUpdateManifestPublicKey(registryBase64);
    }

    private static string DecodeUpdateManifestPublicKey(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "";
        var bytes = Convert.FromBase64String(value.Trim());
        return Encoding.UTF8.GetString(bytes).Trim();
    }

    private static IReadOnlyDictionary<string, string?> ReadUpdateTrustConfigFromRegistry()
    {
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        if (!OperatingSystem.IsWindows())
            return values;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"Software\Cerberus\WindowsAgent", writable: false);
            if (key is null)
                return values;

            values["updateManifestPublicKeyPem"] = key.GetValue("updateManifestPublicKeyPem")?.ToString();
            values["updateManifestPublicKeyB64"] = key.GetValue("updateManifestPublicKeyB64")?.ToString();
            values["updateAllowedArtifactPrefixes"] = key.GetValue("updateAllowedArtifactPrefixes")?.ToString();
        }
        catch (System.Security.SecurityException)
        {
            return values;
        }
        catch (UnauthorizedAccessException)
        {
            return values;
        }

        return values;
    }

    private static TimeSpan ReadTimeSpanFromSeconds(string envName, TimeSpan defaultValue)
    {
        var raw = Environment.GetEnvironmentVariable(envName);
        if (!int.TryParse(raw, out var seconds) || seconds < 30)
            return defaultValue;

        return TimeSpan.FromSeconds(seconds);
    }

    private static async Task ReportUpdateFailureAsync(
        AgentApiClient api,
        AgentBuildMetadata metadata,
        HeartbeatResponse response,
        Exception exception,
        CancellationToken ct)
    {
        var eventId = $"agent.update.failed:{metadata.BootId}:{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}";
        var item = new AgentEventItem(
            EventId: eventId,
            Type: "agent.update.failed",
            OccurredAt: DateTimeOffset.UtcNow.ToString("O"),
            Severity: "warning",
            Payload: new Dictionary<string, object?>
            {
                ["exception_type"] = exception.GetType().Name,
                ["message"] = Sanitizer.Redact(exception.Message),
                ["lifecycle_state"] = response.LifecycleState,
                ["agent_status"] = response.AgentStatus,
            });
        await api.SubmitEventsAsync(
            AgentTelemetryFactory.CreateEvents(metadata, new[] { item }),
            ct).ConfigureAwait(false);
    }

    private static IReadOnlyList<string> SplitCsv(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return Array.Empty<string>();
        return value
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(item => !string.IsNullOrWhiteSpace(item))
            .ToArray();
    }

    private sealed class HealthSnapshotHandler : ICommandHandler
    {
        public string Type => "agent.health.snapshot";

        public Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
        {
            var post = new
            {
                version = "v1",
                uptime_seconds = (long)Environment.TickCount64 / 1000,
                machine_name = Environment.MachineName,
                os_version = Environment.OSVersion.VersionString,
            };
            return Task.FromResult(new CommandResult("DONE", 0, null, null, post));
        }
    }

    private sealed class RdpQuickTestHandler : ICommandHandler
    {
        public string Type => "agent.rdp.quick_test";

        public async Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
        {
            var collector = new Telemetry.Sections.RdpTelemetrySectionCollector();
            var rdp = await collector.CollectAsync(
                new WindowsTelemetryContext(
                    new AgentBuildMetadata(
                        AgentVersion: WindowsDeviceInfo.GetAgentVersion(),
                        BuildId: WindowsDeviceInfo.GetBuildId(),
                        BuildChannel: WindowsDeviceInfo.GetBuildChannel(),
                        BootId: Guid.NewGuid().ToString("N"),
                        SupportedSchemaVersions: AgentSchemaVersions.All),
                    LastHeartbeat: null),
                ct).ConfigureAwait(false);

            return new CommandResult(
                "DONE",
                0,
                null,
                null,
                new
                {
                    source = "agent.rdp.quick_test",
                    rdp,
                });
        }
    }

    private sealed class TailscaleStatusProvider : IAgentStatusProvider
    {
        public async Task<object?> GetTailscaleAsync(CancellationToken ct)
        {
            var (installed, connected, snapshot, err) = await TailscaleStatusProbe.ProbeAsync(
                timeout: TimeSpan.FromSeconds(5),
                ct: ct);
            return new
            {
                installed,
                connected,
                error = Sanitizer.Redact(err),
                state = ExtractSnapshotValue(snapshot, "state"),
                ips = ExtractSnapshotValue(snapshot, "ips") ?? Array.Empty<string>(),
                status = snapshot,
            };
        }
    }

    private static object? ExtractSnapshotValue(object? snapshot, string key)
    {
        return snapshot is IReadOnlyDictionary<string, object?> map && map.TryGetValue(key, out var value)
            ? value
            : null;
    }

    private static object BuildAdStatus()
    {
        var (joined, domain, err) = AdStatusProbe.Probe();
        return new
        {
            domain_joined = joined,
            domain_name = domain,
            last_error = err,
        };
    }
}
