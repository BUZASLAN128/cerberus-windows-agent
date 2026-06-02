using Cerberus.Agent.Core;
using Cerberus.Agent.App.Diagnostics;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.Integrations.Ad;
using Cerberus.Agent.Integrations.Tailscale;
using Cerberus.Agent.Observability;
using Cerberus.Agent.Security;
using System.Net.Http;
using System.IO;

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
        var updateStateStore = AgentUpdateStateStore.CreateDefault();

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

        var diagnosticUploader = new AgentDiagnosticBundleUploader(api, metadata);
        var handlers = new List<ICommandHandler>
        {
            new HealthSnapshotHandler(),
            new RdpQuickTestHandler(),
            new TailscaleEnsureConnectedHandler(),
            new DiagnosticBundleCollectCommandHandler(diagnosticUploader),
        };
        var localUserPolicy = LocalUserCommandPolicy.FromEnvironmentAndRegistry();
        handlers.AddRange(LocalUserCommandHandlers.CreateDefaultHandlers(localUserPolicy));
        handlers.Add(new AgentUpdateRequestCommandHandler(
            () => BuildUpdateCoordinator(updateHttp, log, updateStateStore),
            updateStateStore,
            log,
            agentVersion));

        var dispatcher = new CommandDispatcher(handlers, idempotency);
        var statusProvider = new TailscaleStatusProvider();
        var updateCoordinator = BuildUpdateCoordinator(updateHttp, log, updateStateStore);
        var loop = new HeartbeatLoop(
            api,
            dispatcher,
            minDelayOnError: TimeSpan.FromSeconds(10),
            statusProvider: statusProvider,
            adStatusProvider: _ => Task.FromResult<object?>(BuildAdStatus()),
            updateStatusProvider: async cancel =>
                (await updateStateStore.ReconcileInstallerResultAsync(
                    WindowsDeviceInfo.GetAgentVersion(),
                    cancel).ConfigureAwait(false)).ToHeartbeatStatus(),
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
            backoffResetRequested: HeartbeatBackoffResetSignal.ConsumeDefaultAsync,
            metadata: metadata);

        using var serviceCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var diagnosticScheduler = new DiagnosticBundleScheduler(diagnosticUploader, log);
        var diagnosticSchedulerTask = diagnosticScheduler.RunAsync(serviceCts.Token);

        try
        {
            await loop.RunAsync(serviceCts.Token);
        }
        finally
        {
            serviceCts.Cancel();
            try
            {
                await diagnosticSchedulerTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Expected during service shutdown.
            }
            log.Info("Service mode stopped.");
        }
    }

    private static AgentUpdateCoordinator? BuildUpdateCoordinator(
        HttpClient http,
        IAgentLogger log,
        AgentUpdateStateStore stateStore)
        => AgentUpdateTrustFactory.BuildCoordinator(http, log, stateStore);

    internal static string ResolveUpdateManifestPublicKey(
        string? envPem,
        string? envBase64,
        string? registryPem,
        string? registryBase64)
        => AgentUpdateTrustFactory.ResolveUpdateManifestPublicKey(envPem, envBase64, registryPem, registryBase64);

    internal static IReadOnlyList<string> ResolveUpdateManifestPublicKeys(
        string? embeddedBase64,
        string? envPem,
        string? envBase64,
        string? registryPem,
        string? registryBase64)
        => AgentUpdateTrustFactory.ResolveUpdateManifestPublicKeys(
            embeddedBase64,
            envPem,
            envBase64,
            registryPem,
            registryBase64);

    internal static string ResolveConfiguredUpdateManifestUrl(
        string? envUrl,
        string? legacyEnvUrl,
        string? registryUrl,
        string? defaultUrl = null)
        => AgentUpdateTrustFactory.ResolveConfiguredManifestUrl(envUrl, legacyEnvUrl, registryUrl, defaultUrl);

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
