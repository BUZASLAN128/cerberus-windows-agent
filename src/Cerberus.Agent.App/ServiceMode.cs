using Cerberus.Agent.Core;
using Cerberus.Agent.App.Diagnostics;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Control;
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
        using var log = AgentFileLogger.CreateService(alsoConsole: true);
        var lifecycle = new DurableAgentLifecycleStateStore();
        await AgentCredentialPublication.RecoverAsync(lifecycle, ct).ConfigureAwait(false);
        // Load deny intent before even attempting credential decryption.
        _ = await lifecycle.LoadAsync(ct).ConfigureAwait(false);
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(ct);
        CancellationTokenSource? automatic = null;
        Task? worker = null;
        long? workerGeneration = null;
        var nextCleanupUtc = DateTimeOffset.MinValue;
        var cleanupDelaySeconds = 10;
        async Task QuiesceAsync(CancellationToken _)
        {
            automatic?.Cancel();
            await AgentUpdateLocalService.QuiesceAsync(lifetime.Token).ConfigureAwait(false);
        }
        var controller = new AgentLifecycleController(lifecycle,
            new DpapiSecretStore(SecretStoreScope.Machine), log, QuiesceAsync);
        var control = new AgentLocalControlService(lifecycle, QuiesceAsync);
        var pipeTask = new AgentLocalControlServer(control.HandleAsync).RunAsync(lifetime.Token);
        Task? schedulerTask = null;
        try
        {
            await AgentUpdateLocalService.ReconcileOnServiceStartAsync(lifetime.Token).ConfigureAwait(false);
            schedulerTask = AgentUpdateLocalService.RunScheduledAsync(lifetime.Token);
            while (!ct.IsCancellationRequested)
            {
                if (pipeTask.IsCompleted)
                    throw new InvalidOperationException("Local control listener stopped.", pipeTask.Exception);
                if (schedulerTask.IsFaulted)
                    throw new InvalidOperationException("Update scheduler stopped.", schedulerTask.Exception);
                if (AgentCredentialPublication.RecoveryRequired)
                    await AgentCredentialPublication.RecoverAsync(lifecycle, ct).ConfigureAwait(false);
                var snapshot = await lifecycle.LoadAsync(ct).ConfigureAwait(false);
                if (worker is not null && workerGeneration != snapshot.Generation)
                    automatic?.Cancel();
                if (!snapshot.QuiescenceComplete && DateTimeOffset.UtcNow >= nextCleanupUtc)
                {
                    try { snapshot = await controller.CompletePendingQuiescenceAsync(lifetime.Token).ConfigureAwait(false); }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        log.Warn($"Lifecycle cleanup remains pending ({ex.GetType().Name}).");
                    }
                    nextCleanupUtc = DateTimeOffset.UtcNow.AddSeconds(cleanupDelaySeconds);
                    cleanupDelaySeconds = Math.Min(60, cleanupDelaySeconds * 2);
                }
                if (snapshot.QuiescenceComplete)
                    cleanupDelaySeconds = 10;
                var promotion = await AgentEnrollmentPromotion.ReadAsync(ct).ConfigureAwait(false);
                var awaitingAdoption = AgentEnrollmentPromotion.IsAwaitingAdoption(promotion, snapshot);
                if (AgentLifecycleStates.AllowsAutomaticNetwork(snapshot.State) && snapshot.QuiescenceComplete && !awaitingAdoption)
                {
                    if (worker is null || worker.IsCompleted)
                    {
                        if (worker?.IsFaulted == true && worker.Exception?.GetBaseException() is not OperationCanceledException)
                            await worker.ConfigureAwait(false);
                        automatic?.Dispose();
                        automatic = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
                        workerGeneration = snapshot.Generation;
                        worker = RunAutomaticAsync(automatic.Token, lifecycle, QuiesceAsync);
                    }
                }
                else
                {
                    automatic?.Cancel();
                    if (worker is not null && worker.IsCompleted)
                    {
                        if (worker.IsFaulted && worker.Exception?.GetBaseException() is not OperationCanceledException)
                            await worker.ConfigureAwait(false);
                        worker = null;
                    }
                }
                await Task.Delay(TimeSpan.FromSeconds(2), lifetime.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        finally
        {
            lifetime.Cancel();
            automatic?.Cancel();
            foreach (var task in new[] { worker, schedulerTask, pipeTask })
            {
                if (task is null) continue;
                try { await task.ConfigureAwait(false); }
                catch (OperationCanceledException) { }
            }
            automatic?.Dispose();
        }
    }

    private static async Task RunAutomaticAsync(CancellationToken ct, IAgentLifecycleStateStore lifecycleState,
        Func<CancellationToken, Task> quiesce)
    {
        using var log = AgentFileLogger.CreateService(alsoConsole: true);
        log.Info("Service mode starting.");

        var persistedLifecycle = await lifecycleState.LoadAsync(ct).ConfigureAwait(false);
        if (!AgentLifecycleStates.AllowsAutomaticNetwork(persistedLifecycle.State))
        {
            log.Warn($"Service starting dormant; lifecycle state={persistedLifecycle.State}.");
            await RunDormantAsync(ct).ConfigureAwait(false);
            return;
        }

        var secrets = new DpapiSecretStore(SecretStoreScope.Machine);
        (AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey) loadedSecrets;
        try
        {
            loadedSecrets = await secrets.LoadAsync(ct).ConfigureAwait(false);
        }
        catch (FileNotFoundException)
        {
            await lifecycleState.TransitionAsync(
                AgentLifecycleState.NeedsReenrollment,
                reasonCode: "credentials_missing",
                requestId: null,
                nextAttemptUtc: null,
                genericAuthFailureCount: null,
                ct).ConfigureAwait(false);
            log.Warn("Service starting dormant; machine credentials are not enrolled.");
            await RunDormantAsync(ct).ConfigureAwait(false);
            return;
        }
        catch (DirectoryNotFoundException)
        {
            await lifecycleState.TransitionAsync(
                AgentLifecycleState.NeedsReenrollment,
                reasonCode: "credentials_missing",
                requestId: null,
                nextAttemptUtc: null,
                genericAuthFailureCount: null,
                ct).ConfigureAwait(false);
            log.Warn("Service starting dormant; machine credentials are not enrolled.");
            await RunDormantAsync(ct).ConfigureAwait(false);
            return;
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            await lifecycleState.TransitionAsync(
                AgentLifecycleState.NeedsReenrollment,
                reasonCode: "credentials_unavailable",
                requestId: null,
                nextAttemptUtc: null,
                genericAuthFailureCount: null,
                ct).ConfigureAwait(false);
            log.Warn("Service starting dormant; machine credentials are unavailable.");
            await RunDormantAsync(ct).ConfigureAwait(false);
            return;
        }
        catch (InvalidOperationException)
        {
            await lifecycleState.TransitionAsync(
                AgentLifecycleState.NeedsReenrollment,
                reasonCode: "credentials_invalid",
                requestId: null,
                nextAttemptUtc: null,
                genericAuthFailureCount: null,
                ct).ConfigureAwait(false);
            log.Warn("Service starting dormant; machine credentials could not be decoded.");
            await RunDormantAsync(ct).ConfigureAwait(false);
            return;
        }
        catch (System.Text.Json.JsonException)
        {
            await lifecycleState.TransitionAsync(
                AgentLifecycleState.NeedsReenrollment,
                reasonCode: "credentials_invalid",
                requestId: null,
                nextAttemptUtc: null,
                genericAuthFailureCount: null,
                ct).ConfigureAwait(false);
            log.Warn("Service starting dormant; machine credentials are malformed.");
            await RunDormantAsync(ct).ConfigureAwait(false);
            return;
        }

        if (string.IsNullOrWhiteSpace(loadedSecrets.Identity.AgentId) ||
            string.IsNullOrWhiteSpace(loadedSecrets.Identity.TenantId) ||
            string.IsNullOrWhiteSpace(loadedSecrets.RefreshToken) ||
            string.IsNullOrWhiteSpace(loadedSecrets.PrivateKeyPem) ||
            string.IsNullOrWhiteSpace(loadedSecrets.BackendUrl))
        {
            await lifecycleState.TransitionAsync(
                AgentLifecycleState.NeedsReenrollment,
                reasonCode: "credentials_invalid",
                requestId: null,
                nextAttemptUtc: null,
                genericAuthFailureCount: null,
                ct).ConfigureAwait(false);
            log.Warn("Service starting dormant; machine credentials are incomplete.");
            await RunDormantAsync(ct).ConfigureAwait(false);
            return;
        }

        var privateKeyPem = loadedSecrets.PrivateKeyPem;
        var storedBackendUrl = loadedSecrets.BackendUrl;
        var backendUrl = Environment.GetEnvironmentVariable("CERBERUS_BACKEND_URL") ?? storedBackendUrl;

        if (!Uri.TryCreate(backendUrl.Trim().TrimEnd('/'), UriKind.Absolute, out var baseAddress) ||
            (baseAddress.Scheme != Uri.UriSchemeHttp && baseAddress.Scheme != Uri.UriSchemeHttps))
        {
            await lifecycleState.TransitionAsync(
                AgentLifecycleState.BlockedConfig,
                reasonCode: "backend_url_invalid",
                requestId: null,
                nextAttemptUtc: null,
                genericAuthFailureCount: null,
                ct).ConfigureAwait(false);
            log.Warn("Service starting dormant; configured backend URL is invalid.");
            await RunDormantAsync(ct).ConfigureAwait(false);
            return;
        }

        // Never send registered credentials to an environment selected by a different package or override.
        if (!AgentBuildConfig.SameEndpoint(backendUrl, storedBackendUrl) ||
            (!string.IsNullOrWhiteSpace(AgentBuildConfig.BackendUrl) &&
             !AgentBuildConfig.SameEndpoint(storedBackendUrl, AgentBuildConfig.BackendUrl)))
        {
            await lifecycleState.TransitionAsync(
                AgentLifecycleState.BlockedConfig,
                reasonCode: "backend_environment_mismatch",
                requestId: null,
                nextAttemptUtc: null,
                genericAuthFailureCount: null,
                ct).ConfigureAwait(false);
            log.Warn("Service starting dormant; deployment differs from registered credentials. Use the matching package or explicitly re-enroll. Existing registration was preserved.");
            await RunDormantAsync(ct).ConfigureAwait(false);
            return;
        }

        using var http = new HttpClient { BaseAddress = baseAddress, Timeout = TimeSpan.FromSeconds(30) };
        using var updateHttp = new HttpClient
        {
            BaseAddress = baseAddress,
            Timeout = ReadTimeSpanFromSeconds("CERBERUS_AGENT_UPDATE_TIMEOUT_SECONDS", TimeSpan.FromMinutes(10)),
        };

        var signer = new RequestSigner(privateKeyPem);
        var tokens = new AgentTokenManager(http, secrets, lifecycleState: lifecycleState, quiesce: quiesce);
        var api = new AgentApiClient(http, secrets, tokens, signer, lifecycleState, quiesce: quiesce);
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
                    ReportUpdateFailureAsync(api, metadata, response, exception, cancel),
                lifecycleState: lifecycleState,
                quiesce: quiesce),
            telemetryProvider: new WindowsTelemetryCollector(),
            telemetryBuffer: telemetryBuffer,
            log: log,
            commandTimeout: TimeSpan.FromSeconds(120),
            backoffResetRequested: HeartbeatBackoffResetSignal.ConsumeDefaultAsync,
            metadata: metadata,
            lifecycleState: lifecycleState);

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

    private static async Task RunDormantAsync(CancellationToken ct)
    {
        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            // Dormant service remains healthy until SCM requests stop.
        }
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
