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
#if CERBERUS_SERVER_PROFILE
        // Before anything writes under the data folder, the logger included. The faulted worker ends the process
        // (WindowsServiceHost), so SCM records the failure and applies its recovery.
        ServerServiceStartup.EnsureDataRoot(() => ServerDataRoot.EnsureProtected());
#endif
        // Gate direct service/console startup before the logger can create machine directories.
        AgentUpdateSecurity.EnsureProtectedRoot(AgentUpdateSecurity.DefaultPrivilegedRoot);
        using var log = AgentFileLogger.CreateService(alsoConsole: true);
        var lifecycle = new DurableAgentLifecycleStateStore();
        // Legacy installs may have no lifecycle file yet. Materialize the
        // canonical protected record before recovery, pipe startup or readiness.
        await lifecycle.EnsureInitializedAsync(ct).ConfigureAwait(false);
        await AgentCredentialPublication.RecoverAsync(lifecycle, ct).ConfigureAwait(false);
        // Load deny intent before even attempting credential decryption.
        _ = await lifecycle.LoadAsync(ct).ConfigureAwait(false);
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(ct);
        CancellationTokenSource? automatic = null;
        Task? worker = null;
        long? workerGeneration = null;
        var finalRevokes = new AgentRevokeFinalResults();
        var restartBackoff = new WorkerRestartBackoff();
        var workerStartedUtc = DateTimeOffset.MinValue;
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
        var recovery = AgentBuildProfile.IsServer ? new DormantRecoverySupervisor(lifecycle, controller,
            new DpapiSecretStore(SecretStoreScope.Machine), control.ManualGate, log) : null;
        var pipeTask = new AgentLocalControlServer(control.HandleAsync).RunAsync(lifetime.Token);
        Task? schedulerTask = null;
        try
        {
#if CERBERUS_SERVER_PROFILE
            WindowsUpdateCache.Shared.Start(log);
#endif
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
                if (recovery is not null)
                    snapshot = await recovery.TickAsync(snapshot, awaitingAdoption, lifetime.Token).ConfigureAwait(false);
                if (AgentLifecycleStates.AllowsAutomaticNetwork(snapshot.State) && snapshot.QuiescenceComplete && !awaitingAdoption)
                {
                    if (worker is null || worker.IsCompleted)
                    {
                        if (worker?.IsFaulted == true && worker.Exception?.GetBaseException() is not OperationCanceledException)
                            await worker.ConfigureAwait(false);
                        // Server: a worker that ends by itself after a short run (revoke not recorded) restarts with a growing delay.
                        if (worker is not null && AgentBuildProfile.IsServer)
                        {
                            restartBackoff.OnWorkerEnded(workerStartedUtc, DateTimeOffset.UtcNow,
                                planned: automatic?.IsCancellationRequested == true || workerGeneration != snapshot.Generation);
                            worker = null;
                        }
                        if (restartBackoff.CanStart(DateTimeOffset.UtcNow))
                        {
                            automatic?.Dispose();
                            automatic = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
                            workerGeneration = snapshot.Generation;
                            workerStartedUtc = DateTimeOffset.UtcNow;
                            worker = RunAutomaticAsync(automatic.Token, lifecycle, QuiesceAsync, finalRevokes);
                        }
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
        Func<CancellationToken, Task> quiesce, AgentRevokeFinalResults finalRevokes)
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
        var environmentBackendUrl = Environment.GetEnvironmentVariable("CERBERUS_BACKEND_URL");
        if (AgentBuildProfile.IsServer && ServerBackendMigration.ShouldMigrate(storedBackendUrl, AgentBuildConfig.BackendUrl, environmentBackendUrl))
        {
            try
            {
                var migration = await ServerBackendMigration.MigrateIfCurrentAsync(lifecycleState, persistedLifecycle.Generation,
                    secrets, AgentBuildConfig.BackendUrl, environmentBackendUrl, log, ct).ConfigureAwait(false);
                if (migration == ServerBackendMigration.Result.Superseded)
                    return; // The lifecycle generation changed; the supervisor starts a worker for the new one.
                if (migration == ServerBackendMigration.Result.Migrated)
                    storedBackendUrl = AgentBuildConfig.BackendUrl.Trim();
            }
            catch (Exception ex) when (ServerBackendMigration.IsStoreFailure(ex))
            {
                log.Warn($"Registered backend address could not be updated ({ex.GetType().Name}).");
            }
        }
        var backendUrl = environmentBackendUrl ?? storedBackendUrl;

        var blockReason = BackendConfigCheck.BlockReason(environmentBackendUrl, storedBackendUrl, AgentBuildConfig.BackendUrl);
        if (blockReason is not null)
        {
            await lifecycleState.TransitionAsync(
                AgentLifecycleState.BlockedConfig,
                reasonCode: blockReason,
                requestId: null,
                nextAttemptUtc: null,
                genericAuthFailureCount: null,
                ct).ConfigureAwait(false);
            log.Warn(blockReason == BackendConfigCheck.UrlInvalid
                ? "Service starting dormant; configured backend URL is invalid."
                : "Service starting dormant; deployment differs from registered credentials. Use the matching package or explicitly re-enroll. Existing registration was preserved.");
            await RunDormantAsync(ct).ConfigureAwait(false);
            return;
        }
        var baseAddress = new Uri(backendUrl.Trim().TrimEnd('/'));

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

        var dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            AgentInstallIdentity.DataDirName);
        var idempotency = new IdempotencyCache(Path.Combine(dataDir, "idempotency.json"), maxEntries: 5000, ttl: TimeSpan.FromHours(24));
        var telemetryBuffer = new OfflineTelemetryBuffer(Path.Combine(dataDir, "telemetry-offline.json"),
            maxEntries: 200, maxBytes: 8 * AgentTelemetryLimits.MaxSnapshotBytes, ttl: TimeSpan.FromHours(24));

        var signedState = new AgentSignedStateStore(AgentSignedStateStore.DefaultPath(), log);
        var currentAgentId = signedState.Track(EnvelopeWiring.CurrentAgentId(secrets));
        // Declared before the queue so it is disposed after the queue worker has drained.
        using var serviceCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        EnvelopeExecutionQueue? queue = null;
#if CERBERUS_SERVER_PROFILE
        ManagedAccountManifestPolicy? managedAccounts = null;
        var agentState = new AgentStateCommandHandler(signedState, currentAgentId,
            new AgentLifecycleController(lifecycleState, secrets, log, quiesce), () => queue?.CancelAll(), log,
            stopAutomaticNetwork: serviceCts.Cancel, finalResults: finalRevokes);
        var handlers = AgentCommandRegistry.CreateServer(metadata, agentState);
#else
        var diagnosticUploader = new AgentDiagnosticBundleUploader(api, metadata);
        var managedAccounts = new ManagedAccountManifestPolicy(loadedSecrets.Identity, lifecycleState,
            api.GetManagedAccountManifestAsync, LocalUserCommandHandlers.CreateManifestReconciler(log), log);
        var handlers = AgentCommandRegistry.CreateDesktop(api, loadedSecrets.Identity, lifecycleState, managedAccounts,
            diagnosticUploader, () => BuildUpdateCoordinator(updateHttp, log, updateStateStore), updateStateStore, log, agentVersion);
#endif
        var dispatcher = new CommandDispatcher(handlers, idempotency);
        await using var envelopeQueue = EnvelopeWiring.StartQueue(api, handlers, currentAgentId, signedState, log);
        queue = envelopeQueue;
#if CERBERUS_SERVER_PROFILE
        var revokeAgentId = loadedSecrets.Identity.AgentId;
        var startup = new ServerServiceStartup(
            () => signedState.Load(revokeAgentId).PendingRevoke is not null,
            envelopeQueue.DrainOutboxOnceAsync,
            c => agentState.RecoverPendingRevokeAsync(envelopeQueue.Store, c),
            () => envelopeQueue.Store.IsAvailable, () => serviceCts.IsCancellationRequested, serviceCts.Cancel, log);
        // Revoke not recorded: the supervisor restarts the worker (with a growing delay), which retries it before any request.
        if (!await startup.RecoverPendingRevokeAsync(serviceCts.Token, ct).ConfigureAwait(false))
        {
            log.Info("Service mode stopped.");
            return;
        }
#endif
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
                    cancel).ConfigureAwait(false))?.ToHeartbeatStatus(),
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
                quiesce: quiesce,
                managedAccounts: managedAccounts),
            telemetryProvider: new WindowsTelemetryCollector(publishServiceObservation: true),
            telemetryBuffer: telemetryBuffer,
            log: log,
            backoffResetRequested: HeartbeatBackoffResetSignal.ConsumeDefaultAsync,
            metadata: metadata,
            lifecycleState: lifecycleState,
            commandProcessor: EnvelopeWiring.CreateProcessor(api, envelopeQueue, dispatcher, log));

#if CERBERUS_SERVER_PROFILE
        var diagnosticSchedulerTask = Task.CompletedTask;
#else
        var diagnosticSchedulerTask = new DiagnosticBundleScheduler(diagnosticUploader, log).RunAsync(serviceCts.Token);
#endif

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
