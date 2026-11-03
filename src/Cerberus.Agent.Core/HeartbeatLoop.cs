namespace Cerberus.Agent.Core;

public sealed partial class HeartbeatLoop
{
    private readonly AgentApiClient _api;
    private readonly CommandDispatcher _dispatcher;
    private readonly TimeSpan _minDelayOnError;
    private readonly TimeSpan _maxDelayOnError;
    private readonly IAgentLogger _log;
    private readonly IAgentStatusProvider? _status;
    private readonly Func<CancellationToken, Task<object?>>? _adStatusProvider;
    private readonly Func<CancellationToken, Task<object?>>? _updateStatusProvider;
    private readonly string _agentVersion;
    private readonly string _buildId;
    private readonly string _buildChannel;
    private readonly AgentBuildMetadata _metadata;
    private readonly HeartbeatResponseHandler? _responseHandler;
    private readonly IAgentTelemetryProvider? _telemetryProvider;
    private readonly OfflineTelemetryBuffer? _telemetryBuffer;
    private readonly IHeartbeatCommandProcessor _commandProcessor;
    private readonly AgentTimingPolicy _timing;
    private readonly TimeSpan _initialSnapshotDelay;
    private readonly Func<CancellationToken, Task<bool>>? _backoffResetRequested;
    private readonly IAgentLifecycleStateStore? _lifecycleState;
    private readonly bool _automaticNetwork;
    private readonly AgentWakeupSignal? _wakeupSignal;
    private readonly AgentWakeupClient? _wakeupClient;
    private readonly bool _signedStateOnly;
    private readonly bool _supportsEvents;
    private readonly bool _signedCommandMode;
    private readonly bool _signedCommandsOnly;
    private readonly bool _legacyAsyncSupported;
    private readonly Func<bool> _legacyAsyncReady;
    private readonly AgentSignedStateStore? _signedState;
    private readonly bool _supportsUpdateInstall;
    private readonly TimeProvider _time;
    private readonly Func<double> _retryJitter;

    public HeartbeatLoop(
        AgentApiClient api,
        CommandDispatcher dispatcher,
        TimeSpan minDelayOnError,
        IAgentStatusProvider? statusProvider = null,
        Func<CancellationToken, Task<object?>>? adStatusProvider = null,
        Func<CancellationToken, Task<object?>>? updateStatusProvider = null,
        string agentVersion = "0.0.0",
        string buildId = "unknown",
        string buildChannel = "dev",
        HeartbeatResponseHandler? responseHandler = null,
        IAgentTelemetryProvider? telemetryProvider = null,
        OfflineTelemetryBuffer? telemetryBuffer = null,
        IAgentLogger? log = null,
        TimeSpan? commandTimeout = null,
        int commandConcurrency = 2,
        TimeSpan? initialSnapshotDelay = null,
        TimeSpan? maxDelayOnError = null,
        Func<CancellationToken, Task<bool>>? backoffResetRequested = null,
        AgentBuildMetadata? metadata = null,
        IAgentLifecycleStateStore? lifecycleState = null,
        bool automaticNetwork = true,
        IHeartbeatCommandProcessor? commandProcessor = null,
        AgentTimingPolicy? timingPolicy = null,
        AgentWakeupSignal? wakeupSignal = null,
        AgentWakeupClient? wakeupClient = null,
        bool signedStateOnly = false,
        bool supportsEvents = true,
        bool signedCommandMode = false,
        bool signedCommandsOnly = false,
        bool legacyAsyncSupported = false,
        Func<bool>? legacyAsyncReady = null,
        AgentSignedStateStore? signedState = null,
        bool supportsUpdateInstall = false,
        TimeProvider? timeProvider = null,
        Func<double>? retryJitter = null)
    {
        _timing = timingPolicy ?? AgentTimingPolicy.Current;
        _time = timeProvider ?? TimeProvider.System;
        _retryJitter = retryJitter ?? Random.Shared.NextDouble;
        _api = api;
        _dispatcher = dispatcher;
        _minDelayOnError = minDelayOnError <= TimeSpan.Zero
            ? TimeSpan.FromSeconds(10)
            : minDelayOnError;
        _maxDelayOnError = maxDelayOnError is null || maxDelayOnError.Value < _minDelayOnError
            ? TimeSpan.FromMinutes(10)
            : maxDelayOnError.Value;
        _status = statusProvider;
        _adStatusProvider = adStatusProvider;
        _updateStatusProvider = updateStatusProvider;
        _metadata = metadata ?? new AgentBuildMetadata(
            AgentVersion: string.IsNullOrWhiteSpace(agentVersion) ? "0.0.0" : agentVersion,
            BuildId: string.IsNullOrWhiteSpace(buildId) ? (string.IsNullOrWhiteSpace(agentVersion) ? "0.0.0" : agentVersion) : buildId,
            BuildChannel: string.IsNullOrWhiteSpace(buildChannel) ? "dev" : buildChannel,
            BootId: Guid.NewGuid().ToString("N"),
            SupportedSchemaVersions: AgentSchemaVersions.All);
        _agentVersion = _metadata.AgentVersion;
        _buildId = _metadata.BuildId;
        _buildChannel = _metadata.BuildChannel;
        _responseHandler = responseHandler;
        _telemetryProvider = telemetryProvider;
        _telemetryBuffer = telemetryBuffer;
        _log = log ?? NullAgentLogger.Instance;
        _commandProcessor = commandProcessor ?? new LegacyHeartbeatCommandProcessor(
            api,
            dispatcher,
            commandTimeout is null || commandTimeout.Value <= TimeSpan.Zero ? TimeSpan.FromSeconds(120) : commandTimeout.Value,
            Math.Clamp(commandConcurrency, 1, 8));
        _initialSnapshotDelay = initialSnapshotDelay is null || initialSnapshotDelay.Value < TimeSpan.Zero
            ? TimeSpan.FromSeconds(60)
            : initialSnapshotDelay.Value;
        _backoffResetRequested = lifecycleState is null ? backoffResetRequested : null;
        _lifecycleState = lifecycleState;
        _automaticNetwork = automaticNetwork;
        _wakeupSignal = wakeupClient is not null && wakeupSignal is null
            ? throw new ArgumentException("A wakeup client requires its signal.", nameof(wakeupSignal))
            : wakeupSignal;
        _wakeupClient = wakeupClient;
        _signedStateOnly = signedStateOnly;
        _supportsEvents = supportsEvents;
        _signedCommandMode = signedCommandMode;
        _signedCommandsOnly = signedCommandsOnly;
        _legacyAsyncSupported = legacyAsyncSupported;
        _legacyAsyncReady = legacyAsyncReady ?? (() => true);
        _signedState = signedState;
        _supportsUpdateInstall = AgentBuildProfile.IsServer && supportsUpdateInstall &&
            dispatcher.HandlerTypes.Contains(EnvelopeTypes.AgentUpdateRequest);
    }

    public async Task RunAsync(CancellationToken ct)
    {
        var degraded = false;
        var startedEventSent = false;
        var consecutiveHeartbeatErrors = _lifecycleState is null ? 0 :
            (await _lifecycleState.LoadAsync(ct).ConfigureAwait(false)).TransientFailureCount;
        var nextSnapshotAt = DateTimeOffset.UtcNow.Add(_initialSnapshotDelay);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                if (!await WaitForLifecycleGateAsync(ct).ConfigureAwait(false))
                    return;

                object? tailscale = null;
                if (_status is not null && _signedState?.RecoveryControlOnly != true)
                {
                    try
                    {
                        tailscale = await _status.GetTailscaleAsync(ct);
                    }
                    catch (Exception ex)
                    {
                        _log.Warn($"Status provider error: {ex.GetType().Name}.");
                    }
                }

                var recoveringState = _signedState?.RequiresRecovery == true;
                var controlRecovery = _signedState?.RecoveryControlOnly == true;
                var supported = AgentSchemaVersions.All.AsEnumerable();
                if (_wakeupClient is not null) supported = supported.Append(AgentWakeupProtocol.Capability);
                if (_signedCommandMode) supported = supported.Append(CommandEnvelope.Capability);
                if (_signedCommandsOnly) supported = supported.Append(CommandEnvelope.SignedOnlyCapability);
                var legacyAsyncAvailable = !controlRecovery && _legacyAsyncSupported && _legacyAsyncReady();
                if (legacyAsyncAvailable) supported = supported.Append(LegacyAsyncCommandProcessor.Capability);
                IReadOnlyList<string> capabilities = _dispatcher.HandlerTypes;
                if (_supportsUpdateInstall) capabilities = capabilities.Append("agent.update.install.v1").ToArray();
                var hbReq = new Dictionary<string, object?>
                {
                    ["status"] = degraded || recoveringState ? "degraded" : "connected",
                    ["agent_version"] = _agentVersion,
                    ["build_id"] = _buildId,
                    ["build_channel"] = _buildChannel,
                    ["runtime_mode"] = "service",
                    ["supported_schema_versions"] = supported.ToArray(),
                    ["tailscale"] = tailscale,
                    ["ad"] = controlRecovery || _adStatusProvider is null ? null : await _adStatusProvider(ct),
                    ["update_status"] = controlRecovery || _updateStatusProvider is null ? null : await _updateStatusProvider(ct),
                    ["capabilities"] = capabilities,
                    ["signed_state_reset"] = recoveringState,
                    ["signed_state_floor"] = recoveringState ? _signedState!.RecoveryFloor : 0,
                    ["signed_state_recovery_rejections"] = _commandProcessor is EnvelopeCommandProcessor envelopes &&
                        envelopes.RejectionCounts.TryGetValue(EnvelopeCodes.StateRecoveryRequired, out var rejected) ? rejected : 0,
                };

                var heartbeatStarted = System.Diagnostics.Stopwatch.GetTimestamp();
                var hb = await _api.HeartbeatAsync(hbReq, ct);
                AgentBackendContact.MarkSuccess();

                degraded = false;
                consecutiveHeartbeatErrors = 0;
                await ClearPersistedRetryAsync(ct).ConfigureAwait(false);

                if (recoveringState)
                {
                    _signedState!.SetRecoverySourceSupported(hb.SignedStateRecovery == true);
                    if (hb.SignedStateRecovery == true || _signedState.HasPendingControl)
                    {
                        if (!await WaitForLifecycleGateAsync(ct).ConfigureAwait(false)) return;
                        if (_wakeupClient is not null) await _wakeupClient.StopAsync(ct).ConfigureAwait(false);
                        // No unsigned update, manifest, lease, telemetry or business command during recovery.
                        // Let the signed processor reject ordinary envelopes visibly; it still runs only state recovery.
                        await _commandProcessor.ProcessAsync(hb.PendingCommands, ct).ConfigureAwait(false);
                        await Task.Delay(_timing.ClampContactDelay(TimeSpan.FromSeconds(Math.Max(30, _timing.Bounds.PollFloor))), _time, ct).ConfigureAwait(false);
                        continue;
                    }
                }

                var control = _responseHandler is null
                    ? HeartbeatControlAction.Continue
                    : await _responseHandler.HandleAsync(hb, ct).ConfigureAwait(false);
                if (control == HeartbeatControlAction.SkipCommands)
                    _commandProcessor.SetExecutionPaused(true);
                if (control == HeartbeatControlAction.Stop)
                {
                    if (_wakeupClient is not null)
                        await _wakeupClient.StopAsync(ct).ConfigureAwait(false);
                    return;
                }

                if (!await WaitForLifecycleGateAsync(ct).ConfigureAwait(false))
                    return;

#if !CERBERUS_SERVER_PROFILE
                if (!_signedStateOnly && string.Equals(hb.VersionPolicy?.Decision, "upgrade_required", StringComparison.Ordinal))
                {
                    _commandProcessor.SetExecutionPaused(true);
                    if (_wakeupClient is not null)
                        await _wakeupClient.StopAsync(ct).ConfigureAwait(false);
                    _log.Warn(
                        $"Agent version blocked by server policy: version={_agentVersion}, reason={hb.VersionPolicy?.Reason ?? "unknown"}");
                    _commandProcessor.SignalOutbox();
                    var blockedDelay =_timing.PollDelaySeconds(ApplyJitter(Math.Max(hb.NextPollSeconds, 300), 0.20), 300);
                    await Task.Delay(TimeSpan.FromSeconds(blockedDelay), _time, ct);
                    _wakeupSignal?.Clear();
                    continue;
                }
#endif

                var skipCommands = control == HeartbeatControlAction.SkipCommands;
                if (!skipCommands) _commandProcessor.SetExecutionPaused(false);

                await TryFlushTelemetryBufferAsync(ct).ConfigureAwait(false);

                if (_supportsEvents && !startedEventSent)
                {
                    await TrySubmitEventAsync(
                        "agent.started",
                        "info",
                        new Dictionary<string, object?>
                        {
                            ["boot_id"] = _metadata.BootId,
                            ["agent_version"] = _agentVersion,
                        },
                        idempotencyKey: $"agent.started:{_metadata.BootId}",
                        ct: ct).ConfigureAwait(false);
                    startedEventSent = true;
                }

                var now = DateTimeOffset.UtcNow;
                var snapshotTrigger = _telemetryProvider as IAgentTelemetrySnapshotTrigger;
                var snapshotRefreshRequired = false;
                if (snapshotTrigger is not null)
                {
                    try
                    {
                        _telemetryProvider!.ConfigureSnapshot(TelemetryHeartbeat(hb));
                        snapshotRefreshRequired = snapshotTrigger.IsSnapshotRefreshRequired();
                    }
                    catch (Exception ex)
                    {
                        _log.Warn($"Snapshot refresh check failed: {ex.GetType().Name}: {ex.Message}");
                    }
                }

                if (_telemetryProvider is not null && (now >= nextSnapshotAt || snapshotRefreshRequired))
                {
                    var snapshotSubmitted = await TrySubmitSnapshotAsync(hb, ct).ConfigureAwait(false);
                    if (snapshotSubmitted && snapshotTrigger is not null)
                    {
                        try
                        {
                            snapshotTrigger.MarkSnapshotSubmitted();
                        }
                        catch (Exception ex)
                        {
                            _log.Warn($"Snapshot refresh acknowledgement failed: {ex.GetType().Name}: {ex.Message}");
                        }
                    }
                    nextSnapshotAt = now.AddSeconds(SnapshotDelayWithJitter(_timing, hb.NextSnapshotSeconds));
                }

                if (skipCommands)
                {
                    if (_wakeupClient is not null)
                        await _wakeupClient.StopAsync(ct).ConfigureAwait(false);
                    _commandProcessor.SignalOutbox();
                    var controlDelay = _timing.PollDelaySeconds(ApplyJitter(Math.Max(hb.NextPollSeconds, 60), 0.20), 60);
                    await Task.Delay(TimeSpan.FromSeconds(controlDelay), _time, ct);
                    _wakeupSignal?.Clear();
                    continue;
                }

                if (_wakeupClient is not null)
                    await _wakeupClient.ConfigureAsync(hb.Wakeup, ct).ConfigureAwait(false);
                var commands = legacyAsyncAvailable
                    ? BindLeaseDeadlines(hb.PendingCommands, hb.ServerTime, heartbeatStarted)
                    : hb.PendingCommands;
                await _commandProcessor.ProcessAsync(commands, ct).ConfigureAwait(false);

                var delay = _timing.PollDelaySeconds(ApplyJitter(hb.NextPollSeconds, 0.20));
                if (_wakeupSignal is null)
                    await Task.Delay(TimeSpan.FromSeconds(delay), _time, ct);
                else
                {
                    // Hints share a five-second minimum from the last poll, independently of
                    // profile bounds. An earlier ordinary polling deadline still wins.
                    var pollDelay = TimeSpan.FromSeconds(delay);
                    var remaining = TimeSpan.FromSeconds(5) - System.Diagnostics.Stopwatch.GetElapsedTime(heartbeatStarted);
                    var floor = remaining <= TimeSpan.Zero ? TimeSpan.Zero : remaining < pollDelay ? remaining : pollDelay;
                    await Task.Delay(floor, _time, ct).ConfigureAwait(false);
                    await _wakeupSignal.WaitAsync(pollDelay - floor, ct).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (AgentRetiredException)
            {
                _log.Warn("Heartbeat loop entering retired dormant state.");
                return;
            }
            catch (AgentLifecycleDormantException ex)
            {
                _log.Warn($"Heartbeat loop entering dormant state={ex.State}.");
                return;
            }
            catch (AgentRegistrationChangedException)
            {
                _log.Warn("Heartbeat worker stopped because its registration changed.");
                return;
            }
            catch (Exception ex)
            {
                if (_wakeupClient is not null)
                    await _wakeupClient.StopAsync(CancellationToken.None).ConfigureAwait(false);
                degraded = true;
                consecutiveHeartbeatErrors++;
                await RecordTransientLifecycleFailureAsync(ex, ct).ConfigureAwait(false);
                if (await StopForPersistedLifecycleAsync(ct).ConfigureAwait(false))
                    return;

                var retryDelay = CalculateRetryDelay(ex, consecutiveHeartbeatErrors);
                _wakeupSignal?.Clear();
                await PersistRetryAsync(retryDelay, ct).ConfigureAwait(false);
                _log.Warn($"Heartbeat loop error: {ex.GetType().Name}. Next retry in {FormatDelay(retryDelay)}. at={ExceptionSite.FirstFrame(ex)}");
                bool resetRequested;
                try
                {
                    resetRequested = await DelayForErrorBackoffAsync(retryDelay, ct).ConfigureAwait(false);
                    _wakeupSignal?.Clear();
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    return;
                }

                if (resetRequested)
                {
                    consecutiveHeartbeatErrors = 0;
                    await ClearPersistedRetryAsync(ct).ConfigureAwait(false);
                    _log.Info("Heartbeat retry backoff reset requested.");
                }
            }
        }
    }

    internal static IReadOnlyList<AgentCommand> BindLeaseDeadlines(IReadOnlyList<AgentCommand> commands,
        long serverTime, long heartbeatStarted)
    {
        return commands.Select(command =>
        {
            if (serverTime <= 0 || command.LeaseExpiresAtUnix is not { } expiry || expiry <= serverTime)
                return command;
            // Start the countdown before the HTTP request, not when the reply arrives. The
            // server timestamp is rounded to seconds, so reserve two extra seconds.
            var seconds = Math.Clamp(expiry - serverTime - 2, 0, 3600);
            return command with { SafeLeaseDeadlineTimestamp = heartbeatStarted + seconds * System.Diagnostics.Stopwatch.Frequency };
        }).ToArray();
    }
}
