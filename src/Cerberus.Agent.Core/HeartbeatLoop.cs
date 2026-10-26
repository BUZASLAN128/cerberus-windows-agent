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
        AgentTimingPolicy? timingPolicy = null)
    {
        _timing = timingPolicy ?? AgentTimingPolicy.Current;
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
                if (_status is not null)
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

                var hbReq = new
                {
                    status = degraded ? "degraded" : "connected",
                    agent_version = _agentVersion,
                    build_id = _buildId,
                    build_channel = _buildChannel,
                    runtime_mode = "service",
                    supported_schema_versions = AgentSchemaVersions.All,
                    tailscale,
                    ad = _adStatusProvider is null ? null : await _adStatusProvider(ct),
                    update_status = _updateStatusProvider is null ? null : await _updateStatusProvider(ct),
                    capabilities = _dispatcher.HandlerTypes,
                };

                var hb = await _api.HeartbeatAsync(hbReq, ct);

                degraded = false;
                consecutiveHeartbeatErrors = 0;
                await ClearPersistedRetryAsync(ct).ConfigureAwait(false);

                var control = _responseHandler is null
                    ? HeartbeatControlAction.Continue
                    : await _responseHandler.HandleAsync(hb, ct).ConfigureAwait(false);
                if (control == HeartbeatControlAction.Stop)
                    return;

                if (!await WaitForLifecycleGateAsync(ct).ConfigureAwait(false))
                    return;

#if !CERBERUS_SERVER_PROFILE
                if (string.Equals(hb.VersionPolicy?.Decision, "upgrade_required", StringComparison.Ordinal))
                {
                    _log.Warn(
                        $"Agent version blocked by server policy: version={_agentVersion}, reason={hb.VersionPolicy?.Reason ?? "unknown"}");
                    _commandProcessor.SignalOutbox();
                    var blockedDelay =_timing.PollDelaySeconds(ApplyJitter(Math.Max(hb.NextPollSeconds, 300), 0.20), 300);
                    await Task.Delay(TimeSpan.FromSeconds(blockedDelay), ct);
                    continue;
                }
#endif

                var skipCommands = control == HeartbeatControlAction.SkipCommands;

                await TryFlushTelemetryBufferAsync(ct).ConfigureAwait(false);

                if (!startedEventSent)
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
                    nextSnapshotAt = now.AddSeconds(_timing.SnapshotDelaySeconds(hb.NextSnapshotSeconds));
                }

                if (skipCommands)
                {
                    _commandProcessor.SignalOutbox();
                    var controlDelay = _timing.PollDelaySeconds(ApplyJitter(Math.Max(hb.NextPollSeconds, 60), 0.20), 60);
                    await Task.Delay(TimeSpan.FromSeconds(controlDelay), ct);
                    continue;
                }

                await _commandProcessor.ProcessAsync(hb.PendingCommands, ct).ConfigureAwait(false);

                var delay = _timing.PollDelaySeconds(ApplyJitter(hb.NextPollSeconds, 0.20));
                await Task.Delay(TimeSpan.FromSeconds(delay), ct);
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
            catch (Exception ex)
            {
                degraded = true;
                consecutiveHeartbeatErrors++;
                await RecordTransientLifecycleFailureAsync(ex, ct).ConfigureAwait(false);
                if (await StopForPersistedLifecycleAsync(ct).ConfigureAwait(false))
                    return;

                var retryDelay = CalculateRetryDelay(ex, consecutiveHeartbeatErrors);
                await PersistRetryAsync(retryDelay, ct).ConfigureAwait(false);
                _log.Warn($"Heartbeat loop error: {ex.GetType().Name}. Next retry in {FormatDelay(retryDelay)}. at={ExceptionSite.FirstFrame(ex)}");
                bool resetRequested;
                try
                {
                    resetRequested = await DelayForErrorBackoffAsync(retryDelay, ct).ConfigureAwait(false);
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
}
