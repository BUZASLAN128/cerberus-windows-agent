using System.Security.Cryptography;

namespace Cerberus.Agent.Core;

public sealed class HeartbeatLoop
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
    private readonly TimeSpan _commandTimeout;
    private readonly int _commandConcurrency;
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
        bool automaticNetwork = true)
    {
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
        _commandTimeout = commandTimeout is null || commandTimeout.Value <= TimeSpan.Zero
            ? TimeSpan.FromSeconds(120)
            : commandTimeout.Value;
        _commandConcurrency = Math.Clamp(commandConcurrency, 1, 8);
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

                if (string.Equals(hb.VersionPolicy?.Decision, "upgrade_required", StringComparison.Ordinal))
                {
                    _log.Warn(
                        $"Agent version blocked by server policy: version={_agentVersion}, reason={hb.VersionPolicy?.Reason ?? "unknown"}");
                    var blockedDelay = ApplyJitter(Math.Max(hb.NextPollSeconds, 300), 0.20);
                    await Task.Delay(TimeSpan.FromSeconds(blockedDelay), ct);
                    continue;
                }

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
                if (_telemetryProvider is not null && now >= nextSnapshotAt)
                {
                    await TrySubmitSnapshotAsync(hb, ct).ConfigureAwait(false);
                    var snapshotDelay = Math.Max(hb.NextSnapshotSeconds, 60);
                    nextSnapshotAt = now.AddSeconds(snapshotDelay);
                }

                if (skipCommands)
                {
                    var controlDelay = ApplyJitter(Math.Max(hb.NextPollSeconds, 60), 0.20);
                    await Task.Delay(TimeSpan.FromSeconds(controlDelay), ct);
                    continue;
                }

                await DispatchPendingCommandsAsync(hb.PendingCommands, ct).ConfigureAwait(false);

                var delay = ApplyJitter(hb.NextPollSeconds, 0.20);
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
                _log.Warn($"Heartbeat loop error: {ex.GetType().Name}. Next retry in {FormatDelay(retryDelay)}.");
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

    public static TimeSpan CalculateErrorDelay(TimeSpan minDelay, TimeSpan maxDelay, int consecutiveFailures)
    {
        if (minDelay <= TimeSpan.Zero)
            minDelay = TimeSpan.FromSeconds(10);
        if (maxDelay < minDelay)
            maxDelay = minDelay;

        var multiplier = Math.Pow(2, Math.Clamp(consecutiveFailures - 1, 0, 12));
        var ticks = minDelay.Ticks * multiplier;
        if (ticks >= maxDelay.Ticks)
            return maxDelay;
        return TimeSpan.FromTicks((long)ticks);
    }

    private async Task<bool> WaitForLifecycleGateAsync(CancellationToken ct)
    {
        if (_lifecycleState is null || !_automaticNetwork)
            return true;

        var snapshot = await _lifecycleState.LoadAsync(ct).ConfigureAwait(false);
        if (!AgentLifecycleStates.AllowsAutomaticNetwork(snapshot.State) || !snapshot.QuiescenceComplete)
        {
            _log.Warn($"Heartbeat network paused by lifecycle state={snapshot.State}.");
            return false;
        }

        var nextAttempt = snapshot.NextAttemptUtc;
        if (nextAttempt is null || nextAttempt <= DateTimeOffset.UtcNow)
            return true;

        var remaining = nextAttempt.Value - DateTimeOffset.UtcNow;
        _log.Info($"Heartbeat retry deferred until {nextAttempt.Value:O}.");
        var resetRequested = await DelayForErrorBackoffAsync(remaining, ct).ConfigureAwait(false);
        if (resetRequested)
            await ClearPersistedRetryAsync(ct).ConfigureAwait(false);
        return !ct.IsCancellationRequested;
    }

    private async Task<bool> StopForPersistedLifecycleAsync(CancellationToken ct)
    {
        if (_lifecycleState is null || !_automaticNetwork)
            return false;

        var snapshot = await _lifecycleState.LoadAsync(ct).ConfigureAwait(false);
        return !AgentLifecycleStates.AllowsAutomaticNetwork(snapshot.State);
    }

    private async Task ClearPersistedRetryAsync(CancellationToken ct)
    {
        if (_lifecycleState is null || !_automaticNetwork)
            return;

        var snapshot = await _lifecycleState.LoadAsync(ct).ConfigureAwait(false);
        if (snapshot.NextAttemptUtc is not null)
        {
            await _lifecycleState.TrySaveAsync(
                AgentLifecycleStatePolicy.Normalize(snapshot with
                {
                    NextAttemptUtc = null,
                    TransientFailureCount = 0,
                    UpdatedAtUtc = DateTimeOffset.UtcNow,
                }),
                snapshot.Revision, ct).ConfigureAwait(false);
        }
    }

    private async Task PersistRetryAsync(TimeSpan delay, CancellationToken ct)
    {
        if (_lifecycleState is null || !_automaticNetwork)
            return;

        var snapshot = await _lifecycleState.LoadAsync(ct).ConfigureAwait(false);
        if (!AgentLifecycleStates.AllowsAutomaticNetwork(snapshot.State))
            return;

        await _lifecycleState.TrySaveAsync(
            AgentLifecycleStatePolicy.Normalize(snapshot with
            {
                NextAttemptUtc = DateTimeOffset.UtcNow.Add(delay),
                TransientFailureCount = Math.Min(30, snapshot.TransientFailureCount + 1),
                UpdatedAtUtc = DateTimeOffset.UtcNow,
            }),
                snapshot.Revision, ct).ConfigureAwait(false);
    }

    private async Task RecordTransientLifecycleFailureAsync(Exception exception, CancellationToken ct)
    {
        if (_lifecycleState is null || !_automaticNetwork ||
            !TryGetTransientFailure(exception, out var reasonCode, out var requestId))
        {
            return;
        }

        var controller = new AgentLifecycleController(_lifecycleState, log: _log);
        await controller.RecordTransientFailureAsync(reasonCode, requestId, ct).ConfigureAwait(false);
    }

    private static bool TryGetTransientFailure(
        Exception exception,
        out string reasonCode,
        out string? requestId)
    {
        requestId = null;
        if (exception is AgentHttpException typed)
        {
            requestId = typed.RequestId;
            if (!AgentLifecycleStatePolicy.IsTransientHttpStatus(typed.Failure.StatusCode))
            {
                reasonCode = string.Empty;
                return false;
            }

            reasonCode = TransientReason(typed.Failure.StatusCode);
            return true;
        }

        if (exception is HttpRequestException request)
        {
            if (request.StatusCode is { } statusCode)
            {
                if (!AgentLifecycleStatePolicy.IsTransientHttpStatus(statusCode))
                {
                    reasonCode = string.Empty;
                    return false;
                }

                reasonCode = TransientReason(statusCode);
                return true;
            }

            reasonCode = "network_transient";
            return true;
        }

        if (exception is TimeoutException || exception is TaskCanceledException ||
            exception is OperationCanceledException)
        {
            reasonCode = "request_timeout";
            return true;
        }

        reasonCode = string.Empty;
        return false;
    }

    private static string TransientReason(System.Net.HttpStatusCode statusCode)
        => statusCode switch
        {
            System.Net.HttpStatusCode.RequestTimeout => "request_timeout",
            System.Net.HttpStatusCode.TooManyRequests => "rate_limited",
            _ when (int)statusCode is >= 500 and <= 599 => "server_unavailable",
            _ => "network_transient",
        };

    private TimeSpan CalculateRetryDelay(Exception exception, int consecutiveFailures)
    {
        if (exception is AgentHttpException rateLimit &&
            (rateLimit.RetryAfter is not null || rateLimit.Failure.StatusCode == System.Net.HttpStatusCode.TooManyRequests))
        {
            var retryAfter = rateLimit.RetryAfter ?? TimeSpan.FromSeconds(5);
            retryAfter = TimeSpan.FromSeconds(Math.Clamp(retryAfter.TotalSeconds, 5, 3600));
            var jitterSeconds = RandomNumberGenerator.GetInt32(1, Math.Max(2, (int)Math.Ceiling(retryAfter.TotalSeconds * 0.20) + 1));
            return retryAfter.Add(TimeSpan.FromSeconds(jitterSeconds));
        }

        var cap = TimeSpan.FromMinutes(15);
        var baseDelay = _minDelayOnError <= TimeSpan.Zero ? TimeSpan.FromSeconds(10) : _minDelayOnError;
        if (_lifecycleState is not null && baseDelay < TimeSpan.FromSeconds(10))
            baseDelay = TimeSpan.FromSeconds(10);
        var exponential = TimeSpan.FromTicks(Math.Min(
            cap.Ticks,
            baseDelay.Ticks * (long)Math.Pow(2, Math.Clamp(consecutiveFailures - 1, 0, 20))));
        var upperSeconds = Math.Max(1, (int)Math.Min(int.MaxValue, Math.Ceiling(exponential.TotalSeconds)));
        var jitteredSeconds = RandomNumberGenerator.GetInt32(1, upperSeconds + 1);
        return TimeSpan.FromSeconds(jitteredSeconds);
    }

    private static async Task WaitUntilCancellationAsync(CancellationToken ct)
    {
        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
        }
    }

    private static string FormatDelay(TimeSpan delay)
        => delay >= TimeSpan.FromMinutes(1)
            ? $"{Math.Ceiling(delay.TotalMinutes):0}m"
            : $"{Math.Ceiling(delay.TotalSeconds):0}s";

    private async Task<bool> DelayForErrorBackoffAsync(TimeSpan delay, CancellationToken ct)
    {
        if (_backoffResetRequested is null)
        {
            await Task.Delay(delay, ct).ConfigureAwait(false);
            return false;
        }

        var deadline = DateTimeOffset.UtcNow.Add(delay);
        while (DateTimeOffset.UtcNow < deadline)
        {
            if (await ConsumeBackoffResetRequestAsync(ct).ConfigureAwait(false))
                return true;

            var remaining = deadline - DateTimeOffset.UtcNow;
            if (remaining <= TimeSpan.Zero)
                break;

            await Task.Delay(remaining < TimeSpan.FromSeconds(2) ? remaining : TimeSpan.FromSeconds(2), ct)
                .ConfigureAwait(false);
        }

        return await ConsumeBackoffResetRequestAsync(ct).ConfigureAwait(false);
    }

    private async Task<bool> ConsumeBackoffResetRequestAsync(CancellationToken ct)
    {
        try
        {
            return _backoffResetRequested is not null &&
                   await _backoffResetRequested(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log.Warn($"Heartbeat retry backoff reset check failed: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    private static int ApplyJitter(int seconds, double pct)
    {
        var baseSec = Math.Max(1, seconds);
        var delta = (int)Math.Ceiling(baseSec * pct);
        var off = RandomNumberGenerator.GetInt32(-delta, delta + 1);
        return Math.Max(1, baseSec + off);
    }

    private async Task DispatchPendingCommandsAsync(IReadOnlyList<AgentCommand> commands, CancellationToken ct)
    {
        if (commands.Count == 0)
            return;

        using var gate = new SemaphoreSlim(_commandConcurrency, _commandConcurrency);
        var tasks = commands.Select(cmd => DispatchOneCommandAsync(cmd, gate, ct)).ToArray();
        await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    private async Task DispatchOneCommandAsync(AgentCommand cmd, SemaphoreSlim gate, CancellationToken ct)
    {
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var timeout = string.Equals(cmd.Type, "agent.update.request", StringComparison.Ordinal)
                ? Max(_commandTimeout, TimeSpan.FromMinutes(20))
                : _commandTimeout;
            var res = await _dispatcher.DispatchAsync(cmd, timeout, ct).ConfigureAwait(false);
            var resultBody = new
            {
                status = res.Status,
                exit_code = res.ExitCode,
                stdout = res.Stdout,
                stderr = res.Stderr,
                post_verify = res.PostVerify,
            };
            await _api.SubmitCommandResultAsync(cmd.Id, resultBody, ct).ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    private static TimeSpan Max(TimeSpan left, TimeSpan right)
        => left >= right ? left : right;

    private async Task TrySubmitSnapshotAsync(HeartbeatResponse heartbeat, CancellationToken ct)
    {
        if (_telemetryProvider is null)
            return;

        AgentSnapshotRequest snapshot;
        try
        {
            snapshot = await _telemetryProvider.BuildSnapshotAsync(_metadata, heartbeat, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.Warn($"Snapshot build failed: {ex.GetType().Name}: {ex.Message}");
            return;
        }

        try
        {
            await _api.SubmitSnapshotAsync(snapshot, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.Warn($"Snapshot submit failed: {ex.GetType().Name}: {ex.Message}");
            if (_telemetryBuffer is null)
                return;
            try
            {
                await _telemetryBuffer.EnqueueAsync(
                    OfflineTelemetryKinds.Snapshot,
                    snapshot,
                    idempotencyKey: "snapshot-latest",
                    priority: 1,
                    ct: ct).ConfigureAwait(false);
            }
            catch (Exception bufferEx)
            {
                _log.Warn($"Snapshot offline buffer failed: {bufferEx.GetType().Name}: {bufferEx.Message}");
            }
        }
    }

    private async Task TrySubmitEventAsync(
        string type,
        string severity,
        IReadOnlyDictionary<string, object?> payload,
        string idempotencyKey,
        CancellationToken ct)
    {
        var item = new AgentEventItem(
            EventId: idempotencyKey,
            Type: type,
            OccurredAt: DateTimeOffset.UtcNow.ToString("O"),
            Severity: severity,
            Payload: payload);
        var batch = AgentTelemetryFactory.CreateEvents(_metadata, new[] { item });
        try
        {
            await _api.SubmitEventsAsync(batch, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.Warn($"Event submit failed: {ex.GetType().Name}: {ex.Message}");
            if (_telemetryBuffer is null)
                return;
            try
            {
                await _telemetryBuffer.EnqueueAsync(
                    OfflineTelemetryKinds.Events,
                    batch,
                    idempotencyKey: idempotencyKey,
                    priority: 10,
                    ct: ct).ConfigureAwait(false);
            }
            catch (Exception bufferEx)
            {
                _log.Warn($"Event offline buffer failed: {bufferEx.GetType().Name}: {bufferEx.Message}");
            }
        }
    }

    private async Task TryFlushTelemetryBufferAsync(CancellationToken ct)
    {
        if (_telemetryBuffer is null)
            return;

        IReadOnlyList<OfflineTelemetryRecord> records;
        try
        {
            records = await _telemetryBuffer.ReadBatchAsync(maxItems: 10, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.Warn($"Telemetry offline buffer read failed: {ex.GetType().Name}: {ex.Message}");
            return;
        }

        var flushed = new List<string>();
        foreach (var record in records)
        {
            try
            {
                await _api.SubmitOfflineTelemetryAsync(record, ct).ConfigureAwait(false);
                flushed.Add(record.Id);
            }
            catch (Exception ex)
            {
                _log.Warn($"Telemetry offline flush stopped: {ex.GetType().Name}: {ex.Message}");
                break;
            }
        }

        if (flushed.Count > 0)
            await _telemetryBuffer.RemoveAsync(flushed, ct).ConfigureAwait(false);
    }
}
