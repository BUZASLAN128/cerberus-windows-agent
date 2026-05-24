using System.Security.Cryptography;

namespace Cerberus.Agent.Core;

public sealed class HeartbeatLoop
{
    private readonly AgentApiClient _api;
    private readonly CommandDispatcher _dispatcher;
    private readonly TimeSpan _minDelayOnError;
    private readonly IAgentLogger _log;
    private readonly IAgentStatusProvider? _status;
    private readonly Func<CancellationToken, Task<object?>>? _adStatusProvider;
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

    public HeartbeatLoop(
        AgentApiClient api,
        CommandDispatcher dispatcher,
        TimeSpan minDelayOnError,
        IAgentStatusProvider? statusProvider = null,
        Func<CancellationToken, Task<object?>>? adStatusProvider = null,
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
        AgentBuildMetadata? metadata = null)
    {
        _api = api;
        _dispatcher = dispatcher;
        _minDelayOnError = minDelayOnError;
        _status = statusProvider;
        _adStatusProvider = adStatusProvider;
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
    }

    public async Task RunAsync(CancellationToken ct)
    {
        var degraded = false;
        var startedEventSent = false;
        var nextSnapshotAt = DateTimeOffset.UtcNow.Add(_initialSnapshotDelay);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                object? tailscale = null;
                if (_status is not null)
                {
                    try
                    {
                        tailscale = await _status.GetTailscaleAsync(ct);
                    }
                    catch (Exception ex)
                    {
                        _log.Warn($"Status provider error: {ex.GetType().Name}: {ex.Message}");
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
                    capabilities = _dispatcher.HandlerTypes,
                };

                var hb = await _api.HeartbeatAsync(hbReq, ct);

                degraded = false;

                var control = _responseHandler is null
                    ? HeartbeatControlAction.Continue
                    : await _responseHandler.HandleAsync(hb, ct).ConfigureAwait(false);
                if (control == HeartbeatControlAction.Stop)
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
            catch (Exception ex)
            {
                degraded = true;
                _log.Warn($"Heartbeat loop error: {ex.GetType().Name}: {ex.Message}");
                await Task.Delay(_minDelayOnError, ct);
            }
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
            var res = await _dispatcher.DispatchAsync(cmd, _commandTimeout, ct).ConfigureAwait(false);
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
