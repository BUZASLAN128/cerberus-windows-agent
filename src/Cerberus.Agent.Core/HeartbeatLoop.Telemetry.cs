namespace Cerberus.Agent.Core;

public sealed partial class HeartbeatLoop
{
    private async Task<bool> TrySubmitSnapshotAsync(HeartbeatResponse heartbeat, CancellationToken ct)
    {
        if (_telemetryProvider is null)
            return false;

        AgentSnapshotRequest snapshot;
        try
        {
            snapshot = await _telemetryProvider.BuildSnapshotAsync(_metadata, heartbeat, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _log.Warn($"Snapshot build failed: {ex.GetType().Name}: {ex.Message}");
            return false;
        }

        try
        {
            await _api.SubmitSnapshotAsync(snapshot, ct).ConfigureAwait(false);
            return true;
        }
        catch (Exception ex)
        {
            _log.Warn($"Snapshot submit failed: {ex.GetType().Name}: {ex.Message}");
            if (_telemetryBuffer is null)
                return false;
            try
            {
                await _telemetryBuffer.EnqueueAsync(
                    OfflineTelemetryKinds.Snapshot,
                    // The next live snapshot re-reads failed logons from the last committed cursor.
                    AgentSnapshotFactory.WithoutSectionField(snapshot, "security", "failed_logons"),
                    idempotencyKey: "snapshot-latest",
                    priority: 1,
                    ct: ct).ConfigureAwait(false);
            }
            catch (Exception bufferEx)
            {
                _log.Warn($"Snapshot offline buffer failed: {bufferEx.GetType().Name}: {bufferEx.Message}");
            }
            return false;
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
