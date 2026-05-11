namespace Cerberus.Agent.App.Telemetry.Sections;

internal sealed class ClockTelemetrySectionCollector : IWindowsTelemetrySectionCollector
{
    public string SectionName => "clock";

    public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
    {
        var local = DateTimeOffset.UtcNow;
        long? driftMs = null;
        if (!string.IsNullOrWhiteSpace(context.LastHeartbeat?.ServerTimeUtc) &&
            DateTimeOffset.TryParse(context.LastHeartbeat.ServerTimeUtc, out var server))
        {
            driftMs = (long)Math.Round((local - server).TotalMilliseconds);
        }

        return ValueTask.FromResult<object>(new
        {
            status = "ok",
            local_time_utc = local.ToString("O"),
            server_time_utc = context.LastHeartbeat?.ServerTimeUtc,
            drift_ms = driftMs,
            api_reachability = context.LastHeartbeat is null ? "unknown" : "last_heartbeat_ok",
        });
    }
}
