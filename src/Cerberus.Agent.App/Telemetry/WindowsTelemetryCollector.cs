using Cerberus.Agent.Core;
using Cerberus.Agent.App.Telemetry.Sections;

namespace Cerberus.Agent.App.Telemetry;

public sealed class WindowsTelemetryCollector : IAgentTelemetryProvider, IAgentTelemetrySnapshotTrigger
{
    private readonly IReadOnlyList<IWindowsTelemetrySectionCollector> _sections;
    private readonly IAgentTelemetrySnapshotTrigger? _snapshotTrigger;

    public WindowsTelemetryCollector()
        : this(WindowsTelemetrySectionCatalog.CreateDefault(publishServiceObservation: false))
    {
    }

    internal WindowsTelemetryCollector(bool publishServiceObservation)
        : this(WindowsTelemetrySectionCatalog.CreateDefault(publishServiceObservation))
    {
    }

    internal WindowsTelemetryCollector(IReadOnlyList<IWindowsTelemetrySectionCollector> sections)
    {
        _sections = sections.Count == 0
            ? throw new ArgumentException("At least one telemetry section is required.", nameof(sections))
            : sections;
        _snapshotTrigger = sections.OfType<IAgentTelemetrySnapshotTrigger>().FirstOrDefault();
    }

    public bool IsSnapshotRefreshRequired()
        => _snapshotTrigger?.IsSnapshotRefreshRequired() is true;

    public void MarkSnapshotSubmitted()
        => _snapshotTrigger?.MarkSnapshotSubmitted();

    public async Task<AgentSnapshotRequest> BuildSnapshotAsync(
        AgentBuildMetadata metadata,
        HeartbeatResponse? lastHeartbeat,
        CancellationToken ct)
    {
        var context = new WindowsTelemetryContext(metadata, lastHeartbeat);
        var payload = new Dictionary<string, object?>(StringComparer.Ordinal);

        foreach (var section in _sections)
        {
            payload[section.SectionName] = await TelemetrySectionCapture
                .CaptureAsync(section, context, ct)
                .ConfigureAwait(false);
        }

        return AgentSnapshotFactory.Create(metadata, DateTimeOffset.UtcNow, payload);
    }
}
