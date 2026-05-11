using Cerberus.Agent.Core;
using Cerberus.Agent.App.Telemetry.Sections;

namespace Cerberus.Agent.App.Telemetry;

public sealed class WindowsTelemetryCollector : IAgentTelemetryProvider
{
    private readonly IReadOnlyList<IWindowsTelemetrySectionCollector> _sections;

    public WindowsTelemetryCollector()
        : this(WindowsTelemetrySectionCatalog.CreateDefault())
    {
    }

    internal WindowsTelemetryCollector(IReadOnlyList<IWindowsTelemetrySectionCollector> sections)
    {
        _sections = sections.Count == 0
            ? throw new ArgumentException("At least one telemetry section is required.", nameof(sections))
            : sections;
    }

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
