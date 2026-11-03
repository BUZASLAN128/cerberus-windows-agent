using Cerberus.Agent.Core;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.App.Telemetry.Sections.FailedLogons;

namespace Cerberus.Agent.App.Telemetry;

public sealed class WindowsTelemetryCollector : IAgentTelemetryProvider, IAgentTelemetrySnapshotTrigger
{
    private readonly IReadOnlyList<IWindowsTelemetrySectionCollector> _sections;
    private IReadOnlyList<IAgentTelemetrySnapshotTrigger> _snapshotTriggers = Array.Empty<IAgentTelemetrySnapshotTrigger>();
    private IReadOnlySet<string> _acceptedSections = null!;
    private readonly bool _signedFacts;

    public WindowsTelemetryCollector()
        : this(WindowsTelemetrySectionCatalog.CreateDefault(publishServiceObservation: false))
    {
    }

    internal WindowsTelemetryCollector(bool publishServiceObservation)
        : this(WindowsTelemetrySectionCatalog.CreateDefault(publishServiceObservation))
    {
    }

    internal WindowsTelemetryCollector(IReadOnlyList<IWindowsTelemetrySectionCollector> sections, bool signedFacts = false)
    {
        _sections = sections.Count == 0
            ? throw new ArgumentException("At least one telemetry section is required.", nameof(sections))
            : sections;
        _signedFacts = signedFacts;
        ConfigureSnapshot(null);
    }

    public void ConfigureSnapshot(HeartbeatResponse? heartbeat)
    {
        _acceptedSections = AgentSnapshotFactory.SnapshotSectionsFor(heartbeat?.SnapshotSections, _signedFacts);
        _snapshotTriggers = _sections.Where(section => _acceptedSections.Contains(section.SectionName))
            .OfType<IAgentTelemetrySnapshotTrigger>().ToArray();
    }

    public bool IsSnapshotRefreshRequired()
        => _snapshotTriggers.Any(trigger => trigger.IsSnapshotRefreshRequired());

    public void MarkSnapshotSubmitted()
    {
        foreach (var trigger in _snapshotTriggers)
            trigger.MarkSnapshotSubmitted();
        // The upload was accepted: the failed-logon window of the last scheduled snapshot is now reported.
        FailedLogonSection.CommitPending();
    }

    public async Task<AgentSnapshotRequest> BuildSnapshotAsync(
        AgentBuildMetadata metadata,
        HeartbeatResponse? lastHeartbeat,
        CancellationToken ct)
    {
        ConfigureSnapshot(lastHeartbeat);
        var context = new WindowsTelemetryContext(metadata, lastHeartbeat);
        var payload = new Dictionary<string, object?>(StringComparer.Ordinal);

        foreach (var section in _sections)
        {
            if (!_acceptedSections.Contains(section.SectionName)) continue;
            payload[section.SectionName] = await TelemetrySectionCapture
                .CaptureAsync(section, context, ct)
                .ConfigureAwait(false);
        }

        // Only a failed_logons object that is in this snapshot can have its window committed after the upload.
        FailedLogonSection.KeepPendingIfReported(payload.GetValueOrDefault("security"));
        return AgentSnapshotFactory.Create(metadata, DateTimeOffset.UtcNow, payload, _signedFacts,
            AgentTelemetryLimits.SnapshotBytesFor(lastHeartbeat?.SnapshotMaxBytes));
    }
}
