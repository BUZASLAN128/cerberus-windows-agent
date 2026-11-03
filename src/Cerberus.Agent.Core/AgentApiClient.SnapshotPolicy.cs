namespace Cerberus.Agent.Core;

public sealed partial class AgentApiClient
{
    private int _snapshotByteLimit = AgentTelemetryLimits.DefaultSnapshotBytes;
    private bool _snapshotRejectedAsTooLarge;
    private bool _snapshotSectionsRejected;
    private bool _secondarySnapshot;
    private IReadOnlySet<string> _snapshotSections = AgentSnapshotFactory.SnapshotSectionsFor(null);

    public int SnapshotByteLimit => _snapshotByteLimit;
    public IReadOnlySet<string> SnapshotSections => _snapshotSections;

    public Task<AgentIngestAckResponse> SubmitSnapshotAsync(AgentSnapshotRequest body, CancellationToken ct) =>
        SubmitIngestAsync("snapshot", PrepareSnapshot(body), retryTransient: true, ct: ct);

    private AgentSnapshotRequest PrepareSnapshot(AgentSnapshotRequest body)
        => AgentSnapshotFactory.Fit(AgentSnapshotFactory.ForSections(body, SnapshotSections), SnapshotByteLimit);
}
