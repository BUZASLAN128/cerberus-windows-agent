namespace Cerberus.Agent.Core;

public sealed partial class AgentApiClient
{
    private int _snapshotByteLimit = AgentTelemetryLimits.DefaultSnapshotBytes;
    private bool _snapshotRejectedAsTooLarge;
    private bool _snapshotSectionsRejected;
    private bool _secondarySnapshot;
    private IReadOnlySet<string> _snapshotSections = AgentSnapshotFactory.SnapshotSectionsFor(null);
    private Func<AgentSnapshotRequest, bool, AgentSnapshotRequest>? _snapshotFilter;

    internal void SetSnapshotFilter(Func<AgentSnapshotRequest, bool, AgentSnapshotRequest>? filter) => _snapshotFilter = filter;

    public int SnapshotByteLimit => _snapshotByteLimit;
    public IReadOnlySet<string> SnapshotSections => _snapshotSections;

    public Task<AgentIngestAckResponse> SubmitSnapshotAsync(AgentSnapshotRequest body, CancellationToken ct) =>
        SubmitIngestAsync("snapshot", PrepareSnapshot(body), retryTransient: true, ct: ct);

    private AgentSnapshotRequest PrepareSnapshot(AgentSnapshotRequest body, bool isReplay = false)
        => AgentSnapshotFactory.Fit(AgentSnapshotFactory.ForSections(_snapshotFilter?.Invoke(body, isReplay) ?? body, SnapshotSections), SnapshotByteLimit);
}
