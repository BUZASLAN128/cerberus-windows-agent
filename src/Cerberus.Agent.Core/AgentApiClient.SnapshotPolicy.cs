using System.Text.Json;

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
        SubmitPreparedSnapshotAsync(body, isReplay: false, retryTransient: true, ct);

    private Task<AgentIngestAckResponse> SubmitPreparedSnapshotAsync(AgentSnapshotRequest body,
        bool isReplay, bool retryTransient, CancellationToken ct)
    {
        string PrepareJson() => JsonSerializer.Serialize(PrepareSnapshot(body, isReplay), JsonOpts);
        return SubmitIngestJsonAsync("snapshot", PrepareJson(), retryTransient, ct, PrepareJson);
    }

    private AgentSnapshotRequest PrepareSnapshot(AgentSnapshotRequest body, bool isReplay = false)
        => AgentSnapshotFactory.Fit(AgentSnapshotFactory.ForSections(_snapshotFilter?.Invoke(body, isReplay) ?? body, SnapshotSections), SnapshotByteLimit);
}
