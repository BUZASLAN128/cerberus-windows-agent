using System.Text.Json;

namespace Cerberus.Agent.Core;

public sealed partial class AgentApiClient
{
    private int _snapshotByteLimit = AgentTelemetryLimits.DefaultSnapshotBytes;
    private bool _snapshotRejectedAsTooLarge;
    private bool _snapshotSectionsRejected;
    private bool _secondarySnapshot;
    private IReadOnlySet<string> _snapshotSections = AgentSnapshotFactory.SnapshotSectionsFor(null);
    private Action? _snapshotPrivacyRedacted;

    internal void SetSnapshotPrivacyRedacted(Action? callback) => _snapshotPrivacyRedacted = callback;

    public int SnapshotByteLimit => _snapshotByteLimit;
    public IReadOnlySet<string> SnapshotSections => _snapshotSections;

    public Task<AgentIngestAckResponse> SubmitSnapshotAsync(AgentSnapshotRequest body, CancellationToken ct) =>
        SubmitPreparedSnapshotAsync(body, isReplay: false, retryTransient: true, ct);

    private Task<AgentIngestAckResponse> SubmitPreparedSnapshotAsync(AgentSnapshotRequest body,
        bool isReplay, bool retryTransient, CancellationToken ct)
    {
        string PrepareJson() => JsonSerializer.Serialize(AgentSnapshotFactory.ForSections(body, SnapshotSections), JsonOpts);
        string FitJson(string candidate)
        {
            var snapshot = JsonSerializer.Deserialize<AgentSnapshotRequest>(candidate, JsonOpts)
                ?? throw new InvalidOperationException("Snapshot body missing.");
            return JsonSerializer.Serialize(AgentSnapshotFactory.Fit(snapshot, SnapshotByteLimit), JsonOpts);
        }
        return SubmitIngestJsonAsync("snapshot", PrepareJson(), retryTransient, ct, PrepareJson,
            isReplay ? null : _snapshotPrivacyRedacted, FitJson);
    }
}
