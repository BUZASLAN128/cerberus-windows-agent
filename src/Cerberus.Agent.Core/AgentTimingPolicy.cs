namespace Cerberus.Agent.Core;

/// <summary>
/// Poll and snapshot delay bounds. The values come only from build metadata
/// (<see cref="AgentProfileMetadata"/>); nothing at run time can widen them.
/// </summary>
public sealed class AgentTimingPolicy
{
    private static readonly Lazy<AgentTimingPolicy> CurrentPolicy =
        new(() => new AgentTimingPolicy(AgentProfileMetadata.Timing));

    private readonly AgentTimingBounds _bounds;

    public AgentTimingPolicy(AgentTimingBounds bounds)
    {
        _bounds = bounds;
    }

    public static AgentTimingPolicy Current => CurrentPolicy.Value;

    public AgentTimingBounds Bounds => _bounds;

    /// <summary>
    /// Clamps an already jittered poll delay to [floor, ceiling], then applies an
    /// existing caller minimum (error, blocked or skip-commands) on top.
    /// </summary>
    public int PollDelaySeconds(int jitteredSeconds, int minimumSeconds = 0)
        => Math.Max(minimumSeconds, Math.Clamp(jitteredSeconds, _bounds.PollFloor, _bounds.PollCeiling));

    /// <summary>0 selects the profile default; any other value is clamped to [floor, ceiling].</summary>
    public int SnapshotDelaySeconds(int serverSeconds)
        => serverSeconds == 0
            ? _bounds.SnapshotDefault
            : Math.Clamp(serverSeconds, _bounds.SnapshotFloor, _bounds.SnapshotCeiling);
}
