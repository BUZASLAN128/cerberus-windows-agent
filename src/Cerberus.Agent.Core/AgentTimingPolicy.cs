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
    /// Clamps an already jittered poll delay and any caller minimum to the same bounds.
    /// </summary>
    public int PollDelaySeconds(int jitteredSeconds, int minimumSeconds = 0)
        => Math.Clamp(Math.Max(minimumSeconds, jitteredSeconds), _bounds.PollFloor, _bounds.PollCeiling);

    /// <summary>Final bound for collector-influenced contact waits, after jitter and Retry-After.</summary>
    public TimeSpan ClampContactDelay(TimeSpan delay)
        => delay <= TimeSpan.Zero ? TimeSpan.Zero
            : delay > TimeSpan.FromSeconds(_bounds.PollCeiling) ? TimeSpan.FromSeconds(_bounds.PollCeiling) : delay;

    /// <summary>Capped Retry-After uses downward jitter; smaller values retain their minimum.</summary>
    public TimeSpan JitterContactRetry(TimeSpan requested, double sample)
    {
        if (requested <= TimeSpan.Zero) return TimeSpan.Zero;
        sample = Math.Clamp(sample, 0d, 1d);
        var ceiling = TimeSpan.FromSeconds(_bounds.PollCeiling);
        return requested >= ceiling
            ? TimeSpan.FromTicks((long)(ceiling.Ticks * (0.75 + 0.25 * sample)))
            : ClampContactDelay(requested + TimeSpan.FromTicks((long)(requested.Ticks * 0.20 * sample)));
    }

    /// <summary>0 selects the profile default; any other value is clamped to [floor, ceiling].</summary>
    public int SnapshotDelaySeconds(int serverSeconds)
        => serverSeconds == 0
            ? _bounds.SnapshotDefault
            : Math.Clamp(serverSeconds, _bounds.SnapshotFloor, _bounds.SnapshotCeiling);
}
