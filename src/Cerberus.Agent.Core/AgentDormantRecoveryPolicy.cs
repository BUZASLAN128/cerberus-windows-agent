namespace Cerberus.Agent.Core;

/// <summary>
/// Retry schedule for unattended agents whose lifecycle is paused by a
/// recoverable state. Pure timing and eligibility logic; the caller performs
/// the probe and persists the returned snapshot. The attempt counter and next
/// attempt time are stored in the snapshot's TransientFailureCount and
/// NextAttemptUtc fields, which the transient-retry backoff also uses. A dormant
/// state can therefore carry values written before it went dormant; callers that
/// start a schedule treat them as unset.
/// </summary>
public sealed class AgentDormantRecoveryPolicy
{
    public static readonly TimeSpan InitialDelay = AgentTimingPolicy.Current.ClampContactDelay(TimeSpan.FromMinutes(1));
    public static readonly TimeSpan MaxDelay = AgentTimingPolicy.Current.ClampContactDelay(TimeSpan.FromHours(6));
    public const int MaxAttemptCount = 30;

    private const double MinJitterFactor = 0.75;

    private readonly Func<DateTimeOffset> _clock;
    private readonly Func<double> _nextDouble;
    private readonly TimeProvider _time;
    private (long Generation, DateTimeOffset Next)? _deadlineKey;
    private long _retryStartedAt;
    private TimeSpan _retryDelay;

    public AgentDormantRecoveryPolicy(Func<DateTimeOffset>? clock = null, Func<double>? nextDouble = null, TimeProvider? time = null)
    {
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _nextDouble = nextDouble ?? Random.Shared.NextDouble;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>
    /// True for dormant states that a plain authenticated heartbeat can end.
    /// Retired and cleanup-pending states, and any terminal reason code, are never recoverable.
    /// Missing or invalid credentials and required re-enrollment need a real re-enrollment, so they are not probed.
    /// Locally detected blocks (backend_environment_mismatch, backend_url_invalid) are not answered by a heartbeat:
    /// the server-profile supervisor re-checks the local configuration and returns the state to Active once the cause is gone.
    /// </summary>
    public static bool IsRecoverable(AgentLifecycleSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        return snapshot.QuiescenceComplete &&
            snapshot.State is AgentLifecycleState.AuthSuspect or AgentLifecycleState.BlockedConfig or AgentLifecycleState.NeedsReenrollment &&
            !AgentLifecycleStatePolicy.IsTerminalCode(snapshot.ReasonCode) &&
            snapshot.ReasonCode is not ("backend_environment_mismatch" or "backend_url_invalid") &&
            snapshot.ReasonCode != "agent_reenroll_required" &&
            snapshot.ReasonCode?.StartsWith("credentials_", StringComparison.Ordinal) != true;
    }

    /// <summary>Jittered retry for eligible probes, bounded by the same contact ceiling as polling.</summary>
    public TimeSpan DelayFor(int failedAttempts)
    {
        var attempts = Math.Clamp(failedAttempts, 0, MaxAttemptCount);
        var seconds = InitialDelay.TotalSeconds * Math.Pow(2, attempts);
        var capped = Math.Min(seconds, MaxDelay.TotalSeconds);
        var random = Math.Clamp(_nextDouble(), 0d, 1d);
        var factor = MinJitterFactor + ((1d - MinJitterFactor) * random);
        return AgentTimingPolicy.Current.ClampContactDelay(TimeSpan.FromSeconds(capped * factor));
    }

    /// <summary>True when no schedule exists yet (first dormant observation).</summary>
    public static bool NeedsSchedule(AgentLifecycleSnapshot snapshot)
        => snapshot.NextAttemptUtc is null;

    public bool IsDue(AgentLifecycleSnapshot snapshot)
    {
        if (snapshot.NextAttemptUtc is not { } next) return false;
        if (next <= _clock()) return true;
        if (_deadlineKey != (snapshot.Generation, next))
            RememberDeadline(snapshot.Generation, next, AgentTimingPolicy.Current.ClampContactDelay(next - _clock()));
        return _time.GetElapsedTime(_retryStartedAt) >= _retryDelay;
    }

    /// <summary>Returns the snapshot carrying the next attempt time after <paramref name="failedAttempts"/> unsuccessful probes.</summary>
    public AgentLifecycleSnapshot Schedule(AgentLifecycleSnapshot snapshot, int failedAttempts)
    {
        var attempts = Math.Clamp(failedAttempts, 0, MaxAttemptCount);
        var now = _clock();
        var delay = DelayFor(attempts);
        RememberDeadline(snapshot.Generation, now + delay, delay);
        return AgentLifecycleStatePolicy.Normalize(snapshot with
        {
            NextAttemptUtc = now + delay,
            TransientFailureCount = attempts,
            UpdatedAtUtc = _clock(),
        });
    }

    private void RememberDeadline(long generation, DateTimeOffset next, TimeSpan delay)
    {
        _deadlineKey = (generation, next);
        _retryStartedAt = _time.GetTimestamp();
        _retryDelay = AgentTimingPolicy.Current.ClampContactDelay(delay);
    }
}
