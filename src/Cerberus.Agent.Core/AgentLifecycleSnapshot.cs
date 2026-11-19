namespace Cerberus.Agent.Core;

/// <summary>
/// Durable local state that gates automatic agent network activity.
/// </summary>
public enum AgentLifecycleState
{
    Active = 0,
    AuthSuspect = 1,
    BlockedConfig = 2,
    NeedsReenrollment = 3,
    Retired = 4,
    // Appended to preserve the numeric meaning of states already written by
    // older in-memory/diagnostic callers. Durable files serialize the name.
    Degraded = 5,
}

public static class AgentLifecycleStates
{
    public static bool AllowsAutomaticNetwork(AgentLifecycleState state)
        => state is AgentLifecycleState.Active or AgentLifecycleState.Degraded;

    public static bool IsDormant(AgentLifecycleState state)
        => !AllowsAutomaticNetwork(state);
}

/// <summary>
/// Non-secret lifecycle metadata. The state store must never contain tokens,
/// private keys, response bodies, or other credential material.
/// </summary>
public sealed record AgentLifecycleSnapshot(
    AgentLifecycleState State = AgentLifecycleState.Active,
    string? ReasonCode = null,
    string? LastRequestId = null,
    DateTimeOffset? NextAttemptUtc = null,
    int GenericAuthFailureCount = 0,
    DateTimeOffset? UpdatedAtUtc = null)
{
    public DateTimeOffset EffectiveUpdatedAtUtc => UpdatedAtUtc ?? DateTimeOffset.UtcNow;
    public long Generation { get; init; }
    public long Revision { get; init; }
    public bool QuiescenceComplete { get; init; } = true;
    public int TransientFailureCount { get; init; }
    public string? LastEnrollmentNonce { get; init; }
}
