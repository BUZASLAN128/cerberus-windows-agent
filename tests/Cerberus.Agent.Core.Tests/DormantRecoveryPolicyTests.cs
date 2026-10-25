// Dormant recovery policy. No build conditionals: runs identically in both builds.
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class DormantRecoveryPolicyTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-06-02T00:00:00Z");

    [Theory]
    [InlineData(AgentLifecycleState.AuthSuspect, null, true, true)]
    [InlineData(AgentLifecycleState.BlockedConfig, null, true, true)]
    [InlineData(AgentLifecycleState.NeedsReenrollment, null, true, true)]
    [InlineData(AgentLifecycleState.NeedsReenrollment, "agent_reenroll_required", true, false)]
    [InlineData(AgentLifecycleState.BlockedConfig, "credentials_missing", true, false)]
    [InlineData(AgentLifecycleState.BlockedConfig, "credentials_unavailable", true, false)]
    [InlineData(AgentLifecycleState.BlockedConfig, "credentials_invalid", true, false)]
    [InlineData(AgentLifecycleState.AuthSuspect, "credentials_invalid", true, false)]
    [InlineData(AgentLifecycleState.BlockedConfig, "backend_environment_mismatch", true, false)]
    [InlineData(AgentLifecycleState.BlockedConfig, "backend_url_invalid", true, false)]
    [InlineData(AgentLifecycleState.AuthSuspect, "auth_suspect", true, true)]
    [InlineData(AgentLifecycleState.Retired, null, true, false)]
    [InlineData(AgentLifecycleState.Active, null, true, false)]
    [InlineData(AgentLifecycleState.Degraded, null, true, false)]
    [InlineData(AgentLifecycleState.NeedsReenrollment, "agent_deactivated", true, false)]
    [InlineData(AgentLifecycleState.AuthSuspect, "agent_revoked", true, false)]
    [InlineData(AgentLifecycleState.BlockedConfig, null, false, false)]
    public void Recovery_IsRecoverable_OnlyForNonTerminalDormantStatesWithQuiescence(
        AgentLifecycleState state, string? reason, bool quiescent, bool expected)
    {
        var snapshot = new AgentLifecycleSnapshot(state, reason) { QuiescenceComplete = quiescent };
        Assert.Equal(expected, AgentDormantRecoveryPolicy.IsRecoverable(snapshot));
    }

    [Fact]
    public void Recovery_Backoff_StartsAt15MinutesDoublesAndCapsAt6Hours()
    {
        var noJitter = new AgentDormantRecoveryPolicy(() => Now, () => 1d);
        Assert.Equal(TimeSpan.FromMinutes(15), noJitter.DelayFor(0));
        Assert.Equal(TimeSpan.FromMinutes(30), noJitter.DelayFor(1));
        Assert.Equal(TimeSpan.FromMinutes(60), noJitter.DelayFor(2));
        Assert.Equal(TimeSpan.FromHours(6), noJitter.DelayFor(5));
        Assert.Equal(TimeSpan.FromHours(6), noJitter.DelayFor(1000));
        Assert.Equal(TimeSpan.FromMinutes(15), noJitter.DelayFor(-3));
    }

    [Theory]
    [InlineData(0d)]
    [InlineData(0.5d)]
    [InlineData(1d)]
    [InlineData(7d)]
    [InlineData(-2d)]
    public void Recovery_Jitter_StaysWithin75To100PercentAndNeverAboveCap(double random)
    {
        var policy = new AgentDormantRecoveryPolicy(() => Now, () => random);
        for (var attempt = 0; attempt <= 40; attempt++)
        {
            var unjittered = new AgentDormantRecoveryPolicy(() => Now, () => 1d).DelayFor(attempt);
            var delay = policy.DelayFor(attempt);
            Assert.True(delay >= unjittered * 0.75 - TimeSpan.FromMilliseconds(1), $"attempt {attempt}: {delay}");
            Assert.True(delay <= unjittered, $"attempt {attempt}: {delay}");
            Assert.True(delay <= TimeSpan.FromHours(6));
        }
    }

    [Fact]
    public void Recovery_Schedule_PersistsNextAttemptTimeAndAttemptCount()
    {
        var policy = new AgentDormantRecoveryPolicy(() => Now, () => 1d);
        var scheduled = policy.Schedule(new AgentLifecycleSnapshot(AgentLifecycleState.AuthSuspect), 2);

        Assert.Equal(Now + TimeSpan.FromMinutes(60), scheduled.NextAttemptUtc);
        Assert.Equal(2, scheduled.TransientFailureCount);
        Assert.False(policy.IsDue(scheduled));
        Assert.True(new AgentDormantRecoveryPolicy(() => Now.AddMinutes(60), () => 1d).IsDue(scheduled));
    }
}
