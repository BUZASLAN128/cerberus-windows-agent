using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

// Unit/support: real journal codec and transition owners, isolated temporary files; no installer or service.
public sealed class AgentUpdateRequiredIntentTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "agent-required-intent-" + Guid.NewGuid().ToString("N"));
    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;

    private AgentUpdateJournal Persist(AgentUpdateJournal value)
    {
        Directory.CreateDirectory(_root);
        AgentUpdateDurableFile.Write(Path.Combine(_root, "transaction.json"), _root, value);
        return new AgentUpdateJournalStore(_root).Read();
    }

    private static AgentUpdateJournal Recommended() => new()
    {
        AttemptId = "attempt-a", Phase = AgentUpdateStates.AwaitingConsent, LifecycleGeneration = 7,
        Automatic = true, ApplyNotBeforeUtc = Now.AddDays(1),
    };

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExpiredRequestAuthorityCannotBecomeManualRetryAuthority(bool alreadyExpired)
    {
        var retry = Recommended() with { Required = false, Phase = AgentUpdateStates.RetryableBusy, Automatic = true,
            NextRetryUtc = Now.AddMinutes(-1), InstallRequestAuthorityExpiresUtc = alreadyExpired ? Now.AddMinutes(-1) : null };
        if (alreadyExpired)
            Assert.ThrowsAny<OperationCanceledException>(() => AgentUpdateLocalService.HoldExpiredInstallRequest(retry, true, default));
        else AgentUpdateLocalService.HoldExpiredInstallRequest(retry, true, default);
        AgentUpdateLocalService.HoldExpiredInstallRequest(retry, false, default);
    }

    [Fact]
    public void DeferredSnapshotCannotRestoreExpiredRequestRequiredFlag()
    {
        var request = Recommended() with { Required = true, RequiredInstallAttemptId = "attempt-a",
            InstallRequestAuthorityExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(-1) };
        var deferred = AgentUpdateLocalService.TransitionReconciliationDeferred(request, Now);
        var restored = AgentUpdateLocalService.RestoreReconciliationSnapshot(deferred, 7);
        Assert.False(restored.Required);
        Assert.Null(restored.RequiredInstallAttemptId);
        Assert.Equal(request.InstallRequestAuthorityExpiresUtc, restored.InstallRequestAuthorityExpiresUtc);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void ExplicitManualConsentReplacesExpiredRequestAuthorityAndAllowsItsBusyRetry(bool independent)
    {
        var request = Recommended() with { Required = true, RequiredInstallAttemptId = "attempt-a",
            RequiredPolicyGeneration = independent ? 7 : null, InstallRequestAuthorityExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(-1) };
        var launched = AgentUpdateLocalService.TransitionLaunchRequested(request, 7, false, default);
        Assert.Equal("launch_requested", launched.Phase);
        Assert.False(launched.Automatic);
        Assert.Equal(independent, launched.Required);
        Assert.Equal(independent ? 7L : (long?)null, launched.RequiredPolicyGeneration);
        Assert.Null(launched.RequiredInstallAttemptId);
        Assert.Null(launched.InstallRequestAuthorityExpiresUtc);
        AgentUpdateLocalService.HoldExpiredInstallRequest(launched with { Phase = AgentUpdateStates.RetryableBusy,
            Automatic = true }, true, default);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RequestGrantIsDurablyAttemptScopedWhileIndependentPolicySurvivesRetirement(bool independent)
    {
        var before = Recommended() with { Required = independent, RequiredPolicyGeneration = independent ? 7 : null,
            InstallRequest = new(Now, 7, Now.AddHours(1)) };
        var granted = Persist(AgentUpdateLocalService.TransitionInstallRequested(before, 7, Now));
        Assert.True(granted.Required);
        Assert.Equal(independent ? null : "attempt-a", granted.RequiredInstallAttemptId);
        Assert.Equal(independent ? 7L : (long?)null, granted.RequiredPolicyGeneration);
        Assert.Equal(independent ? null : Now.AddHours(1), granted.InstallRequestAuthorityExpiresUtc);

        var deferred = Persist(AgentUpdateLocalService.TransitionReconciliationDeferred(granted, Now.AddMinutes(5)));
        Assert.Equal(granted.RequiredInstallAttemptId, deferred.RequiredInstallAttemptId);
        Assert.Equal(granted.RequiredPolicyGeneration, deferred.RequiredPolicyGeneration);
        Assert.Equal(granted.InstallRequestAuthorityExpiresUtc, deferred.InstallRequestAuthorityExpiresUtc);
        var restored = Persist(AgentUpdateLocalService.RestoreReconciliationSnapshot(deferred, 7));
        Assert.Equal(granted.RequiredInstallAttemptId, restored.RequiredInstallAttemptId);
        Assert.Equal(granted.InstallRequestAuthorityExpiresUtc, restored.InstallRequestAuthorityExpiresUtc);
        // The production trusted-manifest mismatch owner retires this exact attempt.
        var retired = Persist(AgentUpdateLocalService.TransitionReconciliationFailure(restored, Now));
        Assert.Null(retired.RequiredInstallAttemptId);
        Assert.Null(retired.InstallRequestAuthorityExpiresUtc);
        Assert.Equal(independent, retired.Required);
        var required = AgentUpdateLocalService.CarryRequiredBlockedIntent(retired, false, 7);
        Assert.Equal(independent, required);
        var checking = AgentUpdateLocalService.TransitionCheckStart(retired, true, required, 7, Now.AddDays(1));
        var checkedRelease = AgentUpdateLocalService.TransitionCheckResult(checking, true, required, 7);
        var plan = new AgentUpdatePlan("msi", "2.0.0", "stable", Path.Combine(_root, "never-executed.msi"),
            new string('a', 64), Now.ToString("O"), "fixture-successor", AttemptId: "attempt-b");
        var successor = Persist(AgentUpdateLocalService.TransitionStageResult(
            checkedRelease with { AttemptId = "attempt-b" }, plan, true, required, 7, Now));
        Assert.Equal(independent, successor.Required);
        Assert.Equal(independent ? 7L : (long?)null, successor.RequiredPolicyGeneration);
        Assert.Null(successor.RequiredInstallAttemptId);
    }

    [Fact]
    public void CancellationAndLifecycleMismatchCannotConvertRequestGrantIntoPolicy()
    {
        var granted = AgentUpdateLocalService.TransitionInstallRequested(Recommended(), 7, Now);
        var cancelled = AgentUpdateLocalService.TransitionIntentionalCancellation(granted, granted, Now);
        Assert.Equal("attempt-a", cancelled.RequiredInstallAttemptId);
        Assert.Null(cancelled.RequiredPolicyGeneration);
        var deferred = AgentUpdateLocalService.TransitionReconciliationDeferred(cancelled, Now);
        var stale = AgentUpdateLocalService.RestoreReconciliationSnapshot(deferred, 8);
        Assert.False(stale.Required);
        Assert.Null(stale.RequiredInstallAttemptId);
        Assert.False(AgentUpdateLocalService.CarryRequiredBlockedIntent(stale, false, 8));
    }

    [Fact]
    public void LegacyUnstampedRetiredAuthorityCannotAuthorizeASuccessor()
    {
        var legacy = Persist(Recommended() with { Required = true, Phase = AgentUpdateStates.Blocked });
        Assert.False(AgentUpdateLocalService.CarryRequiredBlockedIntent(legacy, false, 7));
        var retired = AgentUpdateLocalService.TransitionReconciliationFailure(legacy, Now);
        Assert.False(retired.Required);
        Assert.Null(retired.RequiredPolicyGeneration);
    }

    [Theory]
    [InlineData(AgentUpdateStates.AwaitingConsent, false)]
    [InlineData(AgentUpdateStates.AwaitingConsent, true)]
    [InlineData(AgentUpdateStates.RetryableBusy, false)]
    [InlineData(AgentUpdateStates.RetryableBusy, true)]
    [InlineData(AgentUpdateStates.Staged, false)]
    [InlineData(AgentUpdateStates.Staged, true)]
    public void VerifiedIndependentPolicyPersistsThroughRetirementWithoutDelayingAnExistingRequest(string phase, bool requested)
    {
        var current = requested
            ? AgentUpdateLocalService.TransitionInstallRequested(Recommended(), 7, Now.AddMinutes(-5))
            : Recommended() with { ApplyNotBeforeUtc = null };
        current = current with { Phase = phase, NextRetryUtc = Now.AddMinutes(3) };
        var policy = Persist(AgentUpdateLocalService.TransitionVerifiedRequiredPolicy(current, true, 7, 7, Now));
        Assert.True(policy.Required);
        Assert.Equal(7, policy.RequiredPolicyGeneration);
        Assert.Null(policy.RequiredInstallAttemptId);
        Assert.Equal(current.NextRetryUtc, policy.NextRetryUtc);
        if (requested || phase != AgentUpdateStates.AwaitingConsent)
            Assert.Equal(current.ApplyNotBeforeUtc, policy.ApplyNotBeforeUtc);
        else
            Assert.InRange(policy.ApplyNotBeforeUtc!.Value, Now, Now.AddHours(24));
        Assert.Equal(policy, AgentUpdateLocalService.TransitionVerifiedRequiredPolicy(policy, true, 7, 7, Now.AddHours(3)));
        var retired = Persist(AgentUpdateLocalService.TransitionReconciliationFailure(policy, Now));
        Assert.True(AgentUpdateLocalService.CarryRequiredBlockedIntent(retired, false, 7));
        var successor = AgentUpdateLocalService.TransitionStageStart(retired, true,
            AgentUpdateLocalService.CarryRequiredBlockedIntent(retired, false, 7), 7, Now.AddDays(1));
        Assert.True(successor.Required);
        Assert.Equal(7, successor.RequiredPolicyGeneration);
        Assert.Null(successor.RequiredInstallAttemptId);
    }

    [Fact]
    public void VerifiedPolicyDuringDeferredRequestBecomesIndependentWithoutPostponingTheDueTime()
    {
        var granted = AgentUpdateLocalService.TransitionInstallRequested(Recommended(), 7, Now.AddMinutes(-5));
        var deferred = AgentUpdateLocalService.TransitionReconciliationDeferred(granted, Now);
        var restored = Persist(AgentUpdateLocalService.RestoreReconciliationSnapshot(deferred, 7,
            required: true, requiredPolicyGeneration: 7));
        Assert.Equal(granted.ApplyNotBeforeUtc, restored.ApplyNotBeforeUtc);
        Assert.Equal(7, restored.RequiredPolicyGeneration);
        Assert.Null(restored.RequiredInstallAttemptId);
        var retired = AgentUpdateLocalService.TransitionReconciliationFailure(restored, Now);
        Assert.True(AgentUpdateLocalService.CarryRequiredBlockedIntent(retired, false, 7));
    }

    [Theory]
    [InlineData(false, 7L, 7L, AgentUpdateStates.AwaitingConsent)]
    [InlineData(true, null, 7L, AgentUpdateStates.AwaitingConsent)]
    [InlineData(true, 8L, 7L, AgentUpdateStates.AwaitingConsent)]
    [InlineData(true, 7L, 8L, AgentUpdateStates.AwaitingConsent)]
    [InlineData(true, 7L, 7L, "launch_requested")]
    [InlineData(true, 7L, 7L, AgentUpdateStates.Blocked)]
    public void UnverifiedGenerationOrProtectedAttemptCannotReceiveIndependentPolicy(bool required,
        long? signalGeneration, long currentGeneration, string phase)
    {
        var granted = AgentUpdateLocalService.TransitionInstallRequested(Recommended(), 7, Now);
        var current = granted with { LifecycleGeneration = currentGeneration, Phase = phase };
        Assert.Equal(current, AgentUpdateLocalService.TransitionVerifiedRequiredPolicy(current,
            required, signalGeneration, 7, Now));
    }

    [Fact]
    public async Task NoPlanEndsSchedulerTickAfterJournalBecomesCurrent()
    {
        var current = Recommended() with { Required = true, RequiredPolicyGeneration = 7,
            InstallRequest = new(Now.AddMinutes(-1), 7, Now.AddHours(1)) };
        var stale = current;
        var applyCalls = 0;
        var checkCalls = 0;
        AgentUpdateJournal Change(Func<AgentUpdateJournal, AgentUpdateJournal> update) => current = update(current);
        var handled = await AgentUpdateLocalService.HoldOrRunInstallRequestAsync(current,
            new AgentLifecycleSnapshot { Generation = 7 }, () => false, _ => false, Change,
            _ => { current = current with { Phase = AgentUpdateStates.Current, AttemptId = null, Required = false,
                RequiredPolicyGeneration = null, NextCheckUtc = Now.AddMinutes(-1) }; return Task.FromResult(false); },
            NullAgentLogger.Instance, default);
        if (!handled)
        {
            if (stale.Required) applyCalls++;
            if (current.NextCheckUtc <= Now) checkCalls++;
        }
        Assert.True(handled);
        Assert.Equal((0, 0), (applyCalls, checkCalls));
        Assert.Equal(AgentUpdateStates.Current, current.Phase);
        Assert.Null(current.AttemptId);
        Assert.Null(current.InstallRequest);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root)) Directory.Delete(_root, recursive: true);
    }
}
