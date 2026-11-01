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
    public void RequestGrantIsDurablyAttemptScopedWhileIndependentPolicySurvivesRetirement(bool independent)
    {
        var before = Recommended() with { Required = independent, RequiredPolicyGeneration = independent ? 7 : null };
        var granted = Persist(AgentUpdateLocalService.TransitionInstallRequested(before, 7, Now));
        Assert.True(granted.Required);
        Assert.Equal(independent ? null : "attempt-a", granted.RequiredInstallAttemptId);
        Assert.Equal(independent ? 7L : (long?)null, granted.RequiredPolicyGeneration);

        var deferred = Persist(AgentUpdateLocalService.TransitionReconciliationDeferred(granted, Now.AddMinutes(5)));
        Assert.Equal(granted.RequiredInstallAttemptId, deferred.RequiredInstallAttemptId);
        Assert.Equal(granted.RequiredPolicyGeneration, deferred.RequiredPolicyGeneration);
        var restored = Persist(AgentUpdateLocalService.RestoreReconciliationSnapshot(deferred, 7));
        Assert.Equal(granted.RequiredInstallAttemptId, restored.RequiredInstallAttemptId);
        // The production trusted-manifest mismatch owner retires this exact attempt.
        var retired = Persist(AgentUpdateLocalService.TransitionReconciliationFailure(restored, Now));
        Assert.Null(retired.RequiredInstallAttemptId);
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
            new AgentLifecycleSnapshot { Generation = 7 }, () => false, Change,
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
