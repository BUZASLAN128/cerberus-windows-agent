using Cerberus.Agent.App.Updates;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateLabContinuationTests
{
    private readonly AgentUpdateLabPolicy _policy = AgentUpdateLabPolicyTests.Valid();

    private (AgentUpdateLabRuntime.Scope Scope, AgentUpdatePlan Plan, AgentUpdateJournal Journal) Watch()
    {
        var identity = new AgentStateDeliveryContext("pc", "tenant", 7, "nonce", AgentProducts.Cerberus,
            _policy.Targets[0].KeyFingerprint);
        var scope = new AgentUpdateLabRuntime.Scope(_policy, _policy.Targets[0], identity);
        var plan = new AgentUpdatePlan("msi", _policy.Versions[5], "dev", "synthetic.msi", new string('a', 64),
            _policy.NotBeforeUtc.ToString("O"), "lab", AttemptId: "fixture-attempt", Sequence: 100);
        var release = AgentUpdateExpectedPlan.FromPlan(plan);
        var request = new AgentUpdateInstallRequest(_policy.NotBeforeUtc, identity.Generation, _policy.ExpiresAtUtc,
            ExpectedPlan: release, LocalPolicyId: _policy.CampaignId, BoundAttemptId: plan.AttemptId, VerifiedRelease: release,
            LocalSourceVersion: _policy.Versions[4]);
        return (scope, plan, new AgentUpdateJournal { Phase = AgentUpdateWatchJournal.CommittedWatch, AttemptId = plan.AttemptId,
            LifecycleGeneration = identity.Generation, InstallRequest = request });
    }

    [Fact]
    public void OnlyBoundCommittedWatchArmsFiveCrashesAcrossServiceProcesses()
    {
        var (scope, plan, journal) = Watch();
        var now = _policy.NotBeforeUtc.AddMinutes(1);
        Assert.Null(AgentUpdateLabFaults.NextCrashReceipt(scope, journal with { Phase = AgentUpdateStates.HealthPending },
            plan.Version, null, now, 1));
        AgentUpdateLabFaults.Receipt? receipt = null;
        for (var pid = 1; pid <= 5; pid++)
        {
            receipt = AgentUpdateLabFaults.NextCrashReceipt(scope, journal, plan.Version, receipt, now, pid);
            Assert.Equal(pid, receipt!.Count);
            Assert.Null(AgentUpdateLabFaults.NextCrashReceipt(scope, journal, plan.Version, receipt, now, pid));
        }
        Assert.Null(AgentUpdateLabFaults.NextCrashReceipt(scope, journal, plan.Version, receipt, now, 6));
        Assert.Null(AgentUpdateLabFaults.NextCrashReceipt(scope, journal with { Phase = AgentUpdateWatchJournal.RollingBack },
            plan.Version, receipt, now, 6));
    }

    [Fact]
    public void OnlyVerifiedPlannedRollbackRecordsOneSkipAndAllowsTheNextEffectiveHop()
    {
        var (scope, plan, journal) = Watch();
        var now = _policy.NotBeforeUtc.AddMinutes(1);
        var restored = _policy.Versions[4];
        var crash = AgentUpdateLabFaults.NextCrashReceipt(scope, journal, plan.Version, null, now, 1)!;
        var failed = journal with { Phase = AgentUpdateStates.Failed, FailureCode = AgentUpdateWatchJournal.PostCommitRollback,
            FailureAttemptId = plan.AttemptId, NextCheckUtc = now.AddHours(24), InstallRequest = journal.InstallRequest! with
            { TerminalReason = "attempt_failed", TerminalUtc = now } };

        Assert.Null(AgentUpdateLocalService.PlanLabSkip(scope, failed, plan, null, restored, now));
        Assert.Null(AgentUpdateLocalService.PlanLabSkip(scope, failed with { FailureCode = "msi_failed" }, plan, crash, restored, now));
        Assert.Null(AgentUpdateLocalService.PlanLabSkip(scope, failed with { FailureAttemptId = "other" }, plan, crash, restored, now));
        Assert.Null(AgentUpdateLocalService.PlanLabSkip(scope, failed, plan, crash, plan.Version, now));
        var skip = Assert.IsType<AgentUpdateLabRuntimeAdmission.SkippedRelease>(
            AgentUpdateLocalService.PlanLabSkip(scope, failed, plan, crash, restored, now));
        Assert.False(AgentUpdateLocalService.CanContinueLabCampaign(failed, _policy, restored, true));
        Assert.True(AgentUpdateLocalService.CanContinueLabCampaign(failed, _policy, restored, true, skip));
        var effective = AgentUpdateLabRuntimeAdmission.EffectiveVersions(_policy, skip);
        _policy.RequireSuccessor(restored, _policy.Versions[6], effective);
        Assert.Throws<InvalidOperationException>(() => _policy.RequireSuccessor(restored, plan.Version, effective));
        var nextRelease = new AgentUpdateExpectedPlan(_policy.Versions[6], "dev:101", new string('b', 64));
        var next = AgentUpdateLocalService.AdmitLabInstallRequest(failed, _policy, nextRelease, scope.Context.Generation,
            now, restored, committedCurrentBootstrap: true, skip: skip);
        Assert.Equal(nextRelease, next.InstallRequest?.ExpectedPlan);
        Assert.Equal(failed.NextCheckUtc, next.NextCheckUtc);

        var root = Path.Combine(Path.GetTempPath(), "cerberus-lab-skip-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            AgentUpdateLocalService.WriteLabSkip(root, skip);
            Assert.Throws<InvalidOperationException>(() => AgentUpdateLocalService.WriteLabSkip(root, skip with { AttemptId = "other" }));
            Assert.Equal(skip, AgentUpdateDurableFile.Read<AgentUpdateLabRuntimeAdmission.SkippedRelease>(Path.Combine(root, "skipped.json"), root));
        }
        finally { Directory.Delete(root, recursive: true); }
    }
}
