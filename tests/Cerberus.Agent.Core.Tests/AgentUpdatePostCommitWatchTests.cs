using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdatePostCommitWatchTests
{
    private const string Attempt = "watched-attempt";
    private const string RollbackAttempt = "rollback-attempt";
    private const string CurrentVersion = "0.2.1020";
    private const string LkgVersion = "0.2.1019";
    private static readonly DateTimeOffset Now = new(2026, 11, 18, 12, 0, 0, TimeSpan.Zero);
    private static readonly AgentUpdatePlan Plan = new("msi", CurrentVersion, "dev", "agent.msi", new string('a', 64),
        Now.ToString("O"), "test", Sequence: 77);

    [Theory]
    [InlineData(AgentUpdateStates.HealthPending, true)]
    [InlineData(AgentUpdateStates.PendingReboot, true)]
    [InlineData(AgentUpdateStates.RecoveryRequired, true)]
    [InlineData(AgentUpdateStates.HealthPending, false)]
    [InlineData(AgentUpdateStates.RecoveryRequired, false)]
    public void HealthyCommit_UsesTheProfileAndPreservesThePredecessorDuringWatch(string phase, bool server)
    {
        var before = new AgentUpdateJournal
        {
            Phase = phase, AttemptId = Attempt, HealthyInstalledVersion = LkgVersion, HealthyInstalledSequence = 76,
        };
        var after = phase == AgentUpdateStates.RecoveryRequired
            ? AgentUpdateLocalService.CloseRecovery(before, Plan, healthy: true, Now, serverProfile: server)
            : AgentUpdateLocalService.TransitionHealthyInstall(before, Plan, Now, server);

        Assert.Equal(server ? AgentUpdateWatchJournal.CommittedWatch : AgentUpdateStates.Installed, after.Phase);
        Assert.Equal(server ? LkgVersion : CurrentVersion, after.HealthyInstalledVersion);
        Assert.Equal(server ? 76 : 77, after.HealthyInstalledSequence);
        Assert.Equal(server ? Now : (DateTimeOffset?)null, after.WatchRequestedUtc);
        Assert.Equal(server ? Attempt : null, after.WatchAttemptId);
        Assert.Equal(server, after.HasUnfinishedAttempt);
    }

    [Fact]
    public void CommittedWatch_UsesTwoHourMissingAndTwentySixHourStaleDeadlines()
    {
        var before = Journal();
        var open = Watch(AgentUpdateWatchOutcomes.Open);
        Assert.Same(before, AgentUpdateLocalService.TransitionPostCommitWatch(before, null, null, Now.AddHours(2)));
        AssertWatchClosed(before, AgentUpdateLocalService.TransitionPostCommitWatch(before,
            open with { AttemptId = "other-attempt" }, Now.AddHours(2), Now.AddHours(2).AddTicks(1)),
            AgentUpdateWatchJournal.WatchUnavailable);

        var deadline = Now.AddHours(26);
        var stale = deadline.AddMinutes(-31);
        Assert.Same(before, AgentUpdateLocalService.TransitionPostCommitWatch(before, open, stale, deadline.AddTicks(-1)));
        Assert.Same(before, AgentUpdateLocalService.TransitionPostCommitWatch(before, open, deadline.AddMinutes(-30), deadline));
        AssertWatchClosed(before, AgentUpdateLocalService.TransitionPostCommitWatch(before, open, stale, deadline),
            AgentUpdateWatchJournal.WatchUnavailable);
    }

    [Fact]
    public void WatchObservation_ReadsTheActualFileTimestampAndDistinguishesAnUnreadableRecord()
    {
        var root = Directory.CreateTempSubdirectory("cerberus-app-watch-");
        try
        {
            var watchPath = Path.Combine(root.CreateSubdirectory("lkg").FullName, "watch.json");
            var before = Journal();
            var deadline = Now.AddHours(26);
            File.WriteAllText(watchPath, "{");
            Assert.Same(before, AgentUpdateLocalService.ObservePostCommitWatch(root.FullName, before, deadline));

            AgentUpdateWatchStore.Write(root.FullName, Watch(AgentUpdateWatchOutcomes.Open));
            File.SetLastWriteTimeUtc(watchPath, deadline.AddMinutes(-29).UtcDateTime);
            Assert.Same(before, AgentUpdateLocalService.ObservePostCommitWatch(root.FullName, before, deadline));
            File.SetLastWriteTimeUtc(watchPath, deadline.AddMinutes(-31).UtcDateTime);
            AssertWatchClosed(before, AgentUpdateLocalService.ObservePostCommitWatch(root.FullName, before, deadline),
                AgentUpdateWatchJournal.WatchUnavailable);
        }
        finally { root.Delete(recursive: true); }
    }

    [Theory]
    [InlineData(AgentUpdateWatchOutcomes.Superseded, AgentUpdateWatchJournal.WatchUnavailable)]
    [InlineData(AgentUpdateWatchOutcomes.Inconclusive, AgentUpdateWatchJournal.WatchUnavailable)]
    [InlineData(AgentUpdateWatchOutcomes.ForwardOnlyFailed, AgentUpdateWatchJournal.PostCommitUnhealthy)]
    [InlineData(AgentUpdateWatchOutcomes.Passed, null)]
    [InlineData(AgentUpdateWatchOutcomes.RollbackPending, null)]
    public void CommittedWatch_AdoptsOnlyTheHostOutcomesThatNeedNoHostAction(string outcome, string? code)
    {
        var before = Journal();
        var watch = Watch(outcome);
        Assert.Same(before, AgentUpdateLocalService.TransitionPostCommitWatch(before, watch with { AttemptId = "other-attempt" }, Now, Now));
        var after = AgentUpdateLocalService.TransitionPostCommitWatch(before, watch, Now, Now);
        if (code is null)
            Assert.Same(before, after);
        else
            AssertWatchClosed(before, after, code);
    }

    [Theory]
    [InlineData(62, 77)]
    [InlineData(80, 80)]
    public void RollingBack_AfterFortyEightHoursPinsTheMatchingStaleWatchSequence(long previousPin, long expectedPin)
    {
        var before = Journal(AgentUpdateWatchJournal.RollingBack) with
        {
            FailedInstallSequence = previousPin, RollbackAttemptId = RollbackAttempt,
            RollbackFirstUtc = Now, RollbackStartedUtc = Now.AddHours(1),
        };
        var watch = Watch(AgentUpdateWatchOutcomes.RollbackPending);
        var deadline = Now.AddHours(48);
        var stale = deadline.AddMinutes(-31);
        Assert.Same(before, AgentUpdateLocalService.TransitionPostCommitWatch(before, watch, stale, deadline.AddTicks(-1)));
        Assert.Same(before, AgentUpdateLocalService.TransitionPostCommitWatch(before, watch, deadline.AddMinutes(-1), deadline));
        Assert.Same(before, AgentUpdateLocalService.TransitionPostCommitWatch(before, watch with { AttemptId = "other-attempt" }, stale, deadline));
        var retryStarting = before with { RollbackStartedUtc = deadline.AddMinutes(-1) };
        Assert.Same(retryStarting, AgentUpdateLocalService.TransitionPostCommitWatch(retryStarting, watch, stale, deadline));
        var after = AgentUpdateLocalService.TransitionPostCommitWatch(before, watch, stale, deadline);
        Assert.Equal(AgentUpdateStates.Failed, after.Phase);
        Assert.Equal(AgentUpdateWatchJournal.RollbackFailed, after.FailureCode);
        Assert.Equal(Attempt, after.FailureAttemptId);
        Assert.Equal(before.InstallerResult!.ResultId, after.FailureInstallerResultId);
        Assert.Same(before.InstallerResult, after.InstallerResult);
        Assert.Equal(expectedPin, after.FailedInstallSequence);
        Assert.InRange(after.NextCheckUtc!.Value, deadline.AddHours(24), deadline.AddHours(30));
    }

    [Theory]
    [InlineData(AgentUpdateWatchJournal.CommittedWatch, AgentUpdateStates.HealthPending, "pending", "none", null)]
    [InlineData(AgentUpdateWatchJournal.RollingBack, AgentUpdateStates.Installing, "unhealthy", "in_progress", null)]
    [InlineData(AgentUpdateStates.Failed, AgentUpdateStates.Failed, "unknown", "completed", AgentUpdateWatchJournal.PostCommitRollback)]
    [InlineData(AgentUpdateStates.Failed, AgentUpdateStates.Failed, "unknown", "failed", AgentUpdateWatchJournal.RollbackFailed)]
    [InlineData(AgentUpdateStates.Installed, AgentUpdateStates.Installed, "unhealthy", "none", AgentUpdateWatchJournal.PostCommitUnhealthy)]
    [InlineData(AgentUpdateStates.Installed, AgentUpdateStates.Installed, "healthy", "none", AgentUpdateWatchJournal.WatchUnavailable)]
    [InlineData(AgentUpdateStates.Installed, AgentUpdateStates.Installed, "healthy", "none", AgentUpdateWatchJournal.LkgPromotionFailed)]
    [InlineData(AgentUpdateStates.Installed, AgentUpdateStates.Installed, "healthy", "none", AgentUpdateWatchJournal.LkgBelowFloor)]
    public void Projection_UsesExistingPublicStatesAndAttemptBoundCodes(string phase, string state, string health, string rollback,
        string? code)
    {
        var before = Journal(phase);
        var active = before with
        {
            FailureCode = phase == AgentUpdateStates.Failed ? code : null,
            FailureAttemptId = Attempt,
            FailureInstallerResultId = before.InstallerResult!.ResultId,
            WatchOutcomeCode = phase == AgentUpdateStates.Installed ? code : null,
            WatchOutcomeAttemptId = Attempt,
        };

        var projected = Project(active);
        Assert.Equal((state, health, rollback, code), (projected.State, projected.HealthState, projected.RollbackState, projected.LastErrorCode));
    }

    [Fact]
    public void Projection_BoundWatchAndFailureCodesWinOverInstallerResult()
    {
        var active = Journal(AgentUpdateStates.Installed) with
        {
            WatchOutcomeAttemptId = Attempt, WatchOutcomeCode = AgentUpdateWatchJournal.PostCommitUnhealthy,
            InstallerResult = Journal().InstallerResult! with { ErrorCode = AgentUpdateErrorCodes.MsiFailed },
        };
        Assert.Equal(AgentUpdateWatchJournal.PostCommitUnhealthy, Project(active).LastErrorCode);
        var stale = Project(active with { WatchOutcomeAttemptId = "other-attempt" });
        Assert.Equal(("healthy", AgentUpdateErrorCodes.MsiFailed), (stale.HealthState, stale.LastErrorCode));

        var failed = active with
        {
            Phase = AgentUpdateStates.Failed, FailureCode = AgentUpdateWatchJournal.RollbackFailed,
            FailureAttemptId = Attempt, FailureInstallerResultId = active.InstallerResult.ResultId,
        };
        Assert.Equal(AgentUpdateWatchJournal.RollbackFailed, Project(failed).LastErrorCode);
        var wrongResult = Project(failed with { FailureInstallerResultId = "past-result" });
        Assert.Equal(("none", AgentUpdateErrorCodes.MsiFailed), (wrongResult.RollbackState, wrongResult.LastErrorCode));
    }

    [Fact]
    public void RollingBack_OverdueAlertUsesOnlyTheLiveRollbackInstallerAndItsAttempt()
    {
        var active = Journal(AgentUpdateWatchJournal.RollingBack) with
        {
            RollbackAttemptId = RollbackAttempt, RunnerStartedUtc = Now.AddHours(-3),
            InstallerProcessId = 321, InstallerStartedUtc = Now.AddHours(-1),
            AlertAttemptId = Attempt, AlertCode = AgentUpdateErrorCodes.InstallOverdue,
            InstallerResult = Journal().InstallerResult! with { ErrorCode = AgentUpdateErrorCodes.MsiFailed },
        };
        var boot = Now.AddHours(-4);
        Assert.Equal(AgentUpdateErrorCodes.MsiFailed, Project(active).LastErrorCode);
        Assert.Same(active, AgentUpdateLocalService.TransitionInstallOverdue(active, Now.AddTicks(-1), boot, false, true));
        Assert.Same(active, AgentUpdateLocalService.TransitionInstallOverdue(active, Now, boot, true, false));

        var after = AgentUpdateLocalService.TransitionInstallOverdue(active, Now, boot, false, true);
        Assert.Equal(AgentUpdateWatchJournal.RollingBack, after.Phase);
        Assert.Equal(RollbackAttempt, after.AlertAttemptId);
        Assert.Equal(AgentUpdateErrorCodes.InstallOverdue, Project(after).LastErrorCode);
        Assert.Equal(AgentUpdateErrorCodes.MsiFailed, Project(after with { RollbackAttemptId = "next-rollback" }).LastErrorCode);
    }

    [Fact]
    public void StageStartAndCancellation_ClearAndRestoreAllWatchEvidence()
    {
        var prior = Journal(AgentUpdateStates.Installed) with
        {
            WatchOutcomeCode = AgentUpdateWatchJournal.WatchUnavailable, WatchOutcomeAttemptId = Attempt,
            RollbackAttemptId = RollbackAttempt, RollbackFirstUtc = Now.AddHours(-2), RollbackStartedUtc = Now.AddHours(-1),
            RollbackAttemptCount = 2,
        };
        var stage = AgentUpdateLocalService.TransitionStageStart(prior, true, false, 0, Now.AddHours(1));
        Assert.Equal(WatchFields(new AgentUpdateJournal()), WatchFields(stage));
        Assert.Null(Project(stage).LastErrorCode);

        var restored = AgentUpdateLocalService.TransitionIntentionalCancellation(stage, prior, Now);
        Assert.Equal(WatchFields(prior), WatchFields(restored));
        Assert.Equal(AgentUpdateWatchJournal.WatchUnavailable, Project(restored).LastErrorCode);
    }

    [Theory]
    [InlineData(AgentUpdateWatchJournal.CommittedWatch)]
    [InlineData(AgentUpdateWatchJournal.RollingBack)]
    public void WatchPhases_PreserveAuthorityAndEvidenceThroughPreInstallGuards(string phase)
    {
        var before = Journal(phase) with
        {
            Required = true, RequiredInstallAttemptId = Attempt, InstallRequestAuthorityExpiresUtc = Now.AddMinutes(-1),
        };
        Assert.True(before.MayHaveStartedInstallation); // Quiesce and repeat apply both consult this fence.
        Assert.Same(before, AgentUpdateLocalService.TransitionReconciliationDeferred(before, Now, required: true));
        Assert.Same(before, AgentUpdateLocalService.TransitionReconciliationFailure(before, Now, required: true));
        Assert.Same(before, AgentUpdateLocalService.TransitionFailure(before, AgentUpdateErrorCodes.ManifestUnavailable));
        Assert.Same(before, AgentUpdateLocalService.ExpireInstallRequestAuthority(before, Now));
        Assert.Same(before, AgentUpdateLocalService.TransitionIntentionalCancellation(before, new AgentUpdateJournal(), Now));
    }

    [Theory]
    [InlineData(AgentUpdateWatchJournal.CommittedWatch)]
    [InlineData(AgentUpdateWatchJournal.RollingBack)]
    public async Task WatchPhases_NativeJournalPreservesBytesAcrossExistingGuards(string phase)
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-app-journal-" + Guid.NewGuid().ToString("N"));
        var path = Path.Combine(root, "transaction.json");
        try
        {
            AgentUpdateSecurity.EnsureProtectedRoot(root);
            var before = Journal(phase) with
            {
                Revision = 17, Required = true, RequiredInstallAttemptId = Attempt,
                InstallRequestAuthorityExpiresUtc = Now.AddMinutes(-1),
                InstallRequest = new AgentUpdateInstallRequest(DateTimeOffset.UnixEpoch, 0, DateTimeOffset.UnixEpoch.AddMinutes(1)),
            };
            AgentUpdateDurableFile.Write(path, root, before);
            var bytes = await File.ReadAllBytesAsync(path);
            var store = new AgentUpdateJournalStore(root);

            async Task AssertStable()
            {
                Assert.Equal(17, store.Read().Revision);
                Assert.Equal(phase, store.Read().Phase);
                Assert.Equal(bytes, await File.ReadAllBytesAsync(path));
            }

            store.Change(current => current.HasUnfinishedAttempt && !current.MayHaveStartedInstallation
                ? AgentUpdateLocalService.TransitionReconciliationDeferred(current, Now) : current);
            await AssertStable();
            store.ChangeAttempt(Attempt, current => AgentUpdateLocalService.TransitionReconciliationDeferred(current, Now, required: true));
            await AssertStable();
            store.ChangeAttempt(Attempt, current => AgentUpdateLocalService.TransitionReconciliationFailure(current, Now, required: true));
            await AssertStable();
            store.Change(current => AgentUpdateLocalService.ExpireInstallRequestAuthority(current, Now));
            await AssertStable();
            await AgentUpdateLocalService.RunScheduledTickAsync(store, new AgentLifecycleSnapshot { Generation = before.LifecycleGeneration },
                () => false, _ => false, _ => throw new InvalidOperationException("The watch owns the attempt."),
                _ => throw new InvalidOperationException("The watch owns the attempt."),
                () => throw new InvalidOperationException("The watch owns the attempt."), CancellationToken.None);
            await AssertStable();

            var projected = false;
            await AgentUpdateLocalService.ReportFailureAsync(store, () =>
            {
                projected = true;
                return Task.CompletedTask;
            }, new HttpRequestException());
            Assert.True(projected);
            await AssertStable();
        }
        finally
        {
            if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void BoundInstallRequest_WaitsThroughWatchAndRetainsItsTerminalErrorOverride()
    {
        var active = Journal(AgentUpdateWatchJournal.RollingBack) with
        {
            InstallRequest = new(Now.AddHours(-2), 0, Now.AddHours(-1), CommandId: "command",
                CampaignId: "campaign", IdempotencyKey: "key", BoundAttemptId: Attempt,
                VerifiedRelease: AgentUpdateExpectedPlan.FromPlan(Plan)),
        };
        Assert.Same(active, AgentUpdateLocalService.CompleteInstallRequest(active, Plan, Now));
        var progress = AgentUpdateLocalService.ProjectInstallRequest(active, Plan, Project(active));
        Assert.Equal(("command", AgentUpdateStates.Installing, "in_progress"), (progress.CommandId, progress.State, progress.RollbackState));

        var failed = active with
        {
            Phase = AgentUpdateStates.Failed, FailureCode = AgentUpdateWatchJournal.RollbackFailed,
            FailureAttemptId = Attempt, FailureInstallerResultId = active.InstallerResult!.ResultId,
        };
        var completed = AgentUpdateLocalService.CompleteInstallRequest(failed, Plan, Now);
        Assert.Equal("attempt_failed", completed.InstallRequest?.TerminalReason);
        var reported = AgentUpdateLocalService.ProjectInstallRequest(completed, Plan, Project(completed));
        Assert.Equal(("command", "install_request_attempt_failed", "failed"),
            (reported.CommandId, reported.LastErrorCode, reported.RollbackState));
    }

    [Theory]
    [InlineData("blocked_sequence")]
    [InlineData("lkg_version")]
    [InlineData("watch_outcome")]
    public async Task ReportSequence_AdvancesForEachLoneFieldAndDeduplicatesEqualReports(string field)
    {
        var root = Directory.CreateTempSubdirectory("cerberus-app-watch-");
        try
        {
            root.CreateSubdirectory("lkg");
            var host = new AgentUpdateLkgStore(root.FullName);
            var store = new AgentUpdateStateStore(Path.Combine(root.FullName, "state.json"), Path.Combine(root.FullName, "result.json"));
            var journal = Journal();
            var watch = Watch(AgentUpdateWatchOutcomes.Open);
            var hostRecord = new AgentUpdateLkgHostRecord(AgentUpdateLkgStore.HostSchema, CurrentVersion, new string('a', 64),
                "promotion", Now, Attempt, LkgVersion);

            AgentUpdateWatchStore.Write(root.FullName, watch with { AttemptId = "other-attempt" });
            var empty = Project(journal, root.FullName);
            await store.WriteAsync(empty, CancellationToken.None);
            var initial = await store.ReadAsync(CurrentVersion, CancellationToken.None);
            foreach (var name in new[] { "blocked_sequence", "lkg_version", "watch_outcome" })
                Assert.DoesNotContain(name, initial.ToHeartbeatStatus().Keys);

            object expected;
            switch (field)
            {
                case "blocked_sequence":
                    journal = journal with { FailedInstallSequence = 76 };
                    expected = 76L;
                    break;
                case "lkg_version":
                    AgentUpdateLkgStore.WriteRecord(host.HostRecordPath, root.FullName, hostRecord);
                    expected = LkgVersion;
                    break;
                case "watch_outcome":
                    AgentUpdateWatchStore.Write(root.FullName, watch);
                    expected = AgentUpdateWatchOutcomes.Open;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(field));
            }

            var changed = Project(journal, root.FullName);
            await store.WriteAsync(changed, CancellationToken.None);
            var freshStore = new AgentUpdateStateStore(store.StatePath, store.InstallerResultPath);
            var persisted = await freshStore.ReadAsync(CurrentVersion, CancellationToken.None);
            Assert.Equal(initial.ReportSequence + 1, persisted.ReportSequence);
            Assert.Equal(expected, persisted.ToHeartbeatStatus()[field]);
            Assert.Equal(initial.ToHeartbeatStatus().Where(pair => pair.Key is not ("report_sequence" or "last_transition_utc")),
                persisted.ToHeartbeatStatus().Where(pair => pair.Key != field && pair.Key is not ("report_sequence" or "last_transition_utc")));

            var bytes = await File.ReadAllBytesAsync(store.StatePath);
            await freshStore.WriteAsync(Project(journal, root.FullName), CancellationToken.None);
            Assert.Equal(bytes, await File.ReadAllBytesAsync(store.StatePath));
            Assert.Equal(persisted.ToHeartbeatStatus(), (await freshStore.ReadAsync(CurrentVersion, CancellationToken.None)).ToHeartbeatStatus());

            journal = journal with { FailedInstallSequence = 0 };
            File.Delete(host.HostRecordPath);
            AgentUpdateWatchStore.Write(root.FullName, watch with { AttemptId = "other-attempt" });
            await freshStore.WriteAsync(Project(journal, root.FullName), CancellationToken.None);
            var cleared = await freshStore.ReadAsync(CurrentVersion, CancellationToken.None);
            Assert.Equal(persisted.ReportSequence + 1, cleared.ReportSequence);
            Assert.DoesNotContain(field, cleared.ToHeartbeatStatus().Keys);
        }
        finally { root.Delete(recursive: true); }
    }

    private static AgentUpdateJournal Journal(string phase = AgentUpdateWatchJournal.CommittedWatch) => new()
    {
        AttemptId = Attempt, Phase = phase, WatchAttemptId = Attempt, WatchRequestedUtc = Now,
        HealthyInstalledVersion = LkgVersion, HealthyInstalledSequence = 76,
        InstallerResult = new AgentUpdateInstallerResult("agent.update.installer-result.v1", "result-1", "succeeded", Now.ToString("O"),
            0, false, null, null, null, Attempt),
    };

    private static AgentUpdateWatchRecord Watch(string outcome) => new(AgentUpdateWatchRecord.CurrentSchema, Attempt,
        CurrentVersion, Plan.Sequence, Guid.Parse("f1184538-302d-4796-9225-e4d18ffdd337"), LkgVersion, "0.2.1018", Now,
        [], null, 0, 0, null, null, outcome, []);

    private static AgentUpdateState Project(AgentUpdateJournal journal, string? root = null)
        => AgentUpdateLocalService.ProjectJournalState(AgentUpdateState.NotChecked(CurrentVersion), journal, Plan, CurrentVersion, root);

    private static void AssertWatchClosed(AgentUpdateJournal before, AgentUpdateJournal after, string code)
        => Assert.Equal(before with
        {
            Phase = AgentUpdateStates.Installed, WatchOutcomeCode = code, WatchOutcomeAttemptId = Attempt,
        }, after);

    private static object WatchFields(AgentUpdateJournal journal)
        => (journal.WatchOutcomeCode, journal.WatchOutcomeAttemptId, journal.WatchRequestedUtc, journal.WatchAttemptId,
            journal.RollbackAttemptId, journal.RollbackStartedUtc, journal.RollbackFirstUtc, journal.RollbackAttemptCount);
}
