using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateDeadlineTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-18T12:00:00Z");

    [Fact]
    public void Busy1618_NotCountedAndNeverPinned()
    {
        var current = Busy() with { RetryCount = 3, FailedInstallSequence = 41 };
        int[] minutes = [1, 2, 4, 8, 16, 30, 30, 30, 30, 30];
        var round = Now;
        for (var index = 0; index < minutes.Length; index++)
        {
            current = AgentUpdateLocalService.TransitionBusyRetry(current, round);
            Assert.Equal((3, 41L, index + 1), (current.RetryCount, current.FailedInstallSequence, current.InstallerBusyCount));
            Assert.Equal(Now, current.BusySinceUtc);
            Assert.Equal(round.AddMinutes(minutes[index]), current.NextRetryUtc);
            Assert.Equal(AgentUpdateStates.RetryableBusy, current.Phase);
            round = current.NextRetryUtc!.Value;
            AgentUpdateLocalService.RequireInstallerRetryDue(current, round);
            current = current with { NextRetryUtc = null };
        }
        var saturated = AgentUpdateLocalService.TransitionBusyRetry(current with { InstallerBusyCount = 64 }, round);
        Assert.Equal(64, saturated.InstallerBusyCount);
        Assert.Equal(round.AddMinutes(30), saturated.NextRetryUtc);
    }

    [Fact]
    public void Busy1618_ClosesAtDueRetryAfter24Hours_WithBusyTimeoutCode()
    {
        var busy = Busy() with { BusySinceUtc = Now.AddHours(-24), NextRetryUtc = Now, InstallerBusyCount = 48,
            FailedInstallSequence = 41, InstallRequestAuthorityExpiresUtc = Now.AddMinutes(-1) };
        Assert.ThrowsAny<OperationCanceledException>(() => AgentUpdateLocalService.HoldExpiredInstallRequest(busy, true, default));
        Assert.Equal(busy, AgentUpdateLocalService.TransitionBusyRetry(busy, Now.AddTicks(-1)));

        var closed = AgentUpdateLocalService.TransitionBusyRetry(busy, Now);
        Assert.Equal(AgentUpdateStates.Failed, closed.Phase);
        Assert.Equal(busy.RetryCount, closed.RetryCount);
        Assert.Equal(busy.FailedInstallSequence, closed.FailedInstallSequence);
        Assert.Equal(busy.InstallerResult, closed.InstallerResult);
        Assert.Equal(AgentUpdateErrorCodes.InstallerBusy, closed.InstallerResult!.ErrorCode);
        Assert.Equal(AgentUpdateErrorCodes.InstallerBusyTimeout, AgentUpdateLocalService.ProjectedErrorCode(closed, closed.Phase));
        Assert.Null(closed.NextRetryUtc);
        Assert.Equal(Now.AddHours(24).Add(AgentUpdateJournalStore.Offset(busy.ScheduleSeed, TimeSpan.FromHours(6))), closed.NextCheckUtc);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ManualApplyDuringBusyBackoff_StaysRetryableBusy(bool reconciled)
    {
        var busy = Busy() with { NextRetryUtc = reconciled ? Now.AddMinutes(1) : null };
        var result = await AgentUpdateLocalService.RespondToApplyAsync(() =>
        {
            AgentUpdateLocalService.RequireInstallerRetryDue(busy, Now);
            throw new InvalidOperationException("Manual apply reached launch admission.");
        }, _ => throw new InvalidOperationException("Manual retry refusal reached failure reporting."));
        Assert.False(result.Success);
        Assert.Equal("retry_not_due", result.Code);
        Assert.Equal(AgentUpdateStates.RetryableBusy, busy.Phase);
        Assert.Null(busy.FailureCode);
    }

    [Fact]
    public void InstallOverdue_IsAnchoredToBootAndInstaller_AndDoesNotChangePhase()
    {
        var active = new AgentUpdateJournal { AttemptId = "attempt", Phase = AgentUpdateStates.RecoveryRequired,
            RunnerStartedUtc = Now.AddMinutes(-90), InstallerStartedUtc = Now.AddMinutes(-70),
            InstallerResult = AgentUpdateInstallerResult.Failure(new InvalidOperationException("fixture")) };
        var boot = Now.AddHours(-1);
        Assert.Equal(active, AgentUpdateLocalService.TransitionInstallOverdue(active, Now.AddTicks(-1), boot, false, true));
        Assert.Equal(active, AgentUpdateLocalService.TransitionInstallOverdue(active, Now, boot, false, false));
        var recentInstaller = active with { InstallerStartedUtc = Now.AddMinutes(-59) };
        Assert.Equal(recentInstaller, AgentUpdateLocalService.TransitionInstallOverdue(recentInstaller, Now, boot, true, false));

        var alerted = AgentUpdateLocalService.TransitionInstallOverdue(active, Now, boot, false, true);
        Assert.Equal(active, alerted with { AlertCode = null, AlertAttemptId = null });
        Assert.Equal(active.AttemptId, alerted.AlertAttemptId);
        Assert.Equal(AgentUpdateErrorCodes.InstallOverdue, AgentUpdateLocalService.ProjectedErrorCode(alerted, active.Phase));
        Assert.Equal(alerted, AgentUpdateLocalService.TransitionInstallOverdue(alerted, Now.AddMinutes(1), boot, false, true));

        var failed = alerted with { FailureCode = AgentUpdateErrorCodes.MsiEnvironment,
            FailureAttemptId = active.AttemptId, FailureInstallerResultId = active.InstallerResult.ResultId };
        Assert.Equal(AgentUpdateErrorCodes.MsiEnvironment, AgentUpdateLocalService.ProjectedErrorCode(failed, failed.Phase));
        Assert.Equal(AgentUpdateErrorCodes.Unknown,
            AgentUpdateLocalService.ProjectedErrorCode(alerted with { AlertAttemptId = "prior-attempt" }, active.Phase));
    }

    [Fact]
    public void PendingReboot_SameBootAfter24Hours_ProjectsAlertWithoutPromoting()
    {
        var pending = new AgentUpdateJournal { AttemptId = "attempt", Phase = AgentUpdateStates.PendingReboot,
            InstallationBootId = "same-boot", InstallerResult = AgentUpdateInstallerResult.FromMsiExitCode(3010, null, null) with
            { RecordedAtUtc = Now.AddHours(-24).ToString("O") } };
        Assert.Equal(pending, AgentUpdateLocalService.TransitionRebootOverdue(pending, Now.AddTicks(-1), "same-boot"));
        Assert.Equal(pending, AgentUpdateLocalService.TransitionRebootOverdue(pending, Now, "later-boot"));
        var alerted = AgentUpdateLocalService.TransitionRebootOverdue(pending, Now, "same-boot");
        Assert.Equal(pending, alerted with { AlertCode = null, AlertAttemptId = null });
        Assert.True(alerted.HasUnfinishedAttempt);
        Assert.Equal(AgentUpdateErrorCodes.RebootRequired, alerted.InstallerResult!.ErrorCode);
        Assert.Equal(AgentUpdateErrorCodes.RebootOverdue, AgentUpdateLocalService.ProjectedErrorCode(alerted, alerted.Phase));
    }

    [Fact]
    public void Relaunch_ClearsAlertAndPreservesBusyWindow()
    {
        var busy = Busy() with { BusySinceUtc = Now, InstallerBusyCount = 7,
            AlertCode = AgentUpdateErrorCodes.InstallOverdue, AlertAttemptId = "attempt" };
        var launched = AgentUpdateLocalService.TransitionLaunchRequested(busy, generation: 0, automatic: true, default);
        Assert.Equal(AgentUpdaterContract.LaunchRequestedPhase, launched.Phase);
        Assert.Equal((busy.BusySinceUtc, busy.InstallerBusyCount), (launched.BusySinceUtc, launched.InstallerBusyCount));
        Assert.Null(launched.AlertAttemptId);
        Assert.Null(launched.AlertCode);
    }

    [Theory]
    [InlineData(AgentUpdateStates.Checking, null, AgentUpdateStates.NotChecked)]
    [InlineData(AgentUpdateStates.Downloading, "attempt", AgentUpdateStates.Blocked)]
    public void InterruptedPreInstall_Persists15MinuteGate(string phase, string? attempt, string expectedPhase)
    {
        var root = NewRoot();
        try
        {
            var current = new AgentUpdateJournal { Phase = phase, AttemptId = attempt, LifecycleGeneration = 7 };
            if (attempt is not null)
                Directory.CreateDirectory(Path.Combine(root, "attempts", AgentUpdateSecurity.AttemptDirectoryPrefix + attempt));
            AgentUpdateJournal Change(Func<AgentUpdateJournal, AgentUpdateJournal> transition) => current = transition(current);
            var recovered = AgentUpdateLocalService.RecoverActiveAttempt(root, current, 7, Now, false, null, Change,
                (_, transition) => Change(transition), () => current, interruptedRetryAtUtc: Now.AddMinutes(15));
            Assert.Equal(expectedPhase, recovered.Phase);
            Assert.Equal(Now.AddMinutes(15), recovered.NextCheckUtc);
            Assert.Equal(recovered.NextCheckUtc, recovered.PreInstallRetryNotBeforeUtc);
            Assert.True(AgentUpdateLocalService.HoldsPreInstallRetry(recovered, Now));
            Assert.False(AgentUpdateLocalService.HoldsPreInstallRetry(recovered, Now.AddMinutes(15)));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public void InterruptedPreInstallRetry_IsShortOnlyInDevelopmentCampaignBuilds()
    {
        Assert.Equal(TimeSpan.FromMinutes(15), AgentUpdateLocalService.InterruptedPreInstallRetryDelay(labBuild: false));
        Assert.Equal(TimeSpan.FromSeconds(30), AgentUpdateLocalService.InterruptedPreInstallRetryDelay(labBuild: true));
    }

    [Fact]
    public void PreInstallBackoff_IsFlatThirtySecondsOnlyInDevelopmentCampaignBuilds()
    {
        int[] releaseMinutes = [15, 30, 60, 120, 240, 240, 240, 240];
        for (var count = 1; count <= 8; count++)
        {
            Assert.Equal(TimeSpan.FromMinutes(releaseMinutes[count - 1]), AgentUpdateLocalService.PreInstallBackoffDelay(count, labBuild: false));
            Assert.Equal(TimeSpan.FromSeconds(30), AgentUpdateLocalService.PreInstallBackoffDelay(count, labBuild: true));
        }
    }

    [Fact]
    public void InstallRequestRetry_IsShortOnlyInDevelopmentCampaignBuilds()
    {
        Assert.Equal(TimeSpan.FromMinutes(5), AgentUpdateLocalService.InstallRequestRetryDelay(labBuild: false));
        Assert.Equal(TimeSpan.FromSeconds(30), AgentUpdateLocalService.InstallRequestRetryDelay(labBuild: true));
    }

    [Fact]
    public async Task ScheduledPreInstallGate_LeavesPendingRequestUnprocessed()
    {
        var root = NewRoot();
        try
        {
            var now = DateTimeOffset.UtcNow;
            var pending = new AgentUpdateJournal { Phase = AgentUpdateStates.Blocked, AttemptId = "attempt",
                PreInstallRetryNotBeforeUtc = now.AddMinutes(15), NextCheckUtc = now.AddMinutes(-1),
                InstallRequest = new AgentUpdateInstallRequest(now.AddMinutes(-1), 7, now.AddHours(1)) };
            AgentUpdateDurableFile.Write(Path.Combine(root, "transaction.json"), root, pending);
            var journal = new AgentUpdateJournalStore(root);
            await AgentUpdateLocalService.RunScheduledTickAsync(journal, new() { Generation = 7 }, () => false, _ => false,
                _ => throw new InvalidOperationException("Unexpected request staging."),
                _ => throw new InvalidOperationException("Unexpected installer admission."),
                () => throw new InvalidOperationException("Unexpected scheduled check."), default);
            Assert.Equal(pending, journal.Read());
            Assert.True(journal.Read().InstallRequest!.IsPending);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task RuntimeDownloadFailure_DoubleReportCountsOnce_AndStageSuccessResets()
    {
        var root = NewRoot(protectedJournal: true);
        try
        {
            var store = new AgentUpdateJournalStore(root);
            var current = store.Change(_ => new() { Phase = AgentUpdateStates.Downloading, ScheduleSeed = "deadline-fixture" });
            var failure = new InvalidOperationException("BITS update download failed: no progress.");
            var beforeReport = DateTimeOffset.UtcNow;
            await AgentUpdateLocalService.ReportFailureAsync(store, () => Task.CompletedTask, failure);
            var once = store.Read();
            var firstDelay = TimeSpan.FromMinutes(15);
            var jitter = AgentUpdateJournalStore.Offset(current.ScheduleSeed, firstDelay / 4);
            Assert.Equal(1, once.PreInstallFailureCount);
            Assert.Equal(once.NextCheckUtc, once.PreInstallRetryNotBeforeUtc);
            Assert.InRange(once.NextCheckUtc!.Value, beforeReport + firstDelay + jitter, DateTimeOffset.UtcNow + firstDelay + jitter);
            await AgentUpdateLocalService.ReportFailureAsync(store, () => Task.CompletedTask, failure);
            Assert.Equal(once, store.Read() with { Revision = once.Revision });

            var checking = AgentUpdateLocalService.TransitionStageStart(once, true, false, 0, Now.AddHours(24));
            Assert.Equal(once.PreInstallFailureCount, checking.PreInstallFailureCount);
            Assert.Equal(once.PreInstallRetryNotBeforeUtc, checking.PreInstallRetryNotBeforeUtc);
            var checkOnly = AgentUpdateLocalService.TransitionCheckResult(checking, available: false, required: false, lifecycleGeneration: 0);
            Assert.Equal(checking.PreInstallFailureCount, checkOnly.PreInstallFailureCount);
            var failed = RecordPreInstallFailure(checking, AgentUpdateErrorCodes.DownloadFailed, Now);
            Assert.Equal(2, failed.PreInstallFailureCount);
            Assert.Equal(Now.AddMinutes(30).Add(AgentUpdateJournalStore.Offset(current.ScheduleSeed, TimeSpan.FromMinutes(7.5))), failed.NextCheckUtc);

            var success = AgentUpdateLocalService.TransitionStageResult(failed, null, true, false, 0, Now);
            Assert.Equal(0, success.PreInstallFailureCount);
            Assert.Null(success.PreInstallRetryNotBeforeUtc);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public void PreInstallBackoff_CapsBaseAtFourHours_AndTrustFailureKeepsItsSchedule()
    {
        var checking = new AgentUpdateJournal { Phase = AgentUpdateStates.Checking, PreInstallFailureCount = 8,
            NextCheckUtc = Now.AddHours(27), FailedInstallSequence = 41 };
        var failed = RecordPreInstallFailure(checking, AgentUpdateErrorCodes.HashMismatch, Now);
        Assert.Equal(8, failed.PreInstallFailureCount);
        Assert.Equal(Now.AddHours(4).Add(AgentUpdateJournalStore.Offset(checking.ScheduleSeed, TimeSpan.FromHours(1))), failed.NextCheckUtc);
        Assert.Equal(checking.FailedInstallSequence, failed.FailedInstallSequence);

        var trustFailure = RecordPreInstallFailure(checking, AgentUpdateErrorCodes.SignatureInvalid, Now);
        Assert.Equal(checking.NextCheckUtc, trustFailure.NextCheckUtc);
        Assert.Null(trustFailure.PreInstallRetryNotBeforeUtc);
    }

    private static AgentUpdateJournal Busy() => new() { AttemptId = "attempt", Phase = AgentUpdateStates.RetryableBusy,
        InstallerResult = AgentUpdateInstallerResult.FromMsiExitCode(1618, null, null) };

    private static AgentUpdateJournal RecordPreInstallFailure(AgentUpdateJournal before, string code, DateTimeOffset now)
        => AgentUpdateLocalService.ApplyPreInstallBackoff(before, AgentUpdateLocalService.TransitionFailure(before, code), code, now);

    private static string NewRoot(bool protectedJournal = false)
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-update-deadline-" + Guid.NewGuid().ToString("N"));
        if (protectedJournal) AgentUpdateSecurity.EnsureProtectedRoot(root);
        else Directory.CreateDirectory(root);
        return root;
    }
}
