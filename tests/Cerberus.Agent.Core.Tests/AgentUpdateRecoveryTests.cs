using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Support-tier checks for the update-recovery decisions that are reachable without the SYSTEM service.</summary>
public sealed class AgentUpdateRecoveryTests
{
    private static readonly DateTimeOffset Recorded = DateTimeOffset.Parse("2026-10-26T10:00:00Z");

    private static AgentUpdateJournal HealthPending(string? recordedAtUtc) => new()
    {
        AttemptId = "attempt-1",
        Phase = AgentUpdateStates.HealthPending,
        InstallerResult = recordedAtUtc is null ? null : new AgentUpdateInstallerResult(
            "agent.update.installer-result.v1", "result-1", "succeeded", recordedAtUtc, 0, false, null, null, null),
    };

    [Theory]
    [InlineData(0, false)]
    [InlineData(14 * 60 + 59, false)]
    [InlineData(15 * 60, true)]
    [InlineData(16 * 60, true)]
    public void HealthRetry_StaysOpenUntilFifteenMinutesAfterTheInstallerResult(int elapsedSeconds, bool expired)
        => Assert.Equal(expired, AgentUpdateLocalService.HealthRetryExpired(
            HealthPending(Recorded.ToString("O")), Recorded.AddSeconds(elapsedSeconds), DateTimeOffset.MinValue));

    [Theory]
    [InlineData(null)]
    [InlineData("not-a-date")]
    public void HealthRetry_WithoutUsableInstallerTimestampCountsFromServiceStartOnly(string? recorded)
    {
        var started = Recorded.AddMinutes(-1);
        var journal = HealthPending(recorded);
        Assert.False(AgentUpdateLocalService.HealthRetryExpired(journal, Recorded, started));
        Assert.False(AgentUpdateLocalService.HealthRetryExpired(journal, started.AddSeconds(15 * 60 - 1), started));
        Assert.True(AgentUpdateLocalService.HealthRetryExpired(journal, started.AddMinutes(15), started));
        Assert.True(AgentUpdateLocalService.HealthRetryExpired(journal, Recorded, DateTimeOffset.MinValue));
    }

    [Theory]
    [InlineData(60, false)]
    [InlineData(14 * 60 + 59, false)]
    [InlineData(15 * 60, true)]
    public void HealthRetry_AfterARebootCountsFifteenMinutesFromServiceStart(int secondsAfterServiceStart, bool expired)
    {
        var started = Recorded;
        var journal = HealthPending(started.AddHours(-5).ToString("O"));
        Assert.Equal(expired, AgentUpdateLocalService.HealthRetryExpired(journal, started.AddSeconds(secondsAfterServiceStart), started));
    }

    [Fact]
    public void HealthRetry_ServiceStartBeforeTheInstallerResultKeepsTheResultAnchor()
    {
        var journal = HealthPending(Recorded.ToString("O"));
        var started = Recorded.AddHours(-3);
        Assert.False(AgentUpdateLocalService.HealthRetryExpired(journal, Recorded.AddSeconds(15 * 60 - 1), started));
        Assert.True(AgentUpdateLocalService.HealthRetryExpired(journal, Recorded.AddMinutes(15), started));
    }

    [Fact]
    public void RecoveryEvidence_IsTheLatestOfResultRunnerAndInstallerTimestamps()
    {
        var journal = HealthPending(Recorded.ToString("O")) with
        {
            InstallerStartedUtc = Recorded.AddMinutes(3),
            RunnerStartedUtc = Recorded.AddMinutes(-20),
        };
        Assert.Equal(Recorded.AddMinutes(3), AgentUpdateLocalService.LastInstallEvidenceUtc(journal));
        Assert.Equal(Recorded.AddMinutes(1), AgentUpdateLocalService.LastInstallEvidenceUtc(
            journal with { InstallerStartedUtc = null, RunnerStartedUtc = Recorded.AddMinutes(1) }));
        Assert.Equal(Recorded, AgentUpdateLocalService.LastInstallEvidenceUtc(
            journal with { InstallerStartedUtc = null, RunnerStartedUtc = null }));
    }

    [Fact]
    public void RecoveryEvidence_IsNullWhenTheJournalHasNoTimestamp()
        => Assert.Null(AgentUpdateLocalService.LastInstallEvidenceUtc(
            new AgentUpdateJournal { AttemptId = "attempt-1", Phase = AgentUpdateStates.RecoveryRequired }));

    [Fact]
    public void ClosedRecovery_NoLongerBlocksTheSchedulerCheckGate()
    {
        var open = new AgentUpdateJournal { AttemptId = "attempt-1", Phase = AgentUpdateStates.RecoveryRequired };
        Assert.True(open.HasUnfinishedAttempt);
        Assert.False((open with { Phase = AgentUpdateStates.Installed }).HasUnfinishedAttempt);
        Assert.False((open with { Phase = AgentUpdateStates.Failed }).HasUnfinishedAttempt);
    }

    [Fact]
    public void RecoveryTimeout_IsADistinctErrorCode()
        => Assert.Equal("recovery_timeout", AgentUpdateErrorCodes.RecoveryTimeout);

    private static AgentUpdateJournal Recovery(DateTimeOffset? resultAt = null) => new()
    {
        AttemptId = "attempt-1",
        Phase = AgentUpdateStates.RecoveryRequired,
        ScheduleSeed = "seed-1",
        InstallerResult = resultAt is null ? null : new AgentUpdateInstallerResult(
            "agent.update.installer-result.v1", "result-1", "succeeded", resultAt.Value.ToString("O"),
            3010, true, null, "kept message", @"C:\logs\msi.log", "attempt-1", 2),
    };

    private static readonly AgentUpdatePlan Plan = new("msi", "9.9.9", "stable", "a.msi", "00", "2026-10-26T09:00:00Z", "test",
        Sequence: 77);

    [Fact]
    public void RecoveryCloseDue_RequiresAnAttemptAndNoLiveProcess()
    {
        var journal = Recovery(Recorded);
        var later = Recorded.AddMinutes(30);
        Assert.True(AgentUpdateLocalService.RecoveryCloseDue(journal, later, DateTimeOffset.MinValue, false, false));
        Assert.False(AgentUpdateLocalService.RecoveryCloseDue(journal with { AttemptId = null }, later, DateTimeOffset.MinValue, false, false));
        Assert.False(AgentUpdateLocalService.RecoveryCloseDue(journal, later, DateTimeOffset.MinValue, true, false));
        Assert.False(AgentUpdateLocalService.RecoveryCloseDue(journal, later, DateTimeOffset.MinValue, false, true));
    }

    [Theory]
    [InlineData(9 * 60 + 59, false)]
    [InlineData(10 * 60, true)]
    public void RecoveryCloseDue_WaitsTenMinutesAfterTheLatestInstallActivity(int elapsedSeconds, bool due)
    {
        var journal = Recovery(Recorded.AddMinutes(-30)) with { InstallerStartedUtc = Recorded.AddMinutes(-20), RunnerStartedUtc = Recorded };
        Assert.Equal(due, AgentUpdateLocalService.RecoveryCloseDue(journal, Recorded.AddSeconds(elapsedSeconds), DateTimeOffset.MinValue, false, false));
    }

    [Fact]
    public void RecoveryCloseDue_WithoutAnyTimestampClosesWhenTheServiceStartedLongAgo()
        => Assert.True(AgentUpdateLocalService.RecoveryCloseDue(Recovery(), Recorded, DateTimeOffset.MinValue, false, false));

    [Theory]
    [InlineData(9 * 60 + 59, false)]
    [InlineData(10 * 60, true)]
    public void RecoveryCloseDue_AfterARebootCountsTenMinutesFromServiceStart(int secondsAfterServiceStart, bool due)
    {
        var started = Recorded;
        var stale = Recovery(started.AddHours(-5)) with { InstallerStartedUtc = started.AddHours(-5), RunnerStartedUtc = started.AddHours(-5) };
        Assert.Equal(due, AgentUpdateLocalService.RecoveryCloseDue(stale, started.AddSeconds(secondsAfterServiceStart), started, false, false));
        var noEvidence = Recovery();
        Assert.Equal(due, AgentUpdateLocalService.RecoveryCloseDue(noEvidence, started.AddSeconds(secondsAfterServiceStart), started, false, false));
    }

    [Fact]
    public void RecoveryCloseDue_RecentEvidenceBeatsAnOlderServiceStart()
    {
        var journal = Recovery(Recorded);
        var started = Recorded.AddHours(-3);
        Assert.False(AgentUpdateLocalService.RecoveryCloseDue(journal, Recorded.AddSeconds(9 * 60 + 59), started, false, false));
        Assert.True(AgentUpdateLocalService.RecoveryCloseDue(journal, Recorded.AddMinutes(10), started, false, false));
    }

    [Theory]
    [InlineData(AgentUpdateStates.HealthPending)]
    [InlineData(AgentUpdateStates.Installed)]
    [InlineData(AgentUpdateStates.Failed)]
    public void CloseRecovery_LeavesOtherPhasesUntouched(string phase)
    {
        var journal = Recovery(Recorded) with { Phase = phase };
        Assert.Same(journal, AgentUpdateLocalService.CloseRecovery(journal, Plan, healthy: true, Recorded));
        Assert.Same(journal, AgentUpdateLocalService.CloseRecovery(journal, Plan, healthy: false, Recorded));
    }

    [Fact]
    public void CloseRecovery_HealthyPlanBecomesInstalledWithPlanEvidence()
    {
        var closed = AgentUpdateLocalService.CloseRecovery(Recovery(Recorded), Plan, healthy: true, Recorded);
        Assert.Equal(AgentUpdateStates.Installed, closed.Phase);
        Assert.Equal(77, closed.HealthyInstalledSequence);
        Assert.Equal("9.9.9", closed.HealthyInstalledVersion);
        Assert.False(closed.HasUnfinishedAttempt);
    }

    [Fact]
    public void CloseRecovery_HealthyWithoutPlanFails()
        => Assert.Equal(AgentUpdateStates.Failed,
            AgentUpdateLocalService.CloseRecovery(Recovery(Recorded), null, healthy: true, Recorded).Phase);

    [Fact]
    public void CloseRecovery_UnhealthyFailsWithTimeoutAndADayOutSchedule()
    {
        var before = Recovery(Recorded);
        var closed = AgentUpdateLocalService.CloseRecovery(before, Plan, healthy: false, Recorded);
        Assert.Equal(AgentUpdateStates.Failed, closed.Phase);
        Assert.Equal(AgentUpdateStates.Failed, closed.InstallerResult!.State);
        Assert.Equal(AgentUpdateErrorCodes.RecoveryTimeout, closed.InstallerResult.ErrorCode);
        Assert.InRange(closed.NextCheckUtc!.Value, Recorded.AddHours(24), Recorded.AddHours(30));
        Assert.False(closed.HasUnfinishedAttempt);
        var kept = before.InstallerResult!;
        Assert.Equal((kept.ResultId, kept.RecordedAtUtc, kept.MsiExitCode, kept.RequiresReboot, kept.ErrorMessage, kept.MsiLogPath, kept.AttemptId, kept.RetryCount),
            (closed.InstallerResult.ResultId, closed.InstallerResult.RecordedAtUtc, closed.InstallerResult.MsiExitCode, closed.InstallerResult.RequiresReboot,
             closed.InstallerResult.ErrorMessage, closed.InstallerResult.MsiLogPath, closed.InstallerResult.AttemptId, closed.InstallerResult.RetryCount));
    }

    [Fact]
    public void CloseRecovery_WithoutInstallerResultStillRecordsTheTimeout()
    {
        var closed = AgentUpdateLocalService.CloseRecovery(Recovery(), Plan, healthy: false, Recorded);
        Assert.Equal(AgentUpdateErrorCodes.RecoveryTimeout, closed.InstallerResult!.ErrorCode);
        Assert.Equal(AgentUpdateStates.Failed, closed.InstallerResult.State);
    }

    [Theory]
    [InlineData(AgentInstallerHealthPhase.ServiceExecutableHash, 7, 7)]
    [InlineData(AgentInstallerHealthPhase.Stability, 7, 7)]
    [InlineData(AgentInstallerHealthPhase.Stability, 100, 100)]
    [InlineData(AgentInstallerHealthPhase.BackendContact, 7, 5)]
    [InlineData(null, 7, 5)]
    public void CloseRecovery_PinsTheFailedSequenceOnlyForAProvenHealthRollback(AgentInstallerHealthPhase? phase, long planSequence, long expected)
    {
        var plan = Plan with { Sequence = planSequence };
        var closed = AgentUpdateLocalService.CloseRecovery(Recovery(Recorded) with { FailedInstallSequence = 5 }, plan, healthy: false, Recorded, phase);
        Assert.Equal(AgentUpdateStates.Failed, closed.Phase);
        Assert.Equal(AgentUpdateErrorCodes.RecoveryTimeout, closed.InstallerResult!.ErrorCode);
        Assert.Equal(expected, closed.FailedInstallSequence);
    }

    [Fact]
    public void CloseRecovery_NeverLowersAnExistingPin()
        => Assert.Equal(9, AgentUpdateLocalService.CloseRecovery(
            Recovery(Recorded) with { FailedInstallSequence = 9 }, Plan with { Sequence = 7 }, healthy: false, Recorded,
            AgentInstallerHealthPhase.PipeConnect).FailedInstallSequence);

    [Fact]
    public void CloseRecovery_WithoutPlanKeepsTheSequence()
        => Assert.Equal(5, AgentUpdateLocalService.CloseRecovery(
            Recovery(Recorded) with { FailedInstallSequence = 5 }, null, healthy: false, Recorded,
            AgentInstallerHealthPhase.Stability).FailedInstallSequence);

    [Fact]
    public void CloseRecovery_HealthyKeepsTheSequence()
    {
        var closed = AgentUpdateLocalService.CloseRecovery(
            Recovery(Recorded) with { FailedInstallSequence = 5 }, Plan, healthy: true, Recorded, AgentInstallerHealthPhase.Stability);
        Assert.Equal(AgentUpdateStates.Installed, closed.Phase);
        Assert.Equal(5, closed.FailedInstallSequence);
    }

    private static bool Elevated
    {
        get
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return identity.IsSystem || new System.Security.Principal.WindowsPrincipal(identity).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
    }

    [Fact]
    public void RecoveryRollbackPhase_HealthyOrWithoutPlanReadsNothing()
    {
        var missing = Path.Combine(Path.GetTempPath(), "cerberus-recovery-phase-" + Guid.NewGuid().ToString("N"));
        Assert.Null(AgentUpdateLocalService.RecoveryRollbackPhase(true, Plan, Recorded, missing));
        Assert.Null(AgentUpdateLocalService.RecoveryRollbackPhase(false, null, Recorded, missing));
    }

    [Fact]
    public void RecoveryRollbackPhase_UnreadableRootYieldsNullInsteadOfThrowing()
    {
        Assert.Null(AgentUpdateLocalService.RecoveryRollbackPhase(false, Plan, Recorded, ""));
        // A plain temp folder (inherited user ACE) fails the protected-root check, so even a valid-looking record is not trusted.
        var untrusted = Path.Combine(Path.GetTempPath(), "cerberus-recovery-phase-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(untrusted);
        try
        {
            AgentUpdateDurableFile.Write(Path.Combine(untrusted, "a.health-failure.json"), untrusted,
                new AgentInstallerHealthDiagnostic("v1", "health", Recorded.AddMinutes(1), "stability", "unexpected", "Exception", null, "9.9.9", null, null, null, null));
            Assert.Null(AgentUpdateLocalService.RecoveryRollbackPhase(false, Plan, Recorded, untrusted));
        }
        finally { Directory.Delete(untrusted, recursive: true); }
    }

    [Fact]
    public void RecoveryRollbackPhase_UnhealthyWithACurrentAttemptRecordReturnsItsPhase()
    {
        if (!Elevated) return; // the protected root can only be created with an elevated token
        var root = Path.Combine(Path.GetTempPath(), "cerberus-recovery-phase-" + Guid.NewGuid().ToString("N"));
        try
        {
            AgentUpdateSecurity.EnsureProtectedRoot(root);
            AgentUpdateDurableFile.Write(Path.Combine(root, "a.health-failure.json"), root,
                new AgentInstallerHealthDiagnostic("v1", "health", Recorded.AddMinutes(1), "stability", "unexpected", "Exception", null, "9.9.9", null, null, null, null));
            Assert.Equal(AgentInstallerHealthPhase.Stability, AgentUpdateLocalService.RecoveryRollbackPhase(false, Plan, Recorded, root));
            Assert.Null(AgentUpdateLocalService.RecoveryRollbackPhase(true, Plan, Recorded, root));
            Assert.Null(AgentUpdateLocalService.RecoveryRollbackPhase(false, Plan, Recorded.AddHours(1), root));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }
}
