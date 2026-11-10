using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateFailureCodeTests
{
    [Fact]
    public void Classify_SeparatesExpiredManifestFromOtherManifestFailures()
    {
        Assert.Equal(AgentUpdateErrorCodes.ManifestExpired,
            AgentUpdateErrorCodes.Classify(new InvalidOperationException("Update manifest has expired.")));
        Assert.Equal(AgentUpdateErrorCodes.ManifestInvalid,
            AgentUpdateErrorCodes.Classify(new InvalidOperationException("Update manifest is invalid.")));
        Assert.Equal(AgentUpdateErrorCodes.ManifestInvalid,
            AgentUpdateErrorCodes.Classify(new InvalidOperationException("Update manifest expiry is invalid.")));
    }

    [Fact]
    public void ProjectedErrorCode_NeverOutlivesItsAttemptOrInstallerResult()
    {
        var bound = new AgentUpdateJournal
        {
            AttemptId = "attempt-a",
            Phase = AgentUpdateStates.Failed,
            InstallerResult = Result("result-1", AgentUpdateErrorCodes.MsiFailed),
            FailureCode = AgentUpdateErrorCodes.StagingFailed,
            FailureAttemptId = "attempt-a",
            FailureInstallerResultId = "result-1",
        };
        Assert.Equal(AgentUpdateErrorCodes.StagingFailed,
            AgentUpdateLocalService.ProjectedErrorCode(bound, AgentUpdateStates.Failed));

        var newAttemptFailed = bound with
        {
            AttemptId = "attempt-b",
            InstallerResult = Result("result-2", AgentUpdateErrorCodes.MsiFailed),
        };
        Assert.Equal(AgentUpdateErrorCodes.MsiFailed,
            AgentUpdateLocalService.ProjectedErrorCode(newAttemptFailed, AgentUpdateStates.Failed));

        var sameAttemptNewResult = bound with { InstallerResult = Result("result-3", AgentUpdateErrorCodes.InstallerBusy) };
        Assert.Equal(AgentUpdateErrorCodes.InstallerBusy,
            AgentUpdateLocalService.ProjectedErrorCode(sameAttemptNewResult, AgentUpdateStates.Failed));
    }

    [Fact]
    public void TransitionFailure_NeverRewritesInstallerEvidence()
    {
        var installFailed = new AgentUpdateJournal
        {
            AttemptId = "attempt-a",
            Phase = AgentUpdateStates.Failed,
            InstallerResult = Result("result-1", AgentUpdateErrorCodes.MsiFailed),
        };
        var after = AgentUpdateLocalService.TransitionFailure(installFailed, AgentUpdateErrorCodes.ManifestExpired);
        Assert.Equal(installFailed, after);
        Assert.Equal(AgentUpdateErrorCodes.MsiFailed, AgentUpdateLocalService.ProjectedErrorCode(after, AgentUpdateStates.Failed));
    }

    [Fact]
    public void TransitionFailure_RecordsADownloadFailureOnce()
    {
        var moved = AgentUpdateLocalService.TransitionFailure(
            new AgentUpdateJournal { AttemptId = "attempt-a", Phase = AgentUpdateStates.Downloading }, AgentUpdateErrorCodes.DownloadFailed);
        Assert.Equal(AgentUpdateErrorCodes.DownloadFailed, AgentUpdateLocalService.ProjectedErrorCode(moved, AgentUpdateStates.Failed));

        // The stager writes Failed before the service reports the same exception.
        var stagerFailed = AgentUpdateLocalService.TransitionFailure(
            new AgentUpdateJournal { AttemptId = "attempt-a", Phase = AgentUpdateStates.Failed }, AgentUpdateErrorCodes.HashMismatch);
        Assert.Equal(AgentUpdateErrorCodes.HashMismatch, AgentUpdateLocalService.ProjectedErrorCode(stagerFailed, AgentUpdateStates.Failed));

        var reportedAgain = AgentUpdateLocalService.TransitionFailure(stagerFailed, AgentUpdateErrorCodes.StagingFailed);
        Assert.Equal(stagerFailed, reportedAgain);

        var staleCause = stagerFailed with { AttemptId = "attempt-b" };
        Assert.Equal(AgentUpdateErrorCodes.DownloadFailed, AgentUpdateLocalService.TransitionFailure(
            staleCause, AgentUpdateErrorCodes.DownloadFailed).FailureCode);
        Assert.Equal("attempt-b", AgentUpdateLocalService.TransitionFailure(staleCause, AgentUpdateErrorCodes.DownloadFailed).FailureAttemptId);
    }

    [Fact]
    public void IntentionalCancellation_RestoresTheEarlierCause()
    {
        var failed = AgentUpdateLocalService.TransitionFailure(
            new AgentUpdateJournal { AttemptId = "attempt-a", Phase = AgentUpdateStates.Failed }, AgentUpdateErrorCodes.DownloadFailed);
        var now = DateTimeOffset.UtcNow;
        foreach (var started in new[]
                 {
                     AgentUpdateLocalService.TransitionCheckStart(failed, automatic: true, required: false, lifecycleGeneration: 0, now),
                     AgentUpdateLocalService.TransitionStageStart(failed, automatic: true, required: false, lifecycleGeneration: 0, now),
                 })
        {
            Assert.Null(started.FailureCode);
            var restored = AgentUpdateLocalService.TransitionIntentionalCancellation(started, failed, now);
            Assert.Equal(AgentUpdateStates.Failed, restored.Phase);
            Assert.Equal(AgentUpdateErrorCodes.DownloadFailed, AgentUpdateLocalService.ProjectedErrorCode(restored, restored.Phase));
            Assert.Equal(restored, AgentUpdateLocalService.TransitionFailure(restored, AgentUpdateErrorCodes.StagingFailed));
        }
    }

    [Fact]
    public void CloseRecovery_ProjectsRecoveryTimeoutOverAnEarlierCause()
    {
        var recovering = new AgentUpdateJournal
        {
            AttemptId = "attempt-a",
            Phase = AgentUpdateStates.RecoveryRequired,
            InstallerResult = Result("result-1", AgentUpdateErrorCodes.MsiFailed),
        };
        var tickFailed = AgentUpdateLocalService.TransitionFailure(recovering, AgentUpdateErrorCodes.ManifestUnavailable);
        Assert.Equal(recovering, tickFailed);
        var launchFailed = AgentUpdateLocalService.TransitionFailure(
            new AgentUpdateJournal { AttemptId = "attempt-a", Phase = "launch_requested" }, AgentUpdateErrorCodes.StagingFailed);

        foreach (var before in new[] { tickFailed, launchFailed, recovering with
                 {
                     FailureCode = AgentUpdateErrorCodes.StagingFailed, FailureAttemptId = "attempt-a", FailureInstallerResultId = "result-1",
                 } })
        {
            var closed = AgentUpdateLocalService.CloseRecovery(before, plan: null, healthy: false, DateTimeOffset.UtcNow);
            Assert.Equal(AgentUpdateStates.Failed, closed.Phase);
            Assert.Null(closed.FailureCode);
            Assert.Equal(AgentUpdateErrorCodes.RecoveryTimeout, AgentUpdateLocalService.ProjectedErrorCode(closed, closed.Phase));
        }
    }

    [Fact]
    public void ClosedLabFailureReceipt_SurvivesAReportedFailure()
    {
        var root = NewRoot();
        var closed = AgentUpdateLabRemediationTests.ClosedForeignFailure();
        var path = AgentUpdateLocalService.PreserveClosedLabFailure(root, closed);

        Assert.Equal(closed, AgentUpdateLocalService.TransitionFailure(closed, AgentUpdateErrorCodes.ManifestExpired));
        var withCause = closed with
        {
            FailureCode = AgentUpdateErrorCodes.ManifestExpired,
            FailureAttemptId = closed.AttemptId,
            FailureInstallerResultId = closed.InstallerResult!.ResultId,
        };
        Assert.Equal(path, AgentUpdateLocalService.PreserveClosedLabFailure(root, withCause));
        Assert.Throws<InvalidOperationException>(() => AgentUpdateLocalService.PreserveClosedLabFailure(root,
            closed with { FailedInstallSequence = closed.FailedInstallSequence + 1 }));
    }

    [Fact]
    public void ProjectedErrorCode_IsHiddenOutsideFailedStates()
    {
        var failed = AgentUpdateLocalService.TransitionFailure(
            new AgentUpdateJournal { Phase = AgentUpdateStates.Current }, AgentUpdateErrorCodes.ManifestExpired);
        Assert.Equal(AgentUpdateStates.Failed, failed.Phase);
        Assert.Equal(AgentUpdateErrorCodes.ManifestExpired,
            AgentUpdateLocalService.ProjectedErrorCode(failed, AgentUpdateStates.Failed));
        Assert.Null(AgentUpdateLocalService.ProjectedErrorCode(failed, AgentUpdateStates.Checking));

        var checkedAgain = AgentUpdateLocalService.TransitionCheckResult(failed, available: false, required: false, lifecycleGeneration: 0);
        Assert.Null(checkedAgain.FailureCode);
        Assert.Null(checkedAgain.FailureAttemptId);
        Assert.Null(checkedAgain.FailureInstallerResultId);
    }

    [Fact]
    public void TransitionFailure_KeepsInstalledOutcomeWithoutRecordingACause()
    {
        var installed = new AgentUpdateJournal { AttemptId = "attempt-a", Phase = AgentUpdateStates.Installed };
        var after = AgentUpdateLocalService.TransitionFailure(installed, AgentUpdateErrorCodes.ManifestExpired);
        Assert.Equal(AgentUpdateStates.Installed, after.Phase);
        Assert.Null(after.FailureCode);
    }

    [Fact]
    public void TransitionFailure_RecordsCauseForAnInterruptedLaunch()
    {
        var launching = new AgentUpdateJournal { AttemptId = "attempt-a", Phase = "launch_requested" };
        var after = AgentUpdateLocalService.TransitionFailure(launching, AgentUpdateErrorCodes.StagingFailed);
        Assert.Equal(AgentUpdateStates.RecoveryRequired, after.Phase);
        Assert.Equal(AgentUpdateErrorCodes.StagingFailed,
            AgentUpdateLocalService.ProjectedErrorCode(after, AgentUpdateStates.RecoveryRequired));
    }

    [Fact]
    public void DurableJournal_RoundTripsTheRecordedCause()
    {
        // Unit/support: serializer + validation only; protected-root locking needs an elevated token.
        var root = NewRoot();
        var failed = AgentUpdateLocalService.TransitionFailure(new AgentUpdateJournal
        {
            AttemptId = "attempt-a",
            Phase = AgentUpdateStates.Downloading,
            InstallerResult = Result("result-1", AgentUpdateErrorCodes.MsiFailed),
        }, AgentUpdateErrorCodes.Classify(new InvalidOperationException("Update manifest has expired.")));
        AgentUpdateDurableFile.Write(Path.Combine(root, "transaction.json"), root, failed);

        var read = new AgentUpdateJournalStore(root).Read();
        Assert.Equal(AgentUpdateStates.Failed, read.Phase);
        Assert.Equal(AgentUpdateErrorCodes.ManifestExpired, read.FailureCode);
        Assert.Equal("attempt-a", read.FailureAttemptId);
        Assert.Equal("result-1", read.FailureInstallerResultId);
        Assert.Equal(AgentUpdateErrorCodes.ManifestExpired, AgentUpdateLocalService.ProjectedErrorCode(read, read.Phase));
    }

    [Fact]
    public void DurableJournal_RejectsMalformedFailureCause()
    {
        var root = NewRoot();
        var path = Path.Combine(root, "transaction.json");
        AgentUpdateDurableFile.Write(path, root, new AgentUpdateJournal { Phase = AgentUpdateStates.Failed, FailureCode = "Bad Code!" });
        Assert.Throws<InvalidOperationException>(() => new AgentUpdateJournalStore(root).Read());

        AgentUpdateDurableFile.Write(path, root, new AgentUpdateJournal { Phase = AgentUpdateStates.Failed, FailureAttemptId = "..\\x" });
        Assert.Throws<InvalidOperationException>(() => new AgentUpdateJournalStore(root).Read());

        AgentUpdateDurableFile.Write(path, root, new AgentUpdateJournal { Phase = AgentUpdateStates.Failed, FailureInstallerResultId = "..\\unsafe" });
        Assert.Throws<InvalidOperationException>(() => new AgentUpdateJournalStore(root).Read());

        AgentUpdateDurableFile.Write(path, root, new AgentUpdateJournal
        {
            Phase = AgentUpdateStates.Failed,
            InstallerResult = Result("..\\unsafe", AgentUpdateErrorCodes.MsiFailed),
        });
        Assert.Throws<InvalidOperationException>(() => new AgentUpdateJournalStore(root).Read());
    }

    private static AgentUpdateInstallerResult Result(string id, string code)
        => new(AgentUpdateInstallerResult.CurrentSchemaVersion, id, AgentUpdateStates.Failed,
            DateTimeOffset.UtcNow.ToString("O"), 1603, false, code, null, null);

    private static string NewRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-update-failure-code-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }
}
