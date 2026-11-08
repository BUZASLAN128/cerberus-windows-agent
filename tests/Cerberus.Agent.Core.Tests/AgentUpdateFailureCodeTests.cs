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
    }

    [Fact]
    public void ProjectedErrorCode_NeverOutlivesItsAttemptOrInstallerResult()
    {
        var installFailed = new AgentUpdateJournal
        {
            AttemptId = "attempt-a",
            Phase = AgentUpdateStates.Failed,
            InstallerResult = Result("result-1", AgentUpdateErrorCodes.MsiFailed),
        };
        Assert.Equal(AgentUpdateErrorCodes.MsiFailed,
            AgentUpdateLocalService.ProjectedErrorCode(installFailed, AgentUpdateStates.Failed));

        var checkFailed = AgentUpdateLocalService.TransitionFailure(installFailed, AgentUpdateErrorCodes.ManifestExpired);
        Assert.Equal(AgentUpdateStates.Failed, checkFailed.Phase);
        Assert.Same(installFailed.InstallerResult, checkFailed.InstallerResult);
        Assert.Equal(AgentUpdateErrorCodes.ManifestExpired,
            AgentUpdateLocalService.ProjectedErrorCode(checkFailed, AgentUpdateStates.Failed));

        var newAttemptFailed = checkFailed with
        {
            AttemptId = "attempt-b",
            InstallerResult = Result("result-2", AgentUpdateErrorCodes.MsiFailed),
        };
        Assert.Equal(AgentUpdateErrorCodes.MsiFailed,
            AgentUpdateLocalService.ProjectedErrorCode(newAttemptFailed, AgentUpdateStates.Failed));

        var sameAttemptNewResult = checkFailed with { InstallerResult = Result("result-3", AgentUpdateErrorCodes.InstallerBusy) };
        Assert.Equal(AgentUpdateErrorCodes.InstallerBusy,
            AgentUpdateLocalService.ProjectedErrorCode(sameAttemptNewResult, AgentUpdateStates.Failed));
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
