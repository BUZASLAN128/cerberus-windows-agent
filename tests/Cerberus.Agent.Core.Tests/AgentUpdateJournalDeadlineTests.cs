using System.Text.Json.Serialization;
using Cerberus.Agent.App.Updates;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateJournalDeadlineTests
{
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-11-18T12:00:00Z");

    [Fact]
    public void Journal_NewFieldsIgnoredByOldShape_AndBoundsRejected()
    {
        var root = NewRoot();
        try
        {
            var path = Path.Combine(root, "transaction.json");
            var journal = new AgentUpdateJournalStore(root);
            var current = new AgentUpdateJournal { ScheduleSeed = "deadline-fixture", BusySinceUtc = Now,
                InstallerBusyCount = 64, PreInstallFailureCount = 8, PreInstallRetryNotBeforeUtc = Now.AddMinutes(15),
                AlertCode = AgentUpdateErrorCodes.InstallOverdue, AlertAttemptId = "attempt" };

            AgentUpdateDurableFile.Write(path, root, new PreviousJournalShape(AgentUpdaterContract.JournalSchema, current.ScheduleSeed));
            var older = journal.Read();
            Assert.Equal(new AgentUpdateJournal { ScheduleSeed = current.ScheduleSeed }, older);

            AgentUpdateDurableFile.Write(path, root, current);
            var oldShape = AgentUpdateDurableFile.Read<PreviousJournalShape>(path, root)!;
            var extra = oldShape.Extra!;
            Assert.Equal(current.BusySinceUtc, extra["busySinceUtc"].GetDateTimeOffset());
            Assert.Equal(64, extra["installerBusyCount"].GetInt32());
            Assert.Equal(8, extra["preInstallFailureCount"].GetInt32());
            Assert.Equal(current.PreInstallRetryNotBeforeUtc, extra["preInstallRetryNotBeforeUtc"].GetDateTimeOffset());
            Assert.Equal(current.AlertCode, extra["alertCode"].GetString());
            Assert.Equal(current.AlertAttemptId, extra["alertAttemptId"].GetString());
            Assert.Equal(oldShape, AgentUpdateDurableFile.Read<PreviousJournalShape>(path, root));
            AgentUpdateDurableFile.Write(path, root, oldShape);
            Assert.Equal(current, journal.Read());

            foreach (var invalid in new[] { current with { InstallerBusyCount = -1 }, current with { InstallerBusyCount = 65 },
                         current with { PreInstallFailureCount = -1 }, current with { PreInstallFailureCount = 9 },
                         current with { AlertCode = "Bad Code" }, current with { AlertAttemptId = "../attempt" } })
            {
                AgentUpdateDurableFile.Write(path, root, invalid);
                Assert.Throws<InvalidOperationException>(() => journal.Read());
            }
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public void ClosedLabFailure_SurvivesCancelWithNewFields()
    {
        var root = NewRoot();
        try
        {
            var closed = AgentUpdateLabRemediationTests.ClosedForeignFailure() with { BusySinceUtc = Now.AddHours(-1),
                InstallerBusyCount = 3, PreInstallFailureCount = 2, PreInstallRetryNotBeforeUtc = Now.AddMinutes(15),
                AlertCode = AgentUpdateErrorCodes.InstallOverdue };
            closed = closed with { AlertAttemptId = closed.AttemptId };
            var path = AgentUpdateLocalService.PreserveClosedLabFailure(root, closed);
            var checking = AgentUpdateLocalService.TransitionStageStart(closed, true, false, closed.LifecycleGeneration, Now.AddDays(1));
            Assert.Null(checking.BusySinceUtc);
            Assert.Equal(0, checking.InstallerBusyCount);
            Assert.Null(checking.AlertCode);
            Assert.Null(checking.AlertAttemptId);
            // Simulate a distinct stage's backoff so cancellation must also restore the earlier retry fields.
            checking = checking with { PreInstallFailureCount = 5, PreInstallRetryNotBeforeUtc = Now.AddHours(4) };
            var restored = AgentUpdateLocalService.TransitionIntentionalCancellation(checking, closed, Now);
            Assert.Equal((closed.BusySinceUtc, closed.InstallerBusyCount, closed.PreInstallFailureCount,
                closed.PreInstallRetryNotBeforeUtc, closed.AlertCode, closed.AlertAttemptId),
                (restored.BusySinceUtc, restored.InstallerBusyCount, restored.PreInstallFailureCount,
                restored.PreInstallRetryNotBeforeUtc, restored.AlertCode, restored.AlertAttemptId));
            Assert.Equal(path, AgentUpdateLocalService.PreserveClosedLabFailure(root, restored));
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    private sealed record PreviousJournalShape(string SchemaVersion, string ScheduleSeed)
    {
        [JsonExtensionData] public AgentUpdateJsonExtra? Extra { get; init; }
    }

    private static string NewRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-update-journal-deadline-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }
}
