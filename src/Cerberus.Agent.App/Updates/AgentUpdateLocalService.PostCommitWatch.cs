using System.IO;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

internal static partial class AgentUpdateLocalService
{
    private static void ReconcilePostCommitWatch(AgentUpdateJournal active, DateTimeOffset now)
    {
        var root = Root;
        if (ObservePostCommitWatch(root, active, now) == active) return;
        Journal.ChangeAttempt(active.AttemptId!, before => before.Revision == active.Revision
            ? ObservePostCommitWatch(root, before, now)
            : before);
    }

    internal static AgentUpdateJournal ObservePostCommitWatch(string root, AgentUpdateJournal before, DateTimeOffset now)
    {
        try
        {
            var watch = AgentUpdateWatchStore.Read(root);
            DateTimeOffset? lastWrite = null;
            if (watch is not null)
            {
                var file = new FileInfo(Path.Combine(root, AgentUpdateLkgStore.DirectoryName, AgentUpdateWatchStore.FileName));
                if (!file.Exists) return before; // The record changed during the observation.
                lastWrite = file.LastWriteTimeUtc;
            }
            return TransitionPostCommitWatch(before, watch, lastWrite, now);
        }
        catch (Exception ex) when (AgentUpdateRollbackGrant.IsStorageFailure(ex))
        {
            return before; // An unreadable record is not evidence that the host is absent.
        }
    }

    internal static AgentUpdateJournal TransitionPostCommitWatch(AgentUpdateJournal before, AgentUpdateWatchRecord? watch,
        DateTimeOffset? lastWriteUtc, DateTimeOffset now)
    {
        if (before.AttemptId is not { } attempt || before.WatchAttemptId != attempt) return before;
        var matchingWatch = watch?.AttemptId == attempt ? watch : null;
        var stale = lastWriteUtc is { } lastWrite && now - lastWrite > TimeSpan.FromMinutes(30);
        if (before.Phase == AgentUpdateWatchJournal.CommittedWatch && before.WatchRequestedUtc is { } requested)
        {
            var code = matchingWatch?.Outcome switch
            {
                AgentUpdateWatchOutcomes.Superseded or AgentUpdateWatchOutcomes.Inconclusive => AgentUpdateWatchJournal.WatchUnavailable,
                AgentUpdateWatchOutcomes.ForwardOnlyFailed => AgentUpdateWatchJournal.PostCommitUnhealthy,
                _ when (matchingWatch is null && now - requested > TimeSpan.FromHours(2)) ||
                    (stale && now - requested >= TimeSpan.FromHours(26)) => AgentUpdateWatchJournal.WatchUnavailable,
                _ => null,
            };
            if (code is not null)
                return before with
                {
                    Phase = AgentUpdateStates.Installed,
                    WatchOutcomeCode = code,
                    WatchOutcomeAttemptId = attempt,
                };
        }
        else if (before.Phase == AgentUpdateWatchJournal.RollingBack && before.RollbackAttemptId is not null &&
            stale && matchingWatch is not null &&
            // A retry can cross the journal fence before the host refreshes watch.json or records the new PID.
            (before.RollbackStartedUtc is not { } latestStart || now - latestStart > TimeSpan.FromMinutes(30)) &&
            (before.RollbackFirstUtc ?? before.RollbackStartedUtc) is { } started && now - started >= TimeSpan.FromHours(48))
        {
            return before with
            {
                Phase = AgentUpdateStates.Failed,
                FailureCode = AgentUpdateWatchJournal.RollbackFailed,
                FailureAttemptId = attempt,
                FailureInstallerResultId = before.InstallerResult?.ResultId,
                FailedInstallSequence = AgentUpdateWatchPolicy.PostCommitPin(before.FailedInstallSequence, matchingWatch.WatchedSequence),
                NextCheckUtc = now.AddHours(24).Add(AgentUpdateJournalStore.Offset(before.ScheduleSeed, TimeSpan.FromHours(6))),
            };
        }
        return before;
    }
}
