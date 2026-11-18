using System.ComponentModel;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Updater;

// The in-process support fixtures substitute machine authority, service and journal-lock boundaries.
internal sealed record LkgWatchHostPlatform(string UpdatesRoot, string ProcessPath, Func<bool> HasAuthority, Action<bool> Restart,
    Action<string> ValidateHostRoot, Action VerifyTask, Func<string?> ReadInstalledVersion, Func<AgentUpdateJournal, bool> NoInstallerActivity,
    Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> ChangeJournal, Func<long> ReadUptimeMilliseconds);

internal static partial class LkgWatchHost
{
    private const string RestartFailed = "watch_restart_failed";
    private const string TaskRepairFailed = "watch_task_repair_failed";

    private static bool TryRestart(LkgWatchHostOperations operations, bool invokedByScm)
    {
        try
        {
            operations.Restart(invokedByScm);
            return true;
        }
        catch (Win32Exception ex)
        {
            if (operations.LogRestartWin32 is { } log) log(ex.NativeErrorCode);
            else operations.Log(RestartFailed);
            return false;
        }
        catch (Exception ex) when (IsHostFailure(ex))
        {
            operations.Log(RestartFailed);
            return true; // A non-SCM failure does not establish a persistent restart failure.
        }
    }

    private static bool IsUnreportedPreCommit(AgentUpdateJournal? journal) =>
        journal is { } active && AgentUpdateSecurity.IsSafeAttemptId(active.AttemptId) &&
        active.Phase is (AgentUpdaterContract.LaunchRequestedPhase or AgentUpdaterContract.InstallMayHaveStartedPhase or
            AgentUpdateStates.Installing or AgentUpdateStates.RecoveryRequired or AgentUpdateStates.PendingReboot or AgentUpdateStates.HealthPending) &&
        !(active.FailureCode == AgentUpdateWatchJournal.RollbackFailed && active.FailureAttemptId == active.AttemptId);

    internal static bool RecordInterruptedRestart(AgentUpdateJournalStore journal, AgentUpdateJournal expected)
        => RecordInterruptedRestart(journal.Change, expected);

    internal static bool RecordInterruptedRestart(Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> change,
        AgentUpdateJournal expected)
    {
        if (!IsUnreportedPreCommit(expected)) return false;
        return AgentUpdateJournalPatch.TryApply(change, expected.AttemptId!, expected.Phase,
            before => before.Revision == expected.Revision && IsUnreportedPreCommit(before)
                ? before with
                {
                    // Keep the forward phase available to Agent reconciliation when SCM can start it again.
                    FailureCode = AgentUpdateWatchJournal.RollbackFailed,
                    FailureAttemptId = before.AttemptId,
                    FailureInstallerResultId = before.InstallerResult?.ResultId,
                    AlertCode = AgentUpdateWatchJournal.RollbackFailed,
                    AlertAttemptId = before.AttemptId,
                }
                : null);
    }

    private static LkgWatchHostSnapshot VerifyTaskForAction(LkgWatchHostOperations operations, LkgWatchHostSnapshot state)
    {
        try { operations.VerifyTask(); }
        catch (Exception ex) when (IsHostFailure(ex))
        {
            operations.Log(TaskRepairFailed);
            if (state.Watch is { } watch && state.Journal is { } journal &&
                LkgWatchHostBinding.BindsWatch(journal, watch.AttemptId) &&
                !watch.Alerts.Contains(TaskRepairFailed, StringComparer.Ordinal))
            {
                var alerted = watch with { Alerts = [.. watch.Alerts, TaskRepairFailed] };
                try
                {
                    operations.WriteWatch(alerted);
                    state = state with { Watch = alerted };
                }
                catch (Exception alertError) when (IsHostFailure(alertError))
                {
                    // The log still records the alert. The due action must continue.
                }
            }
        }
        return state;
    }
}
