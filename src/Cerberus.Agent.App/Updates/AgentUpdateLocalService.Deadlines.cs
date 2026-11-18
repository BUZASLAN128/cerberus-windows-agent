using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

internal static partial class AgentUpdateLocalService
{
    private sealed class UpdateRetryNotDueException()
        : InvalidOperationException("Update installer retry is not due.");

    internal static void RequireInstallerRetryDue(AgentUpdateJournal active, DateTimeOffset now)
    {
        if (active.Phase == AgentUpdateStates.RetryableBusy && (active.NextRetryUtc > now ||
            IsMsiInstallerBusy(active) && (active.NextRetryUtc is null || InstallerBusyExpired(active, now))))
            throw new UpdateRetryNotDueException();
        if ((active.RetryCount >= 3 && !IsMsiInstallerBusy(active)) || active.NextRetryUtc > now)
            throw new InvalidOperationException("Update installer retry is not admitted.");
    }

    private static bool IsMsiInstallerBusy(AgentUpdateJournal journal)
        => journal.Phase == AgentUpdateStates.RetryableBusy && journal.InstallerResult?.MsiExitCode == 1618;

    private static bool InstallerBusyExpired(AgentUpdateJournal journal, DateTimeOffset now)
        => journal.BusySinceUtc is { } since && now - since >= TimeSpan.FromHours(24);

    private static bool InstallerBusyTimeoutDue(AgentUpdateJournal journal, DateTimeOffset now)
        => IsMsiInstallerBusy(journal) && journal.NextRetryUtc <= now && InstallerBusyExpired(journal, now);

    private static AgentUpdateJournal TransitionInstallerBusy(AgentUpdateJournal before, DateTimeOffset now)
    {
        if (InstallerBusyExpired(before, now))
            return TransitionFailure(before with
            {
                NextRetryUtc = null,
                NextCheckUtc = now.AddHours(24).Add(AgentUpdateJournalStore.Offset(before.ScheduleSeed, TimeSpan.FromHours(6))),
            }, AgentUpdateErrorCodes.InstallerBusyTimeout);

        return before with
        {
            BusySinceUtc = before.BusySinceUtc ?? now,
            InstallerBusyCount = Math.Min(64, before.InstallerBusyCount + 1),
            NextRetryUtc = now.AddMinutes(Math.Min(30, 1 << Math.Min(5, before.InstallerBusyCount))),
        };
    }

    internal static bool HoldsPreInstallRetry(AgentUpdateJournal journal, DateTimeOffset now)
        => !journal.HasUnfinishedAttempt && journal.PreInstallRetryNotBeforeUtc > now;

    private static AgentUpdateJournal DeferInterruptedPreInstall(
        AgentUpdateJournal before, AgentUpdateJournal after, DateTimeOffset? retryAtUtc)
        => retryAtUtc is not null && before.Phase != after.Phase &&
            before.Phase is (AgentUpdateStates.Checking or AgentUpdateStates.Downloading or AgentUpdateStates.Staged)
            ? after with { NextCheckUtc = retryAtUtc, PreInstallRetryNotBeforeUtc = retryAtUtc }
            : after;

    internal static AgentUpdateJournal ApplyPreInstallBackoff(
        AgentUpdateJournal before, AgentUpdateJournal after, string code, DateTimeOffset now)
    {
        if (after == before || after.Phase != AgentUpdateStates.Failed || after.InstallerResult is not null ||
            code is not (AgentUpdateErrorCodes.DownloadFailed or AgentUpdateErrorCodes.HashMismatch or
                AgentUpdateErrorCodes.ManifestUnavailable))
            return after;

        var count = Math.Min(8, before.PreInstallFailureCount + 1);
        var delay = TimeSpan.FromMinutes(Math.Min(240, 15 * (1 << (count - 1))));
        var retryAt = now.Add(delay).Add(AgentUpdateJournalStore.Offset(before.ScheduleSeed, delay / 4));
        return after with { PreInstallFailureCount = count, NextCheckUtc = retryAt, PreInstallRetryNotBeforeUtc = retryAt };
    }

    internal static bool InstallOverdue(AgentUpdateJournal journal, DateTimeOffset now, DateTimeOffset systemStartedUtc,
        bool runnerAlive, bool installerAlive)
        => (runnerAlive || installerAlive) && journal.AttemptId is not null && journal.AlertAttemptId != journal.AttemptId &&
            (journal.InstallerStartedUtc ?? journal.RunnerStartedUtc) is { } started &&
            now - (started < systemStartedUtc ? systemStartedUtc : started) >= TimeSpan.FromHours(1);

    internal static AgentUpdateJournal TransitionInstallOverdue(AgentUpdateJournal journal, DateTimeOffset now,
        DateTimeOffset systemStartedUtc, bool runnerAlive, bool installerAlive)
        => InstallOverdue(journal, now, systemStartedUtc, runnerAlive, installerAlive)
            ? journal with { AlertCode = AgentUpdateErrorCodes.InstallOverdue, AlertAttemptId = journal.AttemptId }
            : journal;

    internal static AgentUpdateJournal TransitionRebootOverdue(AgentUpdateJournal journal, DateTimeOffset now, string bootId)
        => journal.Phase == AgentUpdateStates.PendingReboot && journal.InstallationBootId == bootId &&
            journal.AttemptId is not null && journal.AlertAttemptId != journal.AttemptId &&
            Parse(journal.InstallerResult?.RecordedAtUtc) is { } recorded && now - recorded >= TimeSpan.FromHours(24)
            ? journal with { AlertCode = AgentUpdateErrorCodes.RebootOverdue, AlertAttemptId = journal.AttemptId }
            : journal;

    private static void RecordInstallOverdue(AgentUpdateJournal active, DateTimeOffset now, bool runnerAlive)
    {
        var installerAlive = !runnerAlive && IsProcessAlive(active.InstallerProcessId, active.InstallerStartedUtc);
        var boot = SystemStartedUtc.Value;
        if (!InstallOverdue(active, now, boot, runnerAlive, installerAlive)) return;
        Journal.ChangeAttempt(active.AttemptId!, before => before.Phase == active.Phase
            ? TransitionInstallOverdue(before, now, boot, runnerAlive, installerAlive)
            : before);
    }
}
