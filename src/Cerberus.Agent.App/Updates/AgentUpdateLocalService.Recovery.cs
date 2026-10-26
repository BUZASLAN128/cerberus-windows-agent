using System.Globalization;
using System.IO;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

/// <summary>Bounded recovery so one transient failure never stops automatic updates for good.</summary>
internal static partial class AgentUpdateLocalService
{
    /// <summary>How long a failed local readiness probe is retried after the installer result was recorded.</summary>
    private static readonly TimeSpan HealthRetryWindow = TimeSpan.FromMinutes(15);
    /// <summary>Quiet time after the last recorded install activity before recovery_required is closed.</summary>
    private static readonly TimeSpan RecoveryGrace = TimeSpan.FromMinutes(10);

    private static DateTimeOffset? Parse(string? value)
        => DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed) ? parsed : null;

    /// <summary>Latest durable sign of installer activity; null when the journal has none.</summary>
    internal static DateTimeOffset? LastInstallEvidenceUtc(AgentUpdateJournal journal)
    {
        DateTimeOffset? latest = null;
        foreach (var candidate in new[] { Parse(journal.InstallerResult?.RecordedAtUtc), journal.InstallerStartedUtc, journal.RunnerStartedUtc })
            if (candidate is not null && (latest is null || candidate > latest)) latest = candidate;
        return latest;
    }

    /// <summary>Last system start; retry and grace windows never count time before it, since a reboot can follow the installer by hours, and a service restart does not reset them.</summary>
    private static readonly Lazy<DateTimeOffset> SystemStartedUtc = new(() => DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64));

    internal static bool HealthRetryExpired(AgentUpdateJournal journal, DateTimeOffset now, DateTimeOffset systemStartedUtc)
    {
        var anchor = Parse(journal.InstallerResult?.RecordedAtUtc) is { } recorded && recorded > systemStartedUtc ? recorded : systemStartedUtc;
        return now - anchor >= HealthRetryWindow;
    }

    private static async Task<bool> IsPlanHealthyAsync(AgentUpdatePlan plan, CancellationToken ct)
    {
        try
        {
            if (!string.Equals(WindowsDeviceInfo.GetAgentVersion(), plan.Version, StringComparison.Ordinal) ||
                !IsCanonicalServiceProcess())
                return false;
            await LoadLifecycleAsync(ct).ConfigureAwait(false);
            var ready = await Cerberus.Agent.App.Control.AgentLocalControlClient
                .SendAsync(new AgentLocalControlRequest("status"), ct).ConfigureAwait(false);
            return ready.Success && ready.CurrentVersion == plan.Version;
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { return false; }
    }

    /// <summary>
    /// Closes a recovery_required attempt once no runner or installer is alive and the grace period
    /// passed: Installed when this service is the healthy planned version, otherwise terminal Failed.
    /// The next check is rescheduled a day out so a failing release is not retried in a tight loop.
    /// </summary>
    private static async Task TryCloseRecoveryAsync(AgentUpdateJournal active, CancellationToken ct)
    {
        var now = DateTimeOffset.UtcNow;
        if (active.AttemptId is null ||
            !RecoveryCloseDue(active, now, SystemStartedUtc.Value,
                IsProcessAlive(active.RunnerProcessId, active.RunnerStartedUtc),
                IsProcessAlive(active.InstallerProcessId, active.InstallerStartedUtc)))
            return;
        AgentUpdatePlan? plan;
        try { plan = ReadPlan(active); }
        catch (Exception ex) when (ex is not OperationCanceledException) { plan = null; }
        var healthy = plan is not null && await IsPlanHealthyAsync(plan, ct).ConfigureAwait(false);
        // The installer helper's durable record proves a health rollback even when the updater died before pinning it.
        // The scan reads files, so it runs before the journal lock is taken.
        var rollbackPhase = RecoveryRollbackPhase(healthy, plan, active.InstallerStartedUtc,
            Path.Combine(AgentUpdateSecurity.DefaultPrivilegedRoot, "installer-transactions"));
        Journal.ChangeAttempt(active.AttemptId, before => CloseRecovery(before, plan, healthy, now, rollbackPhase));
    }

    /// <summary>Newest health-rollback phase recorded for this attempt; null when healthy, without a plan, or when the records cannot be read.</summary>
    internal static AgentInstallerHealthPhase? RecoveryRollbackPhase(bool healthy, AgentUpdatePlan? plan, DateTimeOffset? installerStartedUtc, string transactionsRoot)
    {
        if (healthy || plan is null) return null;
        try { return AgentInstallerHealthRecords.NewestPhaseSince(transactionsRoot, installerStartedUtc, plan.Version, null); }
        catch (Exception ex) when (ex is not OperationCanceledException) { return null; }
    }

    /// <summary>True once no runner or installer is alive and the grace period since the last install activity passed.</summary>
    internal static bool RecoveryCloseDue(AgentUpdateJournal active, DateTimeOffset now, DateTimeOffset systemStartedUtc, bool runnerAlive, bool installerAlive)
        => active.AttemptId is not null && !runnerAlive && !installerAlive &&
           now - (LastInstallEvidenceUtc(active) is { } last && last > systemStartedUtc ? last : systemStartedUtc) >= RecoveryGrace;

    /// <summary>Installed when healthy on the planned version, otherwise terminal Failed with a rescheduled check.</summary>
    internal static AgentUpdateJournal CloseRecovery(AgentUpdateJournal before, AgentUpdatePlan? plan, bool healthy, DateTimeOffset now,
        AgentInstallerHealthPhase? rollbackPhase = null)
    {
        if (before.Phase != AgentUpdateStates.RecoveryRequired) return before;
        if (healthy && plan is not null)
            return before with
            {
                Phase = AgentUpdateStates.Installed, HealthyInstalledSequence = plan.Sequence,
                HealthyInstalledVersion = plan.Version,
            };
        var result = before.InstallerResult ?? AgentUpdateInstallerResult.Failure(
            new InvalidOperationException("Update recovery timed out."));
        return before with
        {
            Phase = AgentUpdateStates.Failed,
            InstallerResult = result with { State = AgentUpdateStates.Failed, ErrorCode = AgentUpdateErrorCodes.RecoveryTimeout },
            FailedInstallSequence = plan is null ? before.FailedInstallSequence
                : AgentUpdateRollbackPolicy.NextFailedInstallSequence(before.FailedInstallSequence, AgentUpdateErrorCodes.MsiFailed, plan.Sequence, rollbackPhase),
            NextCheckUtc = now.AddHours(24).Add(AgentUpdateJournalStore.Offset(before.ScheduleSeed, TimeSpan.FromHours(6))),
        };
    }
}
