using System.Globalization;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

/// <summary>Bounded recovery so one transient failure never stops automatic updates for good.</summary>
internal static partial class AgentUpdateLocalService
{
    /// <summary>How long a failed local readiness probe is retried after the installer result was recorded.</summary>
    private static readonly TimeSpan HealthRetryWindow = TimeSpan.FromMinutes(15);
    /// <summary>Quiet time after the last recorded install activity before recovery_required is closed.</summary>
    private static readonly TimeSpan RecoveryGrace = TimeSpan.FromMinutes(10);

    /// <summary>Update checks run in every recoverable lifecycle state; backend calls keep using AllowsAutomatic.</summary>
    internal static bool AllowsAutomaticUpdate(AgentLifecycleSnapshot lifecycle)
        => AgentLifecycleStates.AllowsAutomaticUpdate(lifecycle.State, lifecycle.ReasonCode) && lifecycle.QuiescenceComplete;

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

    internal static bool HealthRetryExpired(AgentUpdateJournal journal, DateTimeOffset now)
        => Parse(journal.InstallerResult?.RecordedAtUtc) is not { } recorded || now - recorded >= HealthRetryWindow;

    private static async Task<bool> IsPlanHealthyAsync(AgentUpdatePlan plan, CancellationToken ct)
    {
        if (!string.Equals(WindowsDeviceInfo.GetAgentVersion(), plan.Version, StringComparison.Ordinal) ||
            !IsCanonicalServiceProcess())
            return false;
        await LoadLifecycleAsync(ct).ConfigureAwait(false);
        try
        {
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
            !RecoveryCloseDue(active, now,
                IsProcessAlive(active.RunnerProcessId, active.RunnerStartedUtc),
                IsProcessAlive(active.InstallerProcessId, active.InstallerStartedUtc)))
            return;
        var plan = ReadPlan(active);
        var healthy = plan is not null && await IsPlanHealthyAsync(plan, ct).ConfigureAwait(false);
        Journal.ChangeAttempt(active.AttemptId, before => CloseRecovery(before, plan, healthy, now));
    }

    /// <summary>True once no runner or installer is alive and the grace period since the last install activity passed.</summary>
    internal static bool RecoveryCloseDue(AgentUpdateJournal active, DateTimeOffset now, bool runnerAlive, bool installerAlive)
        => active.AttemptId is not null && !runnerAlive && !installerAlive &&
           !(LastInstallEvidenceUtc(active) is { } last && now - last < RecoveryGrace);

    /// <summary>Installed when healthy on the planned version, otherwise terminal Failed with a rescheduled check.</summary>
    internal static AgentUpdateJournal CloseRecovery(AgentUpdateJournal before, AgentUpdatePlan? plan, bool healthy, DateTimeOffset now)
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
            NextCheckUtc = now.AddHours(24).Add(AgentUpdateJournalStore.Offset(before.ScheduleSeed, TimeSpan.FromHours(6))),
        };
    }
}
