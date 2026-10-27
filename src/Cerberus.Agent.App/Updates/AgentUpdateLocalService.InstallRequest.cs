using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

/// <summary>
/// Signed operator request to install the newest release. The command only records it; the scheduler stages it as
/// required and applies it through the same path as a required policy, so the serial command queue never waits on a download.
/// </summary>
internal static partial class AgentUpdateLocalService
{
    /// <summary>Latest start a request may ask for: the normal rollout window.</summary>
    internal static readonly TimeSpan MaxInstallRequestDelay = TimeSpan.FromHours(24);

    internal enum InstallRequestStep { None, Drop, Run }

    /// <summary>Records the request for the scheduler; false when the agent state does not allow automatic updates.</summary>
    public static async Task<bool> RequestInstallAsync(DateTimeOffset notBeforeUtc, CancellationToken ct)
    {
        RequireService();
        var lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
        if (!AllowsAutomatic(lifecycle))
            return false;
        Journal.Change(before => before with { InstallRequest = new(notBeforeUtc, lifecycle.Generation) });
        return true;
    }

    /// <summary>A request from another lifecycle generation lapses; a due one waits only for a running install to finish.</summary>
    internal static InstallRequestStep NextInstallRequestStep(AgentUpdateJournal active, long lifecycleGeneration, DateTimeOffset now)
        => active.InstallRequest is not { } request ? InstallRequestStep.None
            : request.LifecycleGeneration != lifecycleGeneration ? InstallRequestStep.Drop
            : active.MayHaveStartedInstallation || active.Phase == "launch_requested" || request.NotBeforeUtc > now
                ? InstallRequestStep.None
                : InstallRequestStep.Run;

    /// <summary>Makes a required attempt of the request's generation due now; any other journal is returned unchanged.</summary>
    internal static AgentUpdateJournal TransitionInstallRequested(AgentUpdateJournal before, long lifecycleGeneration, DateTimeOffset now)
        => before.AttemptId is not null && before.Phase == AgentUpdateStates.AwaitingConsent && before.Required &&
           before.LifecycleGeneration == lifecycleGeneration && (before.ApplyNotBeforeUtc is null || before.ApplyNotBeforeUtc > now)
            ? before with { ApplyNotBeforeUtc = now }
            : before;

    /// <summary>
    /// Scheduler step. The request is consumed before staging, so it runs at most once; a failure is reported like any
    /// other staging failure. Staging as required also lifts an attempt already waiting as recommended. True when it staged.
    /// </summary>
    private static async Task<bool> RunInstallRequestAsync(AgentUpdateJournal active, long lifecycleGeneration, CancellationToken ct)
    {
        var step = NextInstallRequestStep(active, lifecycleGeneration, DateTimeOffset.UtcNow);
        if (step == InstallRequestStep.None)
            return false;
        var request = active.InstallRequest;
        Journal.Change(before => before.InstallRequest == request ? before with { InstallRequest = null } : before);
        if (step == InstallRequestStep.Drop)
            return false;
        await CheckAndStageOwnedAsync(automatic: true, required: true, ct, bypassSchedule: true,
            requiredPolicyGeneration: lifecycleGeneration).ConfigureAwait(false);
        Journal.Change(before => TransitionInstallRequested(before, lifecycleGeneration, DateTimeOffset.UtcNow));
        return true;
    }
}
