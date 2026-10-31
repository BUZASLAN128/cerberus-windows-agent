using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

/// <summary>
/// Signed operator request to install the newest release. The command only records it; the scheduler stages it as
/// required and applies it through the same path as a required policy, so the serial command queue never waits on a download.
/// </summary>
internal static partial class AgentUpdateLocalService
{
    /// <summary>Latest start a request may ask for, and how long it stays valid after that start.</summary>
    internal static readonly TimeSpan MaxInstallRequestDelay = TimeSpan.FromHours(24);
    internal static readonly TimeSpan InstallRequestRetryDelay = TimeSpan.FromMinutes(5);
    internal const int MaxInstallRequestAttempts = 3;

    private static volatile Func<bool>? _serverQuarantined;
    private static IAgentLogger _requestLog = NullAgentLogger.Instance;

    internal enum InstallRequestStep { None, Drop, Run }

    /// <summary>Server build: the worker's signed state, so a quarantine pauses the update scheduler.</summary>
    internal static void ConnectSignedState(Func<bool> quarantined, IAgentLogger log)
    {
        _requestLog = log;
        _serverQuarantined = quarantined;
    }

    /// <summary>The server build counts as quarantined until the worker connects its signed state, or when it cannot be read.</summary>
    private static bool Quarantined()
        => Quarantined(_serverQuarantined, AgentBuildProfile.IsServer);

    internal static bool Quarantined(Func<bool>? signedState, bool isServer)
    {
        if (!isServer)
            return false;
        try { return signedState?.Invoke() ?? true; }
        catch (Exception) { return true; }
    }

    /// <summary>Records the request for the scheduler; false when the agent state does not allow automatic updates.</summary>
    public static async Task<bool> RequestInstallAsync(DateTimeOffset notBeforeUtc, CancellationToken ct)
    {
        RequireService();
        return await RequestInstallAsync(notBeforeUtc, LoadLifecycleAsync, Journal.Change, Quarantined, ct).ConfigureAwait(false);
    }

    internal static async Task<bool> RequestInstallAsync(DateTimeOffset notBeforeUtc,
        Func<CancellationToken, Task<AgentLifecycleSnapshot>> loadLifecycle,
        Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> change,
        Func<bool> quarantined, CancellationToken ct)
    {
        var lifecycle = await loadLifecycle(ct).ConfigureAwait(false);
        if (!AllowsAutomatic(lifecycle) || quarantined())
            return false;
        change(before => before with
        {
            InstallRequest = new(notBeforeUtc, lifecycle.Generation, notBeforeUtc + MaxInstallRequestDelay),
        });
        return true;
    }

    /// <summary>
    /// A request lapses on another lifecycle generation, when automatic updates are not allowed, or at its expiry; a due
    /// one waits only for a running install to finish.
    /// </summary>
    internal static InstallRequestStep NextInstallRequestStep(
        AgentUpdateJournal active, long lifecycleGeneration, bool allowed, DateTimeOffset now)
        => active.InstallRequest is not { } request ? InstallRequestStep.None
            : request.LifecycleGeneration != lifecycleGeneration || !allowed || request.ExpiresUtc <= now
                ? InstallRequestStep.Drop
            : active.MayHaveStartedInstallation || active.Phase == "launch_requested" || request.NotBeforeUtc > now
                ? InstallRequestStep.None
                : InstallRequestStep.Run;

    /// <summary>The request after a failed staging: due again after the retry delay, or null once tries or time run out.</summary>
    internal static AgentUpdateInstallRequest? RetryInstallRequest(AgentUpdateInstallRequest request, DateTimeOffset now)
    {
        var next = request with { Attempts = request.Attempts + 1, NotBeforeUtc = now + InstallRequestRetryDelay };
        return next.Attempts >= MaxInstallRequestAttempts || next.NotBeforeUtc >= request.ExpiresUtc ? null : next;
    }

    /// <summary>Makes a required attempt of the request's generation due now; any other journal is returned unchanged.</summary>
    internal static AgentUpdateJournal TransitionInstallRequested(AgentUpdateJournal before, long lifecycleGeneration, DateTimeOffset now)
        => before.AttemptId is not null && before.Phase == AgentUpdateStates.AwaitingConsent && before.Required &&
           before.LifecycleGeneration == lifecycleGeneration && (before.ApplyNotBeforeUtc is null || before.ApplyNotBeforeUtc > now)
            ? before with { ApplyNotBeforeUtc = now }
            : before;

    /// <summary>
    /// First scheduler step. True when the tick ends here: quarantined (everything waits, a pending request included),
    /// automatic updates not allowed, or the request was staged.
    /// </summary>
    private static async Task<bool> HoldOrRunInstallRequestAsync(
        AgentUpdateJournal active, AgentLifecycleSnapshot lifecycle, CancellationToken ct)
        => await HoldOrRunInstallRequestAsync(active, lifecycle, Quarantined, Journal.Change,
            () => CheckAndStageOwnedAsync(automatic: true, required: true, ct, bypassSchedule: true,
                requiredPolicyGeneration: lifecycle.Generation), _requestLog, ct).ConfigureAwait(false);

    internal static async Task<bool> HoldOrRunInstallRequestAsync(AgentUpdateJournal active,
        AgentLifecycleSnapshot lifecycle, Func<bool> quarantined,
        Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> change,
        Func<Task> stage, IAgentLogger log, CancellationToken ct)
    {
        if (quarantined())
            return true;
        var allowed = AllowsAutomatic(lifecycle);
        var staged = await RunInstallRequestAsync(active, lifecycle.Generation, allowed, change, stage, log, ct).ConfigureAwait(false);
        return staged || !allowed;
    }

    /// <summary>
    /// Drops a lapsed request or stages a due one as required, which also lifts an attempt already waiting as recommended.
    /// The request is cleared once staging returns; a failed staging keeps it for a later try and rethrows, so the failure
    /// is reported like any other. True when it staged.
    /// </summary>
    internal static async Task<bool> RunInstallRequestAsync(
        AgentUpdateJournal active,
        long lifecycleGeneration,
        bool allowed,
        Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> change,
        Func<Task> stage,
        IAgentLogger log,
        CancellationToken ct)
    {
        var step = NextInstallRequestStep(active, lifecycleGeneration, allowed, DateTimeOffset.UtcNow);
        if (step == InstallRequestStep.None)
            return false;
        var request = active.InstallRequest!;
        if (step == InstallRequestStep.Drop)
        {
            change(before => Replace(before, request, null));
            log.Info("Install request dropped: " + (request.LifecycleGeneration != lifecycleGeneration ? "lifecycle changed."
                : !allowed ? "automatic updates are not allowed." : "expired."));
            return false;
        }

        try
        {
            await stage().ConfigureAwait(false);
        }
        catch (Exception) when (!ct.IsCancellationRequested)
        {
            var retry = RetryInstallRequest(request, DateTimeOffset.UtcNow);
            change(before => Replace(before, request, retry));
            log.Warn(retry is null
                ? "Install request staging failed; no tries left."
                : $"Install request staging failed; next try at {retry.NotBeforeUtc:O}.");
            throw;
        }

        var after = change(before => TransitionInstallRequested(Replace(before, request, null), lifecycleGeneration,
            DateTimeOffset.UtcNow));
        log.Info($"Install request handled: update state {after.Phase}.");
        return true;
    }

    /// <summary>An automatic install about to launch waits while the agent is quarantined.</summary>
    internal static void HoldWhileQuarantined(bool automatic, CancellationToken ct, Func<bool>? quarantined = null)
    {
        if (automatic && (quarantined ?? Quarantined)())
            throw new IntentionalUpdateCancellationException("Update held while quarantined.", ct);
    }

    private static AgentUpdateJournal Replace(
        AgentUpdateJournal journal, AgentUpdateInstallRequest expected, AgentUpdateInstallRequest? next)
        => journal.InstallRequest == expected ? journal with { InstallRequest = next } : journal;
}
