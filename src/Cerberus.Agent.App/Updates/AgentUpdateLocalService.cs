using System.Diagnostics;
using System.IO;
using System.Net.Http;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App.Updates;

/// <summary>Signals that a pre-install attempt was preserved for a later identity-verification retry.</summary>
internal sealed class AgentUpdateReconciliationDeferredException(Exception cause)
    : InvalidOperationException(cause.Message, cause)
{
}

/// <summary>The installed service owns update decisions. UI/CLI requests contain operations and attempt IDs only.</summary>
internal static partial class AgentUpdateLocalService
{
    private static readonly TimeSpan ReconciliationRetryDelay = TimeSpan.FromMinutes(5);
    private sealed class IntentionalUpdateCancellationException(string message, CancellationToken cancellationToken)
        : OperationCanceledException(message, cancellationToken);

    private static readonly SemaphoreSlim OperationGate = new(1, 1);
    private static readonly object CancellationGate = new();
    private static CancellationTokenSource? _networkOperation;
    private static string Root => AgentUpdateStager.DefaultStagingRoot;
    private static AgentUpdateJournalStore Journal => new(Root);
    private static AgentUpdateStateStore Projection => AgentUpdateStateStore.CreateDefault();

    private static CancellationToken CancellationTokenFor(
        CancellationToken callerToken,
        CancellationToken operationToken)
        => callerToken.IsCancellationRequested ? callerToken : operationToken;

    private static async Task PersistIntentionalCancellationAsync(AgentUpdateJournal operationStart)
    {
        Journal.Change(current => TransitionIntentionalCancellation(current, operationStart, DateTimeOffset.UtcNow));
        await ProjectAsync(CancellationToken.None).ConfigureAwait(false);
    }

    private static async Task<AgentUpdateJournal> DeferReconciliationAsync(
        string attemptId,
        Exception cause,
        DateTimeOffset retryAtUtc,
        bool required,
        long? requiredPolicyGeneration)
    {
        var reconciled = Journal.ChangeAttempt(
            attemptId,
            before => TransitionReconciliationDeferred(
                before,
                retryAtUtc,
                required,
                requiredPolicyGeneration));
        if (reconciled.Phase == "launch_requested" || reconciled.MayHaveStartedInstallation)
        {
            await ProjectAsync(CancellationToken.None).ConfigureAwait(false);
            return reconciled;
        }

        // The journal commit is the liveness/authority boundary. Projection is
        // non-cancellable so a caller cannot erase the due retry after commit.
        await ProjectAsync(CancellationToken.None).ConfigureAwait(false);
        throw new AgentUpdateReconciliationDeferredException(cause);
    }

    private static bool IsPreservedPreInstallAttempt(AgentUpdateJournal active)
        => active.AttemptId is not null && active.Phase is
            AgentUpdateStates.Checking or AgentUpdateStates.Downloading or AgentUpdateStates.Staged or
            AgentUpdateStates.AwaitingConsent or AgentUpdateStates.RetryableBusy or AgentUpdateStates.Blocked;

    /// <summary>Reprojects journal authority for an adapter that must not synthesize a state.</summary>
    internal static async Task<AgentUpdateState> ProjectCurrentStateAsync(CancellationToken ct)
    {
        await ProjectAsync(ct).ConfigureAwait(false);
        return await Projection.ReadAsync(WindowsDeviceInfo.GetAgentVersion(), ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Returns canonical projection state when a pre-install attempt is still
    /// present; otherwise callers may record their ordinary failure.
    /// </summary>
    internal static async Task<AgentUpdateState?> ProjectPreservedAttemptAsync(CancellationToken ct)
    {
        var active = Journal.Read();
        if (!IsPreservedPreInstallAttempt(active))
            return null;
        return await ProjectCurrentStateAsync(ct).ConfigureAwait(false);
    }

    public static async Task<AgentLocalControlResponse> HandleAsync(AgentLocalControlRequest request, CancellationToken ct)
    {
        RequireService();
        if (request.SchemaVersion != AgentLocalControlProtocol.SchemaVersion || request.Operation is not ("status" or "check" or "apply"))
            return new(false, "operation_denied");
        try
        {
            if (request.Operation == "status")
                return await StatusAsync("ok", ct).ConfigureAwait(false);
            if (request.Operation == "check")
            {
                if (!await OperationGate.WaitAsync(0, ct).ConfigureAwait(false))
                    return await StatusAsync("update_busy", ct).ConfigureAwait(false);
                var handedOff = false;
                try
                {
                    var current = Journal.Read();
                    if (current.HasUnfinishedAttempt)
                        return await StatusAsync("update_busy", ct).ConfigureAwait(false);
                    _ = RunManualCheckAsync();
                    handedOff = true;
                    return await StatusAsync("check_started", ct).ConfigureAwait(false);
                }
                finally { if (!handedOff) OperationGate.Release(); }
            }
            if (!AgentUpdateSecurity.IsSafeAttemptId(request.AttemptId))
                return new(false, "attempt_required");
            await OperationGate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                await ApplyAsync(request.AttemptId!, automatic: false, ct).ConfigureAwait(false);
                return await StatusAsync("apply_admitted", ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                await ReportFailureAsync(ex).ConfigureAwait(false);
                throw;
            }
            finally { OperationGate.Release(); }
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new(false, AgentUpdateErrorCodes.Classify(ex));
        }
    }

    private static async Task RunManualCheckAsync()
    {
        try { await CheckAndStageOwnedAsync(automatic: false, required: false, CancellationToken.None).ConfigureAwait(false); }
        catch (IntentionalUpdateCancellationException) { }
        catch (AgentUpdateReconciliationDeferredException) { }
        catch (Exception ex) { await ReportFailureAsync(ex).ConfigureAwait(false); }
        finally { OperationGate.Release(); }
    }

    public static async Task<AgentUpdatePlan?> CheckAndStageAsync(
        bool automatic,
        bool required,
        CancellationToken ct,
        bool bypassSchedule = false,
        long? requiredPolicyGeneration = null)
    {
        RequireService();
        await OperationGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            return await CheckAndStageOwnedAsync(
                automatic,
                required,
                ct,
                bypassSchedule,
                requiredPolicyGeneration).ConfigureAwait(false);
        }
        finally { OperationGate.Release(); }
    }

    public static async Task HandleHeartbeatAsync(AgentUpdateSignal signal, CancellationToken ct)
    {
        if (!signal.Required && !signal.Recommended)
            return;
        var lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
        if (!AllowsAutomatic(lifecycle))
            return;
        if (signal.LifecycleGeneration is long signalGeneration && signalGeneration != lifecycle.Generation)
            return;
        if (!await OperationGate.WaitAsync(0, ct).ConfigureAwait(false)) return;
        _ = RunHeartbeatWorkAsync(signal.Required, signal.LifecycleGeneration, ct);
    }

    private static async Task RunHeartbeatWorkAsync(
        bool required,
        long? requiredPolicyGeneration,
        CancellationToken ct)
    {
        try
        {
            await CheckAndStageOwnedAsync(
                automatic: true,
                required,
                ct,
                requiredPolicyGeneration: requiredPolicyGeneration).ConfigureAwait(false);
        }
        catch (IntentionalUpdateCancellationException) { }
        catch (AgentUpdateReconciliationDeferredException) { }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception ex) { await ReportFailureAsync(ex).ConfigureAwait(false); }
        finally { OperationGate.Release(); }
    }

    public static async Task QuiesceAsync(CancellationToken ct)
    {
        RequireService();
        lock (CancellationGate) { _networkOperation?.Cancel(); }
        await OperationGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            Journal.Change(before => before.HasUnfinishedAttempt && !before.MayHaveStartedInstallation
                ? TransitionReconciliationDeferred(before, DateTimeOffset.UtcNow)
                : before);
            AgentUpdateBitsDownloader.Quiesce(Root);
            await ProjectAsync(CancellationToken.None).ConfigureAwait(false);
        }
        finally { OperationGate.Release(); }
    }

    public static async Task ReconcileOnServiceStartAsync(CancellationToken ct)
    {
        RequireService();
        AgentUpdateSecurity.EnsureProtectedRoot(Root);
        await OperationGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            AgentUpdateBitsDownloader.Quiesce(Root);
            await ReconcileOwnedAsync(ct, allowHealth: false).ConfigureAwait(false);
            Journal.Change(before => before.NextCheckUtc is not null ? before : before with
            {
                NextCheckUtc = DateTimeOffset.UtcNow.AddHours(24).Add(AgentUpdateJournalStore.Offset(before.ScheduleSeed, TimeSpan.FromHours(6))),
            });
            await ProjectAsync(ct).ConfigureAwait(false);
        }
        finally { OperationGate.Release(); }
    }

    public static async Task RunScheduledAsync(CancellationToken ct)
    {
        RequireService();
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(1));
        await RunScheduledAsync(ct, timer.WaitForNextTickAsync, async token =>
        {
            await ReconcileOwnedAsync(token).ConfigureAwait(false);
            var lifecycle = await LoadLifecycleAsync(token).ConfigureAwait(false);
            await RunScheduledTickAsync(Journal, lifecycle, Quarantined,
                async required => (await CheckAndStageOwnedAsync(automatic: true, required, token,
                    bypassSchedule: true, installRequest: Journal.Read().InstallRequest).ConfigureAwait(false)) is not null,
                id => ApplyAsync(id, automatic: true, token),
                () => CheckAndStageOwnedAsync(automatic: true, required: false, token), token).ConfigureAwait(false);
        }, ReportFailureAsync).ConfigureAwait(false);
    }

    internal static async Task RunScheduledAsync(CancellationToken ct, Func<CancellationToken, ValueTask<bool>> nextTick,
        Func<CancellationToken, Task> iteration, Func<Exception, Task> reportFailure)
    {
        while (await nextTick(ct).ConfigureAwait(false))
        {
            if (!await OperationGate.WaitAsync(0, ct).ConfigureAwait(false)) continue;
            try
            {
                await iteration(ct).ConfigureAwait(false);
            }
            catch (IntentionalUpdateCancellationException) when (!ct.IsCancellationRequested) { }
            catch (AgentUpdateReconciliationDeferredException) when (!ct.IsCancellationRequested) { }
            catch (AgentUpdatePlanMismatchException) when (!ct.IsCancellationRequested) { }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { await reportFailure(ex).ConfigureAwait(false); }
            finally { OperationGate.Release(); }
        }
    }

    internal static async Task RunScheduledTickAsync(AgentUpdateJournalStore journal, AgentLifecycleSnapshot lifecycle,
        Func<bool> quarantined, Func<bool, Task<bool>> stageRequest, Func<string, Task> apply, Func<Task> check, CancellationToken ct)
    {
        var active = ReadInstallAuthority(journal);
        if (await HoldOrRunInstallRequestAsync(active, lifecycle, quarantined, journal.Change, stageRequest,
            _requestLog, ct).ConfigureAwait(false)) return;
        active = journal.Read();
        var now = DateTimeOffset.UtcNow;
        if (active.AttemptId is not null &&
            ((active.Required && active.Phase == AgentUpdateStates.AwaitingConsent && active.ApplyNotBeforeUtc <= now) ||
             (active.Phase == AgentUpdateStates.RetryableBusy && active.NextRetryUtc <= now)))
        {
            HoldExpiredInstallRequest(active, automatic: true, ct);
            await apply(active.AttemptId).ConfigureAwait(false);
        }
        else if (!active.HasUnfinishedAttempt && active.NextCheckUtc <= now) await check().ConfigureAwait(false);
    }

    private static async Task ApplyAsync(string attemptId, bool automatic, CancellationToken ct)
    {
        var active = ReadInstallAuthority(Journal);
        if (active.AttemptId != attemptId)
            throw new InvalidOperationException("Update attempt does not match the requested consent.");
        if (active.MayHaveStartedInstallation || active.Phase == "launch_requested")
            return; // Idempotent apply never launches a second runner.
        if (active.Phase is not (AgentUpdateStates.Staged or AgentUpdateStates.AwaitingConsent or AgentUpdateStates.RetryableBusy))
            throw new InvalidOperationException("Update attempt cannot be applied.");
        var lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
        if (automatic && (!AllowsAutomatic(lifecycle) || active.LifecycleGeneration != lifecycle.Generation))
            throw new InvalidOperationException("Automatic update authorization changed.");
        if (active.RetryCount >= 3 || (active.NextRetryUtc is not null && active.NextRetryUtc > DateTimeOffset.UtcNow))
            throw new InvalidOperationException("Update installer retry is not admitted.");
        HoldExpiredInstallRequest(active, automatic, ct);
        var plan = ReadPlan(active) ?? throw new InvalidOperationException("Update plan is missing.");
        var attemptDirectory = AgentUpdateSecurity.ResolveAttemptDirectory(Root, attemptId);
        var runtimeDirectory = Path.GetDirectoryName(AgentUpdateCoordinator.ResolveUpdaterPath())!;
        var runner = AgentUpdateRunnerFiles.Prepare(runtimeDirectory, attemptDirectory);
        using (await AgentUpdateLaunchFence.AcquireAsync(ct).ConfigureAwait(false))
        {
            lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
            if (automatic && (!AllowsAutomatic(lifecycle) || active.LifecycleGeneration != lifecycle.Generation))
                throw new InvalidOperationException("Automatic update authorization changed.");
            var latest = ReadInstallAuthority(Journal);
            if (latest.AttemptId != attemptId) throw new InvalidOperationException("Update attempt changed before launch.");
            HoldExpiredInstallRequest(latest, automatic, ct);
            HoldWhileQuarantined(automatic, ct);
            AgentUpdateRunnerFiles.ValidateForLaunch(runtimeDirectory, attemptDirectory);
            Journal.ChangeAttempt(attemptId, before => TransitionLaunchRequested(before, lifecycle.Generation, automatic, ct));
            var start = new ProcessStartInfo(runner) { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = Path.GetDirectoryName(runner)! };
            start.ArgumentList.Add("--attempt");
            start.ArgumentList.Add(attemptId);
            using var process = Process.Start(start) ?? throw new InvalidOperationException("Update runner launch failed.");
            Journal.ChangeAttempt(attemptId, before => before with
            {
                RunnerProcessId = process.Id, RunnerStartedUtc = new DateTimeOffset(process.StartTime.ToUniversalTime()),
            });
        }
        await ProjectAsync(ct).ConfigureAwait(false);
    }

    private static async Task<AgentLocalControlResponse> StatusAsync(string code, CancellationToken ct)
    {
        var lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
        var state = await Projection.ReadAsync(WindowsDeviceInfo.GetAgentVersion(), ct).ConfigureAwait(false);
        return new(true, code, lifecycle.State.ToString(), state.State, state.AttemptId,
            WindowsDeviceInfo.GetAgentVersion(), state.TargetVersion, lifecycle.Generation);
    }

    private static Task ReportFailureAsync(Exception error)
        => ReportFailureAsync(Journal, () => ProjectAsync(CancellationToken.None), error);

    internal static async Task ReportFailureAsync(AgentUpdateJournalStore journal, Func<Task> project, Exception error)
    {
        try
        {
            journal.Change(TransitionFailure);
            await project().ConfigureAwait(false);
        }
        catch (Exception) { /* A corrupt/unwritable journal stays unavailable; never create replacement success state. */ }
    }

    private static Task<AgentLifecycleSnapshot> LoadLifecycleAsync(CancellationToken ct)
        => new DurableAgentLifecycleStateStore().LoadAsync(ct);
    private static bool AllowsAutomatic(AgentLifecycleSnapshot lifecycle)
        => AgentLifecycleStates.AllowsAutomaticNetwork(lifecycle.State) && lifecycle.QuiescenceComplete;
    private static void RequireService()
    {
        if (!AgentUpdateSecurity.IsLocalSystem())
            throw new UnauthorizedAccessException("Only the installed SYSTEM service owns updates.");
    }
}
