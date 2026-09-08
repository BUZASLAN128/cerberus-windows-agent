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
internal static class AgentUpdateLocalService
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

    /// <summary>
    /// Rewinds only the pre-install state created by the canceled check/stage operation.
    /// Installer evidence and any state that may have crossed the launch fence remain durable.
    /// </summary>
    internal static AgentUpdateJournal TransitionIntentionalCancellation(
        AgentUpdateJournal current,
        AgentUpdateJournal operationStart,
        DateTimeOffset retryAtUtc)
    {
        if (current.Phase == "launch_requested")
            return current with { Phase = AgentUpdateStates.RecoveryRequired };

        if (current.MayHaveStartedInstallation ||
            current.Phase is AgentUpdateStates.Installed or AgentUpdateStates.Blocked or AgentUpdateStates.Quarantined)
            return current;

        var samePriorAttempt = operationStart.AttemptId is not null &&
            string.Equals(current.AttemptId, operationStart.AttemptId, StringComparison.Ordinal);
        if (current.Phase == AgentUpdateStates.Failed && samePriorAttempt)
            return current with { NextCheckUtc = retryAtUtc }; // This is the prior terminal failure, not a synthetic staging failure.

        if (current.Phase == AgentUpdateStates.Current)
            return current with { NextCheckUtc = retryAtUtc };

        if (current.Phase == AgentUpdateStates.Staged)
            return current with
            {
                Phase = AgentUpdateStates.Blocked,
                RequiredPolicyGeneration = RequiredPolicyGenerationFor(current, current.Required, null),
                NextCheckUtc = retryAtUtc,
            };

        if (current.Phase is AgentUpdateStates.AwaitingConsent or AgentUpdateStates.Available)
            return current with
            {
                RequiredPolicyGeneration = RequiredPolicyGenerationFor(current, current.Required, null),
                NextCheckUtc = retryAtUtc,
            };

        if (operationStart.Phase is AgentUpdateStates.Failed or AgentUpdateStates.Installed or
            AgentUpdateStates.Blocked or AgentUpdateStates.Quarantined)
        {
            // The current checking/downloading/failed record belongs to this operation. Keep the
            // earlier terminal evidence, but make the next check immediately eligible.
            return current with
            {
                Phase = operationStart.Phase,
                AttemptId = operationStart.AttemptId,
                Automatic = operationStart.Automatic,
                Required = operationStart.Required,
                LifecycleGeneration = operationStart.LifecycleGeneration,
                RequiredPolicyGeneration = operationStart.RequiredPolicyGeneration,
                InstallerResult = operationStart.InstallerResult,
                RetryCount = operationStart.RetryCount,
                NextRetryUtc = operationStart.NextRetryUtc,
                ApplyNotBeforeUtc = operationStart.ApplyNotBeforeUtc,
                RunnerProcessId = operationStart.RunnerProcessId,
                RunnerStartedUtc = operationStart.RunnerStartedUtc,
                InstallerProcessId = operationStart.InstallerProcessId,
                InstallerStartedUtc = operationStart.InstallerStartedUtc,
                InstallationBootId = operationStart.InstallationBootId,
                NextCheckUtc = retryAtUtc,
            };
        }

        return current with
        {
            Phase = AgentUpdateStates.NotChecked,
            AttemptId = null,
            InstallerResult = null,
            RetryCount = 0,
            NextRetryUtc = null,
            ApplyNotBeforeUtc = null,
            RunnerProcessId = null,
            RunnerStartedUtc = null,
            InstallerProcessId = null,
            InstallerStartedUtc = null,
            InstallationBootId = null,
            RequiredPolicyGeneration = null,
            NextCheckUtc = retryAtUtc,
        };
    }

    internal static bool IsIntentionalCancellation(
        OperationCanceledException error,
        CancellationToken callerToken,
        CancellationToken operationToken,
        bool authorizationChanged)
        => error is IntentionalUpdateCancellationException || authorizationChanged ||
            callerToken.IsCancellationRequested || operationToken.IsCancellationRequested;

    internal static AgentUpdateJournal TransitionFailure(AgentUpdateJournal before)
        => before.Phase == "launch_requested" ? before with { Phase = AgentUpdateStates.RecoveryRequired } :
            before.MayHaveStartedInstallation || before.Phase is
            AgentUpdateStates.Installed or AgentUpdateStates.Failed or AgentUpdateStates.Blocked or AgentUpdateStates.Quarantined
            ? before : before with { Phase = AgentUpdateStates.Failed, RequiredPolicyGeneration = null };

    /// <summary>
    /// Retires a pre-install attempt whose manifest identity no longer matches,
    /// making a fresh trusted stage eligible. Installer/recovery evidence is
    /// never rewound once the launch fence may have been crossed.
    /// </summary>
    internal static AgentUpdateJournal TransitionReconciliationFailure(
        AgentUpdateJournal current,
        DateTimeOffset retryAtUtc,
        bool required = false,
        long? requiredPolicyGeneration = null)
    {
        // A previously retired attempt is already non-applicable. Preserve it
        // exactly, apart from carrying a newly observed required intent.
        if (current.Phase == AgentUpdateStates.Blocked && current.ReconciliationSnapshot is null)
            return required
                ? current with
                {
                    Required = true,
                    RequiredPolicyGeneration = RequiredPolicyGenerationFor(current, true, requiredPolicyGeneration),
                }
                : current;

        if (current.Phase == "launch_requested" ||
            current.MayHaveStartedInstallation ||
            current.Phase is AgentUpdateStates.Installed or AgentUpdateStates.Failed or AgentUpdateStates.Quarantined)
            return current;

        return current with
        {
            Phase = AgentUpdateStates.Blocked,
            Required = current.Required || required,
            RequiredPolicyGeneration = RequiredPolicyGenerationFor(
                current,
                required,
                requiredPolicyGeneration),
            NextRetryUtc = null,
            ApplyNotBeforeUtc = null,
            NextCheckUtc = retryAtUtc,
            ReconciliationSnapshot = null,
        };
    }

    /// <summary>
    /// Makes a pre-install attempt non-applicable while retaining the exact
    /// policy, consent, retry and rollout fields needed after the same trusted
    /// manifest identity is verified. A later identity mismatch clears this
    /// snapshot and retires the old release instead.
    /// </summary>
    internal static AgentUpdateJournal TransitionReconciliationDeferred(
        AgentUpdateJournal current,
        DateTimeOffset retryAtUtc,
        bool required = false,
        long? requiredPolicyGeneration = null)
    {
        if (current.Phase == AgentUpdateStates.Blocked && current.ReconciliationSnapshot is null)
            return required
                ? current with
                {
                    Required = true,
                    RequiredPolicyGeneration = RequiredPolicyGenerationFor(current, true, requiredPolicyGeneration),
                }
                : current;

        if (current.Phase == "launch_requested" ||
            current.MayHaveStartedInstallation ||
            current.Phase is AgentUpdateStates.Installed or AgentUpdateStates.Failed or AgentUpdateStates.Quarantined)
            return current;

        var snapshot = current.ReconciliationSnapshot ?? new AgentUpdateReconciliationSnapshot(
            current.Phase,
            current.LifecycleGeneration,
            current.Automatic,
            current.Required,
            current.ApplyNotBeforeUtc,
            current.RetryCount,
            current.NextRetryUtc,
            current.NextCheckUtc);
        return current with
        {
            Phase = AgentUpdateStates.Blocked,
            Required = current.Required || required,
            RequiredPolicyGeneration = RequiredPolicyGenerationFor(
                current,
                required,
                requiredPolicyGeneration),
            NextCheckUtc = retryAtUtc,
            ReconciliationSnapshot = snapshot,
        };
    }

    /// <summary>Restores a deferred attempt only after its identity and lifecycle generation match.</summary>
    internal static AgentUpdateJournal RestoreReconciliationSnapshot(
        AgentUpdateJournal current,
        long lifecycleGeneration,
        DateTimeOffset? retryAtUtc = null,
        bool required = false,
        long? requiredPolicyGeneration = null)
    {
        var snapshot = current.ReconciliationSnapshot;
        if (snapshot is null)
            return current;

        if (snapshot.LifecycleGeneration != lifecycleGeneration)
        {
            // A consent/retry snapshot is scoped to the lifecycle generation
            // that authorized it. Retire the old artifact instead of migrating
            // its policy into a newer enrollment or authorization boundary.
            return TransitionReconciliationFailure(
                current,
                retryAtUtc ?? DateTimeOffset.UtcNow,
                required,
                requiredPolicyGeneration);
        }

        var effectiveRequired = current.Required || snapshot.Required || required;
        var applyNotBeforeUtc = snapshot.ApplyNotBeforeUtc;
        if (applyNotBeforeUtc is null && effectiveRequired && !snapshot.Required &&
            snapshot.Phase == AgentUpdateStates.AwaitingConsent && current.AttemptId is not null)
        {
            // A required signal may arrive while a recommended consent record
            // is deferred. Establish its bounded rollout gate only after the
            // same trusted identity has restored the attempt.
            applyNotBeforeUtc = DateTimeOffset.UtcNow.Add(AgentUpdateJournalStore.Offset(
                current.ScheduleSeed + ":rollout:" + current.AttemptId, TimeSpan.FromHours(24)));
        }

        return current with
        {
            Phase = snapshot.Phase,
            LifecycleGeneration = lifecycleGeneration,
            Automatic = snapshot.Automatic,
            Required = effectiveRequired,
            RequiredPolicyGeneration = RequiredPolicyGenerationFor(
                current,
                effectiveRequired,
                requiredPolicyGeneration),
            ApplyNotBeforeUtc = applyNotBeforeUtc,
            RetryCount = snapshot.RetryCount,
            NextRetryUtc = snapshot.NextRetryUtc,
            NextCheckUtc = snapshot.NextCheckUtc,
            ReconciliationSnapshot = null,
        };
    }

    /// <summary>
    /// Carries an explicit required signal, or durable required-policy
    /// provenance through the pre-stage check states of the same lifecycle
    /// generation. Terminal/history records never become a new policy source.
    /// </summary>
    internal static bool CarryRequiredBlockedIntent(
        AgentUpdateJournal current,
        bool required,
        long lifecycleGeneration)
        => required || (current.Required &&
            (current.Phase is AgentUpdateStates.Blocked or AgentUpdateStates.Checking or AgentUpdateStates.Available) &&
            ((current.RequiredPolicyGeneration == lifecycleGeneration &&
                (current.Phase is AgentUpdateStates.Checking or AgentUpdateStates.Available ||
                    current.AttemptId is not null)) ||
             (current.RequiredPolicyGeneration is null && current.Phase == AgentUpdateStates.Blocked &&
                current.AttemptId is not null && current.LifecycleGeneration == lifecycleGeneration)));

    internal static bool IsRequiredSignalCurrent(
        bool required,
        long capturedGeneration,
        long lifecycleGeneration)
        => required && capturedGeneration == lifecycleGeneration;

    /// <summary>
    /// Retains an existing explicit provenance marker across retries. A newly
    /// received generation may add/advance that marker, while a false-required
    /// retry never manufactures one from the old attempt generation.
    /// </summary>
    private static long? RequiredPolicyGenerationFor(
        AgentUpdateJournal current,
        bool required,
        long? incomingGeneration)
    {
        if (!required)
            return current.RequiredPolicyGeneration;

        if (current.RequiredPolicyGeneration is long existing)
        {
            if (incomingGeneration is long incoming && incoming >= 0)
                return Math.Max(existing, incoming);
            return existing;
        }

        return incomingGeneration is long generation && generation >= 0
            ? generation
            : current.LifecycleGeneration;
    }

    private static long? RequiredPolicyGenerationForResult(
        AgentUpdateJournal before,
        bool required,
        long lifecycleGeneration,
        long? incomingGeneration)
        => required
            ? RequiredPolicyGenerationFor(before, true, incomingGeneration) ?? lifecycleGeneration
            : null;

    /// <summary>Starts a check while carrying only current-generation required provenance.</summary>
    internal static AgentUpdateJournal TransitionCheckStart(
        AgentUpdateJournal before,
        bool automatic,
        bool required,
        long lifecycleGeneration,
        DateTimeOffset nextCheckUtc,
        long? requiredPolicyGeneration = null)
        => before with
        {
            AttemptId = null,
            InstallerResult = null,
            Phase = AgentUpdateStates.Checking,
            Automatic = automatic,
            LifecycleGeneration = lifecycleGeneration,
            Required = required,
            RequiredPolicyGeneration = RequiredPolicyGenerationForResult(
                before, required, lifecycleGeneration, requiredPolicyGeneration),
            NextCheckUtc = nextCheckUtc,
        };

    /// <summary>Finishes a check without preserving required policy when no release is available.</summary>
    internal static AgentUpdateJournal TransitionCheckResult(
        AgentUpdateJournal before,
        bool available,
        bool required,
        long lifecycleGeneration,
        long? requiredPolicyGeneration = null)
        => before with
        {
            AttemptId = null,
            InstallerResult = null,
            Phase = available ? AgentUpdateStates.Available : AgentUpdateStates.Current,
            Required = available && required,
            RequiredPolicyGeneration = RequiredPolicyGenerationForResult(
                before, available && required, lifecycleGeneration, requiredPolicyGeneration),
        };

    /// <summary>Starts staging with a required policy bound to the current lifecycle generation.</summary>
    internal static AgentUpdateJournal TransitionStageStart(
        AgentUpdateJournal before,
        bool automatic,
        bool required,
        long lifecycleGeneration,
        DateTimeOffset nextCheckUtc,
        long? requiredPolicyGeneration = null)
        => before with
        {
            Phase = AgentUpdateStates.Checking,
            AttemptId = null,
            InstallerResult = null,
            Automatic = automatic,
            LifecycleGeneration = lifecycleGeneration,
            Required = required,
            RequiredPolicyGeneration = RequiredPolicyGenerationForResult(
                before, required, lifecycleGeneration, requiredPolicyGeneration),
            RetryCount = 0,
            NextRetryUtc = null,
            ApplyNotBeforeUtc = null,
            RunnerProcessId = null,
            RunnerStartedUtc = null,
            InstallerProcessId = null,
            InstallerStartedUtc = null,
            InstallationBootId = null,
            NextCheckUtc = nextCheckUtc,
        };

    /// <summary>Commits a staged outcome without dropping its current-generation policy provenance.</summary>
    internal static AgentUpdateJournal TransitionStageResult(
        AgentUpdateJournal before,
        AgentUpdatePlan? plan,
        bool automatic,
        bool required,
        long lifecycleGeneration,
        DateTimeOffset now,
        long? requiredPolicyGeneration = null)
        => before with
        {
            Phase = plan is null ? AgentUpdateStates.Current : AgentUpdateStates.AwaitingConsent,
            Automatic = automatic,
            LifecycleGeneration = lifecycleGeneration,
            Required = required,
            RequiredPolicyGeneration = RequiredPolicyGenerationForResult(
                before, plan is not null && required, lifecycleGeneration, requiredPolicyGeneration),
            ApplyNotBeforeUtc = plan is null || !required ? null : now.Add(AgentUpdateJournalStore.Offset(
                before.ScheduleSeed + ":rollout:" + plan.Channel + ":" + plan.Sequence, TimeSpan.FromHours(24))),
            NextCheckUtc = now.AddHours(24).Add(AgentUpdateJournalStore.Offset(before.ScheduleSeed, TimeSpan.FromHours(6))),
        };

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

    public static async Task<AgentUpdateCheckResult> CheckOnlyAsync(
        bool automatic,
        CancellationToken ct,
        bool bypassSchedule = false)
    {
        RequireService();
        await OperationGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
            if (automatic && !AllowsAutomatic(lifecycle)) return AgentUpdateCheckResult.None;
            var active = Journal.Read();
            var effectiveRequired = CarryRequiredBlockedIntent(active, required: false, lifecycleGeneration: lifecycle.Generation);
            if (active.ReconciliationSnapshot is not null)
            {
                // A deferred attempt must be identity-reconciled before a
                // check can discard its journal link. This keeps an explicit
                // `mode=check` fail-closed without losing the old artifact.
                var preserved = await ReconcileActiveAttemptAsync(
                    active,
                    lifecycle,
                    automatic,
                    required: false,
                    requiredPolicyGeneration: null,
                    ct).ConfigureAwait(false);
                if (preserved is not null)
                {
                    var reconciled = Journal.Read();
                    return new(true, reconciled.Required, !reconciled.Required,
                        preserved.Version, preserved.Channel, preserved.Reason, null, preserved.ArtifactKind);
                }
                active = Journal.Read();
                lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
                effectiveRequired = CarryRequiredBlockedIntent(active, required: false, lifecycleGeneration: lifecycle.Generation);
            }
            if (active.HasUnfinishedAttempt)
            {
                var existing = ReadPlan(active);
                return existing is null ? AgentUpdateCheckResult.None : new(true, existing.Required, !existing.Required,
                    existing.Version, existing.Channel, existing.Reason, null, existing.ArtifactKind);
            }
            if (automatic && !bypassSchedule && active.NextCheckUtc > DateTimeOffset.UtcNow) return AgentUpdateCheckResult.None;
            var operationStart = active;
            var schedulePersisted = false;
            var authorizationChanged = false;
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(ct);
            lock (CancellationGate) { _networkOperation = cancellation; }
            try
            {
                Journal.Change(before => TransitionCheckStart(
                    before,
                    automatic,
                    effectiveRequired,
                    lifecycle.Generation,
                    DateTimeOffset.UtcNow.AddHours(24).Add(AgentUpdateJournalStore.Offset(
                        before.ScheduleSeed, TimeSpan.FromHours(6)))));
                schedulePersisted = true;
                await ProjectAsync(cancellation.Token).ConfigureAwait(false);
                using var http = new HttpClient(new HttpClientHandler { MaxAutomaticRedirections = 5 }) { Timeout = TimeSpan.FromSeconds(30) };
                var trust = AgentUpdateTrustFactory.BuildTrust();
                var signal = new AgentUpdateSignal(false, true, trust.ConfiguredManifestUrl, "service_update_check", trust.ExpectedChannel);
                var result = await new AgentUpdateStager(http, trust, Root).CheckAsync(signal, cancellation.Token).ConfigureAwait(false);
                var latestLifecycle = await LoadLifecycleAsync(cancellation.Token).ConfigureAwait(false);
                if (automatic && (latestLifecycle.Generation != lifecycle.Generation || !AllowsAutomatic(latestLifecycle)))
                {
                    authorizationChanged = true;
                    cancellation.Cancel();
                    throw new IntentionalUpdateCancellationException("Update authorization changed.", cancellation.Token);
                }
                lifecycle = latestLifecycle;
                Journal.Change(before => TransitionCheckResult(
                    before,
                    result.Available,
                    effectiveRequired,
                    lifecycle.Generation));
                var previous = await Projection.ReadAsync(WindowsDeviceInfo.GetAgentVersion(), cancellation.Token).ConfigureAwait(false);
                await Projection.WriteAsync(previous.Transition(result.Available ? AgentUpdateStates.Available : AgentUpdateStates.Current,
                    WindowsDeviceInfo.GetAgentVersion(), targetVersion: result.Version, channel: result.Channel, markChecked: true)
                    with { AttemptId = null, ReleaseId = null, Sequence = 0 }, cancellation.Token).ConfigureAwait(false);
                return result;
            }
            catch (OperationCanceledException ex) when (schedulePersisted &&
                IsIntentionalCancellation(ex, ct, cancellation.Token, authorizationChanged))
            {
                await PersistIntentionalCancellationAsync(operationStart).ConfigureAwait(false);
                throw new IntentionalUpdateCancellationException(ex.Message,
                    CancellationTokenFor(ct, cancellation.Token));
            }
            catch (OperationCanceledException ex)
            {
                await ReportFailureAsync(ex).ConfigureAwait(false);
                throw;
            }
            catch (Exception ex)
            {
                await ReportFailureAsync(ex).ConfigureAwait(false);
                throw;
            }
            finally { lock (CancellationGate) { if (ReferenceEquals(_networkOperation, cancellation)) _networkOperation = null; } }
        }
        finally { OperationGate.Release(); }
    }

    private static async Task<AgentUpdatePlan?> CheckAndStageOwnedAsync(
        bool automatic,
        bool required,
        CancellationToken ct,
        bool bypassSchedule = false,
        long? requiredPolicyGeneration = null)
    {
        var lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
        if (automatic && !AllowsAutomatic(lifecycle))
            return null;
        // Bind the incoming policy to the generation observed at the start of
        // this owned operation. An unstamped internal signal is bound once to
        // that same generation and is never rebound after reconciliation.
        var capturedRequiredGeneration = requiredPolicyGeneration ?? lifecycle.Generation;
        var incomingRequired = IsRequiredSignalCurrent(
            required,
            capturedRequiredGeneration,
            lifecycle.Generation);
        long? incomingRequiredGeneration = incomingRequired ? capturedRequiredGeneration : null;
        var active = Journal.Read();
        var effectiveRequired = CarryRequiredBlockedIntent(active, incomingRequired, lifecycle.Generation);
        if (active.HasUnfinishedAttempt || active.ReconciliationSnapshot is not null)
        {
            var existingPlan = await ReconcileActiveAttemptAsync(
                active,
                lifecycle,
                automatic,
                effectiveRequired,
                incomingRequiredGeneration,
                ct).ConfigureAwait(false);
            if (existingPlan is not null)
                return existingPlan;
            // The old pre-install attempt was durably blocked. Re-read so its
            // former schedule cannot suppress staging of the current release.
            active = Journal.Read();
            // A required policy must not be downgraded by a later scheduled
            // (recommended) tick while this preserved attempt is retired.
            effectiveRequired = CarryRequiredBlockedIntent(active, incomingRequired, lifecycle.Generation);
            // Reconciliation may have discovered a stale lifecycle generation.
            // Reload before staging so the new attempt is bound to the current
            // authorization boundary rather than the old check snapshot.
            lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
            if (automatic && !AllowsAutomatic(lifecycle))
                return null;
            incomingRequired = IsRequiredSignalCurrent(
                required,
                capturedRequiredGeneration,
                lifecycle.Generation);
            incomingRequiredGeneration = incomingRequired ? capturedRequiredGeneration : null;
            effectiveRequired = CarryRequiredBlockedIntent(active, incomingRequired, lifecycle.Generation);
        }
        if (automatic && !bypassSchedule && active.NextCheckUtc > DateTimeOffset.UtcNow) return null;
        var operationStart = active;
        var schedulePersisted = false;
        var authorizationChanged = false;
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(ct);
        lock (CancellationGate) { _networkOperation = cancellation; }
        try
        {
            Journal.Change(before => TransitionStageStart(
                before,
                automatic,
                effectiveRequired,
                lifecycle.Generation,
                DateTimeOffset.UtcNow.AddHours(24).Add(AgentUpdateJournalStore.Offset(
                    before.ScheduleSeed, TimeSpan.FromHours(6))),
                incomingRequiredGeneration));
            schedulePersisted = true;
            await ProjectAsync(cancellation.Token).ConfigureAwait(false);
            using var http = new HttpClient(new HttpClientHandler { MaxAutomaticRedirections = 5 }) { Timeout = TimeSpan.FromSeconds(30) };
            var trust = AgentUpdateTrustFactory.BuildTrust();
            var signal = new AgentUpdateSignal(
                effectiveRequired,
                !effectiveRequired,
                trust.ConfiguredManifestUrl,
                "service_update_check",
                trust.ExpectedChannel,
                effectiveRequired
                    ? incomingRequiredGeneration ?? lifecycle.Generation
                    : null);
            var stager = new AgentUpdateStager(http, trust, Root);
            var plan = await stager.StageAsync(signal, cancellation.Token).ConfigureAwait(false);
            var latestLifecycle = await LoadLifecycleAsync(cancellation.Token).ConfigureAwait(false);
            if (latestLifecycle.Generation != lifecycle.Generation || (automatic && !AllowsAutomatic(latestLifecycle)))
            {
                authorizationChanged = true;
                cancellation.Cancel();
                throw new IntentionalUpdateCancellationException("Update authorization changed.", cancellation.Token);
            }
            var now = DateTimeOffset.UtcNow;
            Journal.Change(before => TransitionStageResult(
                before,
                plan,
                automatic,
                effectiveRequired,
                lifecycle.Generation,
                now,
                incomingRequiredGeneration));
            await ProjectAsync(cancellation.Token).ConfigureAwait(false);
            return plan;
        }
        catch (OperationCanceledException ex) when (schedulePersisted &&
            IsIntentionalCancellation(ex, ct, cancellation.Token, authorizationChanged))
        {
            await PersistIntentionalCancellationAsync(operationStart).ConfigureAwait(false);
            throw new IntentionalUpdateCancellationException(ex.Message,
                CancellationTokenFor(ct, cancellation.Token));
        }
        catch (OperationCanceledException ex)
        {
            await ReportFailureAsync(ex).ConfigureAwait(false);
            throw;
        }
        catch (Exception ex)
        {
            await ReportFailureAsync(ex).ConfigureAwait(false);
            throw;
        }
        finally
        {
            lock (CancellationGate)
                if (ReferenceEquals(_networkOperation, cancellation)) _networkOperation = null;
        }
    }

    private static async Task<AgentUpdatePlan?> ReconcileActiveAttemptAsync(
        AgentUpdateJournal active,
        AgentLifecycleSnapshot lifecycle,
        bool automatic,
        bool required,
        long? requiredPolicyGeneration,
        CancellationToken callerToken)
    {
        var existing = ReadPlan(active) ?? throw new InvalidOperationException("Active update plan is missing.");

        // A launch/install/recovery state is protected by the launch fence. It is
        // never replaced based on a later manifest.
        if (active.MayHaveStartedInstallation)
        {
            await ProjectAsync(CancellationToken.None).ConfigureAwait(false);
            return existing;
        }

        var authorizationChanged = false;
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(callerToken);
        lock (CancellationGate) { _networkOperation = cancellation; }
        try
        {
            using var http = new HttpClient(new HttpClientHandler { MaxAutomaticRedirections = 5 })
            {
                Timeout = TimeSpan.FromSeconds(30),
            };
            var trust = AgentUpdateTrustFactory.BuildTrust();
            var signal = new AgentUpdateSignal(
                required,
                !required,
                trust.ConfiguredManifestUrl,
                "service_update_check",
                trust.ExpectedChannel,
                required ? requiredPolicyGeneration ?? lifecycle.Generation : null);
            var currentIdentity = await new AgentUpdateStager(http, trust, Root)
                .GetTrustedManifestIdentityAsync(signal, cancellation.Token)
                .ConfigureAwait(false);
            var latestLifecycle = await LoadLifecycleAsync(cancellation.Token).ConfigureAwait(false);
            if (latestLifecycle.Generation != lifecycle.Generation ||
                (automatic && !AllowsAutomatic(latestLifecycle)))
            {
                authorizationChanged = true;
                cancellation.Cancel();
                throw new IntentionalUpdateCancellationException(
                    "Update authorization changed.", cancellation.Token);
            }

            if (!currentIdentity.Matches(existing))
            {
                // Retain the old protected attempt and artifact as audit / recovery
                // evidence. A concurrent launch crossing the fence wins and must
                // never be invalidated by this reconciliation.
                var reconciled = Journal.ChangeAttempt(existing.AttemptId!, before =>
                    TransitionReconciliationFailure(
                        before,
                        DateTimeOffset.UtcNow,
                        required,
                        requiredPolicyGeneration));
                if (reconciled.Phase == "launch_requested" || reconciled.MayHaveStartedInstallation)
                    return ReadPlan(reconciled);

                // The durable blocked+due commit precedes this projection and
                // remains authoritative if the caller is cancelled here.
                await ProjectAsync(CancellationToken.None).ConfigureAwait(false);
                return null;
            }

            var current = Journal.Read();
            if (current.AttemptId != existing.AttemptId || current.Phase == "launch_requested" || current.MayHaveStartedInstallation)
            {
                await ProjectAsync(CancellationToken.None).ConfigureAwait(false);
                return ReadPlan(current);
            }
            if (current.Phase == AgentUpdateStates.Blocked && current.ReconciliationSnapshot is null)
            {
                await ProjectAsync(CancellationToken.None).ConfigureAwait(false);
                return null;
            }

            if (current.ReconciliationSnapshot is not null)
            {
                var snapshotGeneration = current.ReconciliationSnapshot.LifecycleGeneration;
                var restored = Journal.ChangeAttempt(existing.AttemptId!, before =>
                    before.ReconciliationSnapshot is null
                        ? before
                        : RestoreReconciliationSnapshot(
                            before,
                            latestLifecycle.Generation,
                            DateTimeOffset.UtcNow,
                            required,
                            requiredPolicyGeneration));
                await ProjectAsync(CancellationToken.None).ConfigureAwait(false);
                // A generation mismatch retires this old attempt. The caller
                // must stage afresh under the current lifecycle/policy and
                // cannot treat the old consent snapshot as permission.
                return snapshotGeneration == latestLifecycle.Generation ? ReadPlan(restored) : null;
            }

            if (required && !current.Required && current.Phase == AgentUpdateStates.AwaitingConsent)
                Journal.ChangeAttempt(existing.AttemptId!, before => before.LifecycleGeneration == latestLifecycle.Generation
                    ? before with
                    {
                        Required = true,
                        ApplyNotBeforeUtc = DateTimeOffset.UtcNow.Add(AgentUpdateJournalStore.Offset(
                            before.ScheduleSeed + ":rollout:" + before.AttemptId, TimeSpan.FromHours(24))),
                    }
                    : before);
            await ProjectAsync(CancellationToken.None).ConfigureAwait(false);
            return ReadPlan(Journal.Read());
        }
        catch (OperationCanceledException ex) when (ex is not IntentionalUpdateCancellationException &&
            !IsIntentionalCancellation(ex, callerToken, cancellation.Token, authorizationChanged))
        {
            // HttpClient timeout cancellation is a failed identity fetch, not
            // caller intent. Preserve the old attempt and retry verification.
            var reconciled = await DeferReconciliationAsync(
                existing.AttemptId!,
                ex,
                DateTimeOffset.UtcNow.Add(ReconciliationRetryDelay),
                required,
                requiredPolicyGeneration).ConfigureAwait(false);
            return ReadPlan(reconciled);
        }
        catch (OperationCanceledException ex) when (ex is IntentionalUpdateCancellationException ||
            IsIntentionalCancellation(ex, callerToken, cancellation.Token, authorizationChanged))
        {
            // Caller/quiesce cancellation also makes the pre-install artifact
            // non-applicable and due for a later identity check. The durable
            // transition is complete before the exception is returned.
            var reconciled = Journal.ChangeAttempt(
                existing.AttemptId!,
                before => TransitionReconciliationDeferred(
                    before,
                    DateTimeOffset.UtcNow,
                    required,
                    requiredPolicyGeneration));
            if (reconciled.Phase != "launch_requested" && !reconciled.MayHaveStartedInstallation)
                await ProjectAsync(CancellationToken.None).ConfigureAwait(false);
            throw ex is IntentionalUpdateCancellationException intentional
                ? intentional
                : new IntentionalUpdateCancellationException(
                    ex.Message,
                    CancellationTokenFor(callerToken, cancellation.Token));
        }
        catch (Exception ex)
        {
            var reconciled = await DeferReconciliationAsync(
                existing.AttemptId!,
                ex,
                DateTimeOffset.UtcNow.Add(ReconciliationRetryDelay),
                required,
                requiredPolicyGeneration).ConfigureAwait(false);
            return ReadPlan(reconciled);
        }
        finally
        {
            lock (CancellationGate)
                if (ReferenceEquals(_networkOperation, cancellation)) _networkOperation = null;
        }
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
        while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
        {
            if (!await OperationGate.WaitAsync(0, ct).ConfigureAwait(false)) continue;
            try
            {
                await ReconcileOwnedAsync(ct).ConfigureAwait(false);
                var lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
                if (!AllowsAutomatic(lifecycle)) continue;
                var active = Journal.Read();
                var now = DateTimeOffset.UtcNow;
                if (active.AttemptId is not null &&
                    ((active.Required && active.Phase == AgentUpdateStates.AwaitingConsent && active.ApplyNotBeforeUtc <= now) ||
                     (active.Phase == AgentUpdateStates.RetryableBusy && active.NextRetryUtc <= now)))
                    await ApplyAsync(active.AttemptId, automatic: true, ct).ConfigureAwait(false);
                else if (!active.HasUnfinishedAttempt && active.NextCheckUtc <= now)
                    await CheckAndStageOwnedAsync(automatic: true, required: false, ct).ConfigureAwait(false);
            }
            catch (IntentionalUpdateCancellationException) when (!ct.IsCancellationRequested) { }
            catch (AgentUpdateReconciliationDeferredException) when (!ct.IsCancellationRequested) { }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { await ReportFailureAsync(ex).ConfigureAwait(false); }
            finally { OperationGate.Release(); }
        }
    }

    private static async Task ApplyAsync(string attemptId, bool automatic, CancellationToken ct)
    {
        var active = Journal.Read();
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
        var plan = ReadPlan(active) ?? throw new InvalidOperationException("Update plan is missing.");
        var attemptDirectory = AgentUpdateSecurity.ResolveAttemptDirectory(Root, attemptId);
        var runtimeDirectory = Path.GetDirectoryName(AgentUpdateCoordinator.ResolveUpdaterPath())!;
        var runner = AgentUpdateRunnerFiles.Prepare(runtimeDirectory, attemptDirectory);
        using (await AgentUpdateLaunchFence.AcquireAsync(ct).ConfigureAwait(false))
        {
            lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
            if (automatic && (!AllowsAutomatic(lifecycle) || active.LifecycleGeneration != lifecycle.Generation))
                throw new InvalidOperationException("Automatic update authorization changed.");
            AgentUpdateRunnerFiles.ValidateForLaunch(runtimeDirectory, attemptDirectory);
            Journal.ChangeAttempt(attemptId, before => before with
            {
                Phase = "launch_requested", LifecycleGeneration = lifecycle.Generation, Automatic = automatic,
                InstallerResult = null, NextRetryUtc = null,
            });
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

    private static async Task ReconcileOwnedAsync(CancellationToken ct, bool allowHealth = true)
    {
        var active = Journal.Read();
        if (active.AttemptId is null) return;
        if (active.Phase is "launch_requested" or "install_may_have_started" or AgentUpdateStates.Installing)
        {
            if (!IsProcessAlive(active.RunnerProcessId, active.RunnerStartedUtc))
                Journal.ChangeAttempt(active.AttemptId, before => before with { Phase = AgentUpdateStates.RecoveryRequired });
        }
        else if (active.Phase == AgentUpdateStates.RetryableBusy && active.NextRetryUtc is null)
        {
            Journal.ChangeAttempt(active.AttemptId, before => before with
            {
                RetryCount = Math.Min(3, before.RetryCount + 1),
                NextRetryUtc = DateTimeOffset.UtcNow.AddSeconds(Math.Min(30, 4 * Math.Pow(2, before.RetryCount))),
                Phase = before.RetryCount >= 2 ? AgentUpdateStates.Failed : AgentUpdateStates.RetryableBusy,
            });
        }
        else if (active.Phase is AgentUpdateStates.HealthPending or AgentUpdateStates.PendingReboot)
        {
            if (!allowHealth) return; // Startup must open the pipe before health can prove local readiness.
            var plan = ReadPlan(active) ?? throw new InvalidOperationException("Installed update plan is missing.");
            if (active.Phase == AgentUpdateStates.PendingReboot && active.InstallationBootId == AgentUpdateBootIdentity.Read())
            {
                await ProjectAsync(ct).ConfigureAwait(false);
                return;
            }
            if (string.Equals(WindowsDeviceInfo.GetAgentVersion(), plan.Version, StringComparison.Ordinal) &&
                IsCanonicalServiceProcess())
            {
                await LoadLifecycleAsync(ct).ConfigureAwait(false);
                AgentLocalControlResponse ready;
                try { ready = await Cerberus.Agent.App.Control.AgentLocalControlClient.SendAsync(new AgentLocalControlRequest("status"), ct).ConfigureAwait(false); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    Journal.ChangeAttempt(active.AttemptId, before => before with { Phase = AgentUpdateStates.RecoveryRequired });
                    await ProjectAsync(ct).ConfigureAwait(false);
                    return;
                }
                if (!ready.Success || ready.CurrentVersion != plan.Version)
                {
                    Journal.ChangeAttempt(active.AttemptId, before => before with { Phase = AgentUpdateStates.RecoveryRequired });
                    await ProjectAsync(ct).ConfigureAwait(false);
                    return;
                }
                Journal.ChangeAttempt(active.AttemptId, before => before with
                {
                    Phase = AgentUpdateStates.Installed, HealthyInstalledSequence = plan.Sequence,
                    HealthyInstalledVersion = plan.Version,
                });
            }
            else
                Journal.ChangeAttempt(active.AttemptId, before => before with { Phase = AgentUpdateStates.RecoveryRequired });
        }
        else if (active.Phase is AgentUpdateStates.Downloading or AgentUpdateStates.Checking)
            Journal.ChangeAttempt(active.AttemptId, before => before with { Phase = AgentUpdateStates.Failed });
        await ProjectAsync(ct).ConfigureAwait(false);
    }

    private static bool IsCanonicalServiceProcess()
    {
        var directory = Path.GetDirectoryName(AgentUpdateCoordinator.ResolveUpdaterPath())!;
        var expected = Path.Combine(directory, "Cerberus.Agent.Service.exe");
        if (!string.Equals(Environment.ProcessPath, expected, StringComparison.OrdinalIgnoreCase)) return false;
        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"Software\Cerberus\WindowsAgent", writable: false);
        foreach (var (file, name) in new[] { (expected, "serviceExeSha256"), (Path.Combine(directory, "Cerberus.Agent.Service.dll"), "serviceAssemblySha256") })
        {
            var digest = key?.GetValue(name)?.ToString();
            if (digest is null || digest.Length != 64) return false;
            using var stream = File.OpenRead(file);
            if (!Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(stream)).Equals(digest, StringComparison.OrdinalIgnoreCase)) return false;
        }
        return true;
    }

    private static bool IsProcessAlive(int? id, DateTimeOffset? startedUtc)
    {
        if (id is null || startedUtc is null) return false;
        try
        {
            using var process = Process.GetProcessById(id.Value);
            return !process.HasExited && new DateTimeOffset(process.StartTime.ToUniversalTime()) == startedUtc;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception) { return false; }
    }

    private static AgentUpdatePlan? ReadPlan(AgentUpdateJournal active)
    {
        if (active.AttemptId is null) return null;
        var directory = AgentUpdateSecurity.ResolveAttemptDirectory(Root, active.AttemptId);
        return AgentUpdateDurableFile.Read<AgentUpdatePlan>(Path.Combine(directory, AgentUpdateSecurity.PlanFileName), directory);
    }

    private static async Task<AgentLocalControlResponse> StatusAsync(string code, CancellationToken ct)
    {
        var lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
        var state = await Projection.ReadAsync(WindowsDeviceInfo.GetAgentVersion(), ct).ConfigureAwait(false);
        return new(true, code, lifecycle.State.ToString(), state.State, state.AttemptId,
            WindowsDeviceInfo.GetAgentVersion(), state.TargetVersion, lifecycle.Generation);
    }

    private static async Task ProjectAsync(CancellationToken ct)
    {
        var active = Journal.Read();
        var old = await Projection.ReadAsync(WindowsDeviceInfo.GetAgentVersion(), ct).ConfigureAwait(false);
        var plan = ReadPlan(active);
        var state = active.Phase is "launch_requested" or "install_may_have_started" ? AgentUpdateStates.Installing : active.Phase;
        var next = old.Transition(state, WindowsDeviceInfo.GetAgentVersion(), targetVersion: plan?.Version,
            channel: plan?.Channel, attemptId: active.AttemptId, sequence: plan?.Sequence,
            msiExitCode: active.InstallerResult?.MsiExitCode, retryCount: active.RetryCount,
            requiresReboot: state == AgentUpdateStates.PendingReboot) with
        {
            AttemptId = active.AttemptId,
            TargetVersion = plan?.Version,
            Sequence = plan?.Sequence ?? 0,
            ReleaseId = plan is null ? null : plan.Channel + ":" + plan.Sequence,
            Policy = active.Required ? "required" : "recommended",
            RetryAfterUtc = active.NextRetryUtc?.ToString("O"),
            HealthState = state == AgentUpdateStates.Installed ? "healthy" :
                state is AgentUpdateStates.HealthPending or AgentUpdateStates.PendingReboot ? "pending" :
                state == AgentUpdateStates.RecoveryRequired ? "unhealthy" : "unknown",
            RollbackState = state == AgentUpdateStates.RecoveryRequired ? "unavailable" : "none",
            LastErrorCode = active.InstallerResult?.ErrorCode,
            LastErrorMessage = null,
        };
        if (next with { LastTransitionUtc = old.LastTransitionUtc } != old)
            await Projection.WriteAsync(next, ct).ConfigureAwait(false);
    }

    private static async Task ReportFailureAsync(Exception error)
    {
        try
        {
            Journal.Change(TransitionFailure);
            await ProjectAsync(CancellationToken.None).ConfigureAwait(false);
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
