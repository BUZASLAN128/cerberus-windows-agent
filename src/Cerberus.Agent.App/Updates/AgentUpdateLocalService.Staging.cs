using System.Diagnostics;
using System.IO;
using System.Net.Http;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App.Updates;

/// <summary>The installed service owns update decisions. UI/CLI requests contain operations and attempt IDs only.</summary>
internal static partial class AgentUpdateLocalService
{

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
            active = RecoverActiveAttempt(
                Root,
                active,
                lifecycle.Generation,
                DateTimeOffset.UtcNow,
                required: false,
                requiredPolicyGeneration: null,
                Journal.Change,
                Journal.ChangeAttempt,
                Journal.Read);
            effectiveRequired = CarryRequiredBlockedIntent(active, required: false, lifecycleGeneration: lifecycle.Generation);
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
                using var http = new HttpClient(BackendTrust.Apply(new HttpClientHandler { MaxAutomaticRedirections = 5 })) { Timeout = TimeSpan.FromSeconds(30) };
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
                var checkCompletedUtc = DateTimeOffset.UtcNow;
                Journal.Change(before => TransitionCheckResult(
                    before,
                    result.Available,
                    effectiveRequired,
                    lifecycle.Generation,
                    now: checkCompletedUtc));
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
        long? requiredPolicyGeneration = null,
        AgentUpdateInstallRequest? installRequest = null)
    {
        var lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
        if (PendingStateDelivery(lifecycle)) return null;
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
        active = RecoverActiveAttempt(
            Root,
            active,
            lifecycle.Generation,
            DateTimeOffset.UtcNow,
            effectiveRequired,
            incomingRequiredGeneration,
            Journal.Change,
            Journal.ChangeAttempt,
            Journal.Read);
        effectiveRequired = CarryRequiredBlockedIntent(active, incomingRequired, lifecycle.Generation);
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
            {
                var release = AgentUpdateExpectedPlan.FromPlan(existingPlan);
                RequireExpectedRelease(installRequest, release);
                Journal.Change(before => RecordRequestRelease(before, installRequest, release));
                return existingPlan;
            }
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
        var failedInstallSequence = active.FailedInstallSequence;
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
            using var http = new HttpClient(BackendTrust.Apply(new HttpClientHandler { MaxAutomaticRedirections = 5 })) { Timeout = TimeSpan.FromSeconds(30) };
            var trust = AgentUpdateTrustFactory.BuildTrust();
            var signal = new AgentUpdateSignal(
                effectiveRequired,
                !effectiveRequired,
                trust.ConfiguredManifestUrl,
                "service_update_check",
                trust.ExpectedChannel,
                effectiveRequired
                    ? incomingRequiredGeneration ?? lifecycle.Generation
                    : null,
                AgentUpdateRollbackPolicy.SkipSequenceFor(automatic, failedInstallSequence), installRequest?.ExpectedPlan);
            var stager = new AgentUpdateStager(http, trust, Root);
            var result = await stager.StageWithReleaseAsync(signal, cancellation.Token).ConfigureAwait(false);
            var plan = result.Plan;
            if (installRequest is not null && plan is null && !result.IsCurrent)
                throw new InstallReleaseUnavailableException();
            var latestLifecycle = await LoadLifecycleAsync(cancellation.Token).ConfigureAwait(false);
            if (latestLifecycle.Generation != lifecycle.Generation || (automatic && !AllowsAutomatic(latestLifecycle)))
            {
                authorizationChanged = true;
                cancellation.Cancel();
                throw new IntentionalUpdateCancellationException("Update authorization changed.", cancellation.Token);
            }
            var now = DateTimeOffset.UtcNow;
            Journal.Change(before => RecordRequestRelease(TransitionStageResult(
                before,
                plan,
                automatic,
                effectiveRequired,
                lifecycle.Generation,
                now,
                incomingRequiredGeneration), installRequest, result.Release));
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
        catch (AgentUpdatePlanMismatchException)
        {
            await PublishNewStagePlanMismatchAsync(Journal, installRequest, () => ProjectAsync(CancellationToken.None)).ConfigureAwait(false);
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

    internal static void RequireExpectedRelease(AgentUpdateInstallRequest? request, AgentUpdateExpectedPlan actual)
    {
        if (request?.ExpectedPlan is { } expected && !expected.Matches(actual))
            throw new AgentUpdatePlanMismatchException();
    }

    internal static async Task PublishNewStagePlanMismatchAsync(AgentUpdateJournalStore journal,
        AgentUpdateInstallRequest? request, Func<Task> project)
    {
        journal.Change(before =>
        {
            if (request is null || before.AttemptId is not null || before.Phase != AgentUpdateStates.Checking ||
                !MatchesPending(before.InstallRequest, request)) return before;
            var failed = before with { Phase = AgentUpdateStates.Failed };
            return failed with { InstallRequest = AnchorTerminal(failed, Finish(before.InstallRequest!, "plan_mismatch")) };
        });
        await project().ConfigureAwait(false);
    }

    private static AgentUpdateJournal RecordRequestRelease(AgentUpdateJournal journal, AgentUpdateInstallRequest? request,
        AgentUpdateExpectedPlan? release)
        => request is not null && MatchesPending(journal.InstallRequest, request)
            ? journal with { InstallRequest = journal.InstallRequest! with { VerifiedRelease = release } }
            : journal;
}
