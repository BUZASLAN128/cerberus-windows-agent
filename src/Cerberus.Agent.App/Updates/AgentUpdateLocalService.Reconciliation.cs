using System.Diagnostics;
using System.IO;
using System.Net.Http;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App.Updates;

/// <summary>The installed service owns update decisions. UI/CLI requests contain operations and attempt IDs only.</summary>
internal static partial class AgentUpdateLocalService
{

    private static async Task<AgentUpdatePlan?> ReconcileActiveAttemptAsync(
        AgentUpdateJournal active,
        AgentLifecycleSnapshot lifecycle,
        bool automatic,
        bool required,
        long? requiredPolicyGeneration,
        CancellationToken callerToken)
    {
        if (active.AttemptId is null)
            throw new InvalidOperationException("Active update attempt is missing.");

        var existing = LoadOrRetireMissingPlan(
            Root,
            active,
            required,
            requiredPolicyGeneration,
            DateTimeOffset.UtcNow,
            Journal.ChangeAttempt);
        if (existing is null)
        {
            await ProjectAsync(CancellationToken.None).ConfigureAwait(false);
            return null;
        }

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
            using var http = new HttpClient(BackendTrust.Apply(new HttpClientHandler { MaxAutomaticRedirections = 5 }))
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

            var verifiedAt = DateTimeOffset.UtcNow;
            if (TransitionVerifiedRequiredPolicy(current, required, requiredPolicyGeneration,
                latestLifecycle.Generation, verifiedAt) != current)
                Journal.ChangeAttempt(existing.AttemptId!, before => TransitionVerifiedRequiredPolicy(
                    before, required, requiredPolicyGeneration, latestLifecycle.Generation, verifiedAt));
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

    private static bool IsIncompletePreInstallWithoutAttempt(AgentUpdateJournal active)
        => !active.MayHaveStartedInstallation && active.Phase != "launch_requested" &&
            active.Phase is AgentUpdateStates.Checking or AgentUpdateStates.Downloading or
                AgentUpdateStates.Staged or AgentUpdateStates.AwaitingConsent or
                AgentUpdateStates.RetryableBusy ||
           (!active.MayHaveStartedInstallation && active.Phase == AgentUpdateStates.Blocked &&
                active.ReconciliationSnapshot is not null);

    private static bool HasPreInstallAttemptForRecovery(AgentUpdateJournal active)
        => active.Phase is not (AgentUpdateStates.Installed or AgentUpdateStates.Failed or
                AgentUpdateStates.Quarantined) &&
            active.Phase != "launch_requested" && !active.MayHaveStartedInstallation &&
            (active.ReconciliationSnapshot is not null || active.Phase is
                AgentUpdateStates.NotChecked or AgentUpdateStates.Available or AgentUpdateStates.Checking or
                AgentUpdateStates.Downloading or AgentUpdateStates.Staged or AgentUpdateStates.AwaitingConsent or
                AgentUpdateStates.RetryableBusy);

    /// <summary>
    /// Recovers all incomplete pre-install records before startup/scheduler or
    /// check/stage routing can convert or apply them. The delegates keep this
    /// exact decision boundary testable with disposable journal storage while
    /// production binds its canonical Change/ChangeAttempt/Read operations.
    /// </summary>
    internal static AgentUpdateJournal RecoverActiveAttempt(
        string root,
        AgentUpdateJournal active,
        long lifecycleGeneration,
        DateTimeOffset retryAtUtc,
        bool required,
        long? requiredPolicyGeneration,
        Func<Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> change,
        Func<string, Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> changeAttempt,
        Func<AgentUpdateJournal> read)
    {
        if (active.AttemptId is null)
        {
            if (!IsIncompletePreInstallWithoutAttempt(active))
                return active;
            return change(before => before.AttemptId is null && IsIncompletePreInstallWithoutAttempt(before)
                ? TransitionInterruptedPreInstallWithoutAttempt(
                    before,
                    lifecycleGeneration,
                    retryAtUtc,
                    required,
                    requiredPolicyGeneration)
                : before);
        }

        if (!HasPreInstallAttemptForRecovery(active))
            return active;

        var plan = LoadOrRetireMissingPlan(
            root,
            active,
            required,
            requiredPolicyGeneration,
            retryAtUtc,
            changeAttempt);
        if (plan is null)
            return read();

        // A crash can leave a complete plan while its preceding Download/Check
        // phase is still durable. Keep the artifact as evidence, but make the
        // incomplete transaction due for a fresh trusted stage; never auto-apply
        // old consent merely because the file exists.
        if (active.Phase is AgentUpdateStates.Checking or AgentUpdateStates.Downloading or AgentUpdateStates.Staged)
            return changeAttempt(
                active.AttemptId,
                before => before.AttemptId == active.AttemptId &&
                    before.Phase is AgentUpdateStates.Checking or AgentUpdateStates.Downloading or AgentUpdateStates.Staged
                        ? TransitionReconciliationFailure(
                            before,
                            retryAtUtc,
                            required || before.Required,
                            requiredPolicyGeneration)
                        : before);

        return active;
    }

    private static async Task ReconcileOwnedAsync(CancellationToken ct, bool allowHealth = true)
    {
        var lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
        var active = RecoverActiveAttempt(
            Root,
            Journal.Read(),
            lifecycle.Generation,
            DateTimeOffset.UtcNow,
            required: false,
            requiredPolicyGeneration: null,
            Journal.Change,
            Journal.ChangeAttempt,
            Journal.Read);
        if (active.AttemptId is null)
        {
            await ProjectAsync(ct).ConfigureAwait(false);
            return;
        }
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
            AgentUpdatePlan? plan;
            try { plan = ReadPlan(active); }
            catch (Exception ex) when (ex is not OperationCanceledException) { plan = null; }
            if (active.Phase == AgentUpdateStates.PendingReboot && active.InstallationBootId == AgentUpdateBootIdentity.Read())
            {
                await ProjectAsync(ct).ConfigureAwait(false);
                return;
            }
            if (plan is not null && await IsPlanHealthyAsync(plan, ct).ConfigureAwait(false))
                Journal.ChangeAttempt(active.AttemptId, before => before with
                {
                    Phase = AgentUpdateStates.Installed, HealthyInstalledSequence = plan.Sequence,
                    HealthyInstalledVersion = plan.Version,
                });
            else if (plan is not null && !HealthRetryExpired(active,DateTimeOffset.UtcNow, SystemStartedUtc.Value))
                return; // Local readiness can lag on a loaded server; the next tick tries again.
            else
            {
                Journal.ChangeAttempt(active.AttemptId, before => before with { Phase = AgentUpdateStates.RecoveryRequired });
                await ProjectAsync(ct).ConfigureAwait(false);
                return;
            }
        }
        else if (active.Phase == AgentUpdateStates.RecoveryRequired)
        {
            if (!allowHealth) return;
            await TryCloseRecoveryAsync(active, ct).ConfigureAwait(false);
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
        using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(AgentInstallIdentity.RegistryPath, writable: false);
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

    /// <summary>
    /// Reads the trusted attempt plan and durably retires a genuinely absent,
    /// pre-install attempt. The root and compare/transition writer are
    /// parameters so this exact operation can be checked against disposable
    /// attempt storage while production binds its canonical journal writer.
    /// </summary>
    internal static AgentUpdatePlan? LoadOrRetireMissingPlan(
        string root,
        AgentUpdateJournal active,
        bool required,
        long? requiredPolicyGeneration,
        DateTimeOffset retryAtUtc,
        Func<string, Func<AgentUpdateJournal, AgentUpdateJournal>, AgentUpdateJournal> changeAttempt)
    {
        if (active.AttemptId is null)
            throw new InvalidOperationException("Active update attempt is missing.");

        var existing = ReadPlan(root, active);
        if (existing is not null)
            return existing;

        if (active.Phase == "launch_requested" || active.MayHaveStartedInstallation)
            throw new InvalidOperationException("Active update plan is missing.");

        // Staging flushes Downloading before plan creation, so a crash can
        // leave an incomplete pre-install attempt without a plan. Retire it
        // under the journal lock, but never cross the launch fence if another
        // process wins the race before this compare/transition.
        var retired = changeAttempt(
            active.AttemptId,
            before => TransitionReconciliationFailure(
                before,
                retryAtUtc,
                required,
                requiredPolicyGeneration));
        if (retired.Phase == "launch_requested" || retired.MayHaveStartedInstallation)
            throw new InvalidOperationException("Active update plan is missing.");
        return null;
    }

    private static AgentUpdatePlan? ReadPlan(AgentUpdateJournal active)
        => ReadPlan(Root, active);

    private static AgentUpdatePlan? ReadPlan(string root, AgentUpdateJournal active)
    {
        if (active.AttemptId is null) return null;
        var directory = AgentUpdateSecurity.ResolveAttemptDirectory(root, active.AttemptId);
        var path = Path.Combine(directory, AgentUpdateSecurity.PlanFileName);
        // File.Exists hides access errors; probe explicitly so only a genuinely
        // absent plan is eligible for retirement.
        try
        {
            _ = File.GetAttributes(path);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            return null;
        }
        return AgentUpdateDurableFile.Read<AgentUpdatePlan>(path, directory);
    }
}
