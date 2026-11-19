using System.IO;
using System.Text.Json.Serialization;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App.Updates;

/// <summary>Fault schedule and protected once receipts for the authorized two-target campaign.</summary>
internal static class AgentUpdateLabFaults
{
    internal const string InstallerMutexName = @"Global\_MSIExecute";
    internal const string TokenRoute429 = "token-route-429";
    internal const string PostCommitCrash = "service-post-commit-crash";
    private const string ServiceExit = "service-pre-download-exit";
    private const string UpdaterExit = "updater-pre-installer-exit";
    private const string InstallerBusy = "updater-msi-busy-1618";

    // Indexed by the target's position in policy.Versions. Index 0 is bootstrap.
    private static readonly string?[] Schedule = [null, ServiceExit, InstallerBusy, TokenRoute429,
        UpdaterExit, PostCommitCrash, "feed-truncated-artifact", InstallerBusy, UpdaterExit,
        TokenRoute429, ServiceExit];
    // The "fast" profile keeps only faults whose recovery takes about a minute or two.
    private static readonly string?[] FastSchedule = [null, ServiceExit, InstallerBusy, TokenRoute429,
        ServiceExit, InstallerBusy, TokenRoute429, ServiceExit, InstallerBusy, TokenRoute429, ServiceExit];
    internal const string FastProfile = AgentUpdateLabPolicy.FastFaultProfile;
    private static Mutex? _installerBusyHold;

    internal sealed record Receipt(string CampaignId, string AgentId, string TenantId, string KeyFingerprint,
        string Version, string Fault, DateTimeOffset Utc, int ProcessId, string? ArtifactSha256, string? AttemptId,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] int Count = 0);

    internal static string? FaultFor(AgentUpdateLabPolicy? policy, string version)
    {
        if (policy is null) return null;
        var schedule = policy.FaultProfile == FastProfile ? FastSchedule : Schedule;
        var index = Array.IndexOf(policy.Versions, AgentUpdateCampaignTransition.Release(version));
        return index >= 0 && index < schedule.Length ? schedule[index] : null;
    }

    internal static void InterruptServiceOnce(AgentUpdateInstallRequest? request, IAgentLogger log)
    {
        if (request?.LocalPolicyId is null || request.ExpectedPlan is null) return;
        var scope = AgentUpdateLabRuntime.Resolve();
        if (scope is null || request.LocalPolicyId != scope.Policy.CampaignId ||
            !UsesServiceInterruption(scope.Policy, request.ExpectedPlan.Version) ||
            !AgentUpdateLocalService.AllowsLabFault(scope.Context.Generation)) return;
        if (!RecordOnce(scope, request.ExpectedPlan.Version, ServiceExit, request.ExpectedPlan.ArtifactSha256)) return;
        log.Warn("Controlled development campaign service interruption before artifact download.");
        Environment.Exit(86); // Abrupt process exit, no crash dump; SCM owns recovery.
    }

    internal static bool UsesServiceInterruption(AgentUpdateLabPolicy policy, string version)
        => FaultFor(policy, version) == ServiceExit;

    // Called inside the updater launch fence, before a launch grant or the MSI-start marker exists.
    internal static void InterruptUpdaterOnce(AgentUpdateJournal active, AgentUpdatePlan plan,
        AgentLifecycleSnapshot lifecycle, int processId, DateTimeOffset startedUtc, Action<string> log)
    {
        if (active.InstallRequest?.LocalPolicyId is null) return;
        var scope = AgentUpdateLabRuntime.Resolve();
        if (scope is null) throw new InvalidOperationException("Development updater fault authority is missing.");
        AgentUpdateLabRuntime.RequireLaunchScope(scope, active, lifecycle.Generation, DateTimeOffset.UtcNow,
            WindowsDeviceInfo.GetAgentVersion(), AgentUpdateLabRuntime.EffectiveVersions(scope.Policy));
        var state = new AgentSignedStateStore(AgentSignedStateStore.DefaultPathForProduct(scope.Context.Product));
        if (!ShouldInterruptUpdater(scope, active, plan, lifecycle, processId, startedUtc,
            state.IsQuarantined(scope.Context.AgentId), AgentUpdateLocalService.PendingStateDelivery(lifecycle,
                new DpapiSecretStore(SecretStoreScope.Machine)))) return;
        var fault = FaultFor(scope.Policy, plan.Version)!;
        if (!RecordOnce(scope, plan.Version, fault, plan.Sha256, plan.AttemptId)) return;
        if (fault == InstallerBusy)
        {
            // Launch remains on this synchronous updater thread. Windows releases ownership on exit.
            _installerBusyHold ??= TakeInstallerMutex(InstallerMutexName);
            log("Controlled development campaign installer contention before installer handoff.");
            return;
        }
        log("Controlled development campaign updater interruption before installer handoff.");
        Environment.Exit(86); // The flushed installer fence has not been crossed.
    }

    internal static bool ShouldInterruptUpdater(AgentUpdateLabRuntime.Scope scope, AgentUpdateJournal active,
        AgentUpdatePlan plan, AgentLifecycleSnapshot lifecycle, int processId, DateTimeOffset startedUtc,
        bool durableQuarantined, bool pendingState)
        => !durableQuarantined && !pendingState && lifecycle.QuiescenceComplete &&
            AgentLifecycleStates.AllowsAutomaticNetwork(lifecycle.State) && lifecycle.Generation == scope.Context.Generation &&
            lifecycle.LastEnrollmentNonce == scope.Context.EnrollmentNonce &&
            active.LifecycleGeneration == lifecycle.Generation && active.InstallRequest?.LocalPolicyId == scope.Policy.CampaignId &&
            FaultFor(scope.Policy, plan.Version) is (UpdaterExit or InstallerBusy) && active.Phase == "launch_requested" &&
            active.InstallRequest.BoundAttemptId == active.AttemptId &&
            AgentUpdateRunnerFiles.OwnsLaunch(active, plan.AttemptId!, processId, startedUtc) &&
            active.InstallRequest.VerifiedRelease is { } release && release.Matches(AgentUpdateExpectedPlan.FromPlan(plan));

    internal static Mutex TakeInstallerMutex(string name)
    {
        var state = AgentNamedMutex.Open(name, out var mutex);
        if (mutex is null) throw new InvalidOperationException($"Development installer contention could not open its mutex ({state}).");
        try
        {
            if (!TryAcquireMutex(mutex)) throw new InvalidOperationException("Development installer contention found an already held mutex.");
            return mutex;
        }
        catch
        {
            mutex.Dispose();
            throw;
        }
    }

    internal static bool TryAcquireMutex(Mutex mutex)
    {
        try { return mutex.WaitOne(0); }
        catch (AbandonedMutexException) { return true; } // Windows transferred ownership to this thread.
    }

    internal static bool RecordOnce(AgentUpdateLabRuntime.Scope scope, string version, string fault,
        string? artifactSha256 = null, string? attemptId = null)
    {
        var policy = scope.Policy;
        if (!AgentUpdateSecurity.IsLocalSystem()) throw new UnauthorizedAccessException("Lab faults require the installed SYSTEM agent.");
        policy.RequireVersion(version);
        var root = AgentUpdateLabRuntimeAdmission.CampaignRoot(policy);
        using var held = LockFaultRecords(root);
        var path = Path.Combine(root, version + ".json");
        var previous = AgentUpdateDurableFile.Read<Receipt>(path, root);
        if (previous is not null)
        {
            if (previous.CampaignId != policy.CampaignId || previous.AgentId != scope.Context.AgentId ||
                previous.TenantId != scope.Context.TenantId || previous.KeyFingerprint != scope.Context.KeyFingerprint ||
                previous.Version != version || previous.Fault != fault)
                throw new InvalidOperationException("Development fault receipt does not match this campaign.");
            return false;
        }
        AgentUpdateDurableFile.Write(path, root, new Receipt(policy.CampaignId, scope.Context.AgentId, scope.Context.TenantId,
            scope.Context.KeyFingerprint, version, fault, DateTimeOffset.UtcNow, Environment.ProcessId, artifactSha256, attemptId));
        return true;
    }

    internal static void ArmPostCommitCrash(IAgentLogger log, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(AgentUpdateDefaults.LabPolicyB64) || !AgentUpdateSecurity.IsLocalSystem()) return;
        _ = WatchForCrashAsync(log, ct);
    }

    private static async Task WatchForCrashAsync(IAgentLogger log, CancellationToken ct)
    {
        var start = TimeProvider.System.GetTimestamp();
        var root = AgentUpdateStager.DefaultStagingRoot;
        var store = new AgentUpdateJournalStore(root);
        var version = AgentUpdateCampaignTransition.Release(WindowsDeviceInfo.GetAgentVersion());
        string? observedAttempt = null;
        long? observedAt = null;
        try
        {
            while (TimeProvider.System.GetElapsedTime(start) < TimeSpan.FromMinutes(30))
            {
                var scope = AgentUpdateLabRuntime.Resolve();
                if (scope is null || FaultFor(scope.Policy, version) != PostCommitCrash) return;
                var journal = store.Read();
                if (!IsCrashPhase(scope, journal, version))
                {
                    if (observedAttempt is not null) return;
                }
                else if (observedAttempt is null)
                {
                    observedAttempt = journal.AttemptId;
                    observedAt = TimeProvider.System.GetTimestamp();
                }
                else if (journal.AttemptId != observedAttempt) return;
                else if (TimeProvider.System.GetElapsedTime(observedAt!.Value) >= TimeSpan.FromSeconds(30))
                {
                    ct.ThrowIfCancellationRequested();
                    if (!AgentUpdateLocalService.AllowsLabFault(scope.Context.Generation)) return;
                    using var journalLock = AgentUpdateSecurity.AcquireGlobalLock(root);
                    journal = store.Read();
                    if (journal.AttemptId != observedAttempt || !IsCrashPhase(scope, journal, version)) return;
                    var faultRoot = AgentUpdateLabRuntimeAdmission.CampaignRoot(scope.Policy);
                    using var faultLock = LockFaultRecords(faultRoot);
                    var path = Path.Combine(faultRoot, version + ".json");
                    var previous = AgentUpdateDurableFile.Read<Receipt>(path, faultRoot);
                    var receipt = NextCrashReceipt(scope, journal, version, previous, DateTimeOffset.UtcNow, Environment.ProcessId);
                    if (receipt is null) return;
                    AgentUpdateDurableFile.Write(path, faultRoot, receipt);
                    log.Warn("Controlled development campaign service interruption during the post-commit watch.");
                    Environment.Exit(87);
                    return;
                }
                await Task.Delay(TimeSpan.FromSeconds(10), ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception ex) when (AgentUpdateLabRuntimeAdmission.IsLabRecordFailure(ex))
        {
            log.Warn($"Development campaign post-commit fault could not arm: {ex.GetType().Name}.");
        }
    }

    internal static Receipt? NextCrashReceipt(AgentUpdateLabRuntime.Scope scope, AgentUpdateJournal journal,
        string version, Receipt? previous, DateTimeOffset now, int processId)
    {
        if (!IsCrashPhase(scope, journal, version) || now < scope.Policy.NotBeforeUtc || now >= scope.Policy.ExpiresAtUtc) return null;
        if (previous is not null && !MatchesCrashReceipt(scope, journal, version, previous))
            throw new InvalidOperationException("Development post-commit fault receipt does not match this attempt.");
        if (previous is { Count: >= 5 } || previous?.ProcessId == processId) return null;
        return new(scope.Policy.CampaignId, scope.Context.AgentId, scope.Context.TenantId, scope.Context.KeyFingerprint,
            version, PostCommitCrash, now, processId, journal.InstallRequest!.VerifiedRelease!.ArtifactSha256,
            journal.AttemptId, (previous?.Count ?? 0) + 1);
    }

    internal static bool MatchesCrashReceipt(AgentUpdateLabRuntime.Scope scope, AgentUpdateJournal journal,
        string version, Receipt receipt) =>
        receipt.CampaignId == scope.Policy.CampaignId && receipt.AgentId == scope.Context.AgentId &&
        receipt.TenantId == scope.Context.TenantId && receipt.KeyFingerprint == scope.Context.KeyFingerprint &&
        receipt.Version == version && receipt.Fault == PostCommitCrash && receipt.AttemptId == journal.AttemptId &&
        receipt.Count is >= 1 and <= 5 && receipt.Utc >= scope.Policy.NotBeforeUtc && receipt.Utc < scope.Policy.ExpiresAtUtc &&
        receipt.ArtifactSha256 is not null && receipt.ArtifactSha256 == journal.InstallRequest?.VerifiedRelease?.ArtifactSha256;

    private static bool IsCrashPhase(AgentUpdateLabRuntime.Scope scope, AgentUpdateJournal journal, string version) =>
        journal.Phase == AgentUpdateWatchJournal.CommittedWatch && FaultFor(scope.Policy, version) == PostCommitCrash &&
        AgentUpdateLabHttpFaults.IsPostCommit(journal, scope.Policy.CampaignId, scope.Context.Generation, version);

    internal static FileStream LockFaultRecords(string root)
    {
        AgentUpdateSecurity.EnsureProtectedRoot(root);
        var lockPath = Path.Combine(root, "fault.lock");
        AgentUpdateSecurity.ValidateProtectedPath(lockPath, root, allowMissing: true);
        return new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    }
}
