using System.IO;
using System.Net.Http;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

internal static partial class AgentUpdateLocalService
{
    internal static bool AllowsLabFault(long generation)
    {
        var lifecycle = LoadLifecycleAsync(CancellationToken.None).GetAwaiter().GetResult();
        return lifecycle.Generation == generation && AllowsAutomatic(lifecycle) && !Quarantined();
    }

    internal static async Task<bool> RunLabTickAfterBootstrapAsync(AgentUpdateLabRuntime.Scope? scope,
        Func<AgentUpdateLabRuntime.Scope, bool> committed, Func<CancellationToken, Task> tick, CancellationToken ct)
    {
        if (scope is not null && !committed(scope)) return false;
        await tick(ct).ConfigureAwait(false);
        return true;
    }

    /// <summary>A compiled, identity-bound operator campaign uses the normal durable request/scheduler path.</summary>
    private static async Task RunLabCampaignTickAsync(CancellationToken ct)
    {
        var scope = AgentUpdateLabRuntime.Resolve();
        if (scope is null) return;
        var lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
        if (lifecycle.Generation != scope.Context.Generation || !AllowsAutomatic(lifecycle) || Quarantined()) return;
        var active = Journal.Read();
        if (active.HasUnfinishedAttempt || active.InstallRequest is { IsPending: true }) return;
        var installedVersion = AgentUpdateCampaignTransition.Release(WindowsDeviceInfo.GetAgentVersion());
        var skip = AgentUpdateLabRuntimeAdmission.ReadSkipped(scope.Policy);
        if (skip is null && IsRolledBackLabAttempt(active, scope.Policy.CampaignId))
            skip = TryRecordLabSkip(scope, installedVersion);
        // A failed campaign stays stopped. A separately committed operator bootstrap
        // may transfer a closed predecessor, preserving its receipt under the journal lock.
        if (!CanContinueLabCampaign(active, scope.Policy, installedVersion,
                AgentUpdateLabRuntimeAdmission.HasCommittedBootstrap(scope.Policy, scope.Context), skip)) return;
        using var http = new HttpClient(AgentUpdateLabRuntime.CreateUpdateHandler()) { Timeout = TimeSpan.FromSeconds(30) };
        var trust = AgentUpdateTrustFactory.BuildTrust();
        var signal = new AgentUpdateSignal(false, true, trust.ConfiguredManifestUrl, "compiled_lab_campaign", trust.ExpectedChannel);
        var release = await new AgentUpdateStager(http, trust, Root).GetTrustedReleaseAsync(signal, ct).ConfigureAwait(false);
        if (AgentVersionComparer.CompareReleaseCore(release.Version, trust.CurrentVersion) <= 0) return;
        var current = AgentUpdateLabRuntime.Resolve() ?? throw new InvalidOperationException("Development update policy changed.");
        var latestLifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
        if (current.Policy.CampaignId != scope.Policy.CampaignId || current.Context != scope.Context ||
            latestLifecycle.Generation != current.Context.Generation || !AllowsAutomatic(latestLifecycle) || Quarantined()) return;
        Journal.Change(before =>
        {
            // Reattest inside the final decision lock; an earlier true cannot
            // authorize a handover after the registration context changes.
            var locked = AgentUpdateLabRuntime.Resolve();
            if (locked is null || locked.Policy.CampaignId != current.Policy.CampaignId || locked.Context != current.Context ||
                !AgentUpdateLabRuntimeAdmission.HasCommittedBootstrap(locked.Policy, locked.Context)) return before;
            return AdmitLabInstallRequest(before, locked.Policy, release, locked.Context.Generation,
                DateTimeOffset.UtcNow, WindowsDeviceInfo.GetAgentVersion(), true,
                predecessor => PreserveClosedLabFailure(Root, predecessor),
                AgentUpdateLabRuntimeAdmission.ReadSkipped(locked.Policy));
        });
    }

    internal static AgentUpdateJournal AdmitLabInstallRequest(AgentUpdateJournal before, AgentUpdateLabPolicy policy,
        AgentUpdateExpectedPlan release, long generation, DateTimeOffset now, string installedVersion,
        bool committedCurrentBootstrap = false, Action<AgentUpdateJournal>? preserveClosedFailure = null,
        AgentUpdateLabRuntimeAdmission.SkippedRelease? skip = null)
    {
        policy.RequireVersion(release.Version);
        policy.RequireSuccessor(installedVersion, release.Version, AgentUpdateLabRuntimeAdmission.EffectiveVersions(policy, skip));
        if (now < policy.NotBeforeUtc || now >= policy.ExpiresAtUtc || !release.IsValid() || generation < 0 ||
            before.HasUnfinishedAttempt || before.MayHaveStartedInstallation || before.InstallRequest is { IsPending: true }) return before;
        if (!CanContinueLabCampaign(before, policy, installedVersion, committedCurrentBootstrap, skip) ||
            before.InstallRequest is { LocalPolicyId: not null } previous && previous.ExpectedPlan?.Version == release.Version) return before;
        var normalDeadline = now + MaxInstallRequestDelay;
        var request = new AgentUpdateInstallRequest(now, generation,
            policy.ExpiresAtUtc < normalDeadline ? policy.ExpiresAtUtc : normalDeadline,
            ExpectedPlan: release, LocalPolicyId: policy.CampaignId,
            LocalSourceVersion: AgentUpdateCampaignTransition.Release(installedVersion));
        if (!request.IsValid()) return before;
        if (IsClosedLabFailure(before))
        {
            if (preserveClosedFailure is null) return before;
            preserveClosedFailure(before); // A failed write leaves the old journal authoritative.
        }
        return before with { InstallRequest = request };
    }

    internal static bool CanContinueLabCampaign(AgentUpdateJournal before, AgentUpdateLabPolicy policy,
        string installedVersion, bool committedCurrentBootstrap, AgentUpdateLabRuntimeAdmission.SkippedRelease? skip = null)
    {
        if (before.InstallRequest is not { LocalPolicyId: not null } previous) return true;
        if (previous.LocalPolicyId == policy.CampaignId)
        {
            if (IsRolledBackLabAttempt(before, policy.CampaignId))
                return skip is not null && skip.CampaignId == policy.CampaignId && skip.AttemptId == before.AttemptId &&
                    skip.Version == previous.VerifiedRelease?.Version &&
                    skip.RestoredVersion == AgentUpdateCampaignTransition.Release(installedVersion);
            return previous.TerminalReason is "installed" or "current";
        }
        if (!committedCurrentBootstrap || AgentUpdateCampaignTransition.Release(installedVersion) != policy.Versions[0]) return false;
        return previous.TerminalReason is "installed" or "current"
            ? before.Phase is AgentUpdateStates.Installed or AgentUpdateStates.Current
            : IsClosedLabFailure(before);
    }

    private static AgentUpdateLabRuntimeAdmission.SkippedRelease? TryRecordLabSkip(AgentUpdateLabRuntime.Scope scope, string installedVersion)
    {
        if (!AgentUpdateSecurity.IsLocalSystem()) return null;
        using var journalLock = AgentUpdateSecurity.AcquireGlobalLock(Root);
        var active = Journal.Read();
        if (!IsRolledBackLabAttempt(active, scope.Policy.CampaignId) || active.LifecycleGeneration != scope.Context.Generation)
            return null;
        var plan = ReadPlan(active);
        if (plan is null || AgentUpdateLabFaults.FaultFor(scope.Policy, plan.Version) != AgentUpdateLabFaults.PostCommitCrash)
            return null;
        var root = AgentUpdateLabRuntimeAdmission.CampaignRoot(scope.Policy);
        using var faultLock = AgentUpdateLabFaults.LockFaultRecords(root);
        var receipt = AgentUpdateDurableFile.Read<AgentUpdateLabFaults.Receipt>(Path.Combine(root, plan.Version + ".json"), root);
        var skip = PlanLabSkip(scope, active, plan, receipt, installedVersion, DateTimeOffset.UtcNow);
        if (skip is not null) WriteLabSkip(root, skip);
        return skip;
    }

    internal static void WriteLabSkip(string root, AgentUpdateLabRuntimeAdmission.SkippedRelease skip)
    {
        var path = Path.Combine(root, "skipped.json");
        if (AgentUpdateDurableFile.Read<AgentUpdateLabRuntimeAdmission.SkippedRelease>(path, root) is not null)
            throw new InvalidOperationException("Development campaign already has a skipped release.");
        AgentUpdateDurableFile.Write(path, root, skip);
    }

    internal static AgentUpdateLabRuntimeAdmission.SkippedRelease? PlanLabSkip(AgentUpdateLabRuntime.Scope scope,
        AgentUpdateJournal journal, AgentUpdatePlan plan, AgentUpdateLabFaults.Receipt? receipt, string installedVersion,
        DateTimeOffset now)
    {
        if (!IsRolledBackLabAttempt(journal, scope.Policy.CampaignId) || journal.LifecycleGeneration != scope.Context.Generation ||
            plan.AttemptId != journal.AttemptId || journal.InstallRequest?.VerifiedRelease is not { } release ||
            !release.Matches(AgentUpdateExpectedPlan.FromPlan(plan)) ||
            AgentUpdateLabFaults.FaultFor(scope.Policy, plan.Version) != AgentUpdateLabFaults.PostCommitCrash ||
            receipt is null || !AgentUpdateLabFaults.MatchesCrashReceipt(scope, journal, plan.Version, receipt) ||
            now < scope.Policy.NotBeforeUtc || now >= scope.Policy.ExpiresAtUtc || receipt.Utc > now)
            return null;
        var restoredVersion = AgentUpdateCampaignTransition.Release(installedVersion);
        var index = Array.IndexOf(scope.Policy.Versions, plan.Version);
        return index > 0 && scope.Policy.Versions[index - 1] == restoredVersion
            ? new(scope.Policy.CampaignId, plan.Version, plan.AttemptId!, restoredVersion, now) : null;
    }

    private static bool IsRolledBackLabAttempt(AgentUpdateJournal journal, string campaignId) =>
        journal.Phase == AgentUpdateStates.Failed && journal.FailureCode == AgentUpdateWatchJournal.PostCommitRollback &&
        AgentUpdateSecurity.IsSafeAttemptId(journal.AttemptId) && journal.FailureAttemptId == journal.AttemptId &&
        journal.InstallRequest is { } request && request.LocalPolicyId == campaignId &&
        request.LifecycleGeneration == journal.LifecycleGeneration && request.BoundAttemptId == journal.AttemptId;

    internal static bool IsClosedLabFailure(AgentUpdateJournal before)
        => before.Phase == AgentUpdateStates.Failed && !before.HasUnfinishedAttempt && !before.MayHaveStartedInstallation &&
           AgentUpdateSecurity.IsSafeAttemptId(before.AttemptId) &&
           before.InstallRequest is { TerminalReason: "attempt_failed", TerminalUtc: not null,
               TerminalJournalPhase: AgentUpdateStates.Failed, LocalPolicyId: not null,
               VerifiedRelease: not null, ExpectedPlan: not null } request && request.IsValid() &&
           request.BoundAttemptId == before.AttemptId && request.TerminalJournalAttemptId == before.AttemptId &&
           request.LifecycleGeneration == before.LifecycleGeneration && request.ExpectedPlan.Matches(request.VerifiedRelease) &&
           before.InstallerResult is { State: AgentUpdateStates.Failed, ErrorCode: "msi_failed", RequiresReboot: false,
               Quarantined: false, MsiExitCode: not null and not 0 } result && result.AttemptId == before.AttemptId;

    internal static string PreserveClosedLabFailure(string root, AgentUpdateJournal before)
    {
        if (!IsClosedLabFailure(before)) throw new InvalidOperationException("Development predecessor is not a closed MSI failure.");
        root = AgentUpdateSecurity.NormalizeRoot(root);
        var path = Path.Combine(root, "retired-lab-" + before.InstallRequest!.LocalPolicyId + "-" + before.AttemptId + ".json");
        var retained = AgentUpdateDurableFile.Read<AgentUpdateJournal>(path, root);
        if (retained is null) AgentUpdateDurableFile.Write(path, root, before);
        else if (!SameClosedLabFailure(retained, before))
            throw new InvalidOperationException("Development predecessor receipt conflicts with protected history.");
        var verified = AgentUpdateDurableFile.Read<AgentUpdateJournal>(path, root)
            ?? throw new InvalidOperationException("Development predecessor receipt was not retained.");
        if (!SameClosedLabFailure(verified, before))
            throw new InvalidOperationException("Development predecessor receipt verification failed.");
        return path;
    }

    // Scheduling and the diagnostic failure cause are not part of the retained installer evidence.
    private static bool SameClosedLabFailure(AgentUpdateJournal retained, AgentUpdateJournal before)
        => retained with
        {
            Revision = before.Revision, NextCheckUtc = before.NextCheckUtc, FailureCode = before.FailureCode,
            FailureAttemptId = before.FailureAttemptId, FailureInstallerResultId = before.FailureInstallerResultId,
        } == before;
}
