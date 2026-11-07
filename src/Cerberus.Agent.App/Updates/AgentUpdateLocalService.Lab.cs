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
        // A failed campaign stays stopped. A separately committed operator bootstrap
        // may transfer a closed predecessor, preserving its receipt under the journal lock.
        if (!CanContinueLabCampaign(active, scope.Policy, WindowsDeviceInfo.GetAgentVersion(),
                AgentUpdateLabRuntimeAdmission.HasCommittedBootstrap(scope.Policy, scope.Context))) return;
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
                predecessor => PreserveClosedLabFailure(Root, predecessor));
        });
    }

    internal static AgentUpdateJournal AdmitLabInstallRequest(AgentUpdateJournal before, AgentUpdateLabPolicy policy,
        AgentUpdateExpectedPlan release, long generation, DateTimeOffset now, string installedVersion,
        bool committedCurrentBootstrap = false, Action<AgentUpdateJournal>? preserveClosedFailure = null)
    {
        policy.RequireVersion(release.Version);
        policy.RequireSuccessor(installedVersion, release.Version);
        if (now < policy.NotBeforeUtc || now >= policy.ExpiresAtUtc || !release.IsValid() || generation < 0 ||
            before.HasUnfinishedAttempt || before.MayHaveStartedInstallation || before.InstallRequest is { IsPending: true }) return before;
        if (!CanContinueLabCampaign(before, policy, installedVersion, committedCurrentBootstrap) ||
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
        string installedVersion, bool committedCurrentBootstrap)
    {
        if (before.InstallRequest is not { LocalPolicyId: not null } previous) return true;
        if (previous.LocalPolicyId == policy.CampaignId)
            return previous.TerminalReason is "installed" or "current";
        if (!committedCurrentBootstrap || AgentUpdateCampaignTransition.Release(installedVersion) != policy.Versions[0]) return false;
        return previous.TerminalReason is "installed" or "current"
            ? before.Phase is AgentUpdateStates.Installed or AgentUpdateStates.Current
            : IsClosedLabFailure(before);
    }

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
        else if (retained with { Revision = before.Revision, NextCheckUtc = before.NextCheckUtc } != before)
            throw new InvalidOperationException("Development predecessor receipt conflicts with protected history.");
        var verified = AgentUpdateDurableFile.Read<AgentUpdateJournal>(path, root)
            ?? throw new InvalidOperationException("Development predecessor receipt was not retained.");
        if (verified with { Revision = before.Revision, NextCheckUtc = before.NextCheckUtc } != before)
            throw new InvalidOperationException("Development predecessor receipt verification failed.");
        return path;
    }
}
