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

    /// <summary>A compiled, identity-bound operator campaign uses the normal durable request/scheduler path.</summary>
    private static async Task RunLabCampaignTickAsync(CancellationToken ct)
    {
        var scope = AgentUpdateLabRuntime.Resolve();
        if (scope is null) return;
        var lifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
        if (lifecycle.Generation != scope.Context.Generation || !AllowsAutomatic(lifecycle) || Quarantined()) return;
        var active = Journal.Read();
        if (active.HasUnfinishedAttempt || active.InstallRequest is { IsPending: true }) return;
        // Never advance a campaign after a failed recovery, or recreate a failed request with a fresh retry budget.
        if (active.InstallRequest is { LocalPolicyId: not null, TerminalReason: not "installed" and not "current" }) return;
        using var http = new HttpClient(AgentUpdateLabRuntime.CreateUpdateHandler()) { Timeout = TimeSpan.FromSeconds(30) };
        var trust = AgentUpdateTrustFactory.BuildTrust();
        var signal = new AgentUpdateSignal(false, true, trust.ConfiguredManifestUrl, "compiled_lab_campaign", trust.ExpectedChannel);
        var release = await new AgentUpdateStager(http, trust, Root).GetTrustedReleaseAsync(signal, ct).ConfigureAwait(false);
        if (AgentVersionComparer.CompareReleaseCore(release.Version, trust.CurrentVersion) <= 0) return;
        var current = AgentUpdateLabRuntime.Resolve() ?? throw new InvalidOperationException("Development update policy changed.");
        var latestLifecycle = await LoadLifecycleAsync(ct).ConfigureAwait(false);
        if (current.Policy.CampaignId != scope.Policy.CampaignId || current.Context != scope.Context ||
            latestLifecycle.Generation != current.Context.Generation || !AllowsAutomatic(latestLifecycle) || Quarantined()) return;
        Journal.Change(before => AdmitLabInstallRequest(before, current.Policy, release, latestLifecycle.Generation,
            DateTimeOffset.UtcNow, WindowsDeviceInfo.GetAgentVersion()));
    }

    internal static AgentUpdateJournal AdmitLabInstallRequest(AgentUpdateJournal before, AgentUpdateLabPolicy policy,
        AgentUpdateExpectedPlan release, long generation, DateTimeOffset now, string installedVersion)
    {
        policy.RequireVersion(release.Version);
        policy.RequireSuccessor(installedVersion, release.Version);
        if (now < policy.NotBeforeUtc || now >= policy.ExpiresAtUtc || !release.IsValid() || generation < 0 ||
            before.HasUnfinishedAttempt || before.MayHaveStartedInstallation || before.InstallRequest is { IsPending: true }) return before;
        if (before.InstallRequest is { LocalPolicyId: not null } previous &&
            (previous.LocalPolicyId != policy.CampaignId || previous.ExpectedPlan?.Version == release.Version ||
             previous.TerminalReason is not ("installed" or "current"))) return before;
        var normalDeadline = now + MaxInstallRequestDelay;
        var request = new AgentUpdateInstallRequest(now, generation,
            policy.ExpiresAtUtc < normalDeadline ? policy.ExpiresAtUtc : normalDeadline,
            ExpectedPlan: release, LocalPolicyId: policy.CampaignId,
            LocalSourceVersion: AgentUpdateCampaignTransition.Release(installedVersion));
        return request.IsValid() ? before with { InstallRequest = request } : before;
    }
}
