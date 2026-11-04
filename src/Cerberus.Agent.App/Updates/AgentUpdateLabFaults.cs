using System.IO;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App.Updates;

/// <summary>A real, one-shot fault for every transition in the authorized two-target campaign.</summary>
internal static class AgentUpdateLabFaults
{
    private sealed record Receipt(string CampaignId, string AgentId, string TenantId, string KeyFingerprint,
        string Version, string Fault, DateTimeOffset Utc, int ProcessId, string? ArtifactSha256, string? AttemptId);

    internal static void InterruptServiceOnce(AgentUpdateInstallRequest? request, IAgentLogger log)
    {
        if (request?.LocalPolicyId is null || request.ExpectedPlan is null) return;
        var scope = AgentUpdateLabRuntime.Resolve();
        if (scope is null || request.LocalPolicyId != scope.Policy.CampaignId ||
            !UsesServiceInterruption(scope.Policy, request.ExpectedPlan.Version) ||
            !AgentUpdateLocalService.AllowsLabFault(scope.Context.Generation)) return;
        if (!RecordOnce(scope, request.ExpectedPlan.Version, "service-pre-download-exit", request.ExpectedPlan.ArtifactSha256)) return;
        log.Warn("Controlled development campaign service interruption before artifact download.");
        Environment.Exit(86); // Abrupt process exit, no crash dump; SCM owns recovery.
    }

    internal static bool UsesServiceInterruption(AgentUpdateLabPolicy policy, string version)
        => policy.Versions.Skip(1).Contains(version, StringComparer.Ordinal) && version != policy.Versions[8];

    // Called inside the updater launch fence, before a launch grant or the MSI-start marker exists.
    internal static void InterruptUpdaterOnce(AgentUpdateJournal active, AgentUpdatePlan plan,
        AgentLifecycleSnapshot lifecycle, int processId, DateTimeOffset startedUtc, Action<string> log)
    {
        if (active.InstallRequest?.LocalPolicyId is null) return;
        var scope = AgentUpdateLabRuntime.Resolve();
        if (scope is null) throw new InvalidOperationException("Development updater fault authority is missing.");
        AgentUpdateLabRuntime.RequireLaunchScope(scope, active, lifecycle.Generation, DateTimeOffset.UtcNow, WindowsDeviceInfo.GetAgentVersion());
        var state = new AgentSignedStateStore(AgentSignedStateStore.DefaultPathForProduct(scope.Context.Product));
        if (!ShouldInterruptUpdater(scope, active, plan, lifecycle, processId, startedUtc,
            state.IsQuarantined(scope.Context.AgentId), AgentUpdateLocalService.PendingStateDelivery(lifecycle,
                new DpapiSecretStore(SecretStoreScope.Machine)))) return;
        if (!RecordOnce(scope, plan.Version, "updater-pre-installer-exit", plan.Sha256, plan.AttemptId)) return;
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
            plan.Version == scope.Policy.Versions[8] && active.Phase == "launch_requested" &&
            active.InstallRequest.BoundAttemptId == active.AttemptId &&
            AgentUpdateRunnerFiles.OwnsLaunch(active, plan.AttemptId!, processId, startedUtc) &&
            active.InstallRequest.VerifiedRelease is { } release && release.Matches(AgentUpdateExpectedPlan.FromPlan(plan));

    private static bool RecordOnce(AgentUpdateLabRuntime.Scope scope, string version, string fault,
        string? artifactSha256 = null, string? attemptId = null)
    {
        var policy = scope.Policy;
        if (!AgentUpdateSecurity.IsLocalSystem()) throw new UnauthorizedAccessException("Lab faults require the installed SYSTEM agent.");
        policy.RequireVersion(version);
        var root = Path.Combine(AgentUpdateStager.DefaultStagingRoot, "lab-campaign-" + policy.CampaignId);
        AgentUpdateSecurity.EnsureProtectedRoot(root);
        var lockPath = Path.Combine(root, "fault.lock");
        AgentUpdateSecurity.ValidateProtectedPath(lockPath, root, allowMissing: true);
        using var held = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
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
}
