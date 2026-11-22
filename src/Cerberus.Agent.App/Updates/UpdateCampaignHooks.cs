using System.Net.Http;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

// Compiled unless -p:ExcludeUpdateCampaignCode=true; UpdateCampaignHooks.Release.cs replaces it then.
internal static class UpdateCampaignHooks
{
    internal static HttpClientHandler CreateUpdateHandler() => AgentUpdateLabRuntime.CreateUpdateHandler();

    internal static void RequireLaunch(AgentUpdateJournal active, AgentLifecycleSnapshot lifecycle)
        => AgentUpdateLabRuntime.RequireLaunch(active, lifecycle);

    internal static void InterruptServiceOnce(AgentUpdateInstallRequest? request, IAgentLogger log)
        => AgentUpdateLabFaults.InterruptServiceOnce(request, log);

    internal static AgentUpdateTrust? BuildTrust(IAgentLogger? log) => AgentUpdateLabRuntime.BuildTrust(log);
}

internal static partial class AgentUpdateLocalService
{
    private static Task<bool> RunCampaignTickAfterBootstrapAsync(CancellationToken ct)
        => RunLabTickAfterBootstrapAsync(AgentUpdateLabRuntime.Resolve(),
            lab => AgentUpdateLabRuntimeAdmission.HasCommittedBootstrap(lab.Policy, lab.Context), RunLabCampaignTickAsync, ct);

    private static Task<bool> ReconcileUnstartedCampaignRunnerAsync(AgentUpdateJournal observed, CancellationToken ct)
        => ReconcileUnstartedLabRunnerAsync(observed, ct);
}
