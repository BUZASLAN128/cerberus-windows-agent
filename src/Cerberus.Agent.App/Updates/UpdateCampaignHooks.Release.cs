using System.Net.Http;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

// Compiled only with -p:ExcludeUpdateCampaignCode=true. Each member does what the campaign code
// does when no campaign policy is compiled in; the build rejects a policy together with the exclusion.
internal static class UpdateCampaignHooks
{
    internal static HttpClientHandler CreateUpdateHandler()
        => BackendTrust.Apply(new HttpClientHandler { MaxAutomaticRedirections = 5 });

    internal static void RequireLaunch(AgentUpdateJournal active, AgentLifecycleSnapshot lifecycle) { }

    internal static void InterruptServiceOnce(AgentUpdateInstallRequest? request, IAgentLogger log) { }

    internal static AgentUpdateTrust? BuildTrust(IAgentLogger? log) => null;
}

internal static partial class AgentUpdateLocalService
{
    private static Task<bool> RunCampaignTickAfterBootstrapAsync(CancellationToken ct) => Task.FromResult(true);

    private static Task<bool> ReconcileUnstartedCampaignRunnerAsync(AgentUpdateJournal observed, CancellationToken ct)
        => Task.FromResult(false);
}
