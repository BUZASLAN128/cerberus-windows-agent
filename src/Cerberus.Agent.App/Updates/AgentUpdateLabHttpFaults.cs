using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Updates;

internal static class AgentUpdateLabHttpFaults
{
    internal static HttpMessageHandler Wrap(HttpMessageHandler inner) => string.IsNullOrEmpty(AgentUpdateDefaults.LabPolicyB64)
        ? inner
        : new TokenRouteHandler(inner, TryArmToken429);

    private static bool TryArmToken429()
    {
        var scope = AgentUpdateLabRuntime.Resolve();
        var version = AgentUpdateCampaignTransition.Release(WindowsDeviceInfo.GetAgentVersion());
        if (scope is null || AgentUpdateLabFaults.FaultFor(scope.Policy, version) != AgentUpdateLabFaults.TokenRoute429 ||
            !AgentUpdateLocalService.AllowsLabFault(scope.Context.Generation)) return false;

        var journal = new AgentUpdateJournalStore(AgentUpdateStager.DefaultStagingRoot).Read();
        return IsPostCommit(journal, scope.Policy.CampaignId, scope.Context.Generation, version) &&
            !IsInstallerBusy(AgentUpdateLabFaults.InstallerMutexName) &&
            AgentUpdateLabFaults.RecordOnce(scope, version, AgentUpdateLabFaults.TokenRoute429,
                journal.InstallRequest!.VerifiedRelease!.ArtifactSha256, journal.AttemptId);
    }

    internal static bool IsPostCommit(AgentUpdateJournal journal, string campaignId, long generation, string version)
        => journal.Phase is ("committed_watch" or AgentUpdateStates.Installed) &&
            AgentUpdateSecurity.IsSafeAttemptId(journal.AttemptId) && journal.LifecycleGeneration == generation &&
            journal.InstallRequest is { ExpectedPlan: { } expected, VerifiedRelease: { } release } request &&
            request.LocalPolicyId == campaignId && request.LifecycleGeneration == generation &&
            request.BoundAttemptId == journal.AttemptId && release.Version == version && expected.Matches(release);

    internal static bool IsInstallerBusy(string name)
    {
        if (!Mutex.TryOpenExisting(name, out var mutex)) return false;
        using (mutex)
        {
            if (!AgentUpdateLabFaults.TryAcquireMutex(mutex)) return true;
            mutex.ReleaseMutex();
            return false;
        }
    }

    internal sealed class TokenRouteHandler(HttpMessageHandler inner, Func<bool> tryArm) : DelegatingHandler(inner)
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (request.Method == HttpMethod.Post && request.RequestUri is { IsAbsoluteUri: true } uri &&
                uri.AbsolutePath == "/api/v1/agents/token")
            {
                bool armed;
                try { armed = tryArm(); }
                catch (Exception) { armed = false; } // Fault arming must not interrupt the real token request.
                if (armed)
                {
                    var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests)
                    {
                        RequestMessage = request,
                        Content = new StringContent("{}", Encoding.UTF8, "application/json"),
                    };
                    response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(120));
                    return Task.FromResult(response);
                }
            }
            return base.SendAsync(request, cancellationToken);
        }
    }
}
