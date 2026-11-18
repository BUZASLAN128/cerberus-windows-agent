using System.Net;
using System.Net.Http;
using Cerberus.Agent.App.Updates;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateLabHttpFaultTests
{
    private const string TokenRoute = "https://fixture.invalid/api/v1/agents/token";

    [Fact]
    public void NonLabWrapReturnsTheSameHandler()
    {
        using var inner = new RecordingHandler();
        Assert.Same(inner, AgentUpdateLabHttpFaults.Wrap(inner));
    }

    [Fact]
    public async Task OnlyTokenPostArmsOnceAndReturnsRetryAfterWithoutNetwork()
    {
        var inner = new RecordingHandler();
        var armCalls = 0;
        using var client = new HttpClient(new AgentUpdateLabHttpFaults.TokenRouteHandler(inner, () => ++armCalls == 1));
        using var get = await client.GetAsync(TokenRoute);
        using var wrongPath = await client.PostAsync(TokenRoute + "/", null);
        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
        Assert.Equal(HttpStatusCode.OK, wrongPath.StatusCode);
        Assert.Equal(0, armCalls);

        using var fault = await client.PostAsync(TokenRoute, null);
        Assert.Equal(HttpStatusCode.TooManyRequests, fault.StatusCode);
        Assert.Equal(TimeSpan.FromSeconds(120), fault.Headers.RetryAfter!.Delta);
        Assert.Equal("application/json", fault.Content.Headers.ContentType!.MediaType);
        Assert.Equal("{}", await fault.Content.ReadAsStringAsync());
        Assert.Equal(2, inner.Calls);

        using var retry = await client.PostAsync(TokenRoute, null);
        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
        Assert.Equal(3, inner.Calls);
        Assert.Equal(2, armCalls);
    }

    [Fact]
    public async Task ArmingExceptionPassesTheTokenPostThrough()
    {
        var inner = new RecordingHandler();
        using var client = new HttpClient(new AgentUpdateLabHttpFaults.TokenRouteHandler(inner,
            () => throw new InvalidOperationException("fixture could not arm")));
        using var response = await client.PostAsync(TokenRoute, null);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, inner.Calls);
    }

    [Fact]
    public void TokenFaultRequiresTheCurrentCampaignAttemptAfterCommit()
    {
        var policy = AgentUpdateLabPolicyTests.Valid();
        var release = new AgentUpdateExpectedPlan(policy.Versions[3], "dev:3", new string('a', 64));
        var attempt = new string('b', 32);
        var request = new AgentUpdateInstallRequest(policy.NotBeforeUtc, 7, policy.ExpiresAtUtc,
            ExpectedPlan: release, LocalPolicyId: policy.CampaignId, BoundAttemptId: attempt, VerifiedRelease: release,
            LocalSourceVersion: policy.Versions[2]);
        var journal = new AgentUpdateJournal { Phase = "committed_watch", AttemptId = attempt,
            LifecycleGeneration = 7, InstallRequest = request };
        bool Eligible(AgentUpdateJournal state, string? version = null)
            => AgentUpdateLabHttpFaults.IsPostCommit(state, policy.CampaignId, 7, version ?? release.Version);

        Assert.True(Eligible(journal));
        Assert.True(Eligible(journal with { Phase = AgentUpdateStates.Installed }));
        Assert.False(Eligible(journal with { Phase = AgentUpdateStates.HealthPending }));
        Assert.False(Eligible(journal with { Phase = AgentUpdateStates.Failed }));
        Assert.False(Eligible(journal with { AttemptId = new string('c', 32) }));
        Assert.False(Eligible(journal with { LifecycleGeneration = 8 }));
        Assert.False(Eligible(journal with { InstallRequest = request with { LocalPolicyId = Guid.NewGuid().ToString("D") } }));
        Assert.False(Eligible(journal, policy.Versions[9]));
    }

    [Fact]
    public async Task HeldFixtureMutexPassesTokenPostThroughWithoutArming()
    {
        var name = @"Local\CerberusLabFixture-" + Guid.NewGuid().ToString("N");
        using var release = new ManualResetEventSlim();
        var ready = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var holder = Task.Factory.StartNew(() =>
        {
            using var held = AgentUpdateLabFaults.TakeInstallerMutex(name);
            try
            {
                ready.SetResult();
                if (!release.Wait(TimeSpan.FromSeconds(15))) throw new TimeoutException("Fixture mutex release timed out.");
            }
            finally { held.ReleaseMutex(); }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

        var inner = new RecordingHandler();
        var armed = false;
        using var client = new HttpClient(new AgentUpdateLabHttpFaults.TokenRouteHandler(inner,
            () => !AgentUpdateLabHttpFaults.IsInstallerBusy(name) && (armed = true)));
        try
        {
            await ready.Task.WaitAsync(TimeSpan.FromSeconds(10));
            using var response = await client.PostAsync(TokenRoute, null);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal(1, inner.Calls);
            Assert.False(armed);
        }
        finally
        {
            release.Set();
            await holder;
        }
        Assert.False(AgentUpdateLabHttpFaults.IsInstallerBusy(name));
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        internal int Calls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }
}
