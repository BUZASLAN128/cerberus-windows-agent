using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
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
        using var client = new HttpClient(new AgentUpdateLabHttpFaults.TokenRouteHandler(inner,
            () => ++armCalls == 1 ? RefreshAttempt() : null));
        using var get = await client.GetAsync(TokenRoute);
        using var wrongPath = await client.PostAsync(TokenRoute + "/", null);
        Assert.Equal(HttpStatusCode.OK, get.StatusCode);
        Assert.Equal(HttpStatusCode.OK, wrongPath.StatusCode);
        Assert.Equal(0, armCalls);

        using var fault = await client.PostAsync(TokenRoute, null);
        Assert.Equal(HttpStatusCode.TooManyRequests, fault.StatusCode);
        Assert.Equal(TimeSpan.FromSeconds(30), fault.Headers.RetryAfter!.Delta);
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
            () => !AgentUpdateLabHttpFaults.IsInstallerBusy(name) && (armed = true) ? RefreshAttempt() : null));
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

    [Fact]
    public async Task RefreshEvidenceSeparatesSyntheticResponseFromForwardedBackendResponse()
    {
        var attempt = RefreshAttempt();
        var clock = new FakeTime(attempt.Scope.Policy.NotBeforeUtc.AddHours(1).ToUnixTimeSeconds());
        var recorded = new List<AgentUpdateLabHttpFaults.RefreshEvidence>();
        var inner = new RecordingHandler(() =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
            response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(45));
            return response;
        });
        using var client = Observe(inner, attempt, clock, recorded);

        using var synthetic = await client.PostAsync(TokenRoute, null);
        var faultAt = clock.GetUtcNow();
        Assert.Empty(recorded);
        Assert.Equal(0, inner.Calls);
        clock.Advance(TimeSpan.FromSeconds(130));
        using var payload = new StringContent("fixture-data-outside-evidence-scope");
        using var backend = await client.PostAsync(TokenRoute, payload);
        Assert.Equal(HttpStatusCode.TooManyRequests, backend.StatusCode);
        var evidence = Assert.Single(recorded);
        Assert.Equal("READ", evidence.Status);
        Assert.Equal(faultAt, evidence.SinceUtc);
        Assert.Equal(clock.GetUtcNow(), evidence.ThroughUtc);
        Assert.Equal(new AgentUpdateLabHttpFaults.RefreshSample(faultAt, 429, 30), evidence.SyntheticResponse);
        Assert.Equal(new AgentUpdateLabHttpFaults.RefreshSample(clock.GetUtcNow(), 429, 45), Assert.Single(evidence.BackendSends));

        var context = attempt.Scope.Context;
        var receipt = new AgentUpdateLabFaults.Receipt(attempt.Scope.Policy.CampaignId, context.AgentId, context.TenantId,
            context.KeyFingerprint, attempt.Version, AgentUpdateLabFaults.TokenRoute429, faultAt, 100, null, attempt.AttemptId);
        Assert.True(AgentUpdateLabHttpFaults.MatchesFaultReceipt(attempt, evidence, receipt, 100));
        Assert.False(AgentUpdateLabHttpFaults.MatchesFaultReceipt(attempt, evidence, receipt with { Utc = faultAt.AddSeconds(-1) }, 100));
        Assert.False(AgentUpdateLabHttpFaults.MatchesFaultReceipt(attempt, evidence, receipt with { AttemptId = "reused" }, 100));
        Assert.False(AgentUpdateLabHttpFaults.MatchesFaultReceipt(attempt, evidence, receipt, 101));

        using var json = JsonSerializer.SerializeToDocument(evidence with { FaultUtc = faultAt },
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.Equal(new[] { "schema", "campaignId", "version", "attemptId", "status", "sinceUtc", "throughUtc", "faultUtc",
            "syntheticResponse", "backendSends" }, json.RootElement.EnumerateObject().Select(property => property.Name));
        foreach (var sample in new[] { json.RootElement.GetProperty("syntheticResponse"), json.RootElement.GetProperty("backendSends")[0] })
            Assert.Equal(new[] { "utc", "status", "retryAfterSeconds" }, sample.EnumerateObject().Select(property => property.Name));

        using var later = await client.PostAsync(TokenRoute, null);
        Assert.Single(recorded);
    }

    [Fact]
    public async Task EarlyForwardedRefreshIsUnqualifiedAndRemainsForwarded()
    {
        var attempt = RefreshAttempt();
        var clock = new FakeTime(attempt.Scope.Policy.NotBeforeUtc.ToUnixTimeSeconds());
        var recorded = new List<AgentUpdateLabHttpFaults.RefreshEvidence>();
        var inner = new RecordingHandler();
        using var client = Observe(inner, attempt, clock, recorded);
        using var synthetic = await client.PostAsync(TokenRoute, null);
        clock.Advance(TimeSpan.FromSeconds(29));
        using var actual = await client.PostAsync(TokenRoute, null);

        Assert.Equal(HttpStatusCode.OK, actual.StatusCode);
        Assert.Equal(1, inner.Calls);
        var evidence = Assert.Single(recorded);
        Assert.Equal("Unqualified", evidence.Status);
        Assert.Null(Assert.Single(evidence.BackendSends).RetryAfterSeconds);
    }

    [Fact]
    public async Task ExpiredWindowDoesNotPublishOrChangeTheBackendResponse()
    {
        var attempt = RefreshAttempt();
        var clock = new FakeTime(attempt.Scope.Policy.NotBeforeUtc.ToUnixTimeSeconds());
        var recorded = new List<AgentUpdateLabHttpFaults.RefreshEvidence>();
        var inner = new RecordingHandler();
        using var client = Observe(inner, attempt, clock, recorded);
        using var synthetic = await client.PostAsync(TokenRoute, null);
        clock.Advance(AgentUpdateLabHttpFaults.MaxObservation + TimeSpan.FromSeconds(1));
        using var actual = await client.PostAsync(TokenRoute, null);

        Assert.Equal(HttpStatusCode.OK, actual.StatusCode);
        Assert.Equal(1, inner.Calls);
        Assert.Empty(recorded);
    }

    [Fact]
    public async Task AttemptCapDiscardsEvidenceAndDoesNotBlockForwarding()
    {
        var attempt = RefreshAttempt();
        var clock = new FakeTime(attempt.Scope.Policy.NotBeforeUtc.ToUnixTimeSeconds());
        var recorded = new List<AgentUpdateLabHttpFaults.RefreshEvidence>();
        var inner = new HoldingHandler();
        using var client = Observe(inner, attempt, clock, recorded);
        using var synthetic = await client.PostAsync(TokenRoute, null);
        clock.Advance(TimeSpan.FromSeconds(120));
        var pending = Enumerable.Range(0, AgentUpdateLabHttpFaults.MaxBackendSends + 1)
            .Select(_ => client.PostAsync(TokenRoute, null)).ToArray();
        inner.Release.SetResult();

        foreach (var response in await Task.WhenAll(pending))
        {
            using (response) Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }
        Assert.Equal(pending.Length, inner.Calls);
        Assert.Empty(recorded);
    }

    private static AgentUpdateLabHttpFaults.RefreshAttempt RefreshAttempt()
    {
        var policy = AgentUpdateLabPolicyTests.Valid();
        var target = policy.Targets[0];
        return new(new(policy, target, new(target.AgentId, target.TenantId, 7, "nonce", AgentProducts.Cerberus,
            target.KeyFingerprint)), policy.Versions[3], "fixture-attempt");
    }

    private static HttpClient Observe(HttpMessageHandler inner, AgentUpdateLabHttpFaults.RefreshAttempt attempt, TimeProvider time,
        List<AgentUpdateLabHttpFaults.RefreshEvidence> recorded)
    {
        var calls = 0;
        return new(new AgentUpdateLabHttpFaults.TokenRouteHandler(inner, () => ++calls == 1 ? attempt : null,
            (_, evidence) => recorded.Add(evidence), time));
    }

    private sealed class RecordingHandler(Func<HttpResponseMessage>? response = null) : HttpMessageHandler
    {
        internal int Calls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(response?.Invoke() ?? new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    private sealed class HoldingHandler : HttpMessageHandler
    {
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal int Calls { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            await Release.Task.WaitAsync(cancellationToken);
            return new(HttpStatusCode.OK);
        }
    }
}
