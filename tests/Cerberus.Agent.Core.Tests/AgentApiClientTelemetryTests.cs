using System.Net;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;
using Cerberus.Agent.Integrations.Ad;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentApiClientTelemetryTests
{
#if !CERBERUS_SERVER_PROFILE
    [Theory, InlineData(false), InlineData(true)]
    public async Task ManifestHeadersStall_DeadlineReconcilesButCallerCancellationPropagates(bool callerCancels)
    {
        var now = DateTimeOffset.UtcNow;
        var transport = new ManifestHeadersStallHandler(now);
        using var http = new HttpClient(transport)
        {
            BaseAddress = new Uri("http://backend.test"),
            Timeout = callerCancels ? Timeout.InfiniteTimeSpan : TimeSpan.FromMilliseconds(100)
        };
        var state = new InMemoryAgentLifecycleStateStore();
        var secrets = new StaticSecretStore();
        var client = new AgentApiClient(http, secrets, new StaticTokenManager(), new StaticSigner(), lifecycleState: state);
        var owned = new ManifestOwnedAccountStore();
        var policy = new ManagedAccountManifestPolicy(new("a1", "t1"), state, client.GetManagedAccountManifestAsync,
            LocalUserCommandHandlers.CreateManifestReconciler(store: owned), now: () => now);
        var responses = new HeartbeatResponseHandler(secrets, lifecycleState: state, managedAccounts: policy);
        var heartbeat = await client.HeartbeatAsync(new { }, default);
        Assert.Equal(new[] { "windows.local_user.disable", "windows.local_user.delete" }, heartbeat.PendingCommands.Select(c => c.Type));
        using var caller = new CancellationTokenSource();
        var handling = responses.HandleAsync(heartbeat, caller.Token);
        await transport.ManifestStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        if (callerCancels)
        {
            caller.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => handling);
            Assert.True(owned.Enabled);
        }
        else
        {
            Assert.Equal(HeartbeatControlAction.Continue, await handling);
            Assert.False(owned.Enabled);
            Assert.Equal(HeartbeatControlAction.Continue, await responses.HandleAsync(heartbeat, default));
        }
        Assert.Equal(1, transport.ManifestFetches);
    }
#endif

    private sealed class ManifestOwnedAccountStore : IManagedLocalAccountStore
    {
        private readonly ManagedLocalOwnership _account = new(new("assignment", "account", "member",
            "cerb_sennu_k7m2q6x4", "marker", "active"), "a1", "t1", "sid", "sid");
        public bool Enabled { get; private set; } = true;
        public IReadOnlyList<ManagedLocalOwnership> ReadAccounts() => [_account];
        public void Disable(ManagedLocalOwnership ownership)
        {
            Assert.Equal(_account, ownership);
            Enabled = false;
        }
    }

    private sealed class ManifestHeadersStallHandler(DateTimeOffset now) : HttpMessageHandler
    {
        public TaskCompletionSource ManifestStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int ManifestFetches { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/managed-accounts/manifest", StringComparison.Ordinal))
            {
                ManifestFetches++;
                ManifestStarted.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                throw new InvalidOperationException("The simulated manifest headers must never arrive.");
            }
            Assert.EndsWith("/heartbeat", request.RequestUri.AbsolutePath);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(new
                {
                    pending_commands = new[]
                    {
                        new { id = "disable", type = "windows.local_user.disable", idempotency_key = "disable", payload = new { } },
                        new { id = "delete", type = "windows.local_user.delete", idempotency_key = "delete", payload = new { } }
                    },
                    next_poll_seconds = 60, next_snapshot_seconds = 60,
                    manifest_version = "4f53cda18c2baa0c",
                    managed_account_manifest_hash = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
                    manifest_fresh_until = now.AddSeconds(300).ToString("O"),
                    require_manifest_before_unlock = true
                }), Encoding.UTF8, "application/json")
            };
        }
    }

    [Fact]
    public async Task AdCommandAuthority_PostsSignedLeaseAndReadsCanonicalCommand()
    {
        var command = new AgentCommand("cmd-ad", "windows.ad_user.disable", "idem-ad", new { username = "canonical" }, LeaseId: "lease-ad");
        var handler = new CaptureHandler(JsonSerializer.Serialize(new AdCommandAuthority("t1", "a1", DateTimeOffset.UtcNow.AddSeconds(25), command)));
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var authority = await client.GetAdCommandAuthorityAsync(command, default);
        Assert.Equal("lease-ad", authority.Command.LeaseId);
        Assert.Equal("canonical", ((JsonElement)authority.Command.Payload!).GetProperty("username").GetString());
        Assert.Equal(HttpMethod.Post, handler.CapturedRequest!.Method);
        Assert.Equal("/api/v1/agents/a1/commands/cmd-ad/ad-authority", handler.CapturedRequest.RequestUri!.AbsolutePath);
        Assert.Equal("signature", Assert.Single(handler.CapturedRequest.Headers.GetValues("X-Signature")));
        using var body = JsonDocument.Parse(handler.CapturedBody!);
        Assert.Equal("lease-ad", body.RootElement.GetProperty("lease_id").GetString());
        Assert.Single(body.RootElement.EnumerateObject());
    }

    [Fact]
    public async Task AdCommandAckAndResult_PostExactDeliveredLeaseWithSignatures()
    {
        var command = new AgentCommand(
            "cmd-ad",
            "windows.ad_user.disable",
            "idem-ad",
            new { username = "canonical" },
            LeaseId: "lease-ad");
        var handler = new RequestSequenceHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());

        await client.SubmitCommandAckAsync(command, default);
        await client.SubmitCommandResultAsync(
            command,
            new CommandResult("FAILED", 1, null, "not completed", new { code = "ad_authority_required" }),
            default);

        Assert.Equal(2, handler.Requests.Count);
        Assert.Equal(
            "/api/v1/agents/a1/commands/cmd-ad/ack",
            handler.Requests[0].RequestUri!.AbsolutePath);
        Assert.Equal(
            "/api/v1/agents/a1/commands/cmd-ad/result",
            handler.Requests[1].RequestUri!.AbsolutePath);
        Assert.All(handler.Requests, request =>
            Assert.Equal("signature", Assert.Single(request.Headers.GetValues("X-Signature"))));

        using var ack = JsonDocument.Parse(handler.Bodies[0]);
        Assert.Equal("lease-ad", ack.RootElement.GetProperty("lease_id").GetString());
        Assert.Single(ack.RootElement.EnumerateObject());

        using var result = JsonDocument.Parse(handler.Bodies[1]);
        Assert.Equal("lease-ad", result.RootElement.GetProperty("lease_id").GetString());
        Assert.Equal("FAILED", result.RootElement.GetProperty("status").GetString());
        Assert.Equal("ad_authority_required", result.RootElement.GetProperty("post_verify").GetProperty("code").GetString());
    }

    [Fact]
    public async Task NonAdTypedResult_PreservesLegacyBodyAndSkipsAck()
    {
        var command = new AgentCommand("cmd", "test.command", "idem", new { });
        var handler = new RequestSequenceHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());

        await client.SubmitCommandAckAsync(command, default);
        await client.SubmitCommandResultAsync(command, new CommandResult("DONE", 0, null, null, null), default);

        Assert.Single(handler.Requests);
        Assert.EndsWith("/commands/cmd/result", handler.Requests[0].RequestUri!.AbsolutePath, StringComparison.Ordinal);
        using var result = JsonDocument.Parse(handler.Bodies[0]);
        Assert.Equal("DONE", result.RootElement.GetProperty("status").GetString());
        Assert.False(result.RootElement.TryGetProperty("lease_id", out _));
    }

    [Fact]
    public async Task AdCommandAuthority_RejectsCanonicalCommandWithDifferentLease()
    {
        var delivered = new AgentCommand("cmd-ad", "windows.ad_user.disable", "idem-ad", new { }, LeaseId: "lease-delivered");
        var canonical = delivered with { LeaseId = "lease-other" };
        var handler = new CaptureHandler(JsonSerializer.Serialize(
            new AdCommandAuthority("t1", "a1", DateTimeOffset.UtcNow.AddSeconds(25), canonical)));
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetAdCommandAuthorityAsync(delivered, default));
    }

    [Fact]
    public async Task AdCommandLeaseValues_Accept256CharactersAndReject257BeforeSending()
    {
        var acceptedValue = new string('a', 256);
        var accepted = new AgentCommand(
            acceptedValue,
            "windows.ad_user.disable",
            acceptedValue,
            new { username = "bounded" },
            LeaseId: acceptedValue);
        var acceptedHandler = new CaptureHandler(JsonSerializer.Serialize(
            new AdCommandAuthority("t1", "a1", DateTimeOffset.UtcNow.AddSeconds(25), accepted)));
        using var acceptedHttp = new HttpClient(acceptedHandler) { BaseAddress = new Uri("http://backend.test") };
        var acceptedClient = new AgentApiClient(
            acceptedHttp,
            new StaticSecretStore(),
            new StaticTokenManager(),
            new StaticSigner());

        await acceptedClient.GetAdCommandAuthorityAsync(accepted, default);
        Assert.NotNull(acceptedHandler.CapturedRequest);

        var rejectedValue = new string('b', 257);
        var rejected = accepted with { Id = rejectedValue, IdempotencyKey = rejectedValue, LeaseId = rejectedValue };
        var rejectedHandler = new CaptureHandler(JsonSerializer.Serialize(
            new AdCommandAuthority("t1", "a1", DateTimeOffset.UtcNow.AddSeconds(25), rejected)));
        using var rejectedHttp = new HttpClient(rejectedHandler) { BaseAddress = new Uri("http://backend.test") };
        var rejectedClient = new AgentApiClient(
            rejectedHttp,
            new StaticSecretStore(),
            new StaticTokenManager(),
            new StaticSigner());

        await Assert.ThrowsAsync<InvalidOperationException>(() => rejectedClient.GetAdCommandAuthorityAsync(rejected, default));
        Assert.Null(rejectedHandler.CapturedRequest);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.Conflict)]
    public async Task ResourceOperationFailuresDoNotQuiesceLifecycle(HttpStatusCode status)
    {
        var state = new InMemoryAgentLifecycleStateStore();
        var quiesceCalls = 0;
        using var http = new HttpClient(new FailureHandler(
            status,
            new StringContent("{}", Encoding.UTF8, "application/json")))
        {
            BaseAddress = new Uri("http://backend.test")
        };
        var client = new AgentApiClient(
            http,
            new StaticSecretStore(),
            new StaticTokenManager(),
            new StaticSigner(),
            lifecycleState: state,
            quiesce: _ =>
            {
                quiesceCalls++;
                return Task.CompletedTask;
            });

        var command = new AgentCommand(
            "cmd-ad",
            "windows.ad_user.disable",
            "idem-ad",
            new { username = "resource" },
            LeaseId: "lease-ad");
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAdCommandAuthorityAsync(command, default));
        await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitCommandResultAsync(
            "cmd-result", new { status = "DONE" }, default));

        Assert.Equal(AgentLifecycleState.Active, (await state.LoadAsync(default)).State);
        Assert.Equal(0, quiesceCalls);
    }
}
