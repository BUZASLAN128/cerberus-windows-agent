using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class HeartbeatLoopTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task StateRecoveryUsesHashedHeartbeatAndHoldsOnlySupportedProfiles(bool supported)
    {
        await using var h = EnvelopeHarness.Create();
        var path = h.StorePath + ".signed-state";
        Assert.True(new AgentSignedStateStore(path).TrySave(new("agent-1", 7, true, "claimed")));
        File.Delete(path);
        var state = new AgentSignedStateStore(path, enrolledAgentId: "agent-1");
        var wire = new StateRecoveryHandler(supported);
        using var http = new HttpClient(wire) { BaseAddress = new Uri("https://backend.test") };
        var api = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new RecoveryHashSigner());
        var dispatcher = new CommandDispatcher(Array.Empty<ICommandHandler>(),
            new IdempotencyCache(h.StorePath + ".idem", 10, TimeSpan.FromMinutes(5)));
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var processor = new StateRecoveryProcessor(stop);
        var updates = new RecoveryUpdates();
        var wakeCalls = 0;
        Task Listen(JsonElement _, AgentWakeupSignal __, CancellationToken ct)
        { Interlocked.Increment(ref wakeCalls); return Task.Delay(Timeout.InfiniteTimeSpan, ct); }
        var wakeSignal = new AgentWakeupSignal();
        await using var wake = new AgentWakeupClient(api, wakeSignal, Listen);
        var loop = new HeartbeatLoop(api, dispatcher, TimeSpan.FromSeconds(1), signedState: state,
            responseHandler: new HeartbeatResponseHandler(new StaticSecretStore(), updates: updates),
            supportsEvents: false, commandProcessor: processor, wakeupSignal: wakeSignal, wakeupClient: wake,
            adStatusProvider: _ => throw new InvalidOperationException("AD collection during recovery"),
            updateStatusProvider: _ => throw new InvalidOperationException("Update collection during recovery"));
        await loop.RunAsync(stop.Token);
        Assert.Equal(new[] { "/api/v1/agents/agent-1/heartbeat" }, wire.Paths);
        using var body = JsonDocument.Parse(wire.Body);
        Assert.True(body.RootElement.GetProperty("signed_state_reset").GetBoolean());
        Assert.Equal(7, body.RootElement.GetProperty("signed_state_floor").GetInt64());
        Assert.Equal(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(wire.Body))).ToLowerInvariant(), wire.BodyHash);
        Assert.Equal(supported ? new[] { "agent_state" } : new[] { "agent_state", "ping" }, processor.Types);
#if CERBERUS_SERVER_PROFILE
        Assert.Equal(0, updates.Calls); // The server profile never accepts unsigned update hints.
#else
        Assert.Equal(supported ? 0 : 1, updates.Calls);
#endif
        Assert.Equal(supported ? 0 : 1, Volatile.Read(ref wakeCalls));
        Assert.Equal(supported, state.HoldsNormalWork());
        Assert.True(state.IsQuarantined());
    }

    private sealed class StateRecoveryHandler(bool supported) : HttpMessageHandler
    {
        public string Body = "", BodyHash = "";
        public List<string> Paths = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Paths.Add(request.RequestUri!.AbsolutePath);
            Body = await request.Content!.ReadAsStringAsync(ct);
            BodyHash = request.Headers.GetValues("X-Body-Hash").Single();
            var response = JsonSerializer.Serialize(new { signed_state_recovery = supported, next_poll_seconds = 30,
                next_snapshot_seconds = 300, server_time = 1, update = new { available = true },
                wakeup = new { version = 1, path = "/api/v1/agents/agent-1/wakeup" },
                pending_commands = new[] { new { id = "state", type = "agent_state", idempotency_key = "state", payload = new { } },
                                          new { id = "business", type = "ping", idempotency_key = "business", payload = new { } } } });
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, "application/json") };
        }
    }
    private sealed class StateRecoveryProcessor(CancellationTokenSource stop) : IHeartbeatCommandProcessor
    {
        public string[] Types = [];
        public Task ProcessAsync(IReadOnlyList<AgentCommand> commands, CancellationToken ct)
        { Types = commands.Select(c => c.Type).ToArray(); stop.Cancel(); return Task.CompletedTask; }
    }
    private sealed class RecoveryUpdates : IAgentUpdateCoordinator
    {
        public int Calls;
        public Task HandleUpdateAsync(HeartbeatResponse response, CancellationToken ct) { Calls++; return Task.CompletedTask; }
    }
    private sealed class RecoveryHashSigner : IRequestSigner
    {
        public string ComputeBodyHash(byte[] bodyBytes) => Convert.ToHexString(SHA256.HashData(bodyBytes)).ToLowerInvariant();
        public string CanonicalString(string method, string path, string nonce, long timestamp, string bodyHash) => bodyHash;
        public string Sign(string canonical) => "fixture-signature";
    }
}
