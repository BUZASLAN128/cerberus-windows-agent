using System.Net;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class HeartbeatLoopTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task RecoveryHeartbeatReachesSignedRejectAndReportsItsCounter(bool supported)
    {
        await using var h = EnvelopeHarness.Create(o => { o.AgentId = "agent-1"; o.StartQueue = false; });
        var state = new AgentSignedStateStore(h.StorePath + ".signed-state", enrolledAgentId: h.AgentId);
        await using var queue = new EnvelopeExecutionQueue(h.Api, h.Store, new[] { h.Ping },
            state.Track(_ => Task.FromResult(h.AgentId)), state.IsQuarantined, h.Time, h.Log, state);
        var processor = new EnvelopeCommandProcessor(h.Api, new[] { h.Signer.Anchor }, queue, log: h.Log);
        await processor.ProcessAsync(new[] { h.Cmd() }, default);
        var wire = new StateRecoveryHandler(supported, new[] { h.Cmd() });
        using var http = new HttpClient(wire) { BaseAddress = new Uri("https://backend.test") };
        var api = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new RecoveryHashSigner());
        var dispatcher = new CommandDispatcher(Array.Empty<ICommandHandler>(),
            new IdempotencyCache(h.StorePath + ".idem", 10, TimeSpan.FromMinutes(5)));
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        h.Backend.Respond = (_, _) => { stop.Cancel(); return Task.FromResult(HttpStatusCode.OK); };
        var loop = new HeartbeatLoop(api, dispatcher, TimeSpan.FromSeconds(1), signedState: state,
            commandProcessor: processor, supportsEvents: false);
        await loop.RunAsync(stop.Token);
        using var body = JsonDocument.Parse(wire.Body);
        Assert.True(body.RootElement.GetProperty("signed_state_reset").GetBoolean());
        Assert.Equal("degraded", body.RootElement.GetProperty("status").GetString());
        Assert.Equal(1, body.RootElement.GetProperty("signed_state_recovery_rejections").GetInt64());
        Assert.Equal(2, processor.RejectionCounts[EnvelopeCodes.StateRecoveryRequired]);
        Assert.Equal(2, h.Backend.Acks.Count);
        Assert.All(h.Backend.Acks, ack => Assert.Equal(EnvelopeCodes.StateRecoveryRequired,
            ack.Json.GetProperty("reason").GetString()));
        Assert.Equal(0, h.Ping.Calls);
        Assert.Equal(0, queue.QueuedCount);
        Assert.True(state.RequiresRecovery);
    }
}
