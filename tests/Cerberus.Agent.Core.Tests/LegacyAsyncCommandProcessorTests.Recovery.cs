using System.Security.Cryptography;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class LegacyAsyncCommandProcessorTests
{
    [Theory]
    [InlineData("unsupported", false)]
    [InlineData("fresh-state", false)]
    [InlineData("unsupported", true)]
    public async Task RecoveryHoldsStartupProducerAndDrainThenResumesWithoutNewBusiness(string recovery, bool readFailure)
    {
        await using var h = EnvelopeHarness.Create();
        await h.Queue.StopAsync();
        var handler = new FakeCommandHandler("agent.health.snapshot");
        var dispatcher = Dispatcher(h, handler);
        var store = NewStore(h);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var bytes = JsonSerializer.SerializeToUtf8Bytes(FakeCommandHandler.Done(), new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var pending = new CommandReplayRecord(h.AgentId, Guid.NewGuid().ToString("D"), new string('a', 64),
            Guid.NewGuid().ToString("D"), handler.Type, now, now + 300, EnvelopeRecordStates.Reserved, null, null, false);
        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(pending));
        var done = pending with { State = EnvelopeRecordStates.Done, ResultB64 = Convert.ToBase64String(bytes),
            ResultSha256 = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant() };
        Assert.True(store.TryUpdate(done));
        var state = new AgentSignedStateStore(Path.Combine(Path.GetDirectoryName(h.StorePath)!, "state.json"), enrolledAgentId: h.AgentId);
        Assert.True(state.RecoveryControlOnly);
        var reached = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        bool Held()
        {
            reached.TrySetResult();
            if (Volatile.Read(ref readFailure)) throw new IOException("Owned recovery read failure.");
            return state.RecoveryControlOnly;
        }
        await using var legacy = new LegacyAsyncCommandProcessor(h.Api, dispatcher,
            new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromSeconds(5), 1),
            store, _ => Task.FromResult(h.AgentId), recoveryControlOnly: Held);
        await reached.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.False(legacy.CanAdvertise);
        await legacy.ProcessAsync(new[] { Command(), Command() with { LeaseId = null } }, default);
        await legacy.DrainOutboxOnceAsync(default);
        Assert.Equal(done, store.Find(h.AgentId, done.Id));
        Assert.Empty(h.Backend.Results);
        Assert.Equal(0, handler.Calls);

        if (recovery == "unsupported") state.SetRecoverySourceSupported(false);
        else
        {
            var current = state.Track(_ => Task.FromResult(h.AgentId));
            var stateHandler = new AgentStateCommandHandler(state, current,
                new AgentLifecycleController(new InMemoryAgentLifecycleStateStore()), () => { }, h.Log, () => { }, new AgentRevokeFinalResults());
            await using var queue = new EnvelopeExecutionQueue(h.Api, h.Store, new ICommandHandler[] { stateHandler },
                current, state.IsQuarantined, h.Time, signedState: state,
                controlContext: h.ControlContext, currentControlContext: _ => Task.FromResult(h.ControlContext));
            queue.Start();
            var processor = new EnvelopeCommandProcessor(h.Api, new[] { h.Signer.Anchor }, queue, new HashSet<string> { "agent_state" });
            await processor.ProcessAsync(new[] { h.Cmd(p => { p.Type = "agent_state";
                p.PayloadJson = """{"state_seq":1,"quarantine":{"active":false}}"""; }) }, default);
            await queue.DrainOutboxOnceAsync(default);
            Assert.False(state.RequiresRecovery);
        }
        Volatile.Write(ref readFailure, false);
        await legacy.ProcessAsync(Array.Empty<AgentCommand>(), default); // The normal heartbeat wake, no new business.
        await Wait.UntilAsync(() => store.Find(h.AgentId, done.Id)?.ResultSubmitted == true, "retained result resumed after recovery");
        Assert.Single(h.Backend.Results, result => result.Json.TryGetProperty("lease_id", out var lease) && lease.GetString() == done.Nonce);
        Assert.Equal(0, handler.Calls);
        Assert.True(legacy.CanAdvertise);
    }
}
