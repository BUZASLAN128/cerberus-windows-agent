using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentSignedStateTests
{
    [Fact]
    public async Task RecoveryQueueRejectsOldStateAndBusinessUntilNewerSignedStateIsApplied()
    {
        await using var h = EnvelopeHarness.Create();
        await h.Queue.StopAsync();
        Assert.True(new AgentSignedStateStore(StatePath).TrySave(new(h.AgentId, 7, true, "claimed")));
        File.Delete(StatePath);
        var state = new AgentSignedStateStore(StatePath, enrolledAgentId: h.AgentId);
        var current = state.Track(_ => Task.FromResult(h.AgentId));
        var handler = new AgentStateCommandHandler(state, current, new AgentLifecycleController(new InMemoryAgentLifecycleStateStore()),
            () => { }, h.Log, () => { }, new AgentRevokeFinalResults());
        await using var queue = new EnvelopeExecutionQueue(h.Api, h.Store, new ICommandHandler[] { h.Ping, handler },
            current, state.IsQuarantined, h.Time, signedState: state);
        queue.Start();
        var processor = new EnvelopeCommandProcessor(h.Api, new[] { h.Signer.Anchor }, queue,
            new HashSet<string> { "ping", "agent_state" });
        var old = h.Cmd(p => { p.Type = "agent_state"; p.PayloadJson = """{"state_seq":7,"quarantine":{"active":false}}"""; });
        await processor.ProcessAsync(new[] { old, h.Cmd() }, default);
        Assert.True(state.RequiresRecovery);
        Assert.Equal(0, h.Ping.Calls);
        Assert.Empty(h.Backend.Acks);
        var fresh = h.Cmd(p => { p.Type = "agent_state"; p.PayloadJson = """{"state_seq":8,"quarantine":{"active":false}}"""; });
        await processor.ProcessAsync(new[] { fresh }, default);
        Assert.False(state.RequiresRecovery);
        await processor.ProcessAsync(new[] { h.Cmd() }, default);
        await Wait.UntilAsync(() => h.Ping.Calls == 1, "business reopened after fresh state");
        Assert.Equal(8, new AgentSignedStateStore(StatePath).Load(h.AgentId).StateSeq);
    }
}
