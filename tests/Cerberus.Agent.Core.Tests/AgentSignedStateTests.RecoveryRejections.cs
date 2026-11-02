using System.Net;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentSignedStateTests
{
    [Fact]
    public async Task RecoveryRejectsVerifiedBusinessWithWarnCounterAndRetriesFailedAck()
    {
        await using var h = EnvelopeHarness.Create(o => o.StartQueue = false);
        var state = new AgentSignedStateStore(StatePath, enrolledAgentId: h.AgentId);
        await using var queue = new EnvelopeExecutionQueue(h.Api, h.Store, new[] { h.Ping },
            state.Track(_ => Task.FromResult(h.AgentId)), state.IsQuarantined, h.Time, h.Log, state);
        var processor = new EnvelopeCommandProcessor(h.Api, new[] { h.Signer.Anchor }, queue, log: h.Log);
        var command = h.Cmd();
        h.Backend.Respond = (_, _) => Task.FromResult(HttpStatusCode.ServiceUnavailable);
        await processor.ProcessAsync(new[] { command }, default);
        var rejected = Assert.Single(h.Backend.Acks);
        Assert.Equal("rejected", rejected.Json.GetProperty("decision").GetString());
        Assert.Equal(EnvelopeCodes.StateRecoveryRequired, rejected.Json.GetProperty("reason").GetString());
        Assert.Equal(1, processor.RejectionCounts[EnvelopeCodes.StateRecoveryRequired]);
        Assert.Contains(h.Log.Lines, l => l.StartsWith("WARN ") && l.Contains("code=state_recovery_required"));
        Assert.Null(h.Record(command));
        Assert.Equal(0, queue.QueuedCount);
        Assert.Equal(0, h.Ping.Calls);
        h.Backend.Respond = (_, _) => Task.FromResult(HttpStatusCode.OK);
        h.Time.Advance(TimeSpan.FromSeconds(10));
        await processor.ProcessAsync(new[] { command }, default);
        Assert.Equal(2, h.Backend.Acks.Count);
        Assert.Equal(rejected.Body, h.Backend.Acks[1].Body);
        Assert.Equal(2, processor.RejectionCounts[EnvelopeCodes.StateRecoveryRequired]);
        Assert.True(state.RequiresRecovery);
    }

    [Fact]
    public async Task RecoveryDoesNotAckAnUnverifiedEnvelopeOrRejectAnAlreadyCompletedCommand()
    {
        await using var h = EnvelopeHarness.Create();
        var completed = h.Cmd();
        await h.Process(completed);
        await Wait.UntilAsync(() => h.Record(completed)?.ResultSubmitted == true, "initial command completed");
        await h.Queue.StopAsync();
        var state = new AgentSignedStateStore(StatePath, enrolledAgentId: h.AgentId);
        await using var queue = new EnvelopeExecutionQueue(h.Api, h.Store, new[] { h.Ping },
            state.Track(_ => Task.FromResult(h.AgentId)), state.IsQuarantined, h.Time, h.Log, state);
        var processor = new EnvelopeCommandProcessor(h.Api, new[] { h.Signer.Anchor }, queue, log: h.Log);
        var priorAcks = h.Backend.Acks.Count;
        await processor.ProcessAsync(new[] { h.Cmd(p => p.WireKeyId = "ffffffffffffffff") }, default);
        Assert.Equal(priorAcks, h.Backend.Acks.Count);
        await processor.ProcessAsync(new[] { completed }, default);
        Assert.Equal("accepted", h.Backend.Acks.Last().Json.GetProperty("decision").GetString());
        Assert.False(processor.RejectionCounts.ContainsKey(EnvelopeCodes.StateRecoveryRequired));
        Assert.Equal(1, h.Ping.Calls);
        Assert.True(state.RequiresRecovery);
    }
}
