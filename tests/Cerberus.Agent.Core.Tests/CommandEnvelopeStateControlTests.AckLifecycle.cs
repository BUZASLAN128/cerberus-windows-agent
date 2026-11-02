using System.Net;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class CommandEnvelopeStateControlTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task PriorAcceptedReservationSurvivesReplayReopenUntilSignedPolicyClears(bool recovery)
    {
        await using var f = new Worker();
        var backend = new AckLifecycle();
        f.H.Backend.Respond = backend.Apply;
        Assert.True(f.State.TrySave(new(f.H.AgentId, 1, false, "claimed")));
        var command = f.H.Cmd(p => p.Type = EnvelopeTypes.CollectFacts);
        await f.Process(command);
        Assert.Equal("PROCESSING", backend.Status(command.Id));
        if (recovery) File.Delete(f.StatePath);
        await f.Restart(); // Reopens BOTH the replay file and signed-state store; not a SYSTEM/process test.
        if (!recovery)
        {
            var quarantine = f.H.Cmd(p =>
            {
                p.Type = EnvelopeTypes.AgentState;
                p.PayloadJson = """{"state_seq":2,"quarantine":{"active":true}}""";
            });
            await f.Process(quarantine);
            await f.Queue.DrainOutboxOnceAsync(default);
        }
        Assert.Equal(recovery, f.State.RequiresRecovery);
        Assert.True(f.State.IsQuarantined());
        await f.Process(command);
        Assert.Equal(EnvelopeRecordStates.Reserved, f.Replay.Find(f.H.AgentId, command.Id)!.State);
        Assert.Equal("PROCESSING", backend.Status(command.Id));
        Assert.DoesNotContain(f.H.Backend.Acks, a => a.CommandId == command.Id &&
            a.Json.GetProperty("decision").GetString() == "rejected");
        await f.Process(f.StateCommand(recovery ? 2 : 3));
        await f.Queue.DrainOutboxOnceAsync(default);
        Assert.False(f.State.RequiresRecovery);
        await f.Process(command);
        f.Queue.Start();
        await Wait.UntilAsync(() => f.Replay.Find(f.H.AgentId, command.Id)!.ResultSubmitted, "held reservation resumes");
        Assert.Equal(1, f.H.Facts.Calls);
        Assert.Equal("DONE", backend.Status(command.Id));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task TerminalRefusalRemainsNegativeAfterPolicyClearsAndReplayReopens(bool recovery)
    {
        await using var f = new Worker();
        var backend = new AckLifecycle();
        f.H.Backend.Respond = backend.Apply;
        if (!recovery) Assert.True(f.State.TrySave(new(f.H.AgentId, 1, true, "claimed")));
        var command = f.H.Cmd(p => p.Type = EnvelopeTypes.CollectFacts);
        await f.Process(command);
        var first = Assert.Single(f.H.Backend.Acks);
        Assert.Equal(recovery ? EnvelopeCodes.StateRecoveryRequired : EnvelopeCodes.Quarantined,
            first.Json.GetProperty("reason").GetString());
        Assert.Equal("FAILED", backend.Status(command.Id));
        Assert.Equal(EnvelopeRecordStates.RejectedAfterReserve, f.Replay.Find(f.H.AgentId, command.Id)!.State);
        await f.Restart();
        await f.Process(f.StateCommand(recovery ? 1 : 2));
        await f.Queue.DrainOutboxOnceAsync(default);
        Assert.False(f.State.RequiresRecovery);
        Assert.False(f.State.IsQuarantined());
        await f.Process(command);
        var repeated = f.H.Backend.Acks.Last(a => a.CommandId == command.Id);
        Assert.Equal(first.Body, repeated.Body);
        Assert.Equal("FAILED", backend.Status(command.Id));
        Assert.Equal(0, f.H.Facts.Calls);
        Assert.Equal(0, f.Queue.QueuedCount);
        Assert.DoesNotContain(f.H.Backend.Results, r => r.CommandId == command.Id);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task RefusalWriteFailureDoesNotAdvertiseATerminalAck(bool recovery)
    {
        await using var f = new Worker();
        if (!recovery) Assert.True(f.State.TrySave(new(f.H.AgentId, 1, true, "claimed")));
        Assert.True(f.Replay.IsAvailable);
        if (File.Exists(f.H.StorePath)) File.Delete(f.H.StorePath);
        Directory.CreateDirectory(f.H.StorePath); // Deterministic atomic-replace failure in this disposable fixture.
        try
        {
            await f.Process(f.H.Cmd(p => p.Type = EnvelopeTypes.CollectFacts));
            Assert.Empty(f.H.Backend.Acks);
            Assert.Empty(f.Replay.Records(f.H.AgentId));
            Assert.Equal(0, f.H.Facts.Calls);
            Assert.True(f.Processor.RejectionCounts.ContainsKey(EnvelopeCodes.ReplayStoreUnavailable));
        }
        finally { Directory.Delete(f.H.StorePath); }
    }

    [Fact]
    public async Task LostNegativeAckKeepsItsDurableDecisionAcrossReplayReopen()
    {
        await using var f = new Worker();
        var command = f.H.Cmd();
        f.H.Backend.Respond = (_, _) => Task.FromResult(HttpStatusCode.ServiceUnavailable);
        await f.Process(command);
        var lost = Assert.Single(f.H.Backend.Acks);
        Assert.Equal(EnvelopeRecordStates.RejectedAfterReserve, f.Replay.Find(f.H.AgentId, command.Id)!.State);
        await f.Restart();
        var backend = new AckLifecycle();
        f.H.Backend.Respond = backend.Apply;
        await f.Process(command);
        Assert.Equal(lost.Body, f.H.Backend.Acks.Last().Body);
        Assert.Equal("FAILED", backend.Status(command.Id));
        await f.Process(f.StateCommand());
        await f.Queue.DrainOutboxOnceAsync(default);
        await f.Process(command);
        Assert.Equal(lost.Body, f.H.Backend.Acks.Last(a => a.CommandId == command.Id).Body);
        Assert.Equal(0, f.H.Ping.Calls);
        Assert.Equal("FAILED", backend.Status(command.Id));
    }

    [Fact]
    public async Task PriorAcceptedPingKeepsItsQuarantineExemptionAfterReplayReopen()
    {
        await using var f = new Worker();
        var backend = new AckLifecycle();
        f.H.Backend.Respond = backend.Apply;
        Assert.True(f.State.TrySave(new(f.H.AgentId, 1, false, "claimed")));
        var command = f.H.Cmd();
        await f.Process(command);
        await f.Restart();
        await f.Process(f.H.Cmd(p =>
        {
            p.Type = EnvelopeTypes.AgentState;
            p.PayloadJson = """{"state_seq":2,"quarantine":{"active":true}}""";
        }));
        await f.Queue.DrainOutboxOnceAsync(default);
        Assert.True(f.State.IsQuarantined());
        Assert.False(f.State.RequiresRecovery);
        await f.Process(command);
        f.Queue.Start();
        await Wait.UntilAsync(() => f.Replay.Find(f.H.AgentId, command.Id)!.ResultSubmitted, "quarantine-exempt ping completes");
        Assert.Equal(1, f.H.Ping.Calls);
        Assert.Equal("DONE", backend.Status(command.Id));
    }

    // The backend applies only the first ACK; results cannot change terminal FAILED.
    private sealed class AckLifecycle
    {
        private readonly object _gate = new();
        private readonly Dictionary<string, string> _status = new();
        private readonly HashSet<string> _acked = new();
        public string Status(string id) { lock (_gate) return _status.GetValueOrDefault(id, "PROCESSING"); }
        public Task<HttpStatusCode> Apply(BackendRequest request, CancellationToken ct)
        {
            lock (_gate)
            {
                var status = _status.GetValueOrDefault(request.CommandId, "PROCESSING");
                if (request.Leaf == "ack" && status == "PROCESSING" && _acked.Add(request.CommandId))
                    _status[request.CommandId] = request.Json.GetProperty("decision").GetString() == "rejected" ? "FAILED" : "PROCESSING";
                if (request.Leaf == "result" && status == "PROCESSING")
                    _status[request.CommandId] = request.Json.GetProperty("status").GetString()!;
            }
            return Task.FromResult(HttpStatusCode.OK);
        }
    }
}
