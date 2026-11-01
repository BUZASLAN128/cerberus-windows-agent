using System.Net;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class CommandEnvelopeStateControlTests
{
    [Fact]
    public async Task ControlReservedDuringIdentityReadRetainsTheAcceptedBusinessReservation()
    {
        await using var f = new Worker();
        Assert.True(f.State.TrySave(new AgentSignedState(f.H.AgentId, 1, false, null)));
        var business = f.H.Cmd();
        await f.Process(business);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var reread = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var first = 1;
        var released = 0;
        f.CurrentAgent = async ct =>
        {
            if (Interlocked.Exchange(ref first, 0) == 1)
            {
                entered.TrySetResult();
                await release.Task.WaitAsync(ct);
                return f.H.AgentId;
            }
            if (Volatile.Read(ref released) == 1) reread.TrySetResult();
            return f.H.AgentId;
        };
        f.Queue.Start();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            var control = f.StateCommand(2);
            f.H.Backend.Respond = (r, _) => Task.FromResult(r.CommandId == control.Id
                ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK);
            await f.Process(control);
            Assert.True(f.State.HoldsNormalWork());
            Volatile.Write(ref released, 1);
            release.TrySetResult();
            await reread.Task.WaitAsync(TimeSpan.FromSeconds(5));

            Assert.Equal(EnvelopeRecordStates.Reserved, f.Replay.Find(f.H.AgentId, business.Id)!.State);
            Assert.Equal(0, f.H.Ping.Calls);
            Assert.DoesNotContain(f.H.Backend.Results, r => r.CommandId == business.Id);

            f.CurrentAgent = null;
            f.H.Backend.Respond = (_, _) => Task.FromResult(HttpStatusCode.OK);
            f.H.Time.Advance(TimeSpan.FromMinutes(1));
            f.Queue.SignalHeartbeat();
            await Wait.UntilAsync(() => f.Replay.Find(f.H.AgentId, business.Id)!.ResultSubmitted, "interleaved business resumes");
            Assert.Equal(1, f.H.Ping.Calls);
        }
        finally { release.TrySetResult(); }
    }

    [Fact]
    public async Task ControlReservedBetweenOutboxPostsHoldsTheRemainderOfTheBatch()
    {
        await using var f = new Worker();
        Assert.True(f.State.TrySave(new AgentSignedState(f.H.AgentId, 1, false, null)));
        foreach (var id in new[] { "outbox-a", "outbox-b" })
        {
            var record = StoreFileWriter.Record(f.H.AgentId, id, "nonce-" + id, EnvelopeRecordStates.Reserved,
                EnvelopeHarness.T0, EnvelopeHarness.T0 + 120, submitted: false);
            Assert.Equal(ReplayReserveOutcome.Reserved, f.Replay.TryReserve(record));
            var body = CommandEnvelope.BuildResultBody("DONE", 0, null, null, record.EnvelopeSha256);
            Assert.Equal(ReplayUpdateOutcome.Updated, f.Replay.TryUpdate(record with
            {
                State = EnvelopeRecordStates.Done, ResultB64 = Convert.ToBase64String(body),
                ResultSha256 = CommandEnvelope.Sha256Hex(body),
            }, record.State));
        }
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var control = f.StateCommand(2);
        f.H.Backend.Respond = async (request, ct) =>
        {
            if (request.CommandId == "outbox-a")
            {
                entered.TrySetResult();
                await release.Task.WaitAsync(ct);
            }
            return request.CommandId == control.Id ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK;
        };
        var drain = f.Queue.DrainOutboxOnceAsync(default);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await f.Process(control);
            release.TrySetResult();
            await drain.WaitAsync(TimeSpan.FromSeconds(5));

            Assert.True(f.Replay.Find(f.H.AgentId, "outbox-a")!.ResultSubmitted);
            Assert.False(f.Replay.Find(f.H.AgentId, "outbox-b")!.ResultSubmitted);
            Assert.DoesNotContain(f.H.Backend.Results, r => r.CommandId == "outbox-b");

            f.H.Backend.Respond = (_, _) => Task.FromResult(HttpStatusCode.OK);
            f.H.Time.Advance(TimeSpan.FromMinutes(1));
            await f.Queue.DrainOutboxOnceAsync(default);
            await f.Queue.DrainOutboxOnceAsync(default);
            Assert.True(f.Replay.Find(f.H.AgentId, "outbox-b")!.ResultSubmitted);
            Assert.Single(f.H.Backend.Results, r => r.CommandId == "outbox-b");
        }
        finally { release.TrySetResult(); }
    }

    [Fact]
    public async Task HangingStateAckTimesOutAtTenSecondsAndRetainsPreparedDeliveryForRetry()
    {
        await using var f = new Worker();
        var response = new TaskCompletionSource<HttpStatusCode>(TaskCreationOptions.RunContinuationsAsynchronously);
        f.H.Backend.Respond = (_, _) => response.Task; // Also exercise a transport that ignores cancellation.
        var control = f.StateCommand();
        var processing = f.Process(control);
        try
        {
            await Wait.UntilAsync(() => f.H.Backend.Acks.Count == 1, "hanging state ack");
            f.H.Time.Advance(EnvelopeCommandProcessor.AckTimeout);
            await processing.WaitAsync(TimeSpan.FromSeconds(5));

            var record = f.Replay.Find(f.H.AgentId, control.Id)!;
            Assert.Equal(EnvelopeRecordStates.Done, record.State);
            Assert.False(record.StateControl!.AckAccepted);
            Assert.False(record.ResultSubmitted);
            Assert.True(f.ReloadState().HasPersistedState(f.H.AgentId, 1, exactSequence: true));
            Assert.Empty(f.H.Backend.Results);

            response.TrySetResult(HttpStatusCode.OK);
            f.H.Backend.Respond = (_, _) => Task.FromResult(HttpStatusCode.OK);
            f.H.Time.Advance(TimeSpan.FromMinutes(1));
            await f.Queue.DrainOutboxOnceAsync(default);
            Assert.True(f.Replay.Find(f.H.AgentId, control.Id)!.ResultSubmitted);
            Assert.Equal(1, f.Executions);
        }
        finally { response.TrySetResult(HttpStatusCode.OK); }
    }
}
