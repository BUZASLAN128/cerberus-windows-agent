using System.Net;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class CommandEnvelopeStateControlTests
{
    [Theory]
    [InlineData(EnvelopeRecordStates.Reserved, false)]
    [InlineData(EnvelopeRecordStates.Reserved, true)]
    [InlineData(EnvelopeRecordStates.Started, false)]
    [InlineData(EnvelopeRecordStates.Started, true)]
    public async Task EqualSequenceFromAnotherOrLegacySnapshotCannotRecoverDone(string checkpoint, bool hasOtherCommandId)
    {
        await using var f = new Worker();
        Assert.True(f.State.TrySave(new(f.H.AgentId, 1, false, null,
            LastAppliedCommandId: hasOtherCommandId ? "different-owned-command" : null)));
        var command = f.StateCommand();
        f.CurrentAgent = _ => f.Replay.Find(f.H.AgentId, command.Id)?.State == EnvelopeRecordStates.Reserved
            ? throw new IOException("Owned checkpoint before stale-sequence preflight") : Task.FromResult(f.H.AgentId);
        await f.Process(command);
        var reserved = f.Replay.Find(f.H.AgentId, command.Id)!;
        Assert.Equal(EnvelopeRecordStates.Reserved, reserved.State);
        if (checkpoint == EnvelopeRecordStates.Started)
            Assert.Equal(ReplayUpdateOutcome.Updated, f.Replay.TryUpdate(reserved with { State = checkpoint }, reserved.State));
        f.CurrentAgent = null;
        await f.Restart();
        await f.Queue.DrainOutboxOnceAsync(default);
        Assert.Equal(EnvelopeRecordStates.RejectedAfterReserve, f.Replay.Find(f.H.AgentId, command.Id)!.State);
        Assert.Equal("rejected", Assert.Single(f.H.Backend.Acks).Json.GetProperty("decision").GetString());
        Assert.Empty(f.H.Backend.Results);
        Assert.False(f.State.Load(f.H.AgentId).QuarantineActive);
        Assert.False(f.FinalResults.Contains(f.H.AgentId, command.Id));
        Assert.Equal(0, f.Executions);
    }

    [Fact]
    public async Task TimedOutLiveStateHandlerCannotBeClosedBeforeItsLatePersistFinishes()
    {
        await using var f = new Worker();
        Assert.True(f.State.TrySave(new(f.H.AgentId, 1, false, null)));
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.CurrentRegistration = async _ =>
        {
            entered.TrySetResult();
            await release.Task; // Deliberately ignores cancellation, like the reported late-write witness.
            return new(f.H.AgentId, "t1", null);
        };
        var command = f.StateCommand(2, revoke: true);
        f.H.Backend.Respond = (request, _) => Task.FromResult(request.Leaf == "result" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK);
        var processing = f.Process(command);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            f.H.Time.Advance(TimeSpan.FromSeconds(11));
            await processing.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.False(f.Queue.IsInFlight(f.H.AgentId, command.Id));
            await f.Queue.DrainOutboxOnceAsync(default);
            Assert.Equal(EnvelopeRecordStates.Started, f.Replay.Find(f.H.AgentId, command.Id)!.State);
            Assert.Equal(1, f.State.Load(f.H.AgentId).StateSeq);
            Assert.Empty(f.H.Backend.Acks);
            Assert.Empty(f.H.Backend.Results);
            Assert.False(f.FinalResults.Contains(f.H.AgentId, command.Id));
        }
        finally { release.TrySetResult(); }
        await Wait.UntilAsync(() => f.Executions == 1, "late state handler completed its real persist");
        for (var i = 0; i < 100 && f.Replay.Find(f.H.AgentId, command.Id)!.State != EnvelopeRecordStates.Done; i++)
        {
            await f.Queue.DrainOutboxOnceAsync(default);
            if (f.Replay.Find(f.H.AgentId, command.Id)!.State != EnvelopeRecordStates.Done) await Task.Delay(10);
        }
        Assert.Equal(EnvelopeRecordStates.Done, f.Replay.Find(f.H.AgentId, command.Id)!.State);
        Assert.Equal(command.Id, f.State.Load(f.H.AgentId).LastAppliedCommandId);
        Assert.NotNull(f.State.Load(f.H.AgentId).PendingRevoke);
        Assert.False(f.FinalResults.Contains(f.H.AgentId, command.Id));
        Assert.Equal("DONE", Assert.Single(f.H.Backend.Results).Json.GetProperty("status").GetString());
    }
}
