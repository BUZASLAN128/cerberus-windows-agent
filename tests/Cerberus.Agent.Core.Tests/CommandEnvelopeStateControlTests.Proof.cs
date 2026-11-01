using System.Net;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class CommandEnvelopeStateControlTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WaitingHandlerRechecksQuarantineAndPendingControlAfterPermit(bool pendingControlOnly)
    {
        await using var f = new Worker();
        Assert.True(f.State.TrySave(new(f.H.AgentId, 1, false, null)));
        var returned = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.H.Facts.Body = async (_, _) =>
        {
            f.H.Facts.Started.TrySetResult();
            try { await f.H.Facts.Gate.Task; } // Deliberately ignores the first command's timeout.
            finally { returned.TrySetResult(); }
            return FakeCommandHandler.Done();
        };
        var first = f.H.Cmd(p => { p.Type = "collect_facts"; p.Expires = p.Issued + 300; });
        var second = f.H.Cmd(p => { p.Type = "collect_facts"; p.Expires = p.Issued + 300; });
        await f.Processor.ProcessAsync(new[] { first, second }, default);
        Assert.Equal(EnvelopeRecordStates.Reserved, f.Replay.Find(f.H.AgentId, first.Id)!.State);
        Assert.Equal(EnvelopeRecordStates.Reserved, f.Replay.Find(f.H.AgentId, second.Id)!.State);
        f.Queue.Start();
        try
        {
            await f.H.Facts.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
            f.H.Time.Advance(EnvelopeExecutionQueue.TimeoutFor("collect_facts"));
            await Wait.UntilAsync(() => f.Replay.Find(f.H.AgentId, first.Id)?.ResultSubmitted == true, "first handler timeout result");
            await Wait.UntilAsync(() => f.Replay.Find(f.H.AgentId, second.Id)?.State == EnvelopeRecordStates.Started,
                "second command admitted before quarantine and waiting for permit");
            Assert.Equal(1, f.H.Facts.Calls);
            var control = f.H.Cmd(p =>
            {
                p.Type = EnvelopeTypes.AgentState;
                p.PayloadJson = "{\"state_seq\":2,\"quarantine\":{\"active\":" + (pendingControlOnly ? "false" : "true") + "}}";
            });
            await f.Process(control);
            if (!pendingControlOnly)
            {
                await f.Queue.DrainOutboxOnceAsync(default);
                Assert.True(f.Replay.Find(f.H.AgentId, control.Id)!.ResultSubmitted);
                Assert.False(f.State.RequiresRecovery);
                Assert.True(f.State.Load(f.H.AgentId).QuarantineActive);
            }
            else
            {
                Assert.False(f.State.Load(f.H.AgentId).QuarantineActive);
                Assert.True(f.State.HasPendingControl);
            }

            f.H.Facts.Gate.TrySetResult();
            await Wait.UntilAsync(() => f.Replay.Find(f.H.AgentId, second.Id)?.ResultB64 is not null, "waiting command denied after permit");

            Assert.Equal(1, f.H.Facts.Calls);
            using var body = System.Text.Json.JsonDocument.Parse(Convert.FromBase64String(f.Replay.Find(f.H.AgentId, second.Id)!.ResultB64!));
            Assert.Equal("FAILED", body.RootElement.GetProperty("status").GetString());
            Assert.Equal(EnvelopeCodes.Quarantined, body.RootElement.GetProperty("stderr").GetString());
        }
        finally
        {
            f.H.Facts.Gate.TrySetResult();
            if (f.H.Facts.Started.Task.IsCompleted) await returned.Task.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task PendingRevokeProvesDoneAfterNewerStateOrLegacySnapshot(bool legacySnapshot)
    {
        await using var f = new Worker();
        var revoke = f.StateCommand(revoke: true);
        f.H.Backend.Respond = (request, _) => Task.FromResult(
            request.Leaf == "result" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK);
        await f.Process(revoke);
        Assert.Equal(EnvelopeRecordStates.Done, f.Replay.Find(f.H.AgentId, revoke.Id)!.State);
        Assert.True(f.Replay.Find(f.H.AgentId, revoke.Id)!.StateControl!.AckAccepted);
        await f.Queue.DrainOutboxOnceAsync(default);
        Assert.False(f.Replay.Find(f.H.AgentId, revoke.Id)!.ResultSubmitted);
        Assert.Single(f.H.Backend.Results);
        Assert.NotNull(f.State.Load(f.H.AgentId).PendingRevoke);
        if (legacySnapshot)
        {
            File.WriteAllText(f.StatePath, System.Text.Json.JsonSerializer.Serialize(new
            {
                schema = "cerberus.agent-state.v1",
                state = f.State.Load(f.H.AgentId) with { LastAppliedCommandId = null },
            }));
            Assert.DoesNotContain("last_applied_command_id", File.ReadAllText(f.StatePath));
        }
        else
        {
            var quarantine = f.StateCommand(2);
            await f.Process(quarantine);
            Assert.Equal(2, f.State.Load(f.H.AgentId).StateSeq);
            Assert.Equal(quarantine.Id, f.State.Load(f.H.AgentId).LastAppliedCommandId);
            Assert.Equal(EnvelopeRecordStates.Done, f.Replay.Find(f.H.AgentId, revoke.Id)!.State);
        }
        await f.Restart();
        Assert.Equal(revoke.Id, f.State.Load(f.H.AgentId).PendingRevoke!.CommandId);
        f.H.Backend.Respond = async (request, _) =>
        {
            if (request.CommandId == revoke.Id)
            {
                Assert.NotNull(f.State.Load(f.H.AgentId).PendingRevoke);
                Assert.Equal(AgentLifecycleState.Active, (await f.Lifecycle.LoadAsync(default)).State);
            }
            return HttpStatusCode.OK;
        };

        await f.Queue.DrainOutboxOnceAsync(default);

        Assert.True(f.Replay.Find(f.H.AgentId, revoke.Id)!.ResultSubmitted);
        var revokeResults = f.H.Backend.Results.Where(r => r.CommandId == revoke.Id).ToArray();
        Assert.Equal(2, revokeResults.Length);
        Assert.All(revokeResults, result => Assert.Equal("DONE", result.Json.GetProperty("status").GetString()));
        Assert.Equal(AgentLifecycleState.Retired, (await f.Lifecycle.LoadAsync(default)).State);
        Assert.Null(f.State.Load(f.H.AgentId).PendingRevoke);
        Assert.True(f.FinalResults.Contains(f.H.AgentId, revoke.Id));
        Assert.Equal(legacySnapshot ? 1 : 2, f.Executions);
    }

    [Theory]
    [InlineData("command")]
    [InlineData("tenant")]
    [InlineData("agent")]
    [InlineData("nonce")]
    public async Task AnotherCommandsOrRegistrationsPendingRevokeCannotProveDone(string mismatch)
    {
        await using var f = new Worker();
        var revoke = f.StateCommand(revoke: true);
        await f.Process(revoke);
        var state = f.State.Load(f.H.AgentId);
        var pending = state.PendingRevoke!;
        var registration = pending.Registration!;
        pending = mismatch switch
        {
            "command" => pending with { CommandId = "different-owned-command" },
            "tenant" => pending with { Registration = registration with { TenantId = "other-tenant" } },
            "agent" => pending with { Registration = registration with { AgentId = "other-agent" } },
            _ => pending with { Registration = registration with { EnrollmentNonce = Guid.NewGuid().ToString("N") } },
        };
        var storedAgent = mismatch == "agent" ? "other-agent" : f.H.AgentId;
        File.WriteAllText(f.StatePath, System.Text.Json.JsonSerializer.Serialize(new
        {
            schema = "cerberus.agent-state.v1",
            state = state with { AgentId = storedAgent, LastAppliedCommandId = null, PendingRevoke = pending },
        }));
        await f.Restart();

        await f.Queue.DrainOutboxOnceAsync(default);

        var rejected = f.Replay.Find(f.H.AgentId, revoke.Id)!;
        Assert.Equal(EnvelopeRecordStates.RejectedAfterReserve, rejected.State);
        Assert.Equal(EnvelopeCodes.ReplayStoreUnavailable, rejected.RejectReason);
        Assert.False(rejected.ResultSubmitted);
        Assert.Contains(f.H.Backend.Acks, ack => ack.CommandId == revoke.Id &&
            ack.Json.GetProperty("decision").GetString() == "rejected");
        Assert.Empty(f.H.Backend.Results);
        Assert.False(f.FinalResults.Contains(f.H.AgentId, revoke.Id));
        Assert.Equal(pending, f.State.Load(storedAgent).PendingRevoke);
        Assert.Equal(AgentLifecycleState.Active, (await f.Lifecycle.LoadAsync(default)).State);
        Assert.Equal(1, f.Executions);
    }

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
