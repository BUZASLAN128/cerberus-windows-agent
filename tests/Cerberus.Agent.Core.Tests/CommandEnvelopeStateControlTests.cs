using System.Net;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class CommandEnvelopeStateControlTests
{
    [Fact]
    public async Task DefiniteStaleFailureAfterAdmissionStaysRejectedAcrossRestart()
    {
        await using var f = new Worker();
        f.BeforeApply = () => Assert.True(f.State.TrySave(new AgentSignedState(f.H.AgentId, 1, false, null)));
        var stale = f.H.Cmd(p =>
        {
            p.Type = EnvelopeTypes.AgentState;
            p.PayloadJson = "{\"state_seq\":1,\"quarantine\":{\"active\":true}}";
        });
        await f.Process(stale);
        Assert.Equal(1, f.Executions);
        Assert.Equal(EnvelopeRecordStates.RejectedAfterReserve, f.Replay.Find(f.H.AgentId, stale.Id)!.State);
        f.BeforeApply = null;

        await f.Restart();
        await f.Queue.DrainOutboxOnceAsync(default);

        Assert.False(f.State.Load(f.H.AgentId).QuarantineActive);
        Assert.Empty(f.H.Backend.Acks);
        Assert.Empty(f.H.Backend.Results);
        Assert.Equal(EnvelopeRecordStates.RejectedAfterReserve, f.Replay.Find(f.H.AgentId, stale.Id)!.State);
        Assert.Equal(1, f.Executions);
    }

    [Fact]
    public async Task NewCommandAtThePersistedSequenceCannotRecoverAsApplied()
    {
        await using var f = new Worker();
        Assert.True(f.State.TrySave(new AgentSignedState(f.H.AgentId, 1, false, null)));
        var stale = f.H.Cmd(p =>
        {
            p.Type = EnvelopeTypes.AgentState;
            p.PayloadJson = "{\"state_seq\":1,\"quarantine\":{\"active\":true}}";
        });

        await f.Process(stale);
        Assert.Equal(EnvelopeRecordStates.RejectedAfterReserve, f.Replay.Find(f.H.AgentId, stale.Id)!.State);
        await f.Restart();
        await f.Queue.DrainOutboxOnceAsync(default);

        Assert.False(f.State.Load(f.H.AgentId).QuarantineActive);
        Assert.False(f.State.HoldsNormalWork());
        Assert.Empty(f.H.Backend.Acks);
        Assert.Empty(f.H.Backend.Results);
        Assert.Equal(EnvelopeRecordStates.RejectedAfterReserve, f.Replay.Find(f.H.AgentId, stale.Id)!.State);
        Assert.Equal(0, f.Executions);
    }

    [Fact]
    public async Task PreviouslyAcceptedBusinessWaitsForControlDoneInsteadOfFailingQuarantined()
    {
        await using var f = new Worker();
        Assert.True(f.State.TrySave(new AgentSignedState(f.H.AgentId, 1, false, null)));
        var business = f.H.Cmd();
        await f.Process(business);
        var control = f.StateCommand(2);
        f.H.Backend.Respond = (request, _) => Task.FromResult(
            request.CommandId == control.Id && request.Leaf == "result"
                ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK);
        await f.Process(control);
        f.Queue.Start();
        await Wait.UntilAsync(() => f.H.Backend.Results.Any(r => r.CommandId == control.Id), "control delivery attempted");

        Assert.Equal(0, f.H.Ping.Calls);
        Assert.Equal(EnvelopeRecordStates.Reserved, f.Replay.Find(f.H.AgentId, business.Id)!.State);
        Assert.DoesNotContain(f.H.Backend.Results, r => r.CommandId == business.Id);

        f.H.Backend.Respond = (_, _) => Task.FromResult(HttpStatusCode.OK);
        f.H.Time.Advance(TimeSpan.FromMinutes(1));
        f.Queue.SignalHeartbeat();
        await Wait.UntilAsync(() => f.Replay.Find(f.H.AgentId, business.Id)!.ResultSubmitted, "held business resumes");

        Assert.True(f.Replay.Find(f.H.AgentId, control.Id)!.ResultSubmitted);
        Assert.Equal(1, f.H.Ping.Calls);
        Assert.Equal("DONE", f.H.Backend.Results.Single(r => r.CommandId == business.Id).Json.GetProperty("status").GetString());
    }

    [Fact]
    public async Task AppliedStateSurvivesAckFailureAndFreshWorkerDrainsWithoutExecutingAgain()
    {
        await using var f = new Worker();
        var control = f.StateCommand();
        f.H.Backend.Respond = (request, _) =>
        {
            if (request.CommandId == control.Id && request.Leaf == "ack")
            {
                Assert.True(f.ReloadState().HasPersistedState(f.H.AgentId, 1, exactSequence: true));
                Assert.True(f.State.HoldsNormalWork());
                return Task.FromResult(HttpStatusCode.ServiceUnavailable);
            }
            return Task.FromResult(HttpStatusCode.OK);
        };

        await f.Process(control);
        Assert.Equal(EnvelopeRecordStates.Done, f.Replay.Find(f.H.AgentId, control.Id)!.State);
        Assert.False(f.Replay.Find(f.H.AgentId, control.Id)!.StateControl!.AckAccepted);
        Assert.Empty(f.H.Backend.Results);
        await f.Process(f.H.Cmd());
        Assert.Equal(0, f.H.Ping.Calls);

        await f.Restart();
        f.H.Backend.Respond = (request, _) =>
        {
            if (request.CommandId == control.Id) Assert.True(f.State.HoldsNormalWork());
            else if (request.Leaf == "ack") Assert.Equal(0, f.H.Ping.Calls);
            return Task.FromResult(HttpStatusCode.OK);
        };
        await f.Queue.DrainOutboxOnceAsync(default);
        Assert.True(f.Replay.Find(f.H.AgentId, control.Id)!.ResultSubmitted);
        Assert.False(f.State.HoldsNormalWork());
        Assert.Equal(1, f.Executions);
        Assert.Single(f.H.Backend.Results);
        await f.Process(f.H.Cmd());
        f.Queue.Start();
        await Wait.UntilAsync(() => f.H.Ping.Calls == 1, "business resumes after control DONE");
    }

    [Fact]
    public async Task CrashAfterSnapshotWriteRecoversStartedRecordFromDiskBeforeAck()
    {
        await using var f = new Worker { FailAfterApply = true };
        var control = f.StateCommand();
        await f.Process(control);
        Assert.Equal(EnvelopeRecordStates.Started, f.Replay.Find(f.H.AgentId, control.Id)!.State);
        Assert.True(f.ReloadState().HasPersistedState(f.H.AgentId, 1, exactSequence: true));
        Assert.Empty(f.H.Backend.Acks);
        f.FailAfterApply = false;

        await f.Restart();
        await f.Queue.DrainOutboxOnceAsync(default);

        Assert.Equal(1, f.Executions);
        Assert.True(f.Replay.Find(f.H.AgentId, control.Id)!.ResultSubmitted);
        Assert.Single(f.H.Backend.Acks);
        Assert.Single(f.H.Backend.Results);
    }

    [Fact]
    public async Task SnapshotWriteFailureNeverSendsAcceptedAck()
    {
        await using var f = new Worker();
        Directory.CreateDirectory(f.StatePath); // A real filesystem write failure, not a successful state fake.
        var control = f.StateCommand();

        await f.Process(control);

        Assert.False(f.ReloadState().HasPersistedState(f.H.AgentId, 1, exactSequence: true));
        Assert.Empty(f.H.Backend.Acks);
        Assert.Empty(f.H.Backend.Results);
        Assert.True(f.State.HoldsNormalWork());
    }

    [Fact]
    public async Task HighWaterWithoutSnapshotCannotAcknowledgeCachedDoneAndNewAuthorityCanSupersede()
    {
        await using var f = new Worker();
        f.H.Backend.Respond = (_, _) => Task.FromResult(HttpStatusCode.ServiceUnavailable);
        var old = f.StateCommand();
        await f.Process(old);
        Assert.Single(f.H.Backend.Acks);
        File.Delete(f.StatePath);
        await f.Restart();
        Assert.Equal(1, f.State.Load(f.H.AgentId).StateSeq); // The floor survives; it is not the snapshot.
        f.H.Backend.Respond = (_, _) => Task.FromResult(HttpStatusCode.OK);

        await f.Queue.DrainOutboxOnceAsync(default);

        Assert.Single(f.H.Backend.Acks);
        Assert.Empty(f.H.Backend.Results);
        Assert.True(f.State.HoldsNormalWork());
        var newer = f.StateCommand(2);
        await f.Process(newer);
        await f.Queue.DrainOutboxOnceAsync(default);
        Assert.Equal(EnvelopeRecordStates.RejectedAfterReserve, f.Replay.Find(f.H.AgentId, old.Id)!.State);
        Assert.True(f.Replay.Find(f.H.AgentId, newer.Id)!.ResultSubmitted);
        Assert.False(f.State.HoldsNormalWork());
    }

    [Fact]
    public async Task ChangedRegistrationCannotResumePreparedControl()
    {
        await using var f = new Worker();
        f.H.Backend.Respond = (_, _) => Task.FromResult(HttpStatusCode.ServiceUnavailable);
        var control = f.StateCommand();
        await f.Process(control);
        await f.Restart();
        f.CurrentContext = f.CurrentContext with { Generation = 1 };
        f.H.Backend.Respond = (_, _) => Task.FromResult(HttpStatusCode.OK);

        await f.Queue.DrainOutboxOnceAsync(default);

        Assert.Single(f.H.Backend.Acks);
        Assert.Empty(f.H.Backend.Results);
        Assert.False(f.Replay.Find(f.H.AgentId, control.Id)!.ResultSubmitted);
    }

    [Fact]
    public async Task ConfirmedControlDoneRetiresOnlyAfterTheServerResponse()
    {
        await using var f = new Worker();
        f.H.Backend.Respond = async (_, _) =>
        {
            Assert.NotNull(f.State.Load(f.H.AgentId).PendingRevoke);
            Assert.Equal(AgentLifecycleState.Active, (await f.Lifecycle.LoadAsync(default)).State);
            return HttpStatusCode.OK;
        };
        var control = f.StateCommand(revoke: true);

        await f.Process(control);
        Assert.Equal(AgentLifecycleState.Active, (await f.Lifecycle.LoadAsync(default)).State);
        await f.Queue.DrainOutboxOnceAsync(default);

        Assert.True(f.Replay.Find(f.H.AgentId, control.Id)!.ResultSubmitted);
        Assert.Equal(AgentLifecycleState.Retired, (await f.Lifecycle.LoadAsync(default)).State);
        Assert.Null(f.State.Load(f.H.AgentId).PendingRevoke);
    }

    [Fact]
    public async Task PendingRevokeWaitsForConfirmedDoneAndLostReplayCannotInventConfirmation()
    {
        await using var f = new Worker();
        var control = f.StateCommand(revoke: true);
        f.H.Backend.Respond = (request, _) => Task.FromResult(
            request.Leaf == "result" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK);
        await f.Process(control);
        await f.Queue.DrainOutboxOnceAsync(default);
        Assert.NotNull(f.State.Load(f.H.AgentId).PendingRevoke);
        Assert.Equal(AgentLifecycleState.Active, (await f.Lifecycle.LoadAsync(default)).State);
        File.Delete(f.H.StorePath);
        await f.Restart();

        await f.Handler.RecoverPendingRevokeAsync(f.Replay, default);

        Assert.NotNull(f.State.Load(f.H.AgentId).PendingRevoke);
        Assert.Equal(AgentLifecycleState.Active, (await f.Lifecycle.LoadAsync(default)).State);
    }

    private sealed class Worker : IAsyncDisposable
    {
        private readonly string _directory = Path.Combine(Path.GetTempPath(), "cerberus-state-control", Guid.NewGuid().ToString("N"));
        public EnvelopeHarness H { get; } = EnvelopeHarness.Create(o => o.StartQueue = false);
        public string StatePath => Path.Combine(_directory, "state.json");
        public AgentSignedStateStore State { get; private set; } = null!;
        public CommandReplayStore Replay { get; private set; } = null!;
        public EnvelopeExecutionQueue Queue { get; private set; } = null!;
        public EnvelopeCommandProcessor Processor { get; private set; } = null!;
        public AgentStateCommandHandler Handler { get; private set; } = null!;
        public AgentLifecycleController Lifecycle { get; } = new(new InMemoryAgentLifecycleStateStore());
        public AgentStateDeliveryContext CurrentContext { get; set; }
        public bool FailAfterApply { get; set; }
        public Action? BeforeApply { get; set; }
        public Func<CancellationToken, Task<string>>? CurrentAgent { get; set; }
        public int Executions { get; private set; }

        public Worker()
        {
            Directory.CreateDirectory(_directory);
            CurrentContext = H.ControlContext;
            Build();
        }

        public AgentSignedStateStore ReloadState() => new(StatePath, enrolledAgentId: H.AgentId);
        public Task Process(AgentCommand command) => Processor.ProcessAsync(new[] { command }, default);
        public AgentCommand StateCommand(int sequence = 1, bool revoke = false) => H.Cmd(p =>
        {
            p.Type = EnvelopeTypes.AgentState;
            p.PayloadJson = revoke ? "{\"state_seq\":" + sequence + ",\"revoke\":{\"reason_code\":\"agent_revoked\"}}"
                : "{\"state_seq\":" + sequence + ",\"quarantine\":{\"active\":false}}";
        });

        public async Task Restart()
        {
            await Queue.DisposeAsync();
            Build();
        }

        private void Build()
        {
            State = ReloadState();
            Replay = new CommandReplayStore(H.StorePath, H.Time);
            var current = State.Track(ct => CurrentAgent?.Invoke(ct) ?? Task.FromResult(H.AgentId));
            Handler = new AgentStateCommandHandler(State, current, Lifecycle, () => Queue.CancelAll(), H.Log,
                () => { }, new AgentRevokeFinalResults(), _ => Task.FromResult(new AgentRevokeRegistration(H.AgentId, "t1", null)));
            var observed = new ObservedHandler(Handler, () => BeforeApply?.Invoke(),
                () => { Executions++; if (FailAfterApply) throw new IOException("Owned post-write interruption."); });
            Queue = new EnvelopeExecutionQueue(H.Api, Replay, new ICommandHandler[] { H.Ping, observed }, current,
                State.IsQuarantined, H.Time, signedState: State, controlContext: H.ControlContext,
                currentControlContext: _ => Task.FromResult(CurrentContext));
            Processor = new EnvelopeCommandProcessor(H.Api, new[] { H.Signer.Anchor }, Queue,
                new HashSet<string> { "ping", EnvelopeTypes.AgentState });
        }

        public async ValueTask DisposeAsync()
        {
            await Queue.DisposeAsync();
            await H.DisposeAsync();
            Directory.Delete(_directory, true);
        }
    }

    private sealed class ObservedHandler(AgentStateCommandHandler inner, Action before, Action applied) : ICommandHandler, IEnvelopeResultFollowUp
    {
        public string Type => EnvelopeTypes.AgentState;
        public async Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
        {
            before();
            var result = await inner.HandleAsync(command, ct);
            applied();
            return result;
        }
        public Task OnResultFinalAsync(string agentId, string commandId, CancellationToken ct)
            => inner.OnResultFinalAsync(agentId, commandId, ct);
    }
}
