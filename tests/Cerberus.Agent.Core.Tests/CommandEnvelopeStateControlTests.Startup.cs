using System.Net;
using Cerberus.Agent.App;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class CommandEnvelopeStateControlTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task DefinitiveAckRefusalReleasesOnlyDeliveryBarrierAndPreservesRevoke(bool revoke)
    {
        await using var f = new Worker();
        var command = f.StateCommand(revoke: revoke);
        f.H.Backend.Respond = (_, _) => Task.FromResult(HttpStatusCode.Conflict);
        await f.Process(command);
        var state = f.State.Load(f.H.AgentId);
        var refused = f.Replay.Find(f.H.AgentId, command.Id)!;
        Assert.True(refused.StateControl!.TransportRefused);
        Assert.Equal(EnvelopeRecordStates.RejectedAfterReserve, refused.State);
        Assert.False(refused.ResultSubmitted);
        Assert.False(f.FinalResults.Contains(f.H.AgentId, command.Id));
        // Checkpoint produced by the previous worker: refusal was durable but still marked DONE.
        StoreFileWriter.Write(f.H.StorePath, 0, new[] { refused with { State = EnvelopeRecordStates.Done } });
        await f.Restart();
        f.H.Backend.Respond = (_, _) => Task.FromResult(HttpStatusCode.OK);
        await f.Queue.DrainOutboxOnceAsync(default);
        Assert.Equal(state, f.State.Load(f.H.AgentId));
        Assert.False(f.State.HasPendingControl);
        Assert.Equal(EnvelopeRecordStates.RejectedAfterReserve, f.Replay.Find(f.H.AgentId, command.Id)!.State);
        Assert.Equal(revoke, f.State.HoldsNormalWork());
        if (revoke)
        {
            Assert.False(await Startup(f).RecoverPendingRevokeAsync(default, default));
            Assert.NotNull(f.State.Load(f.H.AgentId).PendingRevoke);
            Assert.Equal(AgentLifecycleState.Active, (await f.Lifecycle.LoadAsync(default)).State);
        }
        else
        {
            var normal = f.H.Cmd();
            await f.Process(normal);
            f.Queue.Start();
            await Wait.UntilAsync(() => f.Replay.Find(f.H.AgentId, normal.Id)?.ResultSubmitted == true, "normal work after terminal ack refusal");
            Assert.Equal(1, f.H.Ping.Calls);
        }
    }

    [Theory]
    [InlineData(AgentProducts.Cerberus)]
    [InlineData(AgentProducts.Secondary)]
    public async Task ReenrolledStartupClearsOnlyStaleBoundRevokeAndReachesFirstHeartbeat(string product)
    {
        await using var f = new Worker();
        var old = await f.Lifecycle.CompleteEnrollmentAsync(0, Guid.NewGuid().ToString("N"), default);
        f.CurrentContext = f.CurrentContext with { Product = product, Generation = old.Generation, EnrollmentNonce = old.LastEnrollmentNonce };
        await f.Restart();
        var command = f.StateCommand(revoke: true);
        f.H.Backend.Respond = (request, _) => Task.FromResult(request.Leaf == "result" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK);
        await f.Process(command);
        await f.Queue.DrainOutboxOnceAsync(default);
        var oldRecord = f.Replay.Find(f.H.AgentId, command.Id)!;
        var oldState = f.State.Load(f.H.AgentId);
        Assert.False(oldRecord.ResultSubmitted);
        Assert.NotNull(oldState.PendingRevoke);
        var oldPosts = f.H.Backend.Results.Count;

        var current = await f.Lifecycle.CompleteEnrollmentAsync(old.Generation, Guid.NewGuid().ToString("N"), default);
        f.CurrentContext = f.CurrentContext with { Generation = current.Generation, EnrollmentNonce = current.LastEnrollmentNonce };
        await f.Restart();
        var startup = Startup(f);

        Assert.True(await startup.RecoverPendingRevokeAsync(default, default));
        Assert.False(f.NetworkStopped);
        Assert.Equal(oldState with { PendingRevoke = null }, f.State.Load(f.H.AgentId));
        Assert.Equal(System.Text.Json.JsonSerializer.Serialize(oldRecord),
            System.Text.Json.JsonSerializer.Serialize(f.Replay.Find(f.H.AgentId, command.Id)));
        Assert.False(f.FinalResults.Contains(f.H.AgentId, command.Id));
        Assert.Equal(current, await f.Lifecycle.LoadAsync(default));
        Assert.Equal(oldPosts, f.H.Backend.Results.Count);

        var heartbeat = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.H.Backend.Respond = (request, _) =>
        {
            if (request.Leaf == "heartbeat") heartbeat.TrySetResult();
            return Task.FromResult(HttpStatusCode.OK);
        };
        var dispatcher = new CommandDispatcher(Array.Empty<ICommandHandler>(),
            new IdempotencyCache(f.H.StorePath + ".startup-idem", 10, TimeSpan.FromMinutes(5)));
        var loop = new HeartbeatLoop(f.H.Api, dispatcher, TimeSpan.FromSeconds(1), supportsEvents: false,
            commandProcessor: f.Processor, signedState: f.State, signedStateOnly: true);
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var run = loop.RunAsync(stop.Token);
        try { await heartbeat.Task.WaitAsync(stop.Token); }
        finally { stop.Cancel(); await run; }
        Assert.Contains(f.H.Backend.Requests, request => request.Path.EndsWith("/heartbeat", StringComparison.Ordinal));
        Assert.Equal(current, await f.Lifecycle.LoadAsync(default));
    }

    [Theory]
    [InlineData("same_nonce")]
    [InlineData("missing_current_nonce")]
    [InlineData("missing_binding")]
    [InlineData("unreadable_metadata")]
    public async Task StartupRetainsUnsentRevokeUnlessAnotherRegistrationIsProven(string scenario)
    {
        await using var f = new Worker();
        var old = await f.Lifecycle.CompleteEnrollmentAsync(0, Guid.NewGuid().ToString("N"), default);
        f.CurrentContext = f.CurrentContext with { Generation = old.Generation, EnrollmentNonce = old.LastEnrollmentNonce };
        await f.Restart();
        var command = f.StateCommand(revoke: true);
        f.H.Backend.Respond = (request, _) => Task.FromResult(request.Leaf == "result" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK);
        await f.Process(command);
        await f.Queue.DrainOutboxOnceAsync(default);
        var pending = f.State.Load(f.H.AgentId).PendingRevoke!;
        if (scenario == "missing_binding")
        {
            pending = pending with { Registration = null };
            File.WriteAllText(f.StatePath, System.Text.Json.JsonSerializer.Serialize(new
            {
                schema = "cerberus.agent-state.v1", state = f.State.Load(f.H.AgentId) with { PendingRevoke = pending },
            }));
        }
        f.CurrentContext = f.CurrentContext with { Generation = old.Generation + 1,
            EnrollmentNonce = scenario == "missing_current_nonce" ? null : old.LastEnrollmentNonce };
        if (scenario == "unreadable_metadata")
            f.CurrentRegistration = _ => throw new IOException("Owned unavailable registration fixture");
        await f.Restart();

        Assert.False(await Startup(f).RecoverPendingRevokeAsync(default, default));
        Assert.True(f.NetworkStopped);
        Assert.Equal(pending, f.State.Load(f.H.AgentId).PendingRevoke);
        Assert.False(f.FinalResults.Contains(f.H.AgentId, command.Id));
        Assert.False(f.Replay.Find(f.H.AgentId, command.Id)!.ResultSubmitted);
        Assert.Equal(old, await f.Lifecycle.LoadAsync(default));
    }

    private static ServerServiceStartup Startup(Worker f) => new(
        () => f.State.Load(f.H.AgentId).PendingRevoke is not null, f.Queue.DrainOutboxOnceAsync,
        ct => f.Handler.RecoverPendingRevokeAsync(f.Replay, ct), () => f.Replay.IsAvailable,
        () => f.NetworkStopped, () => f.NetworkStopped = true, f.H.Log);

    [Fact]
    public async Task StaleStateNegativeAckSurvivesLossRestartAndRedelivery()
    {
        await using var f = new Worker();
        Assert.True(f.State.TrySave(new(f.H.AgentId, 1, false, null)));
        var command = f.StateCommand();
        f.H.Backend.Respond = (_, _) => Task.FromResult(HttpStatusCode.ServiceUnavailable);
        await f.Process(command);
        Assert.False(f.Replay.Find(f.H.AgentId, command.Id)!.StateControl!.AckRejected);
        Assert.Single(f.H.Backend.Acks);

        f.H.Backend.Respond = (_, _) => Task.FromResult(HttpStatusCode.OK);
        await f.Restart();
        await f.Queue.DrainOutboxOnceAsync(default);
        Assert.True(f.Replay.Find(f.H.AgentId, command.Id)!.StateControl!.AckRejected);
        Assert.Equal(2, f.H.Backend.Acks.Count);
        await f.Process(command);
        Assert.Equal(3, f.H.Backend.Acks.Count);
        Assert.All(f.H.Backend.Acks, ack =>
        {
            Assert.Equal("rejected", ack.Json.GetProperty("decision").GetString());
            Assert.Equal(EnvelopeCodes.StaleStateSeq, ack.Json.GetProperty("reason").GetString());
        });
        Assert.Empty(f.H.Backend.Results);
        Assert.Equal(0, f.Executions);
        Assert.False(f.State.Load(f.H.AgentId).QuarantineActive);
    }
}
