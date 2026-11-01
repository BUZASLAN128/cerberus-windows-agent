using System.Net;
using Cerberus.Agent.App;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class CommandEnvelopeStateControlTests
{
    [Fact]
    public Task ReservedBeforeStartedCrashClosesFailedAndNormalWorkResumes() => RecoverUnappliedStarted(false, beforeStarted: true);

    [Fact]
    public Task StartedBeforeHighWaterCrashClosesFailedAndNormalWorkResumes() => RecoverUnappliedStarted(false);

    [Fact]
    public Task StartedAfterHighWaterCrashClosesFailedButSnapshotRecoveryStillHolds() => RecoverUnappliedStarted(true);

    private static async Task RecoverUnappliedStarted(bool afterHighWater, bool beforeStarted = false)
    {
        await using var f = new Worker();
        Assert.True(f.State.TrySave(new(f.H.AgentId, 1, false, null)));
        FileStream? blockSnapshot = null;
        f.BeforeApply = () =>
        {
            Assert.Equal(EnvelopeRecordStates.Started, Assert.Single(f.Replay.Records(f.H.AgentId)).State);
            if (afterHighWater)
                blockSnapshot = new FileStream(f.StatePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            else
                throw new IOException("Owned crash checkpoint before high-water and snapshot writes");
        };
        var control = f.StateCommand(2);
        if (beforeStarted)
            f.CurrentAgent = _ => f.Replay.Find(f.H.AgentId, control.Id)?.State == EnvelopeRecordStates.Reserved
                ? throw new IOException("Owned crash checkpoint after reservation, before Started") : Task.FromResult(f.H.AgentId);
        try { await f.Process(control); }
        finally { blockSnapshot?.Dispose(); }
        var checkpoint = f.Replay.Find(f.H.AgentId, control.Id)!;
        Assert.Equal(beforeStarted ? EnvelopeRecordStates.Reserved : EnvelopeRecordStates.Started, checkpoint.State);
        Assert.Null(checkpoint.ResultB64);
        Assert.Equal(afterHighWater ? 2 : 1, new AgentStateHighWater(f.StatePath, f.H.Log, false).Read()!.Value.Seq);
        f.BeforeApply = null;
        f.CurrentAgent = null;

        await f.Restart();
        await f.Queue.DrainOutboxOnceAsync(default);
        var closed = f.Replay.Find(f.H.AgentId, control.Id)!;
        Assert.Equal(EnvelopeRecordStates.RejectedAfterReserve, closed.State);
        Assert.Equal(EnvelopeCodes.ReplayStoreUnavailable, closed.RejectReason);
        Assert.True(closed.StateControl!.AckRejected);
        Assert.False(f.State.HasPendingControl);
        Assert.False(f.FinalResults.Contains(f.H.AgentId, control.Id));
        Assert.Empty(f.H.Backend.Results);
        Assert.Equal("rejected", Assert.Single(f.H.Backend.Acks).Json.GetProperty("decision").GetString());
        Assert.Equal(afterHighWater, f.State.RequiresSnapshotRecovery);
        Assert.Equal(afterHighWater ? 2 : 1, f.State.Load(f.H.AgentId).StateSeq);
        var normal = f.H.Cmd();
        await f.Process(normal);
        f.Queue.Start();
        if (afterHighWater)
        {
            Assert.True(f.State.HoldsNormalWork());
            Assert.Equal(0, f.H.Ping.Calls);
            Assert.DoesNotContain(f.H.Backend.Results, result => result.CommandId == normal.Id);
        }
        else
        {
            await Wait.UntilAsync(() => f.Replay.Find(f.H.AgentId, normal.Id)?.ResultSubmitted == true, "normal work after terminal control failure");
            Assert.Equal(1, f.H.Ping.Calls);
            Assert.Equal("DONE", Assert.Single(f.H.Backend.Results).Json.GetProperty("status").GetString());
        }
    }

    [Fact]
    public async Task FailedRevokeResultAtRealStartupDoublesSupervisorDelay()
    {
        await using var f = new Worker();
        f.CurrentContext = f.CurrentContext with { Product = AgentProducts.Secondary };
        await f.Restart();
        var command = f.StateCommand(revoke: true);
        f.H.Backend.Respond = (request, _) => Task.FromResult(request.Leaf == "result" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK);
        await f.Process(command);
        var backoff = new WorkerRestartBackoff();
        var now = new DateTimeOffset(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);
        foreach (var delay in new[] { 2, 4, 8 })
        {
            Assert.True(backoff.CanStart(now));
            f.NetworkStopped = false;
            await f.Restart();
            Assert.False(await Startup(f).RecoverPendingRevokeAsync(default, default));
            Assert.NotNull(f.State.Load(f.H.AgentId).PendingRevoke);
            Assert.False(f.Replay.Find(f.H.AgentId, command.Id)!.ResultSubmitted);
            backoff.OnWorkerEnded(now, now.AddMilliseconds(100), planned: false);
            now = now.AddMilliseconds(100);
            Assert.False(backoff.CanStart(now.AddSeconds(delay).AddMilliseconds(-1)));
            Assert.True(backoff.CanStart(now.AddSeconds(delay)));
            now = now.AddSeconds(delay);
        }
        Assert.Equal(3, f.H.Backend.Results.Count);
        Assert.DoesNotContain(f.H.Backend.Requests, request => request.Leaf == "heartbeat");
    }
}
