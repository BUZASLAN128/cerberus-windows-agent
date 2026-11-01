using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentSignedStateTests
{
    [Fact]
    public async Task Recovery_UnavailableIdentityStopsNetworkWithoutDiscardingRevokeOrCredentials()
    {
        var f = new Fixture(StatePath);
        await f.Handle("c1", P(1, Revoke(Revoked)));
        f.AgentIdUnavailable = true;
        var replay = new CommandReplayStore(Path.Combine(_dir, CommandReplayStore.FileName), TimeProvider.System);
        await f.Handler.RecoverPendingRevokeAsync(replay, default);
        Assert.Equal(1, f.Stops);
        Assert.NotNull(f.Store.Load("agent-a").PendingRevoke);
        Assert.True(f.Store.IsQuarantined("agent-a"));
        Assert.False(f.Secrets.Cleared);
        Assert.Equal(AgentLifecycleState.Active, (await f.Lifecycle.LoadAsync(default)).State);
    }

#if CERBERUS_SERVER_PROFILE
    [Fact]
    public async Task Startup_SubmittedRevokeWithTransientIdentityFailureCannotReachFirstHeartbeat_AndNextWorkerRecovers()
    {
        var first = new Fixture(StatePath);
        await first.Handle("c1", P(1, Revoke(Revoked)));
        var replayPath = Path.Combine(_dir, CommandReplayStore.FileName);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        StoreFileWriter.Write(replayPath, 0, [StoreFileWriter.Record("agent-a", "c1", "n1",
            issuedAt: now, expiresAt: now + 120, submitted: true)]);
        var replay = new CommandReplayStore(replayPath, TimeProvider.System);
        Assert.True(replay.IsAvailable);
        Assert.True(replay.Find("agent-a", "c1")!.ResultSubmitted);
        first.AgentIdUnavailable = true;
        var heartbeatStarts = 0;
        if (await Startup(first).RecoverPendingRevokeAsync(default, default))
            heartbeatStarts++;
        Assert.Equal(0, heartbeatStarts);
        Assert.Equal(1, first.Stops);
        Assert.NotNull(new AgentSignedStateStore(StatePath).Load("agent-a").PendingRevoke);
        Assert.False(first.Secrets.Cleared);

        // A fresh worker retries the durable submitted receipt after the identity is readable again.
        var next = new Fixture(StatePath);
        Assert.True(await Startup(next).RecoverPendingRevokeAsync(default, default));
        Assert.Equal(AgentLifecycleState.Retired, (await next.Lifecycle.LoadAsync(default)).State);
        Assert.True(next.Secrets.Cleared);
        Assert.Null(new AgentSignedStateStore(StatePath).Load("agent-a").PendingRevoke);

        Cerberus.Agent.App.ServerServiceStartup Startup(Fixture worker)
        {
            var stopped = false;
            return new(() => worker.Store.Load("agent-a").PendingRevoke is not null,
                _ => Task.CompletedTask, ct => worker.Handler.RecoverPendingRevokeAsync(replay, ct),
                () => replay.IsAvailable, () => stopped || worker.Stops > 0,
                () => stopped = true, NullAgentLogger.Instance);
        }
    }
#endif
}
