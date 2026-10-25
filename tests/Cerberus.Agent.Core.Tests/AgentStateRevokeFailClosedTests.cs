using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

// Unit/support evidence: a signed revoke whose retirement cannot be persisted stops automatic network
// activity through the handler callback and stays pending for the next attempt. The supervisor restart that
// performs the retry (ServiceMode) is not covered here.
public sealed class AgentStateRevokeFailClosedTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_dir))
                Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
            // Best-effort cleanup of the per-test temp directory.
        }
    }

    [Fact]
    public async Task FailedRetirementWrite_StopsAutomaticNetworkAndKeepsTheRevokePending()
    {
        var f = await Fixture.WithPendingRevokeAsync(_dir);
        f.Saves.FailSaves = true;

        await f.Handler.OnResultFinalAsync("agent-a", "c1", default);

        Assert.Equal(1, f.Stops);
        Assert.Equal(1, f.Cancels);
        Assert.NotNull(f.Store.Load("agent-a").PendingRevoke);
        Assert.NotEqual(AgentLifecycleState.Retired, (await f.Lifecycle.LoadAsync(default)).State);
        Assert.False(f.Secrets.Cleared);
    }

    [Fact]
    public async Task RetryAfterAFailedWrite_RetiresClearsThePendingRevokeAndDoesNotStopAgain()
    {
        var f = await Fixture.WithPendingRevokeAsync(_dir);
        f.Saves.FailSaves = true;
        await f.Handler.OnResultFinalAsync("agent-a", "c1", default);

        f.Saves.FailSaves = false;
        await f.Handler.OnResultFinalAsync("agent-a", "c1", default);

        Assert.Equal(AgentLifecycleState.Retired, (await f.Lifecycle.LoadAsync(default)).State);
        Assert.True(f.Secrets.Cleared);
        Assert.Null(f.Store.Load("agent-a").PendingRevoke);
        Assert.Equal(1, f.Stops);
    }

    [Fact]
    public async Task SuccessfulRetirement_DoesNotStopAutomaticNetwork()
    {
        var f = await Fixture.WithPendingRevokeAsync(_dir);

        await f.Handler.OnResultFinalAsync("agent-a", "c1", default);

        Assert.Equal(AgentLifecycleState.Retired, (await f.Lifecycle.LoadAsync(default)).State);
        Assert.Equal(0, f.Stops);
    }

    [Fact]
    public async Task RevokeForAnOlderRegistration_DoesNotStopAutomaticNetwork()
    {
        var f = await Fixture.WithPendingRevokeAsync(_dir);
        f.Saves.FailSaves = true;
        f.AgentId = "agent-b";

        await f.Handler.OnResultFinalAsync("agent-a", "c1", default);

        Assert.Equal(0, f.Stops);
        Assert.Equal(0, f.Cancels);
    }

    [Fact]
    public async Task ShutdownCancellation_DoesNotStopAutomaticNetwork()
    {
        var f = await Fixture.WithPendingRevokeAsync(_dir);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => f.Handler.OnResultFinalAsync("agent-a", "c1", cts.Token));

        Assert.Equal(0, f.Stops);
        Assert.NotNull(f.Store.Load("agent-a").PendingRevoke);
    }

    [Fact]
    public async Task RestartAfterBothWritesFailed_StopsAgainBeforeTheHeartbeatLoopAndRetiresOnceWritesRecover()
    {
        var f = await Fixture.WithPendingRevokeAsync(_dir);
        var replay = ReplayWithUnsubmittedDone();
        var final = new AgentRevokeFinalResults();
        f.Saves.FailSaves = true;
        var worker1 = f.NewWorker(final);
        await worker1.Handler.OnResultFinalAsync("agent-a", "c1", default);
        Assert.Equal(1, worker1.Stops);

        var worker2 = f.NewWorker(final);
        await worker2.Handler.RecoverPendingRevokeAsync(replay, default);

        Assert.Equal(1, worker2.Stops);
        Assert.NotNull(f.Store.Load("agent-a").PendingRevoke);

        f.Saves.FailSaves = false;
        var worker3 = f.NewWorker(final);
        await worker3.Handler.RecoverPendingRevokeAsync(replay, default);

        Assert.Equal(AgentLifecycleState.Retired, (await f.Lifecycle.LoadAsync(default)).State);
        Assert.Null(f.Store.Load("agent-a").PendingRevoke);
        Assert.Equal(0, worker3.Stops);
    }

    [Fact]
    public async Task RestartWithAnUnavailableReplayStore_StillReachesTheRecordAttempt()
    {
        var f = await Fixture.WithPendingRevokeAsync(_dir);
        var final = new AgentRevokeFinalResults();
        f.Saves.FailSaves = true;
        await f.NewWorker(final).Handler.OnResultFinalAsync("agent-a", "c1", default);

        // A corrupt replay file that is held open cannot be set aside, so the store cannot load.
        var path = Path.Combine(_dir, CommandReplayStore.FileName);
        File.WriteAllText(path, "not json");
        using var held = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        var unavailable = new CommandReplayStore(path, new FakeTime(1790000060));
        Assert.False(unavailable.IsAvailable);
        var worker2 = f.NewWorker(final);
        await worker2.Handler.RecoverPendingRevokeAsync(unavailable, default);

        Assert.Equal(1, worker2.Stops);
        Assert.NotNull(f.Store.Load("agent-a").PendingRevoke);
    }

    [Fact]
    public async Task RestartInANewProcess_LeavesAnUndeliveredResultToTheOutbox()
    {
        var f = await Fixture.WithPendingRevokeAsync(_dir);
        var worker = f.NewWorker(new AgentRevokeFinalResults());

        await worker.Handler.RecoverPendingRevokeAsync(ReplayWithUnsubmittedDone(), default);

        Assert.Equal(0, worker.Stops);
        Assert.NotEqual(AgentLifecycleState.Retired, (await f.Lifecycle.LoadAsync(default)).State);
        Assert.NotNull(f.Store.Load("agent-a").PendingRevoke);
    }

    private CommandReplayStore ReplayWithUnsubmittedDone()
    {
        var path = Path.Combine(_dir, CommandReplayStore.FileName);
        StoreFileWriter.Write(path, 0, [StoreFileWriter.Record("agent-a", "c1", "n1", submitted: false)]);
        var replay = new CommandReplayStore(path, new FakeTime(1790000060));
        Assert.True(replay.IsAvailable);
        return replay;
    }

    private sealed class Worker
    {
        public AgentStateCommandHandler Handler { get; set; } = null!;
        public int Stops { get; set; }
    }

    private sealed class Fixture
    {
        private Fixture(string dir)
        {
            Store = new AgentSignedStateStore(Path.Combine(dir, AgentSignedStateStore.FileName));
            Lifecycle = new AgentLifecycleController(Saves, Secrets, quiesce: _ => Task.CompletedTask);
            Handler = new AgentStateCommandHandler(
                Store,
                Store.Track(_ => Task.FromResult(AgentId)),
                Lifecycle,
                () => Cancels++,
                stopAutomaticNetwork: () => Stops++);
        }

        // A later worker start in the same service: same stores, its own stop counter.
        public Worker NewWorker(AgentRevokeFinalResults finalResults)
        {
            var worker = new Worker();
            worker.Handler = new AgentStateCommandHandler(
                Store,
                Store.Track(_ => Task.FromResult(AgentId)),
                Lifecycle,
                () => Cancels++,
                stopAutomaticNetwork: () => worker.Stops++,
                finalResults: finalResults);
            return worker;
        }

        public string AgentId { get; set; } = "agent-a";
        public AgentSignedStateStore Store { get; }
        public AgentStateCommandHandler Handler { get; }
        public AgentLifecycleController Lifecycle { get; }
        public FailingStore Saves { get; } = new();
        public Secrets Secrets { get; } = new();
        public int Cancels { get; private set; }
        public int Stops { get; private set; }

        public static async Task<Fixture> WithPendingRevokeAsync(string dir)
        {
            var f = new Fixture(dir);
            var payload = JsonDocument.Parse("""{"state_seq":1,"revoke":{"reason_code":"agent_revoked"}}""").RootElement.Clone();
            var result = await f.Handler.HandleAsync(new AgentCommand("c1", "agent_state", "c1", payload), CancellationToken.None);
            Assert.Equal("DONE", result.Status);
            return f;
        }
    }

    private sealed class FailingStore : IAgentLifecycleStateStore
    {
        private readonly InMemoryAgentLifecycleStateStore _inner = new();

        public bool FailSaves { get; set; }

        public Task<AgentLifecycleSnapshot> LoadAsync(CancellationToken ct) => _inner.LoadAsync(ct);

        public Task SaveAsync(AgentLifecycleSnapshot snapshot, CancellationToken ct) => _inner.SaveAsync(snapshot, ct);

        public Task<AgentLifecycleSnapshot?> TrySaveAsync(AgentLifecycleSnapshot snapshot, long expectedRevision, CancellationToken ct)
            => FailSaves ? throw new IOException("lifecycle write failed") : _inner.TrySaveAsync(snapshot, expectedRevision, ct);

        public Task<bool> ExecuteIfCurrentAsync(long expectedGeneration, Func<CancellationToken, Task> action, CancellationToken ct)
            => _inner.ExecuteIfCurrentAsync(expectedGeneration, action, ct);
    }

    private sealed class Secrets : ISecretStore
    {
        public bool Cleared { get; private set; }

        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
            => Task.FromResult((new AgentIdentity("agent-a", "t1"), "refresh", "key", "https://backend.invalid", (string?)null, (string?)null));

        public Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl, string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct)
            => Task.CompletedTask;

        public Task ClearAsync(CancellationToken ct)
        {
            Cleared = true;
            return Task.CompletedTask;
        }
    }
}
