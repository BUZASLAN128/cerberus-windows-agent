using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

// Unit/support evidence: a signed revoke applies only to the registration (agent id and lifecycle generation) it was
// issued for, and a revoke whose Retired state was saved counts as recorded. ServiceMode wiring is not covered here.
public sealed class AgentStateRevokeGuardTests : IDisposable
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
    public async Task GenerationBumpedBetweenTheReadAndTheWrite_DoesNotRetireTheNewRegistration()
    {
        var f = await Fixture.WithPendingRevokeAsync(_dir);
        f.LifecycleStore.BumpGenerationOnNextLoad = true;

        await f.Handler.OnResultFinalAsync("agent-a", "c1", default);

        Assert.NotEqual(AgentLifecycleState.Retired, (await f.Lifecycle.LoadAsync(default)).State);
        Assert.False(f.Secrets.Cleared);
        Assert.Equal(0, f.Cancels);
        Assert.Equal(0, f.Stops);
        Assert.Null(f.Store.Load("agent-a").PendingRevoke);
    }

    [Fact]
    public async Task Recovery_WhenTheAgentIdChangesBetweenTheRecoveryReadAndTheFollowUp_DoesNotRetire()
    {
        var f = await Fixture.WithPendingRevokeAsync(_dir);
        var replay = new CommandReplayStore(Path.Combine(_dir, CommandReplayStore.FileName), TimeProvider.System);
        Assert.True(replay.IsAvailable);
        f.IdReadsBeforeSwitch = 1;

        await f.Handler.RecoverPendingRevokeAsync(replay, default);

        Assert.NotEqual(AgentLifecycleState.Retired, (await f.Lifecycle.LoadAsync(default)).State);
        Assert.False(f.Secrets.Cleared);
        Assert.Equal(0, f.Cancels);
        Assert.Equal(0, f.Stops);
        Assert.Null(f.Store.Load("agent-a").PendingRevoke);
    }

    [Fact]
    public async Task RetiredSavedButTheCallFailed_CountsAsRecordedWithoutStoppingOrLoggingAnError()
    {
        var f = await Fixture.WithPendingRevokeAsync(_dir);
        f.LifecycleStore.FailAfterSave = true;

        await f.Handler.OnResultFinalAsync("agent-a", "c1", default);

        Assert.Equal(AgentLifecycleState.Retired, (await f.Lifecycle.LoadAsync(default)).State);
        Assert.Equal(0, f.Stops);
        Assert.Equal(1, f.Cancels);
        Assert.Null(f.Store.Load("agent-a").PendingRevoke);
        Assert.Empty(f.Log.Errors);
    }

    private sealed class Fixture
    {
        private Fixture(string dir)
        {
            Store = new AgentSignedStateStore(Path.Combine(dir, AgentSignedStateStore.FileName));
            Lifecycle = new AgentLifecycleController(LifecycleStore, Secrets, quiesce: _ => Task.CompletedTask);
            Handler = new AgentStateCommandHandler(
                Store,
                Store.Track(_ => Task.FromResult(ReadAgentId())),
                Lifecycle,
                () => Cancels++,
                Log,
                () => Stops++,
                new AgentRevokeFinalResults());
        }

        private string ReadAgentId()
            => IdReadsBeforeSwitch == int.MaxValue || IdReadsBeforeSwitch-- > 0 ? "agent-a" : "agent-b";

        // Id reads left before the credential shows "agent-b" (int.MaxValue = never switches).
        public int IdReadsBeforeSwitch { get; set; } = int.MaxValue;
        public AgentSignedStateStore Store { get; }
        public AgentStateCommandHandler Handler { get; }
        public AgentLifecycleController Lifecycle { get; }
        public MutableStore LifecycleStore { get; } = new();
        public Secrets Secrets { get; } = new();
        public CaptureLog Log { get; } = new();
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

    // Lifecycle store that can move the generation on, or fail the call after the snapshot was saved.
    private sealed class MutableStore : IAgentLifecycleStateStore
    {
        private readonly InMemoryAgentLifecycleStateStore _inner = new();
        private int _loads;

        public bool BumpGenerationOnNextLoad { get; set; }
        public bool FailAfterSave { get; set; }

        public async Task<AgentLifecycleSnapshot> LoadAsync(CancellationToken ct)
        {
            // The handler's own read is load 1; the controller's read before its write is load 2.
            if (BumpGenerationOnNextLoad && ++_loads == 2)
            {
                var current = await _inner.LoadAsync(ct);
                Assert.NotNull(await _inner.TrySaveAsync(current with { Generation = current.Generation + 1 }, current.Revision, ct));
            }

            return await _inner.LoadAsync(ct);
        }

        public Task SaveAsync(AgentLifecycleSnapshot snapshot, CancellationToken ct) => _inner.SaveAsync(snapshot, ct);

        public async Task<AgentLifecycleSnapshot?> TrySaveAsync(AgentLifecycleSnapshot snapshot, long expectedRevision, CancellationToken ct)
        {
            var saved = await _inner.TrySaveAsync(snapshot, expectedRevision, ct);
            if (FailAfterSave && saved is not null)
                throw new IOException("failed after the state was saved");
            return saved;
        }

        public Task<bool> ExecuteIfCurrentAsync(long expectedGeneration, Func<CancellationToken, Task> action, CancellationToken ct)
            => _inner.ExecuteIfCurrentAsync(expectedGeneration, action, ct);
    }

    private sealed class CaptureLog : IAgentLogger
    {
        public List<string> Errors { get; } = new();

        public void Info(string message) { }

        public void Warn(string message) { }

        public void Error(string message, Exception? ex = null) => Errors.Add(message);
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
