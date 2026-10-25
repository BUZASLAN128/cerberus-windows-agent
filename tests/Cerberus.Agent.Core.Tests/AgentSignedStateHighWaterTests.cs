using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

// Unit/support evidence: the highest accepted state_seq survives the reset of a corrupt signed-state file.
public sealed class AgentSignedStateHighWaterTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
    private string StatePath => Path.Combine(_dir, AgentSignedStateStore.FileName);

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
    public async Task AfterACorruptFileReset_SignedStateAtOrBelowTheAcceptedSeqStaysStale()
    {
        Assert.Equal("DONE", (await Handle(NewHandler("agent-a"), "c1", 5)).Status);
        File.WriteAllText(StatePath, "{ not json");

        var handler = NewHandler("agent-a");
        foreach (var seq in new long[] { 3, 5 })
        {
            var stale = await Handle(handler, $"s{seq}", seq);
            Assert.Equal("FAILED", stale.Status);
            Assert.Equal(AgentStateCommandHandler.StaleStateSeq, stale.Stderr);
        }

        Assert.Equal("DONE", (await Handle(handler, "c6", 6)).Status);
        Assert.Equal(6, new AgentSignedStateStore(StatePath).Load("agent-a").StateSeq);
    }

    [Fact]
    public async Task AfterACorruptFileReset_AnotherAgentIdStartsAtZero()
    {
        await Handle(NewHandler("agent-a"), "c1", 5);
        File.WriteAllText(StatePath, "{ not json");

        var store = new AgentSignedStateStore(StatePath);

        Assert.Equal(0, store.Load("agent-b").StateSeq);
        Assert.Equal("DONE", (await Handle(NewHandler("agent-b"), "c1", 1)).Status);
    }

    private AgentStateCommandHandler NewHandler(string agentId)
    {
        var store = new AgentSignedStateStore(StatePath);
        return new AgentStateCommandHandler(
            store,
            store.Track(_ => Task.FromResult(agentId)),
            new AgentLifecycleController(new InMemoryAgentLifecycleStateStore(), new NoSecrets()),
            () => { },
            null,
            () => { },
            new AgentRevokeFinalResults());
    }

    private static Task<CommandResult> Handle(AgentStateCommandHandler handler, string id, long seq)
        => handler.HandleAsync(
            new AgentCommand(id, "agent_state", id, JsonDocument.Parse($"{{\"state_seq\":{seq},\"quarantine\":{{\"active\":false}}}}").RootElement.Clone()),
            CancellationToken.None);

    private sealed class NoSecrets : ISecretStore
    {
        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
            => throw new NotSupportedException();

        public Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl, string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct)
            => Task.CompletedTask;

        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }
}
