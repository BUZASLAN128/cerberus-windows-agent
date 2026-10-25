using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

// Unit/support evidence: a persisted reset marker follows the registration binding (contract v1 (b)).
public sealed class AgentSignedStateResetTests : IDisposable
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

    private void WriteMarker(string agentId)
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(StatePath,
            $$$"""{"schema":"cerberus.agent-state.v1","state":{"agent_id":"{{{agentId}}}","state_seq":0,"quarantine_active":true,"registration_state":null,"reset":"unreadable"}}""");
    }

    [Fact]
    public async Task MarkerWithRealId_AfterRestart_QuarantinesOnlyThatIdAndReEnrolledAgentApplies()
    {
        WriteMarker("agent-a");
        var store = new AgentSignedStateStore(StatePath);

        Assert.True(store.IsQuarantined("agent-a"));
        Assert.False(store.IsQuarantined("agent-b"));
        Assert.Equal(0, store.Load("agent-b").StateSeq);
        Assert.False(store.Load("agent-b").QuarantineActive);

        var track = store.Track(_ => Task.FromResult("agent-b"));
        var handler = new AgentStateCommandHandler(
            store, track, new AgentLifecycleController(new InMemoryAgentLifecycleStateStore(), new NoSecrets()), () => { });
        await track(default);
        Assert.False(store.IsQuarantined());

        var result = await handler.HandleAsync(
            new AgentCommand("c1", "agent_state", "c1", JsonDocument.Parse("""{"state_seq":1,"quarantine":{"active":false}}""").RootElement.Clone()),
            CancellationToken.None);

        Assert.Equal("DONE", result.Status);
        var saved = new AgentSignedStateStore(StatePath).Load("agent-b");
        Assert.Equal(1, saved.StateSeq);
        Assert.Null(saved.Reset);
        Assert.DoesNotContain("reset", File.ReadAllText(StatePath));
        Assert.False(new AgentSignedStateStore(StatePath).IsQuarantined("agent-b"));
    }

    [Fact]
    public void MarkerWithUnknownId_AfterRestart_QuarantinesEveryId()
    {
        WriteMarker(AgentSignedState.UnknownAgentId);
        var store = new AgentSignedStateStore(StatePath);

        Assert.True(store.IsQuarantined());
        Assert.True(store.IsQuarantined("agent-a"));
        Assert.True(store.IsQuarantined("agent-b"));
        Assert.Equal(0, store.Load("agent-a").StateSeq);
    }

    private sealed class NoSecrets : ISecretStore
    {
        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
            => Task.FromResult((new AgentIdentity("agent-b", "t1"), "refresh", "key", "https://backend.invalid", (string?)null, (string?)null));

        public Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl, string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct)
            => Task.CompletedTask;

        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }
}
