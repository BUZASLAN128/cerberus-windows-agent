using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

// Test-only doubles shared by the dormant recovery runner, supervisor and migration tests.

internal sealed class CountingLogger : IAgentLogger
{
    public int Warnings;
    public void Info(string message) { }
    public void Warn(string message) => Warnings++;
    public void Error(string message, Exception? ex = null) { }
}

/// <summary>Lifecycle store whose revision-checked saves can be made to fail like a broken durable write.</summary>
internal sealed class FailingSaveLifecycleStore : IAgentLifecycleStateStore
{
    private readonly InMemoryAgentLifecycleStateStore _inner;
    public bool FailSaves;

    public FailingSaveLifecycleStore(AgentLifecycleSnapshot initial) => _inner = new InMemoryAgentLifecycleStateStore(initial);

    public Task<AgentLifecycleSnapshot> LoadAsync(CancellationToken ct) => _inner.LoadAsync(ct);
    public Task SaveAsync(AgentLifecycleSnapshot snapshot, CancellationToken ct) => _inner.SaveAsync(snapshot, ct);
    public Task<AgentLifecycleSnapshot?> TrySaveAsync(AgentLifecycleSnapshot snapshot, long expectedRevision, CancellationToken ct)
        => FailSaves ? throw new IOException("durable write failed") : _inner.TrySaveAsync(snapshot, expectedRevision, ct);
    public Task<bool> ExecuteIfCurrentAsync(long expectedGeneration, Func<CancellationToken, Task> action, CancellationToken ct)
        => _inner.ExecuteIfCurrentAsync(expectedGeneration, action, ct);
}

/// <summary>In-memory credentials with call counters and an optional load failure.</summary>
internal sealed class MemorySecretStore : ISecretStore
{
    private (AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? Login, string? Key) _value;
    public int Loads;
    public int Saves;
    public int Clears;
    public Exception? LoadError;

    public MemorySecretStore(string backendUrl)
        => _value = (new AgentIdentity("agent-id-1", "tenant-id-1"), "refresh-1", "key-pem-1", backendUrl, null, null);

    public string BackendUrl => _value.BackendUrl;

    public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
    {
        Loads++;
        return LoadError is null ? Task.FromResult(_value) : throw LoadError;
    }

    public Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl,
        string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct)
    {
        Saves++;
        _value = (identity, refreshToken, privateKeyPem, backendUrl, tailscaleLoginServer, tailscaleAuthkey);
        return Task.CompletedTask;
    }

    public Task ClearAsync(CancellationToken ct)
    {
        Clears++;
        return Task.CompletedTask;
    }
}
