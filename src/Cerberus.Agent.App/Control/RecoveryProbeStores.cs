using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Control;

/// <summary>
/// Lifecycle store for one scheduled recovery probe. State changes made by the probe stay in a
/// scratch store. A credential write (token rotation) runs only inside the durable store's
/// ExecuteIfCurrentAsync for the generation observed before the probe started, so an adopt,
/// unregister or retire that changed the generation turns the write into a no-op.
/// </summary>
internal sealed class FencedProbeLifecycleStore : IAgentLifecycleStateStore
{
    private readonly InMemoryAgentLifecycleStateStore _scratch = new();
    private readonly AsyncLocal<bool> _insideFence = new();
    private readonly IAgentLifecycleStateStore _durable;

    internal FencedProbeLifecycleStore(IAgentLifecycleStateStore durable, long observedGeneration)
        => (_durable, ObservedGeneration) = (durable, observedGeneration);

    internal long ObservedGeneration { get; }

    internal bool InsideFence => _insideFence.Value;

    public Task<AgentLifecycleSnapshot> LoadAsync(CancellationToken ct) => _scratch.LoadAsync(ct);

    public Task SaveAsync(AgentLifecycleSnapshot snapshot, CancellationToken ct) => _scratch.SaveAsync(snapshot, ct);

    public Task<AgentLifecycleSnapshot?> TrySaveAsync(AgentLifecycleSnapshot snapshot, long expectedRevision, CancellationToken ct)
        => _scratch.TrySaveAsync(snapshot, expectedRevision, ct);

    public async Task<bool> ExecuteIfCurrentAsync(long expectedGeneration, Func<CancellationToken, Task> action, CancellationToken ct)
    {
        var ran = false;
        var current = await _scratch.ExecuteIfCurrentAsync(expectedGeneration, async cancel =>
        {
            ran = await _durable.ExecuteIfCurrentAsync(ObservedGeneration, async inner =>
            {
                _insideFence.Value = true;
                await action(inner).ConfigureAwait(false);
            }, cancel).ConfigureAwait(false);
        }, ct).ConfigureAwait(false);
        return current && ran;
    }
}

/// <summary>
/// Machine credentials as seen by a scheduled recovery probe. Reads pass through; a write is
/// accepted only inside the durable generation fence; clearing is refused.
/// </summary>
internal sealed class RecoveryProbeSecretStore : ISecretStore
{
    private readonly ISecretStore _inner;
    private readonly FencedProbeLifecycleStore _fence;

    internal RecoveryProbeSecretStore(ISecretStore inner, FencedProbeLifecycleStore fence)
        => (_inner, _fence) = (inner, fence);

    public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
        => _inner.LoadAsync(ct);

    public Task SaveAsync(AgentIdentity identity, string refreshToken, string privateKeyPem, string backendUrl,
        string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct)
        => _fence.InsideFence
            ? _inner.SaveAsync(identity, refreshToken, privateKeyPem, backendUrl, tailscaleLoginServer, tailscaleAuthkey, ct)
            : throw new InvalidOperationException("Recovery probe credential writes require the lifecycle generation fence.");

    public Task ClearAsync(CancellationToken ct) => throw new InvalidOperationException("Recovery probe cannot clear credentials.");
}
