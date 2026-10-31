using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Control;

/// <summary>Stop an already-running product worker when enrollment or destination changes.</summary>
internal sealed class ProductBoundSecretStore(ISecretStore inner, AgentIdentity identity, string backendUrl, string? expectedPrivateKeyPem = null) : ISecretStore
{
    public async Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
    {
        var value = await inner.LoadAsync(ct).ConfigureAwait(false);
        if (value.Identity != identity || !AgentBuildConfig.SameEndpoint(value.BackendUrl, backendUrl)
            || (expectedPrivateKeyPem is not null && !string.Equals(value.PrivateKeyPem, expectedPrivateKeyPem, StringComparison.Ordinal)))
            throw new AgentRegistrationChangedException();
        return value;
    }

    public async Task SaveAsync(AgentIdentity value, string refreshToken, string privateKeyPem, string destination,
        string? tailscaleLoginServer, string? tailscaleAuthkey, CancellationToken ct)
    {
        if (value != identity || !AgentBuildConfig.SameEndpoint(destination, backendUrl)
            || (expectedPrivateKeyPem is not null && !string.Equals(privateKeyPem, expectedPrivateKeyPem, StringComparison.Ordinal)))
            throw new AgentRegistrationChangedException();
        await LoadAsync(ct).ConfigureAwait(false);
        await inner.SaveAsync(value, refreshToken, privateKeyPem, destination, tailscaleLoginServer, tailscaleAuthkey, ct)
            .ConfigureAwait(false);
    }

    public async Task ClearAsync(CancellationToken ct)
    {
        await LoadAsync(ct).ConfigureAwait(false);
        await inner.ClearAsync(ct).ConfigureAwait(false);
    }
}
