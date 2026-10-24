using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Control;

/// <summary>
/// Unattended-profile move of the registered backend address to the address compiled
/// into the package. Only the compiled value qualifies; environment, installer and UI
/// configuration values never change a registration. Identity, key and tokens are kept
/// and the new address is published through the secret store's atomic write.
/// </summary>
internal static class ServerBackendMigration
{
    /// <summary>
    /// True when a registered address should be replaced by the compiled one: the profile is
    /// active, no environment override is present, the compiled address is a plain https
    /// endpoint and it differs from the registered address.
    /// </summary>
    internal static bool ShouldMigrate(string storedBackendUrl, string compiledBackendUrl, string? environmentBackendUrl)
    {
        if (!AgentBuildProfile.IsServer || environmentBackendUrl is not null)
            return false;
        if (string.IsNullOrWhiteSpace(compiledBackendUrl) || string.IsNullOrWhiteSpace(storedBackendUrl))
            return false;
        if (!Uri.TryCreate(compiledBackendUrl.Trim().TrimEnd('/'), UriKind.Absolute, out var target) ||
            target.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(target.UserInfo) || !string.IsNullOrEmpty(target.Query) || !string.IsNullOrEmpty(target.Fragment))
            return false;
        return !AgentBuildConfig.SameEndpoint(storedBackendUrl, compiledBackendUrl);
    }

    /// <summary>Host and port only, for logging.</summary>
    internal static string HostPort(string url)
        => Uri.TryCreate(url?.Trim(), UriKind.Absolute, out var uri) ? $"{uri.Host}:{uri.Port}" : "unknown";

    /// <summary>Persists the compiled address next to the unchanged credentials and returns it.</summary>
    internal static async Task<string> MigrateAsync(
        ISecretStore secrets,
        (AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey) current,
        string compiledBackendUrl,
        CancellationToken ct)
    {
        var target = compiledBackendUrl.Trim();
        await secrets.SaveAsync(current.Identity, current.RefreshToken, current.PrivateKeyPem, target,
            current.TailscaleLoginServer, current.TailscaleAuthkey, ct).ConfigureAwait(false);
        return target;
    }
}
