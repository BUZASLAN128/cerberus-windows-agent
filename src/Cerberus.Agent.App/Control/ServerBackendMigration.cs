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
    internal enum Result { Superseded, NotNeeded, AtTarget, Migrated }

    /// <summary>
    /// True when the compiled address may be a migration target: the profile is active, no
    /// environment override is present and the compiled address is a plain https endpoint.
    /// </summary>
    internal static bool IsCompiledTarget(string compiledBackendUrl, string? environmentBackendUrl)
        => AgentBuildProfile.IsServer && environmentBackendUrl is null &&
            !string.IsNullOrWhiteSpace(compiledBackendUrl) &&
            Uri.TryCreate(compiledBackendUrl.Trim().TrimEnd('/'), UriKind.Absolute, out var target) &&
            target.Scheme == Uri.UriSchemeHttps &&
            string.IsNullOrEmpty(target.UserInfo) && string.IsNullOrEmpty(target.Query) && string.IsNullOrEmpty(target.Fragment);

    /// <summary>True when a registered address should be replaced by a valid compiled target that differs from it.</summary>
    internal static bool ShouldMigrate(string storedBackendUrl, string compiledBackendUrl, string? environmentBackendUrl)
        => IsCompiledTarget(compiledBackendUrl, environmentBackendUrl) && !string.IsNullOrWhiteSpace(storedBackendUrl) &&
            !AgentBuildConfig.SameEndpoint(storedBackendUrl, compiledBackendUrl);

    /// <summary>Secret-store and lifecycle-fence failures that leave the registration unchanged.</summary>
    internal static bool IsStoreFailure(Exception ex)
        => ex is System.IO.IOException or UnauthorizedAccessException or InvalidOperationException
            or System.Security.Cryptography.CryptographicException or System.Text.Json.JsonException
            or System.IO.InvalidDataException;

    /// <summary>
    /// Re-reads the registration and moves it to the compiled address only while the durable
    /// lifecycle still has <paramref name="generation"/>. Superseded means the generation changed
    /// and nothing was written.
    /// </summary>
    internal static async Task<Result> MigrateIfCurrentAsync(
        IAgentLifecycleStateStore lifecycle,
        long generation,
        ISecretStore secrets,
        string compiledBackendUrl,
        string? environmentBackendUrl,
        IAgentLogger log,
        CancellationToken ct)
    {
        var result = Result.NotNeeded;
        var from = string.Empty;
        var current = await lifecycle.ExecuteIfCurrentAsync(generation, async cancel =>
        {
            var registered = await secrets.LoadAsync(cancel).ConfigureAwait(false);
            if (ShouldMigrate(registered.BackendUrl, compiledBackendUrl, environmentBackendUrl))
            {
                await MigrateAsync(secrets, registered, compiledBackendUrl, cancel).ConfigureAwait(false);
                (from, result) = (registered.BackendUrl, Result.Migrated);
            }
            else if (IsCompiledTarget(compiledBackendUrl, environmentBackendUrl) &&
                AgentBuildConfig.SameEndpoint(registered.BackendUrl, compiledBackendUrl))
            {
                result = Result.AtTarget;
            }
        }, ct).ConfigureAwait(false);
        if (!current)
            return Result.Superseded;
        if (result == Result.Migrated)
            log.Info($"Registered backend address updated from {HostPort(from)} to {HostPort(compiledBackendUrl)}.");
        return result;
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
