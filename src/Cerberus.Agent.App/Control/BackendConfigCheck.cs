using Cerberus.Agent.Core;

namespace Cerberus.Agent.App.Control;

/// <summary>
/// Local, network-free check of the configured backend address against the registration and the
/// compiled address. Shared by the service start and the server-profile recovery supervisor.
/// </summary>
internal static class BackendConfigCheck
{
    internal const string UrlInvalid = "backend_url_invalid";
    internal const string EnvironmentMismatch = "backend_environment_mismatch";

    /// <summary>
    /// Returns the BlockedConfig reason code for the given environment value, registered address and
    /// compiled address, or null when registered credentials may be used against the effective address.
    /// </summary>
    internal static string? BlockReason(string? environmentBackendUrl, string storedBackendUrl, string compiledBackendUrl)
    {
        var backendUrl = environmentBackendUrl ?? storedBackendUrl;
        if (!Uri.TryCreate(backendUrl.Trim().TrimEnd('/'), UriKind.Absolute, out var baseAddress) ||
            (baseAddress.Scheme != Uri.UriSchemeHttp && baseAddress.Scheme != Uri.UriSchemeHttps))
            return UrlInvalid;

        // Never send registered credentials to an environment selected by a different package or override.
        if (!AgentBuildConfig.SameEndpoint(backendUrl, storedBackendUrl) ||
            (!string.IsNullOrWhiteSpace(compiledBackendUrl) &&
             !AgentBuildConfig.SameEndpoint(storedBackendUrl, compiledBackendUrl)))
            return EnvironmentMismatch;
        return null;
    }
}
