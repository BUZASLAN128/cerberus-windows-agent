using System.Reflection;

namespace Cerberus.Agent.App;

internal static class AgentBuildConfig
{
    public static string BackendUrlBase64 => Metadata("AgentDefaultBackendUrlBase64");
    public static string SsoBaseUrlBase64 => Metadata("AgentDefaultSsoBaseUrlBase64");
    public static string SsoClientIdBase64 => Metadata("AgentDefaultSsoClientIdBase64");
    public static string SsoScopeBase64 => Metadata("AgentDefaultSsoScopeBase64");

    public static int OAuthRedirectPort
        => int.TryParse(Metadata("AgentDefaultOAuthRedirectPort"), out var port) ? port : 0;

    private static string Metadata(string key)
        => typeof(AgentBuildConfig).Assembly
               .GetCustomAttributes<AssemblyMetadataAttribute>()
               .FirstOrDefault(attr => string.Equals(attr.Key, key, StringComparison.Ordinal))?
               .Value
           ?? "";
}
