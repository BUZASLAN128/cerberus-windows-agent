using System.Reflection;

namespace Cerberus.Agent.App;

internal static class AgentBuildConfig
{
    public static string BackendUrl => string.IsNullOrWhiteSpace(BackendUrlBase64)
        ? "" : System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(BackendUrlBase64)).Trim();

    internal static bool SameEndpoint(string first, string second)
        => Uri.TryCreate(first?.Trim().TrimEnd('/'), UriKind.Absolute, out var left)
           && Uri.TryCreate(second?.Trim().TrimEnd('/'), UriKind.Absolute, out var right)
           && string.IsNullOrEmpty(left.UserInfo) && string.IsNullOrEmpty(right.UserInfo)
           && string.IsNullOrEmpty(left.Fragment) && string.IsNullOrEmpty(right.Fragment)
           && string.IsNullOrEmpty(left.Query) && string.IsNullOrEmpty(right.Query)
           && left == right;

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
