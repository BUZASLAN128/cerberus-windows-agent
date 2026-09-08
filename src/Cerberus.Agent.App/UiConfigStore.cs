using System.IO;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

namespace Cerberus.Agent.App;

// Persisted config is deliberately "non-secret" only.
// Secrets must never be stored here; use env vars / OS secret store instead.
internal sealed record PersistedUiConfig(
    string BackendUrl,
    string CasdoorEndpoint,
    string CasdoorClientId,
    string CasdoorScope,
    int OAuthRedirectPort);

// Runtime config may include env-only secrets (not persisted).
internal sealed record RuntimeUiConfig(
    string BackendUrl,
    string CasdoorEndpoint,
    string CasdoorClientId,
    string CasdoorScope,
    int OAuthRedirectPort,
    string? CasdoorClientSecret);

internal static class UiConfigStore
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
    };

    private static string ConfigDir => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "CerberusAgent");

    private static string ConfigPath => Path.Combine(ConfigDir, "ui-config.json");

    private static PersistedUiConfig Default => new(
        // Public values only. Build-time defaults can be provided by CI for dev/local artifacts.
        BackendUrl: BuildDefaultOrEmpty(AgentBuildConfig.BackendUrlBase64),
        CasdoorEndpoint: BuildDefaultOrEmpty(AgentBuildConfig.SsoBaseUrlBase64),
        // NOTE: client_id is public (not a secret). Keep override via env/config for other deployments.
        CasdoorClientId: BuildDefaultOrEmpty(AgentBuildConfig.SsoClientIdBase64),
        // Include "groups" because backend maps tenant from group membership.
        CasdoorScope: BuildDefaultOr(AgentBuildConfig.SsoScopeBase64, "openid profile email groups"),
        OAuthRedirectPort: IsValidPort(AgentBuildConfig.OAuthRedirectPort)
            ? AgentBuildConfig.OAuthRedirectPort
            : 19823);

    internal static bool SameEndpoint(string first, string second)
        => AgentBuildConfig.SameEndpoint(first, second);

    internal static bool MatchesBuildRouting(RuntimeUiConfig config)
        => MatchesBuildRouting(config, Default);

    internal static bool MatchesBuildRouting(RuntimeUiConfig config, PersistedUiConfig build)
        => (string.IsNullOrWhiteSpace(build.BackendUrl) || SameEndpoint(config.BackendUrl, build.BackendUrl))
           && (string.IsNullOrWhiteSpace(build.CasdoorEndpoint) || SameEndpoint(config.CasdoorEndpoint, build.CasdoorEndpoint))
           && (string.IsNullOrWhiteSpace(build.CasdoorClientId)
               || string.Equals(config.CasdoorClientId, build.CasdoorClientId, StringComparison.Ordinal));

    public static PersistedUiConfig Load()
    {
        try
        {
            if (!File.Exists(ConfigPath))
                return Default;

            var raw = File.ReadAllText(ConfigPath);
            var parsed = JsonSerializer.Deserialize<PersistedUiConfig>(raw, JsonOpts);
            if (parsed is null)
                return Default;

            // Preserve deployment identity; upgrading a package must not rebind saved endpoints.
            var migrated = parsed;
            var scope = (migrated.CasdoorScope ?? "").Trim();
            if (string.IsNullOrWhiteSpace(scope))
            {
                migrated = migrated with { CasdoorScope = Default.CasdoorScope };
            }
            else if (string.Equals(scope, "openid profile email", StringComparison.OrdinalIgnoreCase))
            {
                // Ensure tenant mapping works reliably.
                migrated = migrated with { CasdoorScope = Default.CasdoorScope };
            }
            if (migrated.OAuthRedirectPort <= 0 || migrated.OAuthRedirectPort > 65535)
                migrated = migrated with { OAuthRedirectPort = Default.OAuthRedirectPort };

            if (!ReferenceEquals(migrated, parsed))
            {
                try { Save(migrated); } catch { }
            }

            return migrated;
        }
        catch
        {
            return Default;
        }
    }

    public static void Save(PersistedUiConfig config)
    {
        Directory.CreateDirectory(ConfigDir);
        var raw = JsonSerializer.Serialize(config, JsonOpts);
        File.WriteAllText(ConfigPath, raw);
    }

    public static RuntimeUiConfig LoadMergedWithEnv()
    {
        var cfg = Load();
        var installerConfig = LoadInstallerConfig();

        var backendUrl = (Environment.GetEnvironmentVariable("CERBERUS_BACKEND_URL")
                          ?? installerConfig.GetValueOrDefault("backendUrl")
                          ?? cfg.BackendUrl).Trim();
        if (string.IsNullOrWhiteSpace(backendUrl) && IsExplicitDevBootstrap())
            backendUrl = "http://127.0.0.1:8000";

        // Support both generic SSO env vars and legacy CERBERUS_CASDOOR_* ones.
        // Do NOT read plain CASDOOR_* env vars to avoid accidental localhost misconfig on dev machines.
        var casdoorEndpoint = (Environment.GetEnvironmentVariable("CERBERUS_SSO_BASE_URL")
                               ?? Environment.GetEnvironmentVariable("CERBERUS_CASDOOR_ENDPOINT")
                               ?? installerConfig.GetValueOrDefault("ssoBaseUrl")
                               ?? cfg.CasdoorEndpoint).Trim();

        var clientId = (Environment.GetEnvironmentVariable("CERBERUS_SSO_CLIENT_ID")
                        ?? Environment.GetEnvironmentVariable("CERBERUS_CASDOOR_CLIENT_ID")
                        ?? installerConfig.GetValueOrDefault("ssoClientId")
                        ?? cfg.CasdoorClientId).Trim();

        // Secret is env-only and never persisted in ui-config.json
        var clientSecret = (Environment.GetEnvironmentVariable("CERBERUS_SSO_CLIENT_SECRET")
                            ?? Environment.GetEnvironmentVariable("CERBERUS_CASDOOR_CLIENT_SECRET")
                            ?? "").Trim();

        var scope = (Environment.GetEnvironmentVariable("CERBERUS_SSO_SCOPE")
                     ?? Environment.GetEnvironmentVariable("CERBERUS_CASDOOR_SCOPE")
                     ?? installerConfig.GetValueOrDefault("ssoScope")
                     ?? cfg.CasdoorScope).Trim();
        if (string.Equals(scope, "openid profile email", StringComparison.OrdinalIgnoreCase))
            scope = Default.CasdoorScope;

        var redirectPortStr = (Environment.GetEnvironmentVariable("CERBERUS_OAUTH_REDIRECT_PORT") ?? "").Trim();
        var redirectPort = cfg.OAuthRedirectPort;
        if (int.TryParse(redirectPortStr, out var p) && p > 0 && p <= 65535)
            redirectPort = p;

        return new RuntimeUiConfig(
            BackendUrl: backendUrl,
            CasdoorEndpoint: casdoorEndpoint,
            CasdoorClientId: clientId,
            CasdoorScope: string.IsNullOrWhiteSpace(scope) ? Default.CasdoorScope : scope,
            OAuthRedirectPort: redirectPort,
            CasdoorClientSecret: string.IsNullOrWhiteSpace(clientSecret) ? null : clientSecret);
    }

    private static bool IsExplicitDevBootstrap()
    {
        var raw = Environment.GetEnvironmentVariable("CERBERUS_AGENT_DEV_BOOTSTRAP");
        return string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase)
               || string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase)
               || string.Equals(raw, "yes", StringComparison.OrdinalIgnoreCase);
    }

    private static IReadOnlyDictionary<string, string?> LoadInstallerConfig()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Cerberus\WindowsAgent");
            if (key is null)
                return new Dictionary<string, string?>();

            return new Dictionary<string, string?>
            {
                ["backendUrl"] = NonEmpty(key.GetValue("backendUrl")?.ToString()),
                ["ssoBaseUrl"] = NonEmpty(key.GetValue("ssoBaseUrl")?.ToString()),
                ["ssoClientId"] = NonEmpty(key.GetValue("ssoClientId")?.ToString()),
                ["ssoScope"] = NonEmpty(key.GetValue("ssoScope")?.ToString()),
            };
        }
        catch
        {
            return new Dictionary<string, string?>();
        }
    }

    private static string? NonEmpty(string? value)
    {
        var trimmed = (value ?? "").Trim();
        return string.IsNullOrWhiteSpace(trimmed) ? null : trimmed;
    }

    private static string BuildDefaultOrEmpty(string base64)
        => BuildDefaultOr(base64, "");

    private static string BuildDefaultOr(string base64, string fallback)
    {
        if (string.IsNullOrWhiteSpace(base64))
            return fallback;

        try
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(base64)).Trim();
        }
        catch
        {
            return fallback;
        }
    }

    private static bool IsValidPort(int port)
        => port is > 0 and <= 65535;
}
