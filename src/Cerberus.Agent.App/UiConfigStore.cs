using System.IO;
using System.Text;
using System.Text.Json;

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
    string? CasdoorClientSecret,
    string? BootstrapDescriptorUrl);

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
        CasdoorEndpoint: BuildDefaultOr(AgentBuildConfig.SsoBaseUrlBase64, "http://100.101.130.51:31080"),
        // NOTE: client_id is public (not a secret). Keep override via env/config for other deployments.
        CasdoorClientId: BuildDefaultOr(AgentBuildConfig.SsoClientIdBase64, "610f03b77494869da4ef"),
        // Include "groups" because backend maps tenant from group membership.
        CasdoorScope: BuildDefaultOr(AgentBuildConfig.SsoScopeBase64, "openid profile email groups"),
        OAuthRedirectPort: IsValidPort(AgentBuildConfig.OAuthRedirectPort)
            ? AgentBuildConfig.OAuthRedirectPort
            : 19823);

    private static bool IsLegacyLocalBackend(string url)
    {
        var v = (url ?? "").Trim().TrimEnd('/');
        return string.Equals(v, "http://localhost:5001", StringComparison.OrdinalIgnoreCase)
               || string.Equals(v, "http://127.0.0.1:5001", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsLegacyLocalSso(string url)
    {
        var v = (url ?? "").Trim().TrimEnd('/');
        return string.Equals(v, "http://localhost:31080", StringComparison.OrdinalIgnoreCase)
               || string.Equals(v, "http://127.0.0.1:31080", StringComparison.OrdinalIgnoreCase);
    }

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

            // Auto-migrate legacy defaults that break current dev/test setup.
            // If you really want localhost endpoints, override explicitly via env vars.
            var migrated = parsed;
            if (IsLegacyLocalBackend(migrated.BackendUrl))
                migrated = migrated with { BackendUrl = Default.BackendUrl };
            if (IsLegacyLocalSso(migrated.CasdoorEndpoint))
                migrated = migrated with { CasdoorEndpoint = Default.CasdoorEndpoint };
            if (string.IsNullOrWhiteSpace(migrated.CasdoorClientId))
                migrated = migrated with { CasdoorClientId = Default.CasdoorClientId };
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

        var backendUrl = (Environment.GetEnvironmentVariable("CERBERUS_BACKEND_URL") ?? cfg.BackendUrl).Trim();
        if (string.IsNullOrWhiteSpace(backendUrl) && IsExplicitDevBootstrap())
            backendUrl = "http://127.0.0.1:8000";

        // Support both generic SSO env vars and legacy CERBERUS_CASDOOR_* ones.
        // Do NOT read plain CASDOOR_* env vars to avoid accidental localhost misconfig on dev machines.
        var casdoorEndpoint = (Environment.GetEnvironmentVariable("CERBERUS_SSO_BASE_URL")
                               ?? Environment.GetEnvironmentVariable("CERBERUS_CASDOOR_ENDPOINT")
                               ?? cfg.CasdoorEndpoint).Trim();

        var clientId = (Environment.GetEnvironmentVariable("CERBERUS_SSO_CLIENT_ID")
                        ?? Environment.GetEnvironmentVariable("CERBERUS_CASDOOR_CLIENT_ID")
                        ?? cfg.CasdoorClientId).Trim();

        // Secret is env-only and never persisted in ui-config.json
        var clientSecret = (Environment.GetEnvironmentVariable("CERBERUS_SSO_CLIENT_SECRET")
                            ?? Environment.GetEnvironmentVariable("CERBERUS_CASDOOR_CLIENT_SECRET")
                            ?? "").Trim();

        var scope = (Environment.GetEnvironmentVariable("CERBERUS_SSO_SCOPE")
                     ?? Environment.GetEnvironmentVariable("CERBERUS_CASDOOR_SCOPE")
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
            CasdoorClientSecret: string.IsNullOrWhiteSpace(clientSecret) ? null : clientSecret,
            BootstrapDescriptorUrl: NormalizeOptional(
                Environment.GetEnvironmentVariable("CERBERUS_AGENT_BOOTSTRAP_DESCRIPTOR_URL")));
    }

    private static string? NormalizeOptional(string? value)
    {
        var normalized = (value ?? "").Trim();
        return string.IsNullOrWhiteSpace(normalized) ? null : normalized;
    }

    private static bool IsExplicitDevBootstrap()
    {
        var raw = Environment.GetEnvironmentVariable("CERBERUS_AGENT_DEV_BOOTSTRAP");
        return string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase)
               || string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase)
               || string.Equals(raw, "yes", StringComparison.OrdinalIgnoreCase);
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
