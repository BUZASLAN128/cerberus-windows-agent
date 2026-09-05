using Cerberus.Agent.Core;
using Microsoft.Win32;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

namespace Cerberus.Agent.App.Updates;

internal static class AgentUpdateTrustFactory
{
    public static AgentUpdateCoordinator? BuildCoordinator(
        HttpClient http,
        IAgentLogger log,
        AgentUpdateStateStore? stateStore = null)
    {
        try
        {
            var trust = BuildTrust(log);
            return new AgentUpdateCoordinator(
                new AgentUpdateStager(http, trust, AgentUpdateStager.DefaultStagingRoot, log),
                log,
                stateStore);
        }
        catch (InvalidOperationException ex)
        {
            log.Warn($"Agent update trust unavailable: {ex.GetType().Name}.");
            return null;
        }
    }

    internal static AgentUpdateTrust BuildTrust(IAgentLogger? log = null)
    {
        var registryConfig = ReadUpdateTrustConfigFromRegistry();
        var expectedChannel = NormalizeChannel(AgentUpdateDefaults.ReleaseChannel);
        if (!IsSupportedChannel(expectedChannel))
            throw new InvalidOperationException("Agent release channel is invalid.");

        var registryChannel = NormalizeChannel(registryConfig.GetValueOrDefault("updateChannel"));
        if (!string.IsNullOrWhiteSpace(registryChannel) &&
            !string.Equals(registryChannel, expectedChannel, StringComparison.Ordinal))
            throw new InvalidOperationException("Installed update channel does not match this build.");

        var allowDevelopmentOverrides = string.Equals(expectedChannel, "dev", StringComparison.Ordinal);
        var publicKeys = ResolveUpdateManifestPublicKeys(
            AgentUpdateDefaults.ManifestPublicKeysB64,
            allowDevelopmentOverrides ? Environment.GetEnvironmentVariable("CERBERUS_AGENT_UPDATE_MANIFEST_PUBLIC_KEY_PEM") : null,
            allowDevelopmentOverrides ? Environment.GetEnvironmentVariable("CERBERUS_AGENT_UPDATE_MANIFEST_PUBLIC_KEY_B64") : null,
            registryConfig.GetValueOrDefault("updateManifestPublicKeyPem"),
            registryConfig.GetValueOrDefault("updateManifestPublicKeyB64"),
            log);
        if (publicKeys.Count == 0)
            throw new InvalidOperationException("Update manifest public key is not configured.");

        var configuredUrl = ResolveConfiguredManifestUrl(
            allowDevelopmentOverrides ? Environment.GetEnvironmentVariable("CERBERUS_AGENT_UPDATE_MANIFEST_URL") : null,
            allowDevelopmentOverrides ? Environment.GetEnvironmentVariable("AGENT_UPDATE_MANIFEST_URL") : null,
            registryConfig.GetValueOrDefault("updateManifestUrl"),
            AgentUpdateDefaults.ManifestUrl);
        if (string.IsNullOrWhiteSpace(configuredUrl))
            throw new InvalidOperationException("Update manifest URL is not configured.");
        if (!Uri.TryCreate(configuredUrl, UriKind.Absolute, out var configuredUri) ||
            !string.Equals(configuredUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Update manifest URL must use HTTPS.");

        var prefixSource = registryConfig.GetValueOrDefault("updateAllowedArtifactPrefixes");
        if (string.IsNullOrWhiteSpace(prefixSource) || allowDevelopmentOverrides)
            prefixSource = AgentUpdateDefaults.AllowedArtifactPrefixes;
        var prefixes = SplitCsv(prefixSource);
        var allowUnsignedDevBuild = allowDevelopmentOverrides && AgentUpdateDefaults.AllowUnsignedDevBuild;
        return new AgentUpdateTrust(
            ManifestPublicKeyPems: publicKeys,
            ExpectedChannel: expectedChannel,
            AllowedArtifactPrefixes: prefixes,
            CurrentVersion: WindowsDeviceInfo.GetAgentVersion(),
            AllowRollbackManifest: false,
            AllowChannelDowngrade: false,
            ConfiguredManifestUrl: configuredUrl,
            AllowedSignerKeyIdentity: AgentUpdateDefaults.AllowedSignerKeyIdentity,
            AllowUnsignedDevBuild: allowUnsignedDevBuild,
            RequireManifestV2: !string.Equals(expectedChannel, "dev", StringComparison.Ordinal),
            RequireBitsDownloader: true,
            RequireSystemAuthority: true);
    }

    public static AgentUpdateSignal? BuildConfiguredManualSignal()
    {
        var channel = NormalizeChannel(AgentUpdateDefaults.ReleaseChannel);
        var allowDevelopmentOverrides = string.Equals(channel, "dev", StringComparison.Ordinal);
        var config = ReadUpdateTrustConfigFromRegistry();
        var manifestUrl = ResolveConfiguredManifestUrl(
            allowDevelopmentOverrides ? Environment.GetEnvironmentVariable("CERBERUS_AGENT_UPDATE_MANIFEST_URL") : null,
            allowDevelopmentOverrides ? Environment.GetEnvironmentVariable("AGENT_UPDATE_MANIFEST_URL") : null,
            config.GetValueOrDefault("updateManifestUrl"),
            AgentUpdateDefaults.ManifestUrl);
        if (string.IsNullOrWhiteSpace(manifestUrl))
            return null;
        if (!Uri.TryCreate(manifestUrl, UriKind.Absolute, out var manifestUri) ||
            !string.Equals(manifestUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            return null;

        return new AgentUpdateSignal(
            Required: false,
            Recommended: true,
            ManifestUrl: manifestUrl,
            Reason: "manual_update_check",
            Channel: channel);
    }

    public static string ResolveUpdateManifestPublicKey(
        string? envPem,
        string? envBase64,
        string? registryPem,
        string? registryBase64)
        => ResolveUpdateManifestPublicKeys(
                embeddedBase64: null,
                envPem: envPem,
                envBase64: envBase64,
                registryPem: registryPem,
                registryBase64: registryBase64)
            .FirstOrDefault() ?? "";

    public static IReadOnlyList<string> ResolveUpdateManifestPublicKeys(
        string? embeddedBase64,
        string? envPem,
        string? envBase64,
        string? registryPem,
        string? registryBase64,
        IAgentLogger? log = null)
    {
        var publicKeys = new List<string>();
        AddDecodedPublicKeys(publicKeys, embeddedBase64, "embedded", log);
        AddPlainPublicKeys(publicKeys, envPem, "environment PEM", log);
        AddDecodedPublicKeys(publicKeys, envBase64, "environment base64", log);
        AddPlainPublicKeys(publicKeys, registryPem, "registry PEM", log);
        AddDecodedPublicKeys(publicKeys, registryBase64, "registry base64", log);
        return publicKeys;
    }

    public static string ResolveConfiguredManifestUrl(
        string? envUrl,
        string? legacyEnvUrl,
        string? registryUrl,
        string? defaultUrl = null)
    {
        foreach (var candidate in new[] { envUrl, legacyEnvUrl, registryUrl, defaultUrl })
        {
            var normalized = NormalizeManifestUrl(candidate);
            if (!string.IsNullOrWhiteSpace(normalized))
                return normalized;
        }

        return "";
    }

    private static void AddPlainPublicKeys(List<string> publicKeys, string? source, string sourceName, IAgentLogger? log)
    {
        foreach (var candidate in SplitPlainPublicKeySource(source))
            TryAddPublicKey(publicKeys, candidate, sourceName, log);
    }

    private static void AddDecodedPublicKeys(List<string> publicKeys, string? source, string sourceName, IAgentLogger? log)
    {
        foreach (var candidate in SplitPublicKeySource(source))
        {
            try
            {
                TryAddPublicKey(
                    publicKeys,
                    Encoding.UTF8.GetString(Convert.FromBase64String(candidate)).Trim(),
                    sourceName,
                    log);
            }
            catch (FormatException)
            {
                log?.Warn($"Agent update trust ignored invalid {sourceName} manifest public key.");
            }
        }
    }

    private static void TryAddPublicKey(List<string> publicKeys, string publicKeyPem, string sourceName, IAgentLogger? log)
    {
        if (string.IsNullOrWhiteSpace(publicKeyPem))
            return;

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(publicKeyPem);
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or CryptographicException)
        {
            log?.Warn($"Agent update trust ignored invalid {sourceName} manifest public key.");
            return;
        }

        var normalized = publicKeyPem.Trim();
        if (!publicKeys.Contains(normalized, StringComparer.Ordinal))
            publicKeys.Add(normalized);
    }

    private static IReadOnlyDictionary<string, string?> ReadUpdateTrustConfigFromRegistry()
    {
        var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        if (!OperatingSystem.IsWindows())
            return values;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"Software\Cerberus\WindowsAgent", writable: false);
            if (key is null)
                return values;

            values["updateManifestPublicKeyPem"] = key.GetValue("updateManifestPublicKeyPem")?.ToString();
            values["updateManifestPublicKeyB64"] = key.GetValue("updateManifestPublicKeyB64")?.ToString();
            values["updateAllowedArtifactPrefixes"] = key.GetValue("updateAllowedArtifactPrefixes")?.ToString();
            values["updateManifestUrl"] = key.GetValue("updateManifestUrl")?.ToString();
            values["updateChannel"] = key.GetValue("updateChannel")?.ToString();
        }
        catch (System.Security.SecurityException)
        {
            return values;
        }
        catch (UnauthorizedAccessException)
        {
            return values;
        }

        return values;
    }

    private static IReadOnlyList<string> SplitCsv(string? value)
        => string.IsNullOrWhiteSpace(value)
            ? Array.Empty<string>()
            : value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(item => !string.IsNullOrWhiteSpace(item) && !string.Equals(item, "__cerberus_unset__", StringComparison.Ordinal))
                .ToArray();

    private static IEnumerable<string> SplitPublicKeySource(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            yield break;

        foreach (var item in value.Split(
                     new[] { ',', ';', '\r', '\n' },
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (!string.Equals(item, "__cerberus_unset__", StringComparison.Ordinal))
                yield return item;
        }
    }

    private static IEnumerable<string> SplitPlainPublicKeySource(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            yield break;

        var trimmed = value.Trim();
        if (string.Equals(trimmed, "__cerberus_unset__", StringComparison.Ordinal))
            yield break;
        if (trimmed.Contains("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal))
        {
            yield return trimmed;
            yield break;
        }

        foreach (var item in trimmed.Split(',', ';'))
        {
            if (!string.Equals(item.Trim(), "__cerberus_unset__", StringComparison.Ordinal))
                yield return item.Trim();
        }
    }

    private static string NormalizeManifestUrl(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "";
        var trimmed = value.Trim();
        return string.Equals(trimmed, "__cerberus_unset__", StringComparison.Ordinal) ? "" : trimmed;
    }

    private static string NormalizeChannel(string? value)
        => string.IsNullOrWhiteSpace(value) ? "" : value.Trim().ToLowerInvariant();

    private static bool IsSupportedChannel(string channel)
        => channel is "dev" or "preview" or "stable";
}
