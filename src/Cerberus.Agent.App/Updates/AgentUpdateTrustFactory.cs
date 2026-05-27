using Cerberus.Agent.Core;
using Microsoft.Win32;
using System.Net.Http;
using System.Text;

namespace Cerberus.Agent.App.Updates;

internal static class AgentUpdateTrustFactory
{
    public static AgentUpdateCoordinator? BuildCoordinator(HttpClient http, IAgentLogger log)
    {
        var registryConfig = ReadUpdateTrustConfigFromRegistry();
        string publicKey;
        try
        {
            publicKey = ResolveUpdateManifestPublicKey(
                Environment.GetEnvironmentVariable("CERBERUS_AGENT_UPDATE_MANIFEST_PUBLIC_KEY_PEM"),
                Environment.GetEnvironmentVariable("CERBERUS_AGENT_UPDATE_MANIFEST_PUBLIC_KEY_B64"),
                registryConfig.GetValueOrDefault("updateManifestPublicKeyPem"),
                registryConfig.GetValueOrDefault("updateManifestPublicKeyB64"));
        }
        catch (FormatException)
        {
            log.Warn("Agent update trust disabled because the configured manifest public key is not valid base64.");
            return null;
        }

        if (string.IsNullOrWhiteSpace(publicKey))
            return null;

        var prefixSource = Environment.GetEnvironmentVariable("CERBERUS_AGENT_UPDATE_ALLOWED_ARTIFACT_PREFIXES");
        if (string.IsNullOrWhiteSpace(prefixSource))
            registryConfig.TryGetValue("updateAllowedArtifactPrefixes", out prefixSource);

        var trust = new AgentUpdateTrust(
            ManifestPublicKeyPem: publicKey,
            ExpectedChannel: WindowsDeviceInfo.GetBuildChannel(),
            AllowedArtifactPrefixes: SplitCsv(prefixSource),
            CurrentVersion: WindowsDeviceInfo.GetAgentVersion());
        return new AgentUpdateCoordinator(new AgentUpdateStager(http, trust, AgentUpdateStager.DefaultStagingRoot, log), log);
    }

    public static string ResolveUpdateManifestPublicKey(
        string? envPem,
        string? envBase64,
        string? registryPem,
        string? registryBase64)
    {
        if (!string.IsNullOrWhiteSpace(envPem))
            return envPem.Trim();

        var decodedEnv = DecodeUpdateManifestPublicKey(envBase64);
        if (!string.IsNullOrWhiteSpace(decodedEnv))
            return decodedEnv;

        if (!string.IsNullOrWhiteSpace(registryPem))
            return registryPem.Trim();

        return DecodeUpdateManifestPublicKey(registryBase64);
    }

    private static string DecodeUpdateManifestPublicKey(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "";
        var bytes = Convert.FromBase64String(value.Trim());
        return Encoding.UTF8.GetString(bytes).Trim();
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
    {
        if (string.IsNullOrWhiteSpace(value))
            return Array.Empty<string>();
        return value
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(item => !string.IsNullOrWhiteSpace(item) && !string.Equals(item, "__cerberus_unset__", StringComparison.Ordinal))
            .ToArray();
    }
}
