using Cerberus.Agent.Core;
using System.Net.Http;

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
        if (UpdateCampaignHooks.BuildTrust(log) is { } campaign) return campaign;
        return AgentUpdateTrustBuilder.Build(new AgentUpdateBuildMetadata(
            AgentUpdateDefaults.ManifestPublicKeysB64,
            AgentUpdateDefaults.ManifestUrl,
            AgentUpdateDefaults.AllowedArtifactPrefixes,
            AgentUpdateDefaults.ReleaseChannel,
            AgentUpdateDefaults.AllowedSignerKeyIdentity,
            AgentUpdateDefaults.AllowUnsignedDevBuild), WindowsDeviceInfo.GetAgentVersion(), log);
    }

    public static AgentUpdateSignal? BuildConfiguredManualSignal()
    {
        var channel = AgentUpdateTrustBuilder.NormalizeChannel(AgentUpdateDefaults.ReleaseChannel);
        var allowDevelopmentOverrides = string.Equals(channel, "dev", StringComparison.Ordinal);
        var config = AgentUpdateTrustBuilder.ReadUpdateTrustConfigFromRegistry();
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

    public static IReadOnlyList<string> ResolveUpdateManifestPublicKeys(
        string? embeddedBase64, string? envPem, string? envBase64, string? registryPem, string? registryBase64,
        IAgentLogger? log = null)
        => AgentUpdateTrustBuilder.ResolveUpdateManifestPublicKeys(embeddedBase64, envPem, envBase64, registryPem, registryBase64, log);

    public static string ResolveConfiguredManifestUrl(
        string? envUrl, string? legacyEnvUrl, string? registryUrl, string? defaultUrl = null)
        => AgentUpdateTrustBuilder.ResolveConfiguredManifestUrl(envUrl, legacyEnvUrl, registryUrl, defaultUrl);
}
