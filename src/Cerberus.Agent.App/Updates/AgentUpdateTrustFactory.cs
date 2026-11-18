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
        var lab = AgentUpdateLabRuntime.Resolve();
        if (lab is not null)
        {
            if (!AgentUpdateLabRuntimeAdmission.HasCommittedBootstrap(lab.Policy, lab.Context))
                throw new InvalidOperationException("Development update admission waits for bootstrap MSI commit.");
            var keys = ResolveUpdateManifestPublicKeys(AgentUpdateDefaults.ManifestPublicKeysB64, null, null, null, null, log);
            if (keys.Count != 1) throw new InvalidOperationException("Development campaign requires one embedded manifest key.");
            return new(keys, "dev", [lab.Target.ArtifactPrefix], WindowsDeviceInfo.GetAgentVersion(),
                ConfiguredManifestUrl: lab.Target.ManifestUrl, AllowedSignerKeyIdentity: "unsigned-dev",
                AllowUnsignedDevBuild: true, RequireManifestV2: true, RequireBitsDownloader: true,
                RequireSystemAuthority: true, TestCampaignVersions: AgentUpdateLabRuntime.EffectiveVersions(lab.Policy),
                TestCampaignBitsTrust: new(AgentUpdateDefaults.LabFeedRootB64, lab.Target.ArtifactPrefix, lab.Policy.ExpiresAtUtc));
        }
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

    public static string ResolveUpdateManifestPublicKey(
        string? envPem, string? envBase64, string? registryPem, string? registryBase64)
        => AgentUpdateTrustBuilder.ResolveUpdateManifestPublicKey(envPem, envBase64, registryPem, registryBase64);

    public static IReadOnlyList<string> ResolveUpdateManifestPublicKeys(
        string? embeddedBase64, string? envPem, string? envBase64, string? registryPem, string? registryBase64,
        IAgentLogger? log = null)
        => AgentUpdateTrustBuilder.ResolveUpdateManifestPublicKeys(embeddedBase64, envPem, envBase64, registryPem, registryBase64, log);

    public static string ResolveConfiguredManifestUrl(
        string? envUrl, string? legacyEnvUrl, string? registryUrl, string? defaultUrl = null)
        => AgentUpdateTrustBuilder.ResolveConfiguredManifestUrl(envUrl, legacyEnvUrl, registryUrl, defaultUrl);
}
