using System.Reflection;

namespace Cerberus.Agent.Core;

public sealed record AgentUpdateBuildMetadata(
    string ManifestPublicKeysB64,
    string ManifestUrl,
    string AllowedArtifactPrefixes,
    string ReleaseChannel,
    string AllowedSignerKeyIdentity,
    bool AllowUnsignedDevBuild)
{
    public static AgentUpdateBuildMetadata Read(Assembly assembly)
    {
        string ReadValue(string key) => assembly.GetCustomAttributes<AssemblyMetadataAttribute>()
            .FirstOrDefault(attribute => string.Equals(attribute.Key, key, StringComparison.Ordinal))?.Value?.Trim() ?? "";

        var channel = ReadValue("AgentReleaseChannel");
        return new(
            ReadValue("AgentUpdateManifestPublicKeysB64"),
            ReadValue("AgentUpdateManifestUrl"),
            ReadValue("AgentUpdateAllowedArtifactPrefixes"),
            channel.Length > 0 ? channel : "dev",
            ReadValue("AgentUpdateAllowedSignerKeyIdentity"),
            bool.TryParse(ReadValue("AllowUnsignedDevBuild"), out var enabled) && enabled);
    }
}
