using System.Reflection;

namespace Cerberus.Agent.App.Updates;

internal static class AgentUpdateDefaults
{
    public const string ManifestPublicKeysB64MetadataName = "AgentUpdateManifestPublicKeysB64";
    public const string ManifestUrlMetadataName = "AgentUpdateManifestUrl";
    public const string AllowedArtifactPrefixesMetadataName = "AgentUpdateAllowedArtifactPrefixes";
    public const string ReleaseChannelMetadataName = "AgentReleaseChannel";
    public const string AllowedSignerKeyIdentityMetadataName = "AgentUpdateAllowedSignerKeyIdentity";
    public const string AllowUnsignedDevBuildMetadataName = "AllowUnsignedDevBuild";

    public static string ManifestPublicKeysB64 => ReadAssemblyMetadata(ManifestPublicKeysB64MetadataName);

    public static string ManifestUrl => ReadAssemblyMetadata(ManifestUrlMetadataName);

    public static string AllowedArtifactPrefixes => ReadAssemblyMetadata(AllowedArtifactPrefixesMetadataName);

    public static string ReleaseChannel => ReadAssemblyMetadata(ReleaseChannelMetadataName) is { Length: > 0 } channel
        ? channel
        : "dev";

    public static string AllowedSignerKeyIdentity => ReadAssemblyMetadata(AllowedSignerKeyIdentityMetadataName);

    public static bool AllowUnsignedDevBuild
        => bool.TryParse(ReadAssemblyMetadata(AllowUnsignedDevBuildMetadataName), out var enabled) && enabled;

    private static string ReadAssemblyMetadata(string name)
    {
        var assembly = typeof(AgentUpdateDefaults).Assembly;
        foreach (var attribute in assembly.GetCustomAttributes<AssemblyMetadataAttribute>())
        {
            if (string.Equals(attribute.Key, name, StringComparison.Ordinal))
                return attribute.Value?.Trim() ?? "";
        }

        return "";
    }
}
