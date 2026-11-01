using System.Security.Cryptography;
using System.Text.Json;

namespace Cerberus.Agent.Core;

public sealed record AgentUpdateTrust(
    IReadOnlyList<string> ManifestPublicKeyPems,
    string ExpectedChannel,
    IReadOnlyList<string> AllowedArtifactPrefixes,
    string CurrentVersion,
    bool AllowRollbackManifest = false,
    bool AllowChannelDowngrade = false,
    long MaxArtifactBytes = 200 * 1024 * 1024,
    string? ConfiguredManifestUrl = null,
    string? AllowedSignerKeyIdentity = null,
    bool AllowUnsignedDevBuild = false,
    bool RequireManifestV2 = false,
    bool RequireBitsDownloader = false,
    bool RequireSystemAuthority = false);

public sealed record AgentUpdateSignal(
    bool Required,
    bool Recommended,
    string? ManifestUrl,
    string? Reason,
    string? Channel,
    long? LifecycleGeneration = null,
    long? SkipSequenceAtOrBelow = null,
    AgentUpdateExpectedPlan? ExpectedPlan = null);

public sealed record AgentUpdatePlan(
    string ArtifactKind,
    string Version,
    string Channel,
    string ArtifactPath,
    string Sha256,
    string StagedAtUtc,
    string Reason,
    string SchemaVersion = "agent.update.plan.v2",
    string? AttemptId = null,
    long Sequence = 0,
    string? ExpiresAtUtc = null,
    long? ArtifactLength = null,
    string? ManifestPath = null,
    string? SignerKeyIdentity = null,
    bool Required = false,
    bool RollbackAllowed = false,
    int RetryCount = 0,
    string? ManifestDigest = null);

/// <summary>Identity of the currently trusted signed manifest, independent of its artifact.</summary>
public sealed record AgentUpdateManifestIdentity(long Sequence, string ManifestDigest)
{
    public bool Matches(AgentUpdatePlan plan)
        => plan.Sequence == Sequence &&
           !string.IsNullOrWhiteSpace(plan.ManifestDigest) &&
           string.Equals(plan.ManifestDigest, ManifestDigest, StringComparison.OrdinalIgnoreCase);
}

public sealed record AgentUpdateCheckResult(
    bool Available,
    bool Required,
    bool Recommended,
    string? Version,
    string? Channel,
    string? Reason,
    string? ManifestUrl,
    string? ArtifactKind)
{
    public static AgentUpdateCheckResult None { get; } = new(
        Available: false,
        Required: false,
        Recommended: false,
        Version: null,
        Channel: null,
        Reason: null,
        ManifestUrl: null,
        ArtifactKind: null);
}
