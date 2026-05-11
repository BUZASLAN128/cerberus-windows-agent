using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Cerberus.Agent.Core;

public sealed record AgentUpdateManifest(
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("channel")] string Channel,
    [property: JsonPropertyName("artifact_url")] string ArtifactUrl,
    [property: JsonPropertyName("sha256")] string Sha256,
    [property: JsonPropertyName("signing_identity")] string SigningIdentity,
    [property: JsonPropertyName("released_at_utc")] string ReleasedAtUtc,
    [property: JsonPropertyName("minimum_protocol_version")] string MinimumProtocolVersion,
    [property: JsonPropertyName("rollback_allowed")] bool RollbackAllowed,
    [property: JsonPropertyName("signature")] string Signature);

public static class AgentUpdateManifestValidator
{
    private static readonly Regex Sha256Regex = new("^[a-fA-F0-9]{64}$", RegexOptions.Compiled);
    private static readonly Regex VersionPartRegex = new(@"\d+", RegexOptions.Compiled);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static readonly HashSet<string> DisallowedKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "tenant_id",
        "tenant_update_url",
        "tenant_signing_key",
        "signing_key",
        "private_key",
    };

    public static AgentUpdateManifest ParseAndValidateJson(
        string json,
        string publicKeyPem,
        string expectedChannel,
        IReadOnlyList<string> allowedArtifactPrefixes,
        string? currentVersion = null,
        bool allowRollbackManifest = false)
    {
        using var doc = JsonDocument.Parse(json);
        foreach (var property in doc.RootElement.EnumerateObject())
        {
            if (DisallowedKeys.Contains(property.Name))
                throw new InvalidOperationException($"Update manifest rejects {property.Name}.");
        }

        var manifest = JsonSerializer.Deserialize<AgentUpdateManifest>(json, JsonOptions)
            ?? throw new InvalidOperationException("Update manifest is empty.");
        return Validate(
            manifest,
            publicKeyPem,
            expectedChannel,
            allowedArtifactPrefixes,
            currentVersion,
            allowRollbackManifest);
    }

    public static AgentUpdateManifest Validate(
        AgentUpdateManifest manifest,
        string publicKeyPem,
        string expectedChannel,
        IReadOnlyList<string> allowedArtifactPrefixes,
        string? currentVersion = null,
        bool allowRollbackManifest = false)
    {
        Require(manifest.Version, "Update manifest version missing.");
        Require(manifest.Channel, "Update manifest channel missing.");
        Require(manifest.ArtifactUrl, "Update manifest artifact URL missing.");
        Require(manifest.Sha256, "Update manifest checksum missing.");
        Require(manifest.SigningIdentity, "Update manifest signing identity missing.");
        Require(manifest.ReleasedAtUtc, "Update manifest release time missing.");
        Require(manifest.MinimumProtocolVersion, "Update manifest protocol version missing.");
        Require(manifest.Signature, "Update manifest signature missing.");
        Require(publicKeyPem, "Update manifest public key missing.");

        if (!string.Equals(manifest.Channel, expectedChannel, StringComparison.Ordinal))
            throw new InvalidOperationException("Update manifest channel mismatch.");
        if (!Sha256Regex.IsMatch(manifest.Sha256))
            throw new InvalidOperationException("Update manifest checksum invalid.");
        if (!DateTimeOffset.TryParse(manifest.ReleasedAtUtc, out _))
            throw new InvalidOperationException("Update manifest release time invalid.");
        if (!Uri.TryCreate(manifest.ArtifactUrl, UriKind.Absolute, out _))
            throw new InvalidOperationException("Update manifest artifact URL invalid.");
        if (allowedArtifactPrefixes.Count > 0 &&
            !allowedArtifactPrefixes.Any(prefix => manifest.ArtifactUrl.StartsWith(prefix, StringComparison.Ordinal)))
            throw new InvalidOperationException("Update manifest artifact URL denied.");

        var current = ParseVersion(currentVersion);
        var target = ParseVersion(manifest.Version);
        if (current is not null && target is not null && CompareVersions(target, current) < 0)
        {
            if (!(allowRollbackManifest && manifest.RollbackAllowed))
                throw new InvalidOperationException("Update manifest downgrade denied.");
        }

        using var rsa = RSA.Create();
        rsa.ImportFromPem(publicKeyPem);
        var signature = Convert.FromBase64String(manifest.Signature);
        var ok = rsa.VerifyData(
            Encoding.UTF8.GetBytes(CanonicalPayload(manifest)),
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        if (!ok)
            throw new InvalidOperationException("Update manifest signature invalid.");
        return manifest;
    }

    public static string CanonicalPayload(AgentUpdateManifest manifest)
        => string.Join(
            "\n",
            manifest.Version,
            manifest.Channel,
            manifest.ArtifactUrl,
            manifest.Sha256.ToLowerInvariant(),
            manifest.SigningIdentity,
            manifest.ReleasedAtUtc,
            manifest.MinimumProtocolVersion,
            manifest.RollbackAllowed ? "true" : "false");

    private static void Require(string value, string message)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new InvalidOperationException(message);
    }

    private static int[]? ParseVersion(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;
        var parts = VersionPartRegex.Matches(value).Select(match => int.Parse(match.Value)).Take(4).ToList();
        if (parts.Count == 0)
            return null;
        while (parts.Count < 4)
            parts.Add(0);
        return parts.ToArray();
    }

    private static int CompareVersions(int[] left, int[] right)
    {
        for (var i = 0; i < 4; i++)
        {
            var compare = left[i].CompareTo(right[i]);
            if (compare != 0)
                return compare;
        }
        return 0;
    }
}
