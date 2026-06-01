using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace Cerberus.Agent.Core;

public sealed record AgentUpdateManifest(
    [property: JsonPropertyName("artifact_kind")] string ArtifactKind,
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
        bool allowRollbackManifest = false,
        bool allowChannelDowngrade = false)
        => ParseAndValidateJson(
            json,
            new[] { publicKeyPem },
            expectedChannel,
            allowedArtifactPrefixes,
            currentVersion,
            allowRollbackManifest,
            allowChannelDowngrade);

    public static AgentUpdateManifest ParseAndValidateJson(
        string json,
        IReadOnlyList<string> publicKeyPems,
        string expectedChannel,
        IReadOnlyList<string> allowedArtifactPrefixes,
        string? currentVersion = null,
        bool allowRollbackManifest = false,
        bool allowChannelDowngrade = false)
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
            publicKeyPems,
            expectedChannel,
            allowedArtifactPrefixes,
            currentVersion,
            allowRollbackManifest,
            allowChannelDowngrade);
    }

    public static AgentUpdateManifest Validate(
        AgentUpdateManifest manifest,
        string publicKeyPem,
        string expectedChannel,
        IReadOnlyList<string> allowedArtifactPrefixes,
        string? currentVersion = null,
        bool allowRollbackManifest = false,
        bool allowChannelDowngrade = false)
        => Validate(
            manifest,
            new[] { publicKeyPem },
            expectedChannel,
            allowedArtifactPrefixes,
            currentVersion,
            allowRollbackManifest,
            allowChannelDowngrade);

    public static AgentUpdateManifest Validate(
        AgentUpdateManifest manifest,
        IReadOnlyList<string> publicKeyPems,
        string expectedChannel,
        IReadOnlyList<string> allowedArtifactPrefixes,
        string? currentVersion = null,
        bool allowRollbackManifest = false,
        bool allowChannelDowngrade = false)
    {
        Require(manifest.ArtifactKind, "Update manifest artifact kind missing.");
        Require(manifest.Version, "Update manifest version missing.");
        Require(manifest.Channel, "Update manifest channel missing.");
        Require(manifest.ArtifactUrl, "Update manifest artifact URL missing.");
        Require(manifest.Sha256, "Update manifest checksum missing.");
        Require(manifest.SigningIdentity, "Update manifest signing identity missing.");
        Require(manifest.ReleasedAtUtc, "Update manifest release time missing.");
        Require(manifest.MinimumProtocolVersion, "Update manifest protocol version missing.");
        Require(manifest.Signature, "Update manifest signature missing.");
        if (publicKeyPems.Count == 0 || publicKeyPems.All(string.IsNullOrWhiteSpace))
            throw new InvalidOperationException("Update manifest public key missing.");

        if (!string.Equals(manifest.ArtifactKind, "msi", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Update manifest artifact kind denied.");
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

        var versionCompare = AgentVersionComparer.CompareReleaseCore(manifest.Version, currentVersion);
        if (versionCompare is < 0)
        {
            if (!(allowChannelDowngrade || (allowRollbackManifest && manifest.RollbackAllowed)))
                throw new InvalidOperationException("Update manifest downgrade denied.");
        }

        var signature = Convert.FromBase64String(manifest.Signature);
        var payload = Encoding.UTF8.GetBytes(CanonicalPayload(manifest));
        if (!VerifyWithAnyPublicKey(payload, signature, publicKeyPems))
            throw new InvalidOperationException("Update manifest signature invalid.");
        return manifest;
    }

    public static string CanonicalPayload(AgentUpdateManifest manifest)
        => string.Join(
            "\n",
            manifest.ArtifactKind.ToLowerInvariant(),
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

    private static bool VerifyWithAnyPublicKey(
        byte[] payload,
        byte[] signature,
        IReadOnlyList<string> publicKeyPems)
    {
        foreach (var publicKeyPem in publicKeyPems)
        {
            if (string.IsNullOrWhiteSpace(publicKeyPem))
                continue;

            try
            {
                using var rsa = RSA.Create();
                rsa.ImportFromPem(publicKeyPem);
                if (rsa.VerifyData(payload, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                    return true;
            }
            catch (Exception ex) when (ex is ArgumentException or FormatException or CryptographicException)
            {
            }
        }

        return false;
    }

}
