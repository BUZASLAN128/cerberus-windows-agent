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
    [property: JsonPropertyName("signature")] string Signature,
    [property: JsonPropertyName("schema_version")] string? SchemaVersion = null,
    [property: JsonPropertyName("sequence")] long Sequence = 0,
    [property: JsonPropertyName("expires_at_utc")] string? ExpiresAtUtc = null,
    [property: JsonPropertyName("artifact_length")] long? ArtifactLength = null,
    [property: JsonPropertyName("signer_key_identity")] string? SignerKeyIdentity = null)
{
    public const string V1SchemaVersion = "agent.update.manifest.v1";
    public const string V2SchemaVersion = "agent.update.manifest.v2";

    public bool IsV2 => string.Equals(SchemaVersion, V2SchemaVersion, StringComparison.Ordinal);

    public string? EffectiveSignerKeyIdentity =>
        string.IsNullOrWhiteSpace(SignerKeyIdentity) ? null : SignerKeyIdentity.Trim();
}

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
        if (string.IsNullOrWhiteSpace(json))
            throw new InvalidOperationException("Update manifest is empty.");

        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException("Update manifest is invalid.");
        foreach (var property in doc.RootElement.EnumerateObject())
        {
            if (DisallowedKeys.Contains(property.Name))
                throw new InvalidOperationException($"Update manifest rejects {property.Name}.");
        }

        var manifest = JsonSerializer.Deserialize<AgentUpdateManifest>(json, JsonOptions)
            ?? throw new InvalidOperationException("Update manifest is empty.");
        manifest = NormalizeV2Aliases(manifest, doc.RootElement);
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
        ArgumentNullException.ThrowIfNull(manifest);
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
        if (!DateTimeOffset.TryParse(manifest.ReleasedAtUtc, out var releasedAt))
            throw new InvalidOperationException("Update manifest release time invalid.");
        if (releasedAt > DateTimeOffset.UtcNow.AddMinutes(5))
            throw new InvalidOperationException("Update manifest release time is in the future.");
        if (!Uri.TryCreate(manifest.ArtifactUrl, UriKind.Absolute, out var artifactUri) ||
            !string.Equals(artifactUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Update manifest artifact URL invalid.");
        if (allowedArtifactPrefixes.Count > 0 &&
            !allowedArtifactPrefixes.Any(prefix => manifest.ArtifactUrl.StartsWith(prefix, StringComparison.Ordinal)))
            throw new InvalidOperationException("Update manifest artifact URL denied.");

        if (manifest.IsV2)
        {
            if (manifest.Sequence <= 0)
                throw new InvalidOperationException("Update manifest sequence is invalid.");
            if (!DateTimeOffset.TryParse(manifest.ExpiresAtUtc, out var expiresAt) ||
                expiresAt <= DateTimeOffset.UtcNow)
                throw new InvalidOperationException("Update manifest has expired.");
            if (manifest.ArtifactLength is <= 0)
                throw new InvalidOperationException("Update manifest artifact length is invalid.");
            if (string.IsNullOrWhiteSpace(manifest.EffectiveSignerKeyIdentity))
                throw new InvalidOperationException("Update manifest signer identity missing.");
        }

        var versionCompare = AgentVersionComparer.CompareReleaseCore(manifest.Version, currentVersion);
        if (versionCompare is < 0)
        {
            if (!(allowChannelDowngrade || (allowRollbackManifest && manifest.RollbackAllowed)))
                throw new InvalidOperationException("Update manifest downgrade denied.");
        }

        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(manifest.Signature);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException("Update manifest signature invalid.", ex);
        }

        var payload = Encoding.UTF8.GetBytes(CanonicalPayload(manifest));
        if (!VerifyWithAnyPublicKey(payload, signature, publicKeyPems))
            throw new InvalidOperationException("Update manifest signature invalid.");
        return manifest;
    }

    public static string CanonicalPayload(AgentUpdateManifest manifest)
    {
        var payload = new List<string>
        {
            manifest.ArtifactKind.ToLowerInvariant(),
            manifest.Version,
            manifest.Channel,
            manifest.ArtifactUrl,
            manifest.Sha256.ToLowerInvariant(),
            manifest.SigningIdentity,
            manifest.ReleasedAtUtc,
            manifest.MinimumProtocolVersion,
            manifest.RollbackAllowed ? "true" : "false",
        };

        if (manifest.IsV2)
        {
            payload.Add(manifest.SchemaVersion!);
            payload.Add(manifest.Sequence.ToString(System.Globalization.CultureInfo.InvariantCulture));
            payload.Add(manifest.ExpiresAtUtc ?? "");
            payload.Add(manifest.ArtifactLength?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "");
            payload.Add(manifest.EffectiveSignerKeyIdentity ?? "");
        }

        return string.Join("\n", payload);
    }

    private static AgentUpdateManifest NormalizeV2Aliases(AgentUpdateManifest manifest, JsonElement root)
    {
        if (string.IsNullOrWhiteSpace(manifest.SchemaVersion) &&
            (root.TryGetProperty("sequence", out _) ||
             root.TryGetProperty("sequence_number", out _) ||
             root.TryGetProperty("expires_at_utc", out _) ||
             root.TryGetProperty("manifest_expires_at_utc", out _) ||
             root.TryGetProperty("expires_utc", out _) ||
             root.TryGetProperty("artifact_length", out _)))
        {
            manifest = manifest with { SchemaVersion = AgentUpdateManifest.V2SchemaVersion };
        }

        if (string.IsNullOrWhiteSpace(manifest.ExpiresAtUtc))
        {
            var expiresAt = ReadString(root, "manifest_expires_at_utc") ?? ReadString(root, "expires_utc");
            if (!string.IsNullOrWhiteSpace(expiresAt))
                manifest = manifest with { ExpiresAtUtc = expiresAt };
        }

        if (string.IsNullOrWhiteSpace(manifest.SignerKeyIdentity))
        {
            var alias = ReadString(root, "authenticode_signer_key_identity") ??
                        ReadString(root, "authenticode_signer_identity") ??
                        ReadString(root, "authenticode_signer_thumbprint") ??
                        ReadString(root, "signer_key_id") ??
                        ReadString(root, "allowed_signer_key_identity");
            if (!string.IsNullOrWhiteSpace(alias))
                manifest = manifest with { SignerKeyIdentity = alias };
        }

        if (manifest.ArtifactLength is null)
        {
            var length = ReadInt64(root, "artifact_length_bytes") ??
                         ReadInt64(root, "artifact_size_bytes") ??
                         ReadInt64(root, "artifact_size") ??
                         ReadInt64(root, "length");
            if (length is not null)
                manifest = manifest with { ArtifactLength = length };
        }

        if (manifest.Sequence == 0)
        {
            var sequence = ReadInt64(root, "manifest_sequence") ?? ReadInt64(root, "sequence_number");
            if (sequence is not null)
                manifest = manifest with { Sequence = sequence.Value };
        }

        return manifest;
    }

    private static string? ReadString(JsonElement root, string name)
        => root.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;

    private static long? ReadInt64(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var property))
            return null;
        if (property.ValueKind == JsonValueKind.Number && property.TryGetInt64(out var number))
            return number;
        return property.ValueKind == JsonValueKind.String && long.TryParse(property.GetString(), out var parsed)
            ? parsed
            : null;
    }

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
