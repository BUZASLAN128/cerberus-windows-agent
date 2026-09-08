using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Cerberus.Agent.Integrations.Ad;

public sealed record RdpCredentialMetadata(string? CredentialProfileId, string? TenantKeyId, int? KeyVersion,
    string? PublicKeyPem, string? PublicKeyFingerprint, string? CipherAlg, string? Aad, string? AadHash);

public sealed record RdpCredentialEnvelope(
    [property: JsonPropertyName("auth_type")] string AuthType,
    [property: JsonPropertyName("credential_id")] string CredentialId,
    [property: JsonPropertyName("username_hint")] string UsernameHint,
    [property: JsonPropertyName("domain")] string? Domain,
    [property: JsonPropertyName("tenant_key_id")] string TenantKeyId,
    [property: JsonPropertyName("key_version")] int KeyVersion,
    [property: JsonPropertyName("cipher_alg")] string CipherAlg,
    [property: JsonPropertyName("wrapped_dek")] string WrappedDek,
    [property: JsonPropertyName("cipher_nonce")] string CipherNonce,
    [property: JsonPropertyName("ciphertext")] string Ciphertext,
    [property: JsonPropertyName("aad_hash")] string AadHash)
{
    internal Dictionary<string, object?> AsDictionary() => new()
    {
        ["auth_type"] = AuthType, ["credential_id"] = CredentialId, ["username_hint"] = UsernameHint,
        ["domain"] = Domain, ["tenant_key_id"] = TenantKeyId, ["key_version"] = KeyVersion,
        ["cipher_alg"] = CipherAlg, ["wrapped_dek"] = WrappedDek, ["cipher_nonce"] = CipherNonce,
        ["ciphertext"] = Ciphertext, ["aad_hash"] = AadHash
    };
}

/// <summary>The existing local-user tenant-encrypted RDP envelope codec, shared with AD without changing its wire format.</summary>
internal static class RdpCredentialCodec
{
    internal const string CipherAlgorithm = "aes256gcm+rsa-oaep";

    internal static string? ValidationError(RdpCredentialMetadata metadata)
    {
        if (string.IsNullOrWhiteSpace(metadata.PublicKeyPem)) return null;
        if (string.IsNullOrWhiteSpace(metadata.CredentialProfileId) || string.IsNullOrWhiteSpace(metadata.TenantKeyId) ||
            metadata.KeyVersion is null || string.IsNullOrWhiteSpace(metadata.Aad) || string.IsNullOrWhiteSpace(metadata.AadHash))
            return "missing_rdp_credential_metadata";
        if (metadata.CipherAlg != CipherAlgorithm) return "unsupported_rdp_cipher";
        var actualAadHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(metadata.Aad))).ToLowerInvariant();
        if (!StringComparer.OrdinalIgnoreCase.Equals(actualAadHash, metadata.AadHash)) return "rdp_aad_hash_mismatch";
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(metadata.PublicKeyPem.AsSpan());
            if (rsa.KeySize < 2048) return "weak_rdp_public_key";
            if (!string.IsNullOrWhiteSpace(metadata.PublicKeyFingerprint))
            {
                var actual = Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(metadata.PublicKeyPem))).ToLowerInvariant();
                if (!StringComparer.OrdinalIgnoreCase.Equals(actual, metadata.PublicKeyFingerprint)) return "rdp_public_key_fingerprint_mismatch";
            }
            return null;
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException) { return "invalid_rdp_public_key"; }
    }

    internal static RdpCredentialEnvelope Encrypt(string password, string username, string? domain, RdpCredentialMetadata metadata)
    {
        if (string.IsNullOrWhiteSpace(metadata.PublicKeyPem) || ValidationError(metadata) is not null)
            throw new InvalidOperationException("RDP credential metadata is invalid.");
        using var plaintext = new MemoryStream();
        using (var writer = new Utf8JsonWriter(plaintext))
        {
            writer.WriteStartObject();
            writer.WriteString("username", username);
            writer.WriteString("password", password);
            if (!string.IsNullOrWhiteSpace(domain)) writer.WriteString("domain", domain);
            writer.WriteEndObject();
        }
        var aad = Encoding.UTF8.GetBytes(metadata.Aad!);
        var dek = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plaintextSpan = plaintext.GetBuffer().AsSpan(0, checked((int)plaintext.Length));
        var ciphertext = new byte[plaintextSpan.Length];
        var tag = new byte[16];
        try
        {
            using (var aes = new AesGcm(dek, 16)) aes.Encrypt(nonce, plaintextSpan, ciphertext, tag, aad);
            var cipherWithTag = new byte[ciphertext.Length + tag.Length];
            Buffer.BlockCopy(ciphertext, 0, cipherWithTag, 0, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, cipherWithTag, ciphertext.Length, tag.Length);
            using var rsa = RSA.Create();
            rsa.ImportFromPem(metadata.PublicKeyPem.AsSpan());
            var wrappedDek = rsa.Encrypt(dek, RSAEncryptionPadding.OaepSHA256);
            return new("password", metadata.CredentialProfileId!, username, string.IsNullOrWhiteSpace(domain) ? null : domain,
                metadata.TenantKeyId!, metadata.KeyVersion!.Value, CipherAlgorithm, Convert.ToBase64String(wrappedDek),
                Convert.ToBase64String(nonce), Convert.ToBase64String(cipherWithTag), metadata.AadHash!);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
            CryptographicOperations.ZeroMemory(plaintext.GetBuffer().AsSpan(0, checked((int)plaintext.Length)));
            CryptographicOperations.ZeroMemory(ciphertext);
            CryptographicOperations.ZeroMemory(tag);
        }
    }

    internal static string GeneratePassword()
    {
        const string lower = "abcdefghijkmnopqrstuvwxyz", upper = "ABCDEFGHJKLMNPQRSTUVWXYZ", digits = "23456789", symbols = "!@#$%^*-_+=";
        const string all = lower + upper + digits + symbols;
        Span<char> chars = stackalloc char[28];
        chars[0] = lower[RandomNumberGenerator.GetInt32(lower.Length)];
        chars[1] = upper[RandomNumberGenerator.GetInt32(upper.Length)];
        chars[2] = digits[RandomNumberGenerator.GetInt32(digits.Length)];
        chars[3] = symbols[RandomNumberGenerator.GetInt32(symbols.Length)];
        for (var i = 4; i < chars.Length; i++) chars[i] = all[RandomNumberGenerator.GetInt32(all.Length)];
        for (var i = chars.Length - 1; i > 0; i--)
        {
            var j = RandomNumberGenerator.GetInt32(i + 1);
            (chars[i], chars[j]) = (chars[j], chars[i]);
        }
        var password = new string(chars);
        chars.Clear();
        return password;
    }
}
