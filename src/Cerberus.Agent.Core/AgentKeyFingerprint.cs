using System.Security.Cryptography;

namespace Cerberus.Agent.Core;

/// <summary>Key fingerprint format: "sha256:" + lowercase hex of SHA-256 over the SubjectPublicKeyInfo.</summary>
public static class AgentKeyFingerprint
{
    public const string Prefix = "sha256:";

    public static string FromSubjectPublicKeyInfo(ReadOnlySpan<byte> subjectPublicKeyInfo)
        => Prefix + Convert.ToHexString(SHA256.HashData(subjectPublicKeyInfo)).ToLowerInvariant();

    public static string FromPrivateKeyPem(string privateKeyPem)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        return FromSubjectPublicKeyInfo(rsa.ExportSubjectPublicKeyInfo());
    }

    public static string? TryFromPrivateKeyPem(string privateKeyPem)
    {
        try
        {
            return FromPrivateKeyPem(privateKeyPem);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            return null;
        }
    }
}
