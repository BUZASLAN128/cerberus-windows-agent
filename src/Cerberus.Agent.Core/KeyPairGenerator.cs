using System.Security.Cryptography;

namespace Cerberus.Agent.Core;

public interface IKeyPairGenerator
{
    (string PrivateKeyPem, string PublicKeyPem) GenerateKeyPair(int keySize);
}

public sealed class RsaKeyPairGenerator : IKeyPairGenerator
{
    public static readonly RsaKeyPairGenerator Instance = new();

    private RsaKeyPairGenerator() { }

    public (string PrivateKeyPem, string PublicKeyPem) GenerateKeyPair(int keySize)
    {
        using var rsa = RSA.Create(keySize);
        return (rsa.ExportPkcs8PrivateKeyPem(), rsa.ExportSubjectPublicKeyInfoPem());
    }
}

