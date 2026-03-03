using System.Security.Cryptography;

namespace Cerberus.Agent.Security;

public static class RsaKeyManager
{
    public static (string PrivateKeyPem, string PublicKeyPem) GenerateKeyPair(int keySize = 2048)
    {
        using var rsa = RSA.Create(keySize);
        var priv = rsa.ExportPkcs8PrivateKeyPem();
        var pub = rsa.ExportSubjectPublicKeyInfoPem();
        return (priv, pub);
    }
}

