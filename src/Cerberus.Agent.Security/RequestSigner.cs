using System.Security.Cryptography;
using System.Text;

namespace Cerberus.Agent.Security;

public sealed class RequestSigner : Cerberus.Agent.Core.IRequestSigner
{
    private readonly RSA _rsa;

    public RequestSigner(string privateKeyPem)
    {
        _rsa = RSA.Create();
        _rsa.ImportFromPem(privateKeyPem);
    }

    public string ComputeBodyHash(byte[] bodyBytes)
    {
        var hash = SHA256.HashData(bodyBytes);
        return Convert.ToBase64String(hash);
    }

    public string CanonicalString(string method, string path, string nonce, long timestamp, string bodyHash)
    {
        return $"v1:{method.ToUpperInvariant()}:{path}:{nonce}:{timestamp}:{bodyHash}";
    }

    public string Sign(string canonical)
    {
        var data = Encoding.UTF8.GetBytes(canonical);
        var sig = _rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return Convert.ToBase64String(sig);
    }
}

