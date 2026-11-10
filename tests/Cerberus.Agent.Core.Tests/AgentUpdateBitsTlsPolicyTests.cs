using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateBitsTlsPolicyTests
{
    private static readonly Uri Source = new("https://127.0.0.1:8443/updates/devtest/packages/0.2.1013/agent.msi");

    [Fact]
    public void ActualLeafMustChainToSelectedRootAndMatchSanAndScope()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root = Root(key);
        using var leaf = Leaf(root, "127.0.0.1");
        var policy = Policy(root);
        Assert.True(policy.ValidateCertificate(Source, leaf));
        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var wrongRoot = Root(wrongKey);
        Assert.False(Policy(wrongRoot).ValidateCertificate(Source, leaf));
        using var wrongSan = Leaf(root, "127.0.0.2");
        Assert.False(policy.ValidateCertificate(Source, wrongSan));
        Assert.False(policy.ValidateCertificate(Source, null));
        Assert.Throws<InvalidOperationException>(() => policy.ValidateCertificate(new("https://127.0.0.1:8443/updates/preview/agent.msi"), leaf));
        Assert.Throws<InvalidOperationException>(() => policy.ValidateCertificate(new(Source + "?x=1"), leaf));
        Assert.Throws<InvalidOperationException>(() => (policy with { ExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(-1) }).ValidateCertificate(Source, leaf));
    }

    [Fact]
    public void CallbackRecordsOnlyVerifiedCertificateAndFailsClosedOnMalformedInput()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root = Root(key);
        using var leaf = Leaf(root, "127.0.0.1");
        var proofs = new List<string>();
        var callback = new AgentUpdateBitsCertificateValidation(Policy(root), Source, proofs.Add);
        var bytes = leaf.RawData;
        var pointer = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, pointer, bytes.Length);
            Assert.Equal(0, callback.ValidateServerCertificate(0, 0, (uint)bytes.Length, pointer, 1, 0, 0));
            Assert.True(callback.Verified);
            Assert.False(callback.Rejected);
            Assert.Equal(Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), Assert.Single(proofs));
            var rejected = new AgentUpdateBitsCertificateValidation(Policy(root), Source, _ => throw new Exception("Must not record invalid input."));
            Assert.True(rejected.ValidateServerCertificate(0, 0, 0, 0, 1, 0, 0) < 0);
            Assert.True(rejected.Rejected);
            Assert.False(rejected.Verified);
        }
        finally { Marshal.FreeHGlobal(pointer); }
    }

    private static AgentUpdateBitsTlsPolicy Policy(X509Certificate2 root)
        => new(Convert.ToBase64String(root.RawData), "https://127.0.0.1:8443/updates/devtest/", DateTimeOffset.UtcNow.AddHours(1));

    private static X509Certificate2 Root(ECDsa key)
    {
        var request = new CertificateRequest("CN=Unit campaign root", key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(2));
    }

    private static X509Certificate2 Leaf(X509Certificate2 root, string ip)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Unit leaf", key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(IPAddress.Parse(ip));
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
        return request.Create(root, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1), RandomNumberGenerator.GetBytes(16));
    }
}
