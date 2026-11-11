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

    [Fact]
    public void CallbackUsesPeerIntermediatesWithoutTrustingPeerRoots()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var root = Root(key);
        using var issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=Unit intermediate", issuerKey, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        using var issued = request.Create(root, DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddMinutes(90), RandomNumberGenerator.GetBytes(16));
        using var issuer = issued.CopyWithPrivateKey(issuerKey);
        using var publicRoot = X509CertificateLoader.LoadCertificate(root.RawData);
        var store = new X509Certificate2Collection(new X509Certificate2[] { issued, publicRoot })
            .Export(X509ContentType.SerializedStore)!;
        using var leaf = Leaf(issuer, "127.0.0.1");
        using var wrongSan = Leaf(issuer, "127.0.0.2");
        using var wrongKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var wrongRoot = Root(wrongKey);
        Assert.Equal(0, InvokeCallback(Policy(root), leaf, store));
        Assert.True(InvokeCallback(Policy(wrongRoot), leaf, store) < 0);
        Assert.True(InvokeCallback(Policy(root), wrongSan, store) < 0);
        Assert.True(InvokeCallback(Policy(root), leaf, [1, 2, 3]) < 0);
        Assert.True(InvokeCallback(Policy(root), leaf, store, 1024 * 1024 + 1) < 0);
    }

    private static int InvokeCallback(AgentUpdateBitsTlsPolicy policy, X509Certificate2 leaf,
        byte[] store, uint? declaredLength = null)
    {
        var leafBytes = leaf.RawData;
        var leafPointer = Marshal.AllocHGlobal(leafBytes.Length);
        var storePointer = Marshal.AllocHGlobal(store.Length);
        try
        {
            Marshal.Copy(leafBytes, 0, leafPointer, leafBytes.Length);
            Marshal.Copy(store, 0, storePointer, store.Length);
            var proofs = new List<string>();
            var callback = new AgentUpdateBitsCertificateValidation(policy, Source, proofs.Add);
            int result = callback.ValidateServerCertificate(0, 0, (uint)leafBytes.Length, leafPointer,
                1, declaredLength ?? (uint)store.Length, storePointer);
            Assert.Equal(result == 0, callback.Verified);
            Assert.Equal(result != 0, callback.Rejected);
            Assert.Equal(result == 0 ? 1 : 0, proofs.Count);
            return result;
        }
        finally { Marshal.FreeHGlobal(storePointer); Marshal.FreeHGlobal(leafPointer); }
    }

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
