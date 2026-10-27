// Backend TLS trust compiled into the binary: a private CA is accepted only through the configured anchors.
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Cerberus.Agent.Core.Tests;

public sealed class BackendTrustTests
{
    [Fact]
    public async Task Handler_WithAnchor_AcceptsPrivateCaChain()
    {
        using var pki = TestPki.Create();
        await using var server = TlsServer.Start(pki.Leaf);
        using var http = new HttpClient(BackendTrust.Apply(new HttpClientHandler(), pki.Anchors()));

        Assert.Equal("ok", await http.GetStringAsync($"https://localhost:{server.Port}/"));
    }

    [Fact]
    public async Task Handler_WithoutAnchors_KeepsPlatformDecision()
    {
        using var pki = TestPki.Create();
        await using var server = TlsServer.Start(pki.Leaf);
        using var http = new HttpClient(BackendTrust.Apply(new HttpClientHandler(), new X509Certificate2Collection()));

        await Assert.ThrowsAsync<HttpRequestException>(() => http.GetStringAsync($"https://localhost:{server.Port}/"));
    }

    [Fact]
    public async Task Handler_SameNameRootWithOtherKey_Rejects()
    {
        using var pki = TestPki.Create();
        using var other = TestPki.Create(); // same subject names, other keys
        await using var server = TlsServer.Start(pki.Leaf);
        using var http = new HttpClient(BackendTrust.Apply(new HttpClientHandler(), other.Anchors()));

        await Assert.ThrowsAsync<HttpRequestException>(() => http.GetStringAsync($"https://localhost:{server.Port}/"));
    }

    [Fact]
    public async Task Handler_NameMismatch_IsNeverAcceptedByAnchor()
    {
        using var pki = TestPki.Create();
        await using var server = TlsServer.Start(pki.Leaf);
        using var http = new HttpClient(BackendTrust.Apply(new HttpClientHandler(), pki.Anchors()));

        await Assert.ThrowsAsync<HttpRequestException>(() => http.GetStringAsync($"https://127.0.0.1:{server.Port}/"));
    }

    [Fact]
    public async Task Handler_LeafWithoutServerAuthentication_Rejects()
    {
        using var pki = TestPki.Create(leafUsage: "1.3.6.1.5.5.7.3.2");
        await using var server = TlsServer.Start(pki.Leaf);
        using var http = new HttpClient(BackendTrust.Apply(new HttpClientHandler(), pki.Anchors()));

        await Assert.ThrowsAsync<HttpRequestException>(() => http.GetStringAsync($"https://localhost:{server.Port}/"));
    }

    [Fact]
    public async Task Handler_PlatformChainFaultBeyondTrust_IsNotRepairedByAnchor()
    {
        // With revocation checking on, the platform adds RevocationStatusUnknown to the chain status; the anchor
        // re-check (no revocation) must not override it.
        using var pki = TestPki.Create();
        await using var server = TlsServer.Start(pki.Leaf);
        var handler = BackendTrust.Apply(new HttpClientHandler { CheckCertificateRevocationList = true }, pki.Anchors());
        using var http = new HttpClient(handler);

        await Assert.ThrowsAsync<HttpRequestException>(() => http.GetStringAsync($"https://localhost:{server.Port}/"));
    }

    [Theory]
    [InlineData(SslPolicyErrors.RemoteCertificateNameMismatch)]
    [InlineData(SslPolicyErrors.RemoteCertificateNotAvailable)]
    [InlineData(SslPolicyErrors.RemoteCertificateChainErrors | SslPolicyErrors.RemoteCertificateNameMismatch)]
    public void Validate_OtherErrors_AreRejectedEvenWithMatchingAnchor(SslPolicyErrors errors)
    {
        using var pki = TestPki.Create();

        Assert.False(BackendTrust.Validate(pki.Leaf, null, errors, pki.Anchors()));
    }

    [Fact]
    public void Validate_ExpiredLeaf_IsRejectedByMatchingAnchor()
    {
        using var current = TestPki.Create();
        using var expired = TestPki.Create(expiredLeaf: true);

        Assert.True(BackendTrust.Validate(current.Leaf, null, SslPolicyErrors.RemoteCertificateChainErrors, current.Anchors()));
        Assert.False(BackendTrust.Validate(expired.Leaf, null, SslPolicyErrors.RemoteCertificateChainErrors, expired.Anchors()));
    }

    [Fact]
    public void Validate_IntermediateFromPresentedChain_CompletesThePath()
    {
        using var pki = TestPki.Create(withIntermediate: true);
        Assert.False(BackendTrust.Validate(pki.Leaf, null, SslPolicyErrors.RemoteCertificateChainErrors, pki.Anchors()));

        // What the TLS stack hands over when the server sends leaf + intermediate and the root is unknown to the machine.
        using var presented = new X509Chain();
        presented.ChainPolicy.ExtraStore.Add(pki.Intermediate!);
        presented.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        presented.ChainPolicy.DisableCertificateDownloads = true;
        Assert.False(presented.Build(pki.Leaf));

        Assert.True(BackendTrust.Validate(pki.Leaf, presented, SslPolicyErrors.RemoteCertificateChainErrors, pki.Anchors()));
    }

    [Theory]
    [InlineData(X509ChainStatusFlags.UntrustedRoot, true)]
    [InlineData(X509ChainStatusFlags.PartialChain, true)]
    [InlineData(X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.PartialChain, true)]
    [InlineData(X509ChainStatusFlags.ExplicitDistrust, false)]
    [InlineData(X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.ExplicitDistrust, false)]
    [InlineData(X509ChainStatusFlags.Revoked, false)]
    [InlineData(X509ChainStatusFlags.NotTimeValid, false)]
    [InlineData(X509ChainStatusFlags.NotSignatureValid, false)]
    public void OnlyTrustMissing_AllowsOnlyUnknownRootOrMissingIssuer(X509ChainStatusFlags flags, bool expected)
    {
        Assert.Equal(expected, BackendTrust.OnlyTrustMissing([new X509ChainStatus { Status = flags }]));
        Assert.Equal(expected, BackendTrust.OnlyTrustMissing([new X509ChainStatus { Status = X509ChainStatusFlags.UntrustedRoot }, new X509ChainStatus { Status = flags }]));
        Assert.True(BackendTrust.OnlyTrustMissing([]));
    }

    [Fact]
    public void Validate_NoErrors_Accepts()
        => Assert.True(BackendTrust.Validate(null, null, SslPolicyErrors.None, new X509Certificate2Collection()));

    [Fact]
    public void ParseAnchors_SkipsMalformedEntriesAndReadsDerList()
    {
        using var pki = TestPki.Create();
        var der = Convert.ToBase64String(pki.Root.RawData);

        var anchors = BackendTrust.ParseAnchors($"{der}, not-base64!, {Convert.ToBase64String([1, 2, 3])},");

        Assert.Single(anchors);
        Assert.Equal(pki.Root.Thumbprint, anchors[0].Thumbprint);
        Assert.Empty(BackendTrust.ParseAnchors(null));
    }

    private sealed class TestPki : IDisposable
    {
        public required X509Certificate2 Root { get; init; }
        public X509Certificate2? Intermediate { get; init; }
        public required X509Certificate2 Leaf { get; init; }

        public static TestPki Create(string leafUsage = "1.3.6.1.5.5.7.3.1", bool withIntermediate = false, bool expiredLeaf = false)
        {
            var now = DateTimeOffset.UtcNow;
            using var rootKey = RSA.Create(2048);
            using var root = CaRequest("CN=Test Backend Root", rootKey).CreateSelfSigned(now.AddDays(-30), now.AddDays(30));
            using var intermediateKey = RSA.Create(2048);
            using var intermediate = withIntermediate
                ? CaRequest("CN=Test Backend Intermediate", intermediateKey)
                    .Create(root, now.AddDays(-20), now.AddDays(20), RandomNumberGenerator.GetBytes(8))
                : null;
            using var issuer = intermediate?.CopyWithPrivateKey(intermediateKey);

            using var leafKey = RSA.Create(2048);
            var leafRequest = new CertificateRequest("CN=localhost", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName("localhost");
            leafRequest.CertificateExtensions.Add(names.Build());
            leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(leafUsage)], false));
            using var issued = expiredLeaf
                ? leafRequest.Create(issuer ?? root, now.AddDays(-10), now.AddDays(-1), RandomNumberGenerator.GetBytes(8))
                : leafRequest.Create(issuer ?? root, now.AddDays(-1), now.AddDays(10), RandomNumberGenerator.GetBytes(8));
            using var withKey = issued.CopyWithPrivateKey(leafKey);
            return new TestPki
            {
                Root = X509CertificateLoader.LoadCertificate(root.RawData),
                Intermediate = intermediate is null ? null : X509CertificateLoader.LoadCertificate(intermediate.RawData),
                Leaf = X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pfx), null),
            };
        }

        public X509Certificate2Collection Anchors() => [Root];

        public void Dispose()
        {
            Root.Dispose();
            Intermediate?.Dispose();
            Leaf.Dispose();
        }

        private static CertificateRequest CaRequest(string subject, RSA key)
        {
            var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
            return request;
        }
    }

    private sealed class TlsServer : IAsyncDisposable
    {
        private readonly TcpListener _listener;
        private readonly Task _loop;

        private TlsServer(TcpListener listener, X509Certificate2 certificate)
        {
            _listener = listener;
            _loop = Task.Run(async () =>
            {
                while (true)
                {
                    TcpClient client;
                    try { client = await listener.AcceptTcpClientAsync(); }
                    catch (Exception ex) when (ex is ObjectDisposedException or SocketException) { return; }
                    _ = Task.Run(() => Serve(client, certificate));
                }
            });
        }

        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public static TlsServer Start(X509Certificate2 certificate)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            return new TlsServer(listener, certificate);
        }

        private static async Task Serve(TcpClient client, X509Certificate2 certificate)
        {
            using (client)
            {
                try
                {
                    await using var tls = new SslStream(client.GetStream());
                    await tls.AuthenticateAsServerAsync(certificate);
                    var buffer = new byte[4096];
                    _ = await tls.ReadAsync(buffer);
                    await tls.WriteAsync("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"u8.ToArray());
                    await tls.FlushAsync();
                }
                catch (Exception ex) when (ex is IOException or AuthenticationException or SocketException) { } // the client rejected the certificate
            }
        }

        public async ValueTask DisposeAsync()
        {
            _listener.Stop();
            await _loop;
        }
    }
}
