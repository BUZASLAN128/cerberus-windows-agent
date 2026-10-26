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
    public async Task Handler_WithOtherAnchor_Rejects()
    {
        using var pki = TestPki.Create();
        using var other = TestPki.Create();
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
        public required X509Certificate2 Leaf { get; init; }

        public static TestPki Create(string leafUsage = "1.3.6.1.5.5.7.3.1")
        {
            using var rootKey = RSA.Create(2048);
            var rootRequest = new CertificateRequest("CN=Test Backend Root", rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
            using var root = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

            using var leafKey = RSA.Create(2048);
            var leafRequest = new CertificateRequest("CN=localhost", leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName("localhost");
            leafRequest.CertificateExtensions.Add(names.Build());
            leafRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid(leafUsage)], false));
            using var issued = leafRequest.Create(root, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(10), RandomNumberGenerator.GetBytes(8));
            using var withKey = issued.CopyWithPrivateKey(leafKey);
            return new TestPki
            {
                Root = X509CertificateLoader.LoadCertificate(root.RawData),
                Leaf = X509CertificateLoader.LoadPkcs12(withKey.Export(X509ContentType.Pfx), null),
            };
        }

        public X509Certificate2Collection Anchors() => [Root];

        public void Dispose()
        {
            Root.Dispose();
            Leaf.Dispose();
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
