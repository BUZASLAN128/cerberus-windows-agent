using System.Net;
using System.Net.Sockets;
using System.Text;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class BackendTrustTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ConnectProxyPreservesTheBackendCertificateDecision(bool wrongRoot)
    {
        using var pki = TestPki.Create();
        using var other = TestPki.Create();
        await using var origin = TlsServer.Start(pki.Leaf);
        await using var proxy = new ConnectProxy(origin.Port);
        using var handler = BackendTrust.Apply(new HttpClientHandler(), wrongRoot ? other.Anchors() : pki.Anchors());
        AgentProxySettings.Apply(handler, AgentProxySettings.Parse($"http://127.0.0.1:{proxy.Port}"));
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        var url = $"https://localhost:{origin.Port}/";
        if (wrongRoot) await Assert.ThrowsAsync<HttpRequestException>(() => http.GetStringAsync(url));
        else Assert.Equal("ok", await http.GetStringAsync(url));
        Assert.Equal($"CONNECT localhost:{origin.Port} HTTP/1.1", proxy.RequestLine);
    }

    // Loopback only, fixed upstream: the fixture cannot be used as an external forwarding proxy.
    private sealed class ConnectProxy : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _stop = new(TimeSpan.FromSeconds(15));
        private readonly Task _connection;
        public string? RequestLine { get; private set; }
        public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

        public ConnectProxy(int originPort)
        {
            _listener.Start();
            _connection = ForwardAsync(originPort);
        }

        private async Task ForwardAsync(int originPort)
        {
            using var client = await _listener.AcceptTcpClientAsync(_stop.Token);
            await using var incoming = client.GetStream();
            var header = new List<byte>();
            var one = new byte[1];
            while (header.Count < 8192)
            {
                if (await incoming.ReadAsync(one, _stop.Token) == 0) throw new IOException("Incomplete proxy header.");
                header.Add(one[0]);
                if (header.Count >= 4 && header[^4] == 13 && header[^3] == 10 && header[^2] == 13 && header[^1] == 10) break;
            }
            RequestLine = Encoding.ASCII.GetString(header.ToArray()).Split("\r\n")[0];
            using var upstream = new TcpClient();
            await upstream.ConnectAsync(IPAddress.Loopback, originPort, _stop.Token);
            await using var outgoing = upstream.GetStream();
            await incoming.WriteAsync("HTTP/1.1 200 Connection established\r\n\r\n"u8.ToArray(), _stop.Token);
            await incoming.FlushAsync(_stop.Token);
            var upload = incoming.CopyToAsync(outgoing, _stop.Token);
            var download = outgoing.CopyToAsync(incoming, _stop.Token);
            await Task.WhenAny(upload, download);
            _stop.Cancel();
            try { await Task.WhenAll(upload, download); }
            catch (Exception ex) when (ex is OperationCanceledException or IOException) { }
        }

        public async ValueTask DisposeAsync()
        {
            _stop.Cancel();
            _listener.Stop();
            try { await _connection; }
            catch (Exception ex) when (ex is OperationCanceledException or IOException or SocketException) { }
            _stop.Dispose();
        }
    }
}
