using System.Net;
using System.Net.Sockets;
using System.Text;
using Cerberus.Agent.App;

namespace Cerberus.Agent.Core.Tests;

public sealed class LoopbackRedirectServerTests
{
    [Fact]
    public async Task WaitForCodeAsync_RejectsOversizedRequestLine()
    {
        var port = GetFreeLoopbackPort();
        using var server = new LoopbackRedirectServer(port);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        var wait = server.WaitForCodeAsync(cts.Token);
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, cts.Token);
        await using (var stream = client.GetStream())
        {
            var request = "GET /callback?" + new string('a', 9000) + " HTTP/1.1\r\n\r\n";
            var bytes = Encoding.ASCII.GetBytes(request);
            await stream.WriteAsync(bytes, cts.Token);
        }

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => wait);
        Assert.Contains("too long", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static int GetFreeLoopbackPort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }
}
