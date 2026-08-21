using Cerberus.Agent.App;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Diagnostics;

namespace Cerberus.Agent.Core.Tests;

public sealed class CasdoorOAuthClientTests
{
    [Fact]
    public void WriteManualBrowserUrl_WritesUrlToRequestedFile()
    {
        var dir = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
        var path = Path.Combine(dir, "oauth-url.txt");
        var url = new Uri("https://sso.example/login/oauth/authorize?client_id=agent-client");

        CasdoorOAuthClient.WriteManualBrowserUrl(url, path);

        Assert.Equal(url.ToString(), File.ReadAllText(path));
    }

    [Fact]
    public void WriteManualBrowserUrl_NoopsWhenPathMissing()
    {
        var url = new Uri("https://sso.example/login/oauth/authorize");

        CasdoorOAuthClient.WriteManualBrowserUrl(url, null);
        CasdoorOAuthClient.WriteManualBrowserUrl(url, "");

        Assert.True(true);
    }

    [Fact]
    public void BuildTokenExchangeForm_DoesNotIncludeClientSecretForPublicPkce()
    {
        var form = CasdoorOAuthClient.BuildTokenExchangeForm(
            "agent-public-client",
            "oauth-code",
            new Uri("http://127.0.0.1:19823/callback"),
            "pkce-verifier");

        Assert.Equal("authorization_code", form["grant_type"]);
        Assert.Equal("agent-public-client", form["client_id"]);
        Assert.Equal("oauth-code", form["code"]);
        Assert.Equal("pkce-verifier", form["code_verifier"]);
        Assert.False(form.ContainsKey("client_secret"));
    }

    [Fact]
    public async Task LoginWithPkceAsync_OnMaliciousNonSuccessResponse_ThrowsStatusOnly()
    {
        var urlPath = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"), "oauth-url.txt");
        var previousBrowserMode = Environment.GetEnvironmentVariable("CERBERUS_AGENT_OAUTH_BROWSER");
        var previousUrlPath = Environment.GetEnvironmentVariable("CERBERUS_AGENT_OAUTH_URL_FILE");
        var sensitiveBody = "sql=SELECT topology tenant=0000 token=secret-token <html>internal details</html> "
                            + new string('x', 64 * 1024);

        try
        {
            Environment.SetEnvironmentVariable("CERBERUS_AGENT_OAUTH_BROWSER", "manual");
            Environment.SetEnvironmentVariable("CERBERUS_AGENT_OAUTH_URL_FILE", urlPath);

            using var tokenListener = new TcpListener(IPAddress.Loopback, 0);
            tokenListener.Start();
            var tokenPort = ((IPEndPoint)tokenListener.LocalEndpoint).Port;
            var callbackPort = GetFreeLoopbackPort();
            var tokenResponse = ServeTokenFailureAsync(tokenListener, sensitiveBody);

            var client = new CasdoorOAuthClient(
                new Uri($"http://127.0.0.1:{tokenPort}"),
                "agent-client",
                clientSecret: null,
                "openid");
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var login = client.LoginWithPkceAsync(callbackPort, cancellation.Token);

            var authorizeUrl = await WaitForUrlAsync(urlPath, cancellation.Token);
            var state = WebUtility.UrlDecode(new Uri(authorizeUrl).Query
                .Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Single(part => part.StartsWith("state=", StringComparison.Ordinal))["state=".Length..]);
            await SendCallbackAsync(callbackPort, state, cancellation.Token);

            var exception = await Assert.ThrowsAsync<HttpRequestException>(() => login);
            await tokenResponse;

            Assert.Equal("Token exchange failed (502).", exception.Message);
            Assert.Equal(HttpStatusCode.BadGateway, exception.StatusCode);
            foreach (var marker in new[] { "sql=SELECT", "topology", "tenant=0000", "secret-token", "<html>", "internal details", new string('x', 1024) })
                Assert.DoesNotContain(marker, exception.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Environment.SetEnvironmentVariable("CERBERUS_AGENT_OAUTH_BROWSER", previousBrowserMode);
            Environment.SetEnvironmentVariable("CERBERUS_AGENT_OAUTH_URL_FILE", previousUrlPath);
            if (File.Exists(urlPath))
                File.Delete(urlPath);
            var directory = Path.GetDirectoryName(urlPath);
            if (!string.IsNullOrWhiteSpace(directory) && Directory.Exists(directory))
                Directory.Delete(directory);
        }
    }

    [Fact]
    public async Task LoginWithPkceAsync_OnStalledNonSuccessBodyReturnsStatusOnlyWithoutWaiting()
    {
        var urlPath = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"), "oauth-url.txt");
        var previousBrowserMode = Environment.GetEnvironmentVariable("CERBERUS_AGENT_OAUTH_BROWSER");
        var previousUrlPath = Environment.GetEnvironmentVariable("CERBERUS_AGENT_OAUTH_URL_FILE");
        try
        {
            Environment.SetEnvironmentVariable("CERBERUS_AGENT_OAUTH_BROWSER", "manual");
            Environment.SetEnvironmentVariable("CERBERUS_AGENT_OAUTH_URL_FILE", urlPath);
            using var tokenListener = new TcpListener(IPAddress.Loopback, 0);
            tokenListener.Start();
            var tokenPort = ((IPEndPoint)tokenListener.LocalEndpoint).Port;
            var callbackPort = GetFreeLoopbackPort();
            using var serverCancellation = new CancellationTokenSource();
            var serverReady = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var tokenResponse = ServeTokenStalledFailureAsync(tokenListener, serverReady, serverCancellation.Token);

            var client = new CasdoorOAuthClient(new Uri($"http://127.0.0.1:{tokenPort}"), "agent-client", null, "openid");
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var login = client.LoginWithPkceAsync(callbackPort, cancellation.Token);
            var authorizeUrl = await WaitForUrlAsync(urlPath, cancellation.Token);
            var state = WebUtility.UrlDecode(new Uri(authorizeUrl).Query.Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Single(part => part.StartsWith("state=", StringComparison.Ordinal))["state=".Length..]);
            await SendCallbackAsync(callbackPort, state, cancellation.Token);
            await serverReady.Task.WaitAsync(cancellation.Token);
            var stopwatch = Stopwatch.StartNew();

            var exception = await Assert.ThrowsAsync<HttpRequestException>(() => login);

            stopwatch.Stop();
            Assert.Equal("Token exchange failed (502).", exception.Message);
            Assert.DoesNotContain("casdoor-stalled-body-marker", exception.Message, StringComparison.Ordinal);
            Assert.InRange(stopwatch.Elapsed, TimeSpan.Zero, TimeSpan.FromSeconds(2));
            serverCancellation.Cancel();
            await tokenResponse;
        }
        finally
        {
            Environment.SetEnvironmentVariable("CERBERUS_AGENT_OAUTH_BROWSER", previousBrowserMode);
            Environment.SetEnvironmentVariable("CERBERUS_AGENT_OAUTH_URL_FILE", previousUrlPath);
            if (File.Exists(urlPath)) File.Delete(urlPath);
            var directory = Path.GetDirectoryName(urlPath);
            if (!string.IsNullOrWhiteSpace(directory) && Directory.Exists(directory)) Directory.Delete(directory);
        }
    }

    [Fact]
    public async Task LoginWithPkceAsync_OnSuccessBodyOver64KiBFailsWithoutExposingBody()
    {
        var urlPath = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"), "oauth-url.txt");
        var previousBrowserMode = Environment.GetEnvironmentVariable("CERBERUS_AGENT_OAUTH_BROWSER");
        var previousUrlPath = Environment.GetEnvironmentVariable("CERBERUS_AGENT_OAUTH_URL_FILE");
        var body = "{\"access_token\":\"access-token\",\"token_type\":\"Bearer\"}" + new string(' ', 65537);
        try
        {
            Environment.SetEnvironmentVariable("CERBERUS_AGENT_OAUTH_BROWSER", "manual");
            Environment.SetEnvironmentVariable("CERBERUS_AGENT_OAUTH_URL_FILE", urlPath);
            using var tokenListener = new TcpListener(IPAddress.Loopback, 0);
            tokenListener.Start();
            var tokenPort = ((IPEndPoint)tokenListener.LocalEndpoint).Port;
            var callbackPort = GetFreeLoopbackPort();
            var tokenResponse = ServeTokenResponseAsync(tokenListener, "200 OK", body);

            var client = new CasdoorOAuthClient(new Uri($"http://127.0.0.1:{tokenPort}"), "agent-client", null, "openid");
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var login = client.LoginWithPkceAsync(callbackPort, cancellation.Token);
            var authorizeUrl = await WaitForUrlAsync(urlPath, cancellation.Token);
            var state = WebUtility.UrlDecode(new Uri(authorizeUrl).Query.Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Single(part => part.StartsWith("state=", StringComparison.Ordinal))["state=".Length..]);
            await SendCallbackAsync(callbackPort, state, cancellation.Token);

            var exception = await Assert.ThrowsAsync<HttpRequestException>(() => login);

            Assert.Equal("Token exchange failed (200).", exception.Message);
            Assert.DoesNotContain("access-token", exception.Message, StringComparison.Ordinal);
            await tokenResponse;
        }
        finally
        {
            Environment.SetEnvironmentVariable("CERBERUS_AGENT_OAUTH_BROWSER", previousBrowserMode);
            Environment.SetEnvironmentVariable("CERBERUS_AGENT_OAUTH_URL_FILE", previousUrlPath);
            if (File.Exists(urlPath)) File.Delete(urlPath);
            var directory = Path.GetDirectoryName(urlPath);
            if (!string.IsNullOrWhiteSpace(directory) && Directory.Exists(directory)) Directory.Delete(directory);
        }
    }

    private static async Task<string> WaitForUrlAsync(string path, CancellationToken ct)
    {
        while (!File.Exists(path))
            await Task.Delay(10, ct);
        return await File.ReadAllTextAsync(path, ct);
    }

    private static async Task SendCallbackAsync(int port, string state, CancellationToken ct)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, port, ct);
        await using var stream = client.GetStream();
        var request = $"GET /callback?code=test-code&state={Uri.EscapeDataString(state)} HTTP/1.1\r\nHost: localhost\r\n\r\n";
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request), ct);
        var buffer = new byte[256];
        while (await stream.ReadAsync(buffer, ct) > 0)
        {
        }
    }

    private static async Task ServeTokenFailureAsync(TcpListener listener, string body)
    {
        using var client = await listener.AcceptTcpClientAsync();
        await using var stream = client.GetStream();
        var request = new byte[8192];
        var received = 0;
        while (received < request.Length)
        {
            var count = await stream.ReadAsync(request.AsMemory(received));
            if (count == 0)
                break;
            received += count;
            if (Encoding.ASCII.GetString(request, 0, received).Contains("\r\n\r\n", StringComparison.Ordinal))
                break;
        }
        var bytes = Encoding.UTF8.GetBytes(body);
        var header = Encoding.ASCII.GetBytes(
            $"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(header);
        await stream.WriteAsync(bytes);
    }

    private static async Task ServeTokenResponseAsync(TcpListener listener, string status, string body)
    {
        using var client = await listener.AcceptTcpClientAsync();
        await using var stream = client.GetStream();
        var request = new byte[8192];
        var received = 0;
        while (received < request.Length)
        {
            var count = await stream.ReadAsync(request.AsMemory(received));
            if (count == 0) break;
            received += count;
            if (Encoding.ASCII.GetString(request, 0, received).Contains("\r\n\r\n", StringComparison.Ordinal)) break;
        }

        var bytes = Encoding.UTF8.GetBytes(body);
        var header = Encoding.ASCII.GetBytes($"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(header);
        await stream.WriteAsync(bytes);
    }

    private static async Task ServeTokenStalledFailureAsync(TcpListener listener, TaskCompletionSource ready, CancellationToken ct)
    {
        using var client = await listener.AcceptTcpClientAsync(ct);
        await using var stream = client.GetStream();
        var request = new byte[8192];
        var received = 0;
        while (received < request.Length)
        {
            var count = await stream.ReadAsync(request.AsMemory(received), ct);
            if (count == 0) break;
            received += count;
            if (Encoding.ASCII.GetString(request, 0, received).Contains("\r\n\r\n", StringComparison.Ordinal)) break;
        }

        var header = Encoding.ASCII.GetBytes("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: 1048576\r\nConnection: keep-alive\r\n\r\ncasdoor-stalled-body-marker");
        await stream.WriteAsync(header, ct);
        ready.SetResult();
        try
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return;
        }
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
