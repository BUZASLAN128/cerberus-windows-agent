using System.Net;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;
using Cerberus.Agent.Integrations.Ad;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentApiClientTelemetryTests
{
    [Fact]
    public async Task GetTailscalePreauthAsync_OnHttpFailure_ThrowsStatusOnlyAndDoesNotExposeResponseBody()
    {
        var sensitiveBody = "sql=SELECT topology tenant=0000 token=secret-token <html>internal details</html>" + new string('x', 64 * 1024);
        var handler = new FailureHandler(
            HttpStatusCode.BadGateway,
            new StringContent(sensitiveBody, Encoding.UTF8, "text/plain"));
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.GetTailscalePreauthAsync(CancellationToken.None));

        Assert.Equal(HttpStatusCode.BadGateway, exception.StatusCode);
        Assert.Equal("Tailscale preauth failed (502).", exception.Message);
        Assert.DoesNotContain(sensitiveBody, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetTailscalePreauthAsync_AcceptsValidSuccessBodyAt65536Bytes()
    {
        var body = PadToLength("{\"tailscale_login_server\":\"https://login.test\",\"tailscale_authkey\":\"tskey-test\"}", 65536);
        var handler = new FailureHandler(HttpStatusCode.OK, new ByteArrayContent(Encoding.UTF8.GetBytes(body)));
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());

        var result = await client.GetTailscalePreauthAsync(CancellationToken.None);

        Assert.Equal("https://login.test", result.LoginServer);
    }

    [Fact]
    public async Task GetTailscalePreauthAsync_RejectsSuccessBodyAt65537BytesWithStatusOnlyException()
    {
        var body = PadToLength("{\"tailscale_login_server\":\"https://login.test\",\"tailscale_authkey\":\"tskey-test\"}", 65537);
        var handler = new FailureHandler(HttpStatusCode.OK, new ByteArrayContent(Encoding.UTF8.GetBytes(body)));
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() => client.GetTailscalePreauthAsync(CancellationToken.None));

        Assert.Equal("Tailscale preauth failed (200).", exception.Message);
    }

    [Fact]
    public async Task GetTailscalePreauthAsync_WhenErrorBodyStalls_UsesBoundedReadDeadline()
    {
        var handler = new FailureHandler(HttpStatusCode.BadRequest, new StallingContent());
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test"), Timeout = TimeSpan.FromMilliseconds(50) };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() => client.GetTailscalePreauthAsync(CancellationToken.None));

        Assert.Equal("Tailscale preauth failed (400).", exception.Message);
    }

    [Fact]
    public async Task GetTailscalePreauthAsync_WhenCallerCancelsStalledErrorBody_PropagatesCancellation()
    {
        var handler = new FailureHandler(HttpStatusCode.BadRequest, new StallingContent());
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test"), Timeout = Timeout.InfiniteTimeSpan };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.GetTailscalePreauthAsync(cts.Token));
    }

    [Fact]
    public async Task GetTailscalePreauthAsync_WhenSuccessBodyStalls_UsesHttpClientTimeoutAndDoesNotExposeBody()
    {
        var handler = new FailureHandler(HttpStatusCode.OK, new StallingContent("preauth-body-marker"));
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test"), Timeout = TimeSpan.FromMilliseconds(50) };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());

        // The body never completes, so only the client timeout can end the call.
        // The guard turns a missing timeout into a failure instead of a hang.
        var exception = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetTailscalePreauthAsync(CancellationToken.None).WaitAsync(HangGuard));

        Assert.Equal("Tailscale preauth failed (200).", exception.Message);
        Assert.DoesNotContain("preauth-body-marker", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GetTailscalePreauthAsync_WhenHeadersConsumeMostTimeout_BodyDeadlineUsesOneBudget()
    {
        const int timeoutMs = 2000;
        var content = new StallingContent("preauth-delay-marker");
        var handler = new FailureHandler(HttpStatusCode.OK, content, TimeSpan.FromMilliseconds(1000));
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test"), Timeout = TimeSpan.FromMilliseconds(timeoutMs) };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());

        var exception = await Assert.ThrowsAsync<HttpRequestException>(
            () => client.GetTailscalePreauthAsync(CancellationToken.None).WaitAsync(HangGuard));

        Assert.Equal("Tailscale preauth failed (200).", exception.Message);
        Assert.DoesNotContain("preauth-delay-marker", exception.Message, StringComparison.Ordinal);
        Assert.NotEqual(0, content.StallStartedAt);
        Assert.NotEqual(0, content.CancelledAt);
        // The body read starts after the 1000 ms header delay. Cancellation is relative to the body read start:
        // a fresh body budget cannot cancel before the full 2000 ms has passed, while one shared budget leaves
        // about 1000 ms. The 1750 ms bound separates them with no dependence on total elapsed time.
        var bodyWait = Stopwatch.GetElapsedTime(content.StallStartedAt, content.CancelledAt);
        Assert.True(bodyWait < TimeSpan.FromMilliseconds(timeoutMs - 250), $"body read was cancelled after {bodyWait}");
    }

    [Fact]
    public async Task GetTailscalePreauthAsync_WhenCallerCancelsStalledSuccessBody_PropagatesCancellationWithoutBody()
    {
        var handler = new FailureHandler(HttpStatusCode.OK, new StallingContent("preauth-body-marker"));
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test"), Timeout = Timeout.InfiniteTimeSpan };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => client.GetTailscalePreauthAsync(cts.Token).WaitAsync(HangGuard));

        Assert.DoesNotContain("preauth-body-marker", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SelfDeactivateAsync_PostsSignedDeactivateEndpoint()
    {
        var handler = new CaptureHandler(
            """{"status":"deactivated","agent_id":"a1","registration_state":"deactivated","revoked_tokens":1}""");
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());

        var response = await client.SelfDeactivateAsync(
            new AgentSelfDeactivateRequest(
                SchemaVersion: "agent.self-deactivate.v1",
                ReasonCode: "agent_unregister_device",
                Reason: "unit"),
            CancellationToken.None);

        Assert.Equal("deactivated", response.Status);
        Assert.Equal(1, response.RevokedTokens);
        Assert.Equal("/api/v1/agents/a1/deactivate", handler.CapturedRequest!.RequestUri!.AbsolutePath);
        Assert.Contains("X-Signature", handler.CapturedRequest.Headers.Select(h => h.Key));
        using var doc = JsonDocument.Parse(handler.CapturedBody!);
        Assert.Equal("agent.self-deactivate.v1", doc.RootElement.GetProperty("schema_version").GetString());
        Assert.Equal("agent_unregister_device", doc.RootElement.GetProperty("reason_code").GetString());
    }

    [Fact]
    public async Task HeartbeatAsync_OnUnauthorizedRefreshesTokenAndRetriesOnceWithNewNonce()
    {
        var handler = new UnauthorizedThenOkHandler(HeartbeatResponseJson());
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var tokens = new RefreshAwareTokenManager();
        var client = new AgentApiClient(http, new StaticSecretStore(), tokens, new StaticSigner());

        var response = await client.HeartbeatAsync(new { status = "connected" }, CancellationToken.None);

        Assert.Equal(60, response.NextPollSeconds);
        Assert.Equal(2, handler.CapturedAuthorizations.Count);
        Assert.Equal(1, tokens.RefreshCount);
        Assert.Equal("Bearer stale-token", handler.CapturedAuthorizations[0]);
        Assert.Equal("Bearer fresh-token", handler.CapturedAuthorizations[1]);
        Assert.NotEqual(handler.CapturedNonces[0], handler.CapturedNonces[1]);
    }

    [Fact]
    public async Task GetTailscalePreauthAsync_OnUnauthorizedDisposesFirstResponseAndRetriesOnce()
    {
        var firstContent = new DisposableContent("{\"detail\":\"expired\"}");
        var handler = new UnauthorizedPreauthThenOkHandler(firstContent);
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var tokens = new RefreshAwareTokenManager();
        var client = new AgentApiClient(http, new StaticSecretStore(), tokens, new StaticSigner());

        var result = await client.GetTailscalePreauthAsync(CancellationToken.None);

        Assert.Equal("https://login.test", result.LoginServer);
        Assert.True(firstContent.Disposed);
        Assert.Equal(2, handler.Attempts);
        Assert.Equal(1, tokens.RefreshCount);
    }
}
