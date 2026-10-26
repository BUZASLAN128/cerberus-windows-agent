using System.Net;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;
using Cerberus.Agent.App;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentRegistrarTests
{
    [Theory]
    [InlineData("http://100.64.0.10:8000", false)]
    [InlineData("http://100.64.0.10:8000", true)]
    [InlineData("https://foreign.example", false)]
    [InlineData(null, false)]
    public async Task RegisterAsync_AdvertisementCannotRebindSelectedDeployment(string? advertisement, bool explicitReenrollment)
    {
        const string selected = "http://127.0.0.1:8000";
        var response = JsonSerializer.Serialize(new {
            agent_id = "a1", tenant_id = "t1", agent_refresh_token = "rt1",
            telemetry_base_url = advertisement
        });
        var handler = new CaptureHandler(new HttpResponseMessage(HttpStatusCode.OK) {
            Content = new StringContent(response, Encoding.UTF8, "application/json")
        });
        using var http = new HttpClient(handler) { BaseAddress = new Uri(selected) };
        using var cts = new CancellationTokenSource();
        // Stop ancillary UI-context writes after observing the persistence boundary.
        var secrets = new CaptureSecretStore {
            CancelAfterSave = cts,
            Existing = explicitReenrollment
                ? (new AgentIdentity("old-agent", "old-tenant"), "old-refresh", "old-key", "http://100.64.0.10:8000", null, null)
                : null
        };
        var registrar = new AgentRegistrar(http, secrets, new StubKeyPairs("priv", "pub"));

        await registrar.RegisterAsync("oauth", selected, "fp", "1.2.3", "build", "dev", cts.Token,
            replaceExisting: explicitReenrollment);

        var saved = Assert.NotNull(secrets.LastSaved);
        Assert.Equal(selected, saved.BackendUrl);
        Assert.True(AgentBuildConfig.SameEndpoint(selected, saved.BackendUrl));
        Assert.False(AgentBuildConfig.SameEndpoint("https://foreign.example", saved.BackendUrl));
    }

    [Fact]
    public async Task RegisterAsync_WithExistingStoredRegistration_DoesNotCallBackendOrGenerateCredentials()
    {
        var handler = new CaptureHandler(
            new HttpResponseMessage(HttpStatusCode.InternalServerError)
            {
                Content = new StringContent("should not be used", Encoding.UTF8, "text/plain"),
            });
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://example.test") };
        var secrets = new CaptureSecretStore
        {
            Existing = (
                new AgentIdentity("existing-agent", "existing-tenant"),
                "existing-refresh",
                "existing-private-key",
                "http://existing-backend",
                null,
                null),
        };
        var keys = new StubKeyPairs("new-priv-pem", "new-pub-pem");

        var registrar = new AgentRegistrar(http, secrets, keys, log: NullAgentLogger.Instance);
        var identity = await registrar.RegisterAsync(
            oauthToken: "Bearer tok",
            backendUrlForStorage: "http://backend",
            deviceFingerprint: "fp",
            agentVersion: "1.2.3",
            buildId: "build-abc",
            buildChannel: "dev",
            ct: CancellationToken.None);

        Assert.Equal("existing-agent", identity.AgentId);
        Assert.Equal("existing-tenant", identity.TenantId);
        Assert.Null(handler.CapturedRequest);
        Assert.Null(secrets.LastSaved);
        Assert.Equal(0, keys.GenerateCount);
    }

    [Fact]
    public async Task RegisterAsync_WithIncompleteStoredRegistration_FailsClosedWithoutGeneratingCredentials()
    {
        var handler = new CaptureHandler(
            new HttpResponseMessage(HttpStatusCode.InternalServerError)
            {
                Content = new StringContent("should not be used", Encoding.UTF8, "text/plain"),
            });
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://example.test") };
        var secrets = new CaptureSecretStore
        {
            Existing = (
                new AgentIdentity("existing-agent", "existing-tenant"),
                "",
                "existing-private-key",
                "http://existing-backend",
                null,
                null),
        };
        var keys = new StubKeyPairs("new-priv-pem", "new-pub-pem");

        var registrar = new AgentRegistrar(http, secrets, keys, log: NullAgentLogger.Instance);

        await Assert.ThrowsAsync<InvalidOperationException>(() => registrar.RegisterAsync(
            oauthToken: "Bearer tok",
            backendUrlForStorage: "http://backend",
            deviceFingerprint: "fp",
            agentVersion: "1.2.3",
            buildId: "build-abc",
            buildChannel: "dev",
            ct: CancellationToken.None));

        Assert.Null(handler.CapturedRequest);
        Assert.Null(secrets.LastSaved);
        Assert.Equal(0, keys.GenerateCount);
    }

    [Fact]
    public async Task RegisterAsync_UsesDirectRegister_AndStoresSecrets()
    {
        var handler = new CaptureHandler(
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """
                    {
                      "agent_id": "a1",
                      "tenant_id": "t1",
                      "tailscale_login_server": null,
                      "tailscale_authkey": null,
                      "agent_refresh_token": "rt1",
                      "agent_access_token": null,
                      "jwt_public_key_pem": null,
                      "telemetry_base_url": "http://telemetry.test",
                      "version_policy": {
                        "minimum_supported_version": null,
                        "latest_recommended_version": null,
                        "blocked_versions": [],
                        "decision": "accepted",
                        "reason": null,
                        "download_hint": null
                      }
                    }
                    """,
                    Encoding.UTF8,
                    "application/json"),
            });
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://example.test") };

        var secrets = new CaptureSecretStore();
        var keys = new StubKeyPairs("priv-pem", "pub-pem");

        var registrar = new AgentRegistrar(http, secrets, keys, log: NullAgentLogger.Instance);
        var identity = await registrar.RegisterAsync(
            oauthToken: "Bearer tok",
            backendUrlForStorage: "http://backend",
            deviceFingerprint: "fp",
            agentVersion: "1.2.3",
            buildId: "build-abc",
            buildChannel: "dev",
            ct: CancellationToken.None);

        Assert.Equal("a1", identity.AgentId);
        Assert.Equal("t1", identity.TenantId);

        Assert.NotNull(handler.CapturedRequest);
        Assert.Equal(HttpMethod.Post, handler.CapturedRequest!.Method);
        Assert.Equal("/api/v1/agents/register", handler.CapturedRequest!.RequestUri!.AbsolutePath);

        Assert.NotNull(handler.CapturedBody);
        using var doc = JsonDocument.Parse(handler.CapturedBody!);
        var root = doc.RootElement;

        Assert.Equal("Bearer tok", root.GetProperty("oauth_token").GetString());
        Assert.Equal("pub-pem", root.GetProperty("agent_public_key_pem").GetString());
        Assert.Equal("fp", root.GetProperty("device_fingerprint").GetString());
        Assert.Equal("1.2.3", root.GetProperty("agent_version").GetString());
        Assert.Equal("build-abc", root.GetProperty("build_id").GetString());
        Assert.Equal("dev", root.GetProperty("build_channel").GetString());
        Assert.False(root.TryGetProperty("bootstrap_descriptor", out _));

        Assert.NotNull(secrets.LastSaved);
        Assert.Equal("a1", secrets.LastSaved!.Value.Identity.AgentId);
        Assert.Equal("t1", secrets.LastSaved!.Value.Identity.TenantId);
        Assert.Equal("rt1", secrets.LastSaved!.Value.RefreshToken);
        Assert.Equal("priv-pem", secrets.LastSaved!.Value.PrivateKeyPem);
        Assert.Equal("http://backend", secrets.LastSaved!.Value.BackendUrl);
    }

    [Fact]
    public async Task RegisterAsync_OnHttpFailure_ThrowsStatusOnlyAndDoesNotExposeResponseBody()
    {
        var sensitiveBody = "sql=SELECT topology tenant=0000 token=secret-token <html>internal details</html>" + new string('x', 64 * 1024);
        var handler = new CaptureHandler(new HttpResponseMessage(HttpStatusCode.BadGateway)
        {
            Content = new StringContent(sensitiveBody, Encoding.UTF8, "text/plain"),
        });
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://example.test") };
        var registrar = new AgentRegistrar(
            http,
            new CaptureSecretStore(),
            new StubKeyPairs("priv-pem", "pub-pem"),
            log: NullAgentLogger.Instance);

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() => registrar.RegisterAsync(
            oauthToken: "Bearer tok",
            backendUrlForStorage: "http://backend",
            deviceFingerprint: "fp",
            agentVersion: "1.2.3",
            buildId: "build-abc",
            buildChannel: "dev",
            ct: CancellationToken.None));

        Assert.Equal(HttpStatusCode.BadGateway, exception.StatusCode);
        Assert.Equal("Register failed (502).", exception.Message);
        Assert.DoesNotContain(sensitiveBody, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RegisterAsync_OnCanonicalError_RetainsCodeAndRequestIdWithoutBody()
    {
        var handler = new CaptureHandler(new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("{\"error_code\":\"REQUEST_INVALID\",\"detail\":\"secret\"}", Encoding.UTF8, "application/json"),
        });
        handler.Response.Headers.Add("X-Request-ID", "req-123");
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://example.test") };
        var registrar = NewRegistrar(http);

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() => Register(registrar));

        Assert.Equal("Register failed (400). [code=REQUEST_INVALID, request_id=req-123]", exception.Message);
        Assert.DoesNotContain("secret", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("{\"error_code\":\"REQUEST_FAILED\"}", "req-123")]
    [InlineData("{\"error_code\":\"UNKNOWN\"}", "req-123")]
    [InlineData("{\"error_code\":\"REQUEST_INVALID\",\"error_code\":\"REQUEST_INVALID\"}", "req-123")]
    [InlineData("not-json", "req-123")]
    [InlineData("{\"error_code\":\"REQUEST_INVALID\"}", "bad value")]
    [InlineData("{\"error_code\":\"REQUEST_INVALID\"}", "é")]
    [InlineData("{\"error_code\":\"REQUEST_INVALID\"}", "12345678901234567890123456789012345678901234567890123456789012345")]
    public async Task RegisterAsync_OnInvalidErrorEnvelopeOrRequestId_FallsBackToStatusOnly(string body, string requestId)
    {
        var handler = new CaptureHandler(new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        });
        handler.Response.Headers.TryAddWithoutValidation("X-Request-ID", requestId);
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://example.test") };
        var registrar = NewRegistrar(http);

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() => Register(registrar));

        var expected = body.Contains("REQUEST_INVALID", StringComparison.Ordinal) && !body.Contains("error_code\":\"REQUEST_INVALID\",\"error_code", StringComparison.Ordinal)
            ? requestId == "req-123"
                ? "Register failed (400). [code=REQUEST_INVALID, request_id=req-123]"
                : "Register failed (400). [code=REQUEST_INVALID]"
            : requestId == "req-123"
                ? "Register failed (400). [request_id=req-123]"
                : "Register failed (400).";
        Assert.Equal(expected, exception.Message);
    }

    [Fact]
    public async Task RegisterAsync_WithMultipleRequestIds_FallsBackToStatusOnly()
    {
        var response = new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StringContent("{\"error_code\":\"REQUEST_INVALID\"}", Encoding.UTF8, "application/json"),
        };
        response.Headers.Add("X-Request-ID", new[] { "req-1", "req-2" });
        var handler = new CaptureHandler(response);
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://example.test") };

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() => Register(NewRegistrar(http)));

        Assert.Equal("Register failed (400). [code=REQUEST_INVALID]", exception.Message);
    }

    [Fact]
    public async Task RegisterAsync_WithUnknownLengthOversizedBody_InspectsAtMostMaxPlusOneBytes()
    {
        var content = new CountingContent(Encoding.UTF8.GetBytes("{\"error_code\":\"REQUEST_INVALID\"}MARKER" + new string('x', 64 * 1024)));
        var handler = new CaptureHandler(new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = content });
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://example.test") };
        var registrar = NewRegistrar(http);

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() => Register(registrar));

        Assert.Equal("Register failed (400).", exception.Message);
        Assert.InRange(content.BytesRead, 1, 4097);
        Assert.DoesNotContain("MARKER", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RegisterAsync_WhenErrorBodyReadFails_FallsBackToStatusOnly()
    {
        var handler = new CaptureHandler(new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new ThrowingContent(),
        });
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://example.test") };
        var registrar = NewRegistrar(http);

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() => Register(registrar));

        Assert.Equal("Register failed (400).", exception.Message);
    }

    [Fact]
    public async Task RegisterAsync_AcceptsValidSuccessBodyAt65536Bytes()
    {
        var body = PadToLength(RegisterResponseJson(), 65536);
        var handler = new CaptureHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes(body)),
        });
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://example.test") };

        var identity = await Register(NewRegistrar(http));

        Assert.Equal("a1", identity.AgentId);
    }

    [Fact]
    public async Task RegisterAsync_RejectsSuccessBodyAt65537BytesWithoutBodyInException()
    {
        var body = PadToLength(RegisterResponseJson(), 65537);
        var handler = new CaptureHandler(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes(body)),
        });
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://example.test") };

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() => Register(NewRegistrar(http)));

        Assert.Equal("Register failed (200).", exception.Message);
        Assert.DoesNotContain("MARKER", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RegisterAsync_WhenSuccessBodyStalls_UsesBoundedReadDeadline()
    {
        var handler = new CaptureHandler(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StallingContent() });
        using var http = new HttpClient(handler)
        {
            BaseAddress = new Uri("http://example.test"),
            Timeout = TimeSpan.FromMilliseconds(50),
        };

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() => Register(NewRegistrar(http)));

        Assert.Equal("Register failed (200).", exception.Message);
    }

    [Fact]
    public async Task RegisterAsync_WhenErrorBodyStalls_UsesHttpClientTimeoutAndDoesNotExposeBody()
    {
        var handler = new CaptureHandler(new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StallingContent("register-body-marker"),
        });
        using var http = new HttpClient(handler)
        {
            BaseAddress = new Uri("http://example.test"),
            Timeout = TimeSpan.FromMilliseconds(50),
        };

        // The body never completes, so only the client timeout can end the call.
        var exception = await Assert.ThrowsAsync<HttpRequestException>(
            () => Register(NewRegistrar(http)).WaitAsync(HangGuard));

        Assert.Equal("Register failed (400).", exception.Message);
        Assert.DoesNotContain("register-body-marker", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RegisterAsync_WhenHeadersConsumeTheWholeTimeout_BodyGetsNoFreshBudget()
    {
        var content = new StallingContent("register-delay-marker");
        var handler = new CaptureHandler(new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = content }, headersArriveAfterDeadline: true);
        // HttpClient's own timer and the registrar's deadline both fire after 50 ms, in either order. The handler
        // returns only after a settle period far above that skew, so the shared deadline is certain to have fired.
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://example.test"), Timeout = TimeSpan.FromMilliseconds(50) };

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() => Register(NewRegistrar(http)).WaitAsync(HangGuard));

        Assert.Equal("Register failed (400).", exception.Message);
        Assert.DoesNotContain("register-delay-marker", exception.Message, StringComparison.Ordinal);
        // One budget: the deadline had already fired when the headers arrived, so no body read may start with a live token.
        // A fresh body budget would hand the read a token that is not cancelled yet.
        Assert.False(content.ReadStartedWithLiveToken);
    }

    [Fact]
    public async Task RegisterAsync_WhenCallerCancelsStalledErrorBody_PropagatesCancellationWithoutBody()
    {
        var handler = new CaptureHandler(new HttpResponseMessage(HttpStatusCode.BadRequest)
        {
            Content = new StallingContent("register-body-marker"),
        });
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://example.test"), Timeout = Timeout.InfiniteTimeSpan };
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Register(NewRegistrar(http), cts.Token).WaitAsync(HangGuard));

        Assert.DoesNotContain("register-body-marker", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task RegisterAsync_WhenCallerCancelsStalledSuccessBody_PropagatesCancellation()
    {
        var handler = new CaptureHandler(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StallingContent() });
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://example.test"), Timeout = Timeout.InfiniteTimeSpan };
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Register(NewRegistrar(http), cts.Token));
    }
}
