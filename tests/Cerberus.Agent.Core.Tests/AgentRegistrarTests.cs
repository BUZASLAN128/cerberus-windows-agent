using System.Net;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;
using Cerberus.Agent.App;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentRegistrarTests
{
    [Theory]
    [InlineData("http://100.101.130.51:8000", false)]
    [InlineData("http://100.101.130.51:8000", true)]
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
                ? (new AgentIdentity("old-agent", "old-tenant"), "old-refresh", "old-key", "http://100.101.130.51:8000", null, null)
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
        var stopwatch = Stopwatch.StartNew();

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() => Register(NewRegistrar(http)));

        stopwatch.Stop();
        Assert.Equal("Register failed (400).", exception.Message);
        Assert.DoesNotContain("register-body-marker", exception.Message, StringComparison.Ordinal);
        Assert.InRange(stopwatch.Elapsed, TimeSpan.Zero, TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task RegisterAsync_WhenHeadersConsumeMostTimeout_BodyDeadlineUsesOneBudget()
    {
        const int timeoutMs = 2000;
        var handler = new CaptureHandler(
            new HttpResponseMessage(HttpStatusCode.BadRequest) { Content = new StallingContent("register-delay-marker") },
            TimeSpan.FromMilliseconds(1500));
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://example.test"), Timeout = TimeSpan.FromMilliseconds(timeoutMs) };
        var stopwatch = Stopwatch.StartNew();

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() => Register(NewRegistrar(http)));

        stopwatch.Stop();
        Assert.Equal("Register failed (400).", exception.Message);
        Assert.DoesNotContain("register-delay-marker", exception.Message, StringComparison.Ordinal);
        Assert.InRange(stopwatch.Elapsed, TimeSpan.FromMilliseconds(1200), TimeSpan.FromSeconds(3));
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
        var stopwatch = Stopwatch.StartNew();

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Register(NewRegistrar(http), cts.Token));

        stopwatch.Stop();
        Assert.DoesNotContain("register-body-marker", exception.Message, StringComparison.Ordinal);
        Assert.InRange(stopwatch.Elapsed, TimeSpan.Zero, TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task RegisterAsync_WhenCallerCancelsStalledSuccessBody_PropagatesCancellation()
    {
        var handler = new CaptureHandler(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StallingContent() });
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://example.test"), Timeout = Timeout.InfiniteTimeSpan };
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Register(NewRegistrar(http), cts.Token));
    }

    private static AgentRegistrar NewRegistrar(HttpClient http) => new(
        http,
        new CaptureSecretStore(),
        new StubKeyPairs("priv-pem", "pub-pem"),
        log: NullAgentLogger.Instance);

    private static Task<AgentIdentity> Register(AgentRegistrar registrar) => registrar.RegisterAsync(
        oauthToken: "Bearer tok",
        backendUrlForStorage: "http://backend",
        deviceFingerprint: "fp",
        agentVersion: "1.2.3",
        buildId: "build-abc",
        buildChannel: "dev",
        ct: CancellationToken.None);

    private static Task<AgentIdentity> Register(AgentRegistrar registrar, CancellationToken ct) => registrar.RegisterAsync(
        oauthToken: "Bearer tok",
        backendUrlForStorage: "http://backend",
        deviceFingerprint: "fp",
        agentVersion: "1.2.3",
        buildId: "build-abc",
        buildChannel: "dev",
        ct: ct);

    private static string RegisterResponseJson() =>
        "{\"agent_id\":\"a1\",\"tenant_id\":\"t1\",\"agent_refresh_token\":\"rt1\",\"jwt_public_key_pem\":null,\"telemetry_base_url\":\"http://telemetry.test\"}";

    private static string PadToLength(string value, int length)
    {
        var current = Encoding.UTF8.GetByteCount(value);
        Assert.True(current <= length);
        return value + new string(' ', length - current);
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        private readonly HttpResponseMessage _response;

        public HttpRequestMessage? CapturedRequest { get; private set; }
        public string? CapturedBody { get; private set; }
        public HttpResponseMessage Response => _response;

        public CaptureHandler(HttpResponseMessage response, TimeSpan? headerDelay = null)
        {
            _response = response;
            _headerDelay = headerDelay ?? TimeSpan.Zero;
        }

        private readonly TimeSpan _headerDelay;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CapturedRequest = request;
            if (request.Content is not null)
                CapturedBody = await request.Content.ReadAsStringAsync(cancellationToken);
            if (_headerDelay > TimeSpan.Zero)
                await Task.Delay(_headerDelay, cancellationToken);
            return _response;
        }
    }

    private sealed class CountingContent : HttpContent
    {
        private readonly byte[] _bytes;

        public CountingContent(byte[] bytes) => _bytes = bytes;
        public int BytesRead { get; private set; }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => throw new NotSupportedException();

        protected override Task<Stream> CreateContentReadStreamAsync() =>
            Task.FromResult<Stream>(new CountingStream(_bytes, this));

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }

        private sealed class CountingStream : MemoryStream
        {
            private readonly byte[] _bytes;
            private readonly CountingContent _owner;
            public CountingStream(byte[] bytes, CountingContent owner) : base(bytes, writable: false)
            {
                _bytes = bytes;
                _owner = owner;
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                var read = base.Read(buffer, offset, count);
                _owner.BytesRead += read;
                return read;
            }

            public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                var remaining = _bytes.Length - (int)Position;
                var read = Math.Min(buffer.Length, Math.Max(remaining, 0));
                if (read > 0)
                {
                    _bytes.AsMemory((int)Position, read).CopyTo(buffer);
                    Position += read;
                }
                _owner.BytesRead += read;
                return ValueTask.FromResult(read);
            }
        }
    }

    private sealed class ThrowingContent : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => throw new IOException("body unavailable");
        protected override Task<Stream> CreateContentReadStreamAsync() => throw new IOException("body unavailable");
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
    }

    private sealed class StallingContent : HttpContent
    {
        private readonly byte[] _prefix;

        public StallingContent(string? prefix = null) => _prefix = Encoding.UTF8.GetBytes(prefix ?? string.Empty);

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => throw new NotSupportedException();
        protected override Task<Stream> CreateContentReadStreamAsync() => Task.FromResult<Stream>(new StallingStream(_prefix));
        protected override bool TryComputeLength(out long length) { length = 0; return false; }

        private sealed class StallingStream : Stream
        {
            private readonly byte[] _prefix;
            private int _offset;

            public StallingStream(byte[] prefix) => _prefix = prefix;

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Length => 0;
            public override long Position { get => 0; set => throw new NotSupportedException(); }
            public override void Flush() => throw new NotSupportedException();
            public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
            public override void SetLength(long value) => throw new NotSupportedException();
            public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
            public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
            {
                if (_offset < _prefix.Length)
                {
                    var count = Math.Min(buffer.Length, _prefix.Length - _offset);
                    _prefix.AsSpan(_offset, count).CopyTo(buffer.Span);
                    _offset += count;
                    return count;
                }

                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                return 0;
            }
        }
    }

    private sealed class CaptureSecretStore : ISecretStore
    {
        public CancellationTokenSource? CancelAfterSave { get; init; }
        public (AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)? Existing { get; init; }
        public (AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)? LastSaved { get; private set; }

        public Task SaveAsync(
            AgentIdentity identity,
            string refreshToken,
            string privateKeyPem,
            string backendUrl,
            string? tailscaleLoginServer,
            string? tailscaleAuthkey,
            CancellationToken ct)
        {
            LastSaved = (identity, refreshToken, privateKeyPem, backendUrl, tailscaleLoginServer, tailscaleAuthkey);
            CancelAfterSave?.Cancel();
            return Task.CompletedTask;
        }

        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
        {
            return Existing is { } existing
                ? Task.FromResult(existing)
                : throw new FileNotFoundException("No stored test registration.");
        }

        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class StubKeyPairs : IKeyPairGenerator
    {
        private readonly string _priv;
        private readonly string _pub;

        public int GenerateCount { get; private set; }

        public StubKeyPairs(string priv, string pub)
        {
            _priv = priv;
            _pub = pub;
        }

        public (string PrivateKeyPem, string PublicKeyPem) GenerateKeyPair(int keySize)
        {
            GenerateCount++;
            return (_priv, _pub);
        }
    }
}
