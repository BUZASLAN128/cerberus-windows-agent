using System.Net;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;
using Cerberus.Agent.Integrations.Ad;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentApiClientTelemetryTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ManifestHeadersStall_DeadlineReconcilesButCallerCancellationPropagates(bool callerCancels)
    {
        var now = DateTimeOffset.UtcNow;
        var transport = new ManifestHeadersStallHandler(now);
        using var http = new HttpClient(transport)
        {
            BaseAddress = new Uri("http://backend.test"),
            Timeout = callerCancels ? Timeout.InfiniteTimeSpan : TimeSpan.FromMilliseconds(100)
        };
        var state = new InMemoryAgentLifecycleStateStore();
        var secrets = new StaticSecretStore();
        var client = new AgentApiClient(http, secrets, new StaticTokenManager(), new StaticSigner(), lifecycleState: state);
        var owned = new ManifestOwnedAccountStore();
        var policy = new ManagedAccountManifestPolicy(new("a1", "t1"), state, client.GetManagedAccountManifestAsync,
            LocalUserCommandHandlers.CreateManifestReconciler(store: owned), now: () => now);
        var responses = new HeartbeatResponseHandler(secrets, lifecycleState: state, managedAccounts: policy);
        var heartbeat = await client.HeartbeatAsync(new { }, default);
        Assert.Equal(new[] { "windows.local_user.disable", "windows.local_user.delete" }, heartbeat.PendingCommands.Select(c => c.Type));
        using var caller = new CancellationTokenSource();
        var handling = responses.HandleAsync(heartbeat, caller.Token);
        await transport.ManifestStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        if (callerCancels)
        {
            caller.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => handling);
            Assert.True(owned.Enabled);
        }
        else
        {
            Assert.Equal(HeartbeatControlAction.Continue, await handling);
            Assert.False(owned.Enabled);
            Assert.Equal(HeartbeatControlAction.Continue, await responses.HandleAsync(heartbeat, default));
        }
        Assert.Equal(1, transport.ManifestFetches);
    }

    private sealed class ManifestOwnedAccountStore : IManagedLocalAccountStore
    {
        private readonly ManagedLocalOwnership _account = new(new("assignment", "account", "member",
            "cerb_sennu_k7m2q6x4", "marker", "active"), "a1", "t1", "sid", "sid");
        public bool Enabled { get; private set; } = true;
        public IReadOnlyList<ManagedLocalOwnership> ReadAccounts() => [_account];
        public void Disable(ManagedLocalOwnership ownership)
        {
            Assert.Equal(_account, ownership);
            Enabled = false;
        }
    }

    private sealed class ManifestHeadersStallHandler(DateTimeOffset now) : HttpMessageHandler
    {
        public TaskCompletionSource ManifestStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int ManifestFetches { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/managed-accounts/manifest", StringComparison.Ordinal))
            {
                ManifestFetches++;
                ManifestStarted.TrySetResult();
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                throw new InvalidOperationException("The simulated manifest headers must never arrive.");
            }
            Assert.EndsWith("/heartbeat", request.RequestUri.AbsolutePath);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(new
                {
                    pending_commands = new[]
                    {
                        new { id = "disable", type = "windows.local_user.disable", idempotency_key = "disable", payload = new { } },
                        new { id = "delete", type = "windows.local_user.delete", idempotency_key = "delete", payload = new { } }
                    },
                    next_poll_seconds = 60, next_snapshot_seconds = 60,
                    manifest_version = "4f53cda18c2baa0c",
                    managed_account_manifest_hash = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
                    manifest_fresh_until = now.AddSeconds(300).ToString("O"),
                    require_manifest_before_unlock = true
                }), Encoding.UTF8, "application/json")
            };
        }
    }

    [Fact]
    public async Task AdCommandAuthority_PostsSignedLeaseAndReadsCanonicalCommand()
    {
        var command = new AgentCommand("cmd-ad", "windows.ad_user.disable", "idem-ad", new { username = "canonical" }, LeaseId: "lease-ad");
        var handler = new CaptureHandler(JsonSerializer.Serialize(new AdCommandAuthority("t1", "a1", DateTimeOffset.UtcNow.AddSeconds(25), command)));
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var authority = await client.GetAdCommandAuthorityAsync(command, default);
        Assert.Equal("lease-ad", authority.Command.LeaseId);
        Assert.Equal("canonical", ((JsonElement)authority.Command.Payload!).GetProperty("username").GetString());
        Assert.Equal(HttpMethod.Post, handler.CapturedRequest!.Method);
        Assert.Equal("/api/v1/agents/a1/commands/cmd-ad/ad-authority", handler.CapturedRequest.RequestUri!.AbsolutePath);
        Assert.Equal("signature", Assert.Single(handler.CapturedRequest.Headers.GetValues("X-Signature")));
        using var body = JsonDocument.Parse(handler.CapturedBody!);
        Assert.Equal("lease-ad", body.RootElement.GetProperty("lease_id").GetString());
        Assert.Single(body.RootElement.EnumerateObject());
    }

    [Fact]
    public async Task ManagedAccountManifest_UsesSignedAgentScopedGetWithEmptyBody()
    {
        var handler = new CaptureHandler("""{"version":"v","hash":"h","fresh_until":"2026-09-06T12:05:00Z","require_manifest_before_unlock":true,"accounts":[]}""");
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var manifest = await client.GetManagedAccountManifestAsync(default);
        Assert.True(manifest.RequireManifestBeforeUnlock);
        Assert.Empty(manifest.Accounts);
        Assert.Equal(HttpMethod.Get, handler.CapturedRequest!.Method);
        Assert.Equal("/api/v1/agents/a1/managed-accounts/manifest", handler.CapturedRequest.RequestUri!.AbsolutePath);
        Assert.Equal("a1", Assert.Single(handler.CapturedRequest.Headers.GetValues("X-Agent-Id")));
        Assert.Equal("signature", Assert.Single(handler.CapturedRequest.Headers.GetValues("X-Signature")));
        Assert.Equal("", handler.CapturedBody);
    }

    [Fact]
    public async Task SubmitSnapshotAsync_PostsSignedSnapshotEndpoint()
    {
        var handler = new CaptureHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());

        var snapshot = AgentSnapshotFactory.Create(
            Metadata(),
            DateTimeOffset.Parse("2026-05-07T00:00:00Z"),
            new Dictionary<string, object?> { ["identity"] = new { status = "ok" } });

        var ack = await client.SubmitSnapshotAsync(snapshot, CancellationToken.None);

        Assert.Equal("accepted", ack.Status);
        Assert.Equal("/api/v1/agents/a1/snapshot", handler.CapturedRequest!.RequestUri!.AbsolutePath);
        Assert.Contains("X-Signature", handler.CapturedRequest.Headers.Select(h => h.Key));
        using var doc = JsonDocument.Parse(handler.CapturedBody!);
        Assert.Equal(AgentSchemaVersions.Snapshot, doc.RootElement.GetProperty("schema_version").GetString());
    }

    [Fact]
    public async Task SubmitEventsAndProbeResult_PostExpectedEndpoints()
    {
        var handler = new CaptureHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());

        var events = AgentTelemetryFactory.CreateEvents(
            Metadata(),
            new[]
            {
                new AgentEventItem(
                    EventId: "evt-12345678",
                    Type: "agent.started",
                    OccurredAt: "2026-05-07T00:00:00Z",
                    Severity: "info",
                    Payload: new Dictionary<string, object?>()),
            });
        await client.SubmitEventsAsync(events, CancellationToken.None);
        Assert.Equal("/api/v1/agents/a1/events", handler.CapturedRequest!.RequestUri!.AbsolutePath);

        var probe = AgentTelemetryFactory.CreateProbeResult(
            Metadata(),
            resultId: "res-12345678",
            probeId: "agent.self_test",
            status: "ok",
            payload: new Dictionary<string, object?>());
        await client.SubmitProbeResultAsync(probe, CancellationToken.None);
        Assert.Equal("/api/v1/agents/a1/probe-results", handler.CapturedRequest!.RequestUri!.AbsolutePath);
    }

    [Fact]
    public async Task SafeTelemetrySubmit_RetriesSnapshotProbeAndDiagnosticOnceOnTransientOutage()
    {
        var handler = new TransientThenOkHandler(
            expectedPaths:
            [
                "/api/v1/agents/a1/snapshot",
                "/api/v1/agents/a1/probe-results",
                "/api/v1/agents/a1/diagnostic-bundles",
            ],
            okBodies:
            [
                """{"status":"accepted","accepted":1,"ignored":0,"reason":null,"changed_sections":["identity"]}""",
                """{"status":"accepted","accepted":1,"ignored":0,"reason":null,"changed_sections":[]}""",
                """{"status":"accepted","bundle_id":"bundle-1","accepted":1,"ignored":0,"reason":null}""",
            ]);
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());

        await client.SubmitSnapshotAsync(
            AgentSnapshotFactory.Create(
                Metadata(),
                DateTimeOffset.Parse("2026-05-07T00:00:00Z"),
                new Dictionary<string, object?> { ["identity"] = new { status = "ok" } }),
            CancellationToken.None);
        await client.SubmitProbeResultAsync(
            AgentTelemetryFactory.CreateProbeResult(
                Metadata(),
                resultId: "res-12345678",
                probeId: "agent.self_test",
                status: "ok",
                payload: new Dictionary<string, object?>()),
            CancellationToken.None);
        await client.SubmitDiagnosticBundleAsync(
            AgentTelemetryFactory.CreateDiagnosticBundle(
                Metadata(),
                clientBundleId: "diag-12345678",
                manifest: new Dictionary<string, object?>(),
                summary: new Dictionary<string, object?>(),
                payload: new Dictionary<string, object?>(),
                collectedAtUtc: DateTimeOffset.Parse("2026-05-07T00:00:00Z")),
            CancellationToken.None);

        Assert.Equal(2, handler.AttemptsByPath["/api/v1/agents/a1/snapshot"]);
        Assert.Equal(2, handler.AttemptsByPath["/api/v1/agents/a1/probe-results"]);
        Assert.Equal(2, handler.AttemptsByPath["/api/v1/agents/a1/diagnostic-bundles"]);
    }

    [Fact]
    public async Task UnsafeTelemetrySubmit_DoesNotRetryEventsCommandResultPreauthOrSelfDeactivate()
    {
        var handler = new AlwaysUnavailableHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());

        await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitEventsAsync(
            AgentTelemetryFactory.CreateEvents(
                Metadata(),
                new[]
                {
                    new AgentEventItem(
                        EventId: "evt-12345678",
                        Type: "agent.started",
                        OccurredAt: "2026-05-07T00:00:00Z",
                        Severity: "info",
                        Payload: new Dictionary<string, object?>()),
                }),
            CancellationToken.None));
        await Assert.ThrowsAsync<HttpRequestException>(() => client.SubmitCommandResultAsync(
            "cmd-1",
            new { status = "DONE" },
            CancellationToken.None));
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetTailscalePreauthAsync(CancellationToken.None));
        await Assert.ThrowsAsync<HttpRequestException>(() => client.SelfDeactivateAsync(
            new AgentSelfDeactivateRequest(
                SchemaVersion: "agent.self-deactivate.v1",
                ReasonCode: "unit",
                Reason: "unit"),
            CancellationToken.None));

        Assert.Equal(1, handler.AttemptsByPath["/api/v1/agents/a1/events"]);
        Assert.Equal(1, handler.AttemptsByPath["/api/v1/agents/a1/commands/cmd-1/result"]);
        Assert.Equal(1, handler.AttemptsByPath["/api/v1/agents/a1/tailscale/preauth"]);
        Assert.Equal(1, handler.AttemptsByPath["/api/v1/agents/a1/deactivate"]);
    }

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
        var stopwatch = Stopwatch.StartNew();

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() => client.GetTailscalePreauthAsync(CancellationToken.None));

        stopwatch.Stop();
        Assert.Equal("Tailscale preauth failed (200).", exception.Message);
        Assert.DoesNotContain("preauth-body-marker", exception.Message, StringComparison.Ordinal);
        Assert.InRange(stopwatch.Elapsed, TimeSpan.Zero, TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task GetTailscalePreauthAsync_WhenHeadersConsumeMostTimeout_BodyDeadlineUsesOneBudget()
    {
        const int timeoutMs = 2000;
        var handler = new FailureHandler(
            HttpStatusCode.OK,
            new StallingContent("preauth-delay-marker"),
            TimeSpan.FromMilliseconds(1500));
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test"), Timeout = TimeSpan.FromMilliseconds(timeoutMs) };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var stopwatch = Stopwatch.StartNew();

        var exception = await Assert.ThrowsAsync<HttpRequestException>(() => client.GetTailscalePreauthAsync(CancellationToken.None));

        stopwatch.Stop();
        Assert.Equal("Tailscale preauth failed (200).", exception.Message);
        Assert.DoesNotContain("preauth-delay-marker", exception.Message, StringComparison.Ordinal);
        Assert.InRange(stopwatch.Elapsed, TimeSpan.FromMilliseconds(1200), TimeSpan.FromSeconds(3));
    }

    [Fact]
    public async Task GetTailscalePreauthAsync_WhenCallerCancelsStalledSuccessBody_PropagatesCancellationWithoutBody()
    {
        var handler = new FailureHandler(HttpStatusCode.OK, new StallingContent("preauth-body-marker"));
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test"), Timeout = Timeout.InfiniteTimeSpan };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        var stopwatch = Stopwatch.StartNew();

        var exception = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.GetTailscalePreauthAsync(cts.Token));

        stopwatch.Stop();
        Assert.DoesNotContain("preauth-body-marker", exception.Message, StringComparison.Ordinal);
        Assert.InRange(stopwatch.Elapsed, TimeSpan.Zero, TimeSpan.FromSeconds(2));
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

    private static AgentBuildMetadata Metadata() => new(
        AgentVersion: "1.2.3",
        BuildId: "build-1",
        BuildChannel: "dev",
        BootId: "boot-1",
        SupportedSchemaVersions: AgentSchemaVersions.All);

    private static string HeartbeatResponseJson() =>
        """
        {
          "pending_commands": [],
          "next_poll_seconds": 60,
          "server_time": 0,
          "server_time_utc": "2026-06-01T00:00:00Z",
          "command_batch_size": 0,
          "next_snapshot_seconds": 300,
          "config_version": "agent-config.v1",
          "lifecycle_state": "connected",
          "registration_state": "claimed",
          "claim_required": false,
          "manifest_version": null,
          "managed_account_manifest_hash": null,
          "manifest_fresh_until": null,
          "require_manifest_before_unlock": true,
          "agent_status": "connected",
          "version_policy": null,
          "update": null,
          "revoke": null,
          "quarantine": null
        }
        """;

    private static string PadToLength(string value, int length)
    {
        var current = Encoding.UTF8.GetByteCount(value);
        Assert.True(current <= length);
        return value + new string(' ', length - current);
    }

    private sealed class CaptureHandler : HttpMessageHandler
    {
        private readonly string _responseBody;

        public CaptureHandler(string? responseBody = null)
        {
            _responseBody = responseBody
                ?? """{"status":"accepted","accepted":1,"ignored":0,"reason":null,"changed_sections":["identity"]}""";
        }

        public HttpRequestMessage? CapturedRequest { get; private set; }
        public string? CapturedBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CapturedRequest = request;
            CapturedBody = request.Content is null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    _responseBody,
                    Encoding.UTF8,
                    "application/json"),
            };
        }
    }

    private sealed class FailureHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _statusCode;
        private readonly HttpContent _content;

        public FailureHandler(HttpStatusCode statusCode, HttpContent content, TimeSpan? headerDelay = null)
        {
            _statusCode = statusCode;
            _content = content;
            _headerDelay = headerDelay ?? TimeSpan.Zero;
        }

        private readonly TimeSpan _headerDelay;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (_headerDelay > TimeSpan.Zero)
                await Task.Delay(_headerDelay, cancellationToken);
            return new HttpResponseMessage(_statusCode) { Content = _content };
        }
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

    private sealed class TransientThenOkHandler : HttpMessageHandler
    {
        private readonly Queue<string> _expectedPaths;
        private readonly Queue<string> _okBodies;

        public Dictionary<string, int> AttemptsByPath { get; } = new(StringComparer.Ordinal);

        public TransientThenOkHandler(IEnumerable<string> expectedPaths, IEnumerable<string> okBodies)
        {
            _expectedPaths = new Queue<string>(expectedPaths);
            _okBodies = new Queue<string>(okBodies);
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            AttemptsByPath.TryGetValue(path, out var attempts);
            AttemptsByPath[path] = attempts + 1;

            if (attempts == 0)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
                {
                    Content = new StringContent("""{"detail":"unavailable"}""", Encoding.UTF8, "application/json"),
                });
            }

            Assert.Equal(_expectedPaths.Dequeue(), path);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_okBodies.Dequeue(), Encoding.UTF8, "application/json"),
            });
        }
    }

    private sealed class AlwaysUnavailableHandler : HttpMessageHandler
    {
        public Dictionary<string, int> AttemptsByPath { get; } = new(StringComparer.Ordinal);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            AttemptsByPath.TryGetValue(path, out var attempts);
            AttemptsByPath[path] = attempts + 1;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)
            {
                Content = new StringContent("""{"detail":"unavailable"}""", Encoding.UTF8, "application/json"),
            });
        }
    }

    private sealed class UnauthorizedThenOkHandler : HttpMessageHandler
    {
        private readonly string _okResponseBody;

        public List<string?> CapturedAuthorizations { get; } = [];
        public List<string> CapturedNonces { get; } = [];
        public List<string?> CapturedBodies { get; } = [];

        public UnauthorizedThenOkHandler(string okResponseBody)
        {
            _okResponseBody = okResponseBody;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            CapturedAuthorizations.Add(request.Headers.Authorization?.ToString());
            CapturedNonces.Add(request.Headers.GetValues("X-Nonce").Single());
            CapturedBodies.Add(request.Content is null
                ? null
                : await request.Content.ReadAsStringAsync(cancellationToken));
            if (CapturedAuthorizations.Count == 1)
            {
                return new HttpResponseMessage(HttpStatusCode.Unauthorized)
                {
                    Content = new StringContent("""{"detail":"expired"}""", Encoding.UTF8, "application/json"),
                };
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_okResponseBody, Encoding.UTF8, "application/json"),
            };
        }
    }

    private sealed class UnauthorizedPreauthThenOkHandler : HttpMessageHandler
    {
        private readonly DisposableContent _firstContent;
        public int Attempts { get; private set; }

        public UnauthorizedPreauthThenOkHandler(DisposableContent firstContent) => _firstContent = firstContent;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Attempts++;
            return Task.FromResult(Attempts == 1
                ? new HttpResponseMessage(HttpStatusCode.Unauthorized) { Content = _firstContent }
                : new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("{\"tailscale_login_server\":\"https://login.test\",\"tailscale_authkey\":\"tskey-test\"}", Encoding.UTF8, "application/json"),
                });
        }
    }

    private sealed class DisposableContent : StringContent
    {
        public bool Disposed { get; private set; }
        public DisposableContent(string content) : base(content, Encoding.UTF8, "application/json") { }
        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }

    private sealed class StaticSecretStore : ISecretStore
    {
        public Task SaveAsync(
            AgentIdentity identity,
            string refreshToken,
            string privateKeyPem,
            string backendUrl,
            string? tailscaleLoginServer,
            string? tailscaleAuthkey,
            CancellationToken ct) => Task.CompletedTask;

        public Task<(AgentIdentity Identity, string RefreshToken, string PrivateKeyPem, string BackendUrl, string? TailscaleLoginServer, string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
        {
            return Task.FromResult((
                new AgentIdentity("a1", "t1"),
                "refresh",
                "private",
                "http://backend.test",
                (string?)null,
                (string?)null));
        }

        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class StaticTokenManager : ITokenManager
    {
        public Task<string> GetAccessTokenAsync(CancellationToken ct) => Task.FromResult("token");
        public Task RefreshAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class RefreshAwareTokenManager : ITokenManager
    {
        public int RefreshCount { get; private set; }

        public Task<string> GetAccessTokenAsync(CancellationToken ct) =>
            Task.FromResult(RefreshCount == 0 ? "stale-token" : "fresh-token");

        public Task RefreshAsync(CancellationToken ct)
        {
            RefreshCount++;
            return Task.CompletedTask;
        }
    }

    private sealed class StaticSigner : IRequestSigner
    {
        public string ComputeBodyHash(byte[] bodyBytes) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bodyBytes)).ToLowerInvariant();
        public string CanonicalString(string method, string path, string nonce, long timestamp, string bodyHash) => $"{method}:{path}:{nonce}:{timestamp}:{bodyHash}";
        public string Sign(string canonical) => "signature";
    }
}
