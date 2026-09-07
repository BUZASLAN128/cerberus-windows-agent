using System.Net;
using System.Text;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class HeartbeatLoopTests
{
    [Fact]
    public async Task RunAsync_SubmitsSnapshot_WhenResponseSkipsCommands()
    {
        var handler = new LoopCaptureHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var cachePath = Path.Combine(
            Path.GetTempPath(),
            "cerberus-agent-tests",
            Guid.NewGuid().ToString("N"),
            "idempotency.json");
        var dispatcher = new CommandDispatcher(
            new[] { new CaptureCommandHandler() },
            new IdempotencyCache(cachePath, maxEntries: 10, ttl: TimeSpan.FromMinutes(5)));
        var loop = new HeartbeatLoop(
            client,
            dispatcher,
            minDelayOnError: TimeSpan.FromMilliseconds(10),
            responseHandler: new HeartbeatResponseHandler(new StaticSecretStore(), NullAgentLogger.Instance),
            telemetryProvider: new StaticTelemetryProvider(),
            log: NullAgentLogger.Instance,
            initialSnapshotDelay: TimeSpan.Zero);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = loop.RunAsync(cts.Token);
        await handler.SnapshotSubmittedTask.WaitAsync(cts.Token);
        cts.Cancel();
        await runTask;

        Assert.True(handler.SnapshotSubmitted);
        Assert.False(handler.CommandResultSubmitted);
    }

    [Fact]
    public async Task RunAsync_SubmitsRefreshSnapshotOnNextHeartbeat_AndKeepsChangeMadeDuringCollectionPending()
    {
        var provider = new RefreshableTelemetryProvider();
        provider.DuringBuild = buildNumber =>
        {
            if (buildNumber == 1)
                provider.RequestRefresh();
        };
        var handler = new SchedulingLoopHandler(attempt =>
        {
            if (attempt == 1)
                provider.RequestRefresh();
        });
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var dispatcher = new CommandDispatcher(
            Array.Empty<ICommandHandler>(),
            new IdempotencyCache(Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"), "idempotency.json"), 10, TimeSpan.FromMinutes(5)));
        var loop = new HeartbeatLoop(
            client,
            dispatcher,
            minDelayOnError: TimeSpan.FromMilliseconds(10),
            telemetryProvider: provider,
            log: NullAgentLogger.Instance,
            initialSnapshotDelay: TimeSpan.FromMinutes(5));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = loop.RunAsync(cts.Token);
        await handler.SecondSnapshotSubmittedTask.WaitAsync(cts.Token);
        cts.Cancel();
        await runTask;

        Assert.Equal(2, handler.SnapshotAttempts);
        Assert.Equal(2, provider.BuildCount);
        Assert.Equal(2, provider.SubmittedVersion);
        Assert.False(provider.IsSnapshotRefreshRequired());
    }

    [Fact]
    public async Task RunAsync_DoesNotSubmitSnapshotForStableTelemetryBeforeNormalCadence()
    {
        var provider = new RefreshableTelemetryProvider();
        var handler = new SchedulingLoopHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var dispatcher = new CommandDispatcher(
            Array.Empty<ICommandHandler>(),
            new IdempotencyCache(Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"), "idempotency.json"), 10, TimeSpan.FromMinutes(5)));
        var loop = new HeartbeatLoop(
            client,
            dispatcher,
            minDelayOnError: TimeSpan.FromMilliseconds(10),
            telemetryProvider: provider,
            log: NullAgentLogger.Instance,
            initialSnapshotDelay: TimeSpan.FromMinutes(5));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = loop.RunAsync(cts.Token);
        await handler.SecondHeartbeatTask.WaitAsync(cts.Token);
        cts.Cancel();
        await runTask;

        Assert.Equal(0, handler.SnapshotAttempts);
        Assert.Equal(0, provider.BuildCount);
    }

    [Fact]
    public async Task RunAsync_RetriesRefreshSnapshotAfterSubmissionFailureWithoutAcknowledgingIt()
    {
        var provider = new RefreshableTelemetryProvider();
        provider.RequestRefresh();
        var handler = new SchedulingLoopHandler(snapshotFailuresBeforeSuccess: 1);
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var dispatcher = new CommandDispatcher(
            Array.Empty<ICommandHandler>(),
            new IdempotencyCache(Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"), "idempotency.json"), 10, TimeSpan.FromMinutes(5)));
        var loop = new HeartbeatLoop(
            client,
            dispatcher,
            minDelayOnError: TimeSpan.FromMilliseconds(10),
            telemetryProvider: provider,
            log: NullAgentLogger.Instance,
            initialSnapshotDelay: TimeSpan.FromMinutes(5));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = loop.RunAsync(cts.Token);
        await handler.SnapshotSubmittedTask.WaitAsync(cts.Token);
        cts.Cancel();
        await runTask;

        Assert.Equal(2, handler.SnapshotAttempts);
        Assert.Equal(2, provider.BuildCount);
        Assert.Equal(1, provider.MarkSubmittedCount);
        Assert.False(provider.IsSnapshotRefreshRequired());
    }

    [Fact]
    public async Task RunAsync_IncludesUpdateStatusProviderPayload()
    {
        var handler = new LoopCaptureHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var cachePath = Path.Combine(
            Path.GetTempPath(),
            "cerberus-agent-tests",
            Guid.NewGuid().ToString("N"),
            "idempotency.json");
        var dispatcher = new CommandDispatcher(
            new[] { new CaptureCommandHandler() },
            new IdempotencyCache(cachePath, maxEntries: 10, ttl: TimeSpan.FromMinutes(5)));
        var loop = new HeartbeatLoop(
            client,
            dispatcher,
            minDelayOnError: TimeSpan.FromMilliseconds(10),
            updateStatusProvider: _ => Task.FromResult<object?>(new
            {
                schema_version = "agent.update.status.v1",
                state = "staged",
                target_version = "0.2.0",
            }),
            responseHandler: new HeartbeatResponseHandler(new StaticSecretStore(), NullAgentLogger.Instance),
            log: NullAgentLogger.Instance);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = loop.RunAsync(cts.Token);
        await handler.HeartbeatSubmittedTask.WaitAsync(cts.Token);
        cts.Cancel();
        await runTask;

        Assert.Contains(handler.HeartbeatBodies, body => body.Contains("\"update_status\""));
        Assert.Contains(handler.HeartbeatBodies, body => body.Contains("\"state\":\"staged\""));
    }

    [Fact]
    public async Task RunAsync_SubmitsFailedResultAndContinues_WhenCommandHandlerThrows()
    {
        var handler = new CommandFailureLoopHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var cachePath = Path.Combine(
            Path.GetTempPath(),
            "cerberus-agent-tests",
            Guid.NewGuid().ToString("N"),
            "idempotency.json");
        var dispatcher = new CommandDispatcher(
            new ICommandHandler[] { new ThrowingCommandHandler(), new CaptureCommandHandler() },
            new IdempotencyCache(cachePath, maxEntries: 10, ttl: TimeSpan.FromMinutes(5)));
        var loop = new HeartbeatLoop(
            client,
            dispatcher,
            minDelayOnError: TimeSpan.FromMilliseconds(10),
            responseHandler: new HeartbeatResponseHandler(new StaticSecretStore(), NullAgentLogger.Instance),
            log: NullAgentLogger.Instance,
            commandTimeout: TimeSpan.FromMilliseconds(100));

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(350));
        await loop.RunAsync(cts.Token);

        Assert.Equal(2, handler.CommandResults.Count);
        Assert.Contains(handler.CommandResults, body => body.Contains("\"status\":\"FAILED\""));
        Assert.Contains(handler.CommandResults, body => body.Contains("\"status\":\"DONE\""));
    }

    [Fact]
    public void CalculateErrorDelay_BacksOffAndCaps_WhenBackendStaysUnavailable()
    {
        var min = TimeSpan.FromSeconds(10);
        var max = TimeSpan.FromMinutes(10);

        Assert.Equal(TimeSpan.FromSeconds(10), HeartbeatLoop.CalculateErrorDelay(min, max, 1));
        Assert.Equal(TimeSpan.FromSeconds(20), HeartbeatLoop.CalculateErrorDelay(min, max, 2));
        Assert.Equal(TimeSpan.FromSeconds(40), HeartbeatLoop.CalculateErrorDelay(min, max, 3));
        Assert.Equal(max, HeartbeatLoop.CalculateErrorDelay(min, max, 20));
    }

    [Fact]
    public async Task RunAsync_RetriesImmediately_WhenBackoffResetRequested()
    {
        var handler = new InvalidHeartbeatPayloadHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var cachePath = Path.Combine(
            Path.GetTempPath(),
            "cerberus-agent-tests",
            Guid.NewGuid().ToString("N"),
            "idempotency.json");
        var dispatcher = new CommandDispatcher(
            Array.Empty<ICommandHandler>(),
            new IdempotencyCache(cachePath, maxEntries: 10, ttl: TimeSpan.FromMinutes(5)));
        var resetChecks = 0;
        var loop = new HeartbeatLoop(
            client,
            dispatcher,
            minDelayOnError: TimeSpan.FromSeconds(30),
            maxDelayOnError: TimeSpan.FromMinutes(10),
            backoffResetRequested: _ =>
                Task.FromResult(Interlocked.Increment(ref resetChecks) == 1),
            log: NullAgentLogger.Instance);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var runTask = loop.RunAsync(cts.Token);
        await handler.SecondHeartbeatAttemptTask.WaitAsync(cts.Token);
        cts.Cancel();
        await runTask;

        Assert.True(handler.HeartbeatAttempts >= 2);
        Assert.True(resetChecks >= 1);
    }

    private sealed class LoopCaptureHandler : HttpMessageHandler
    {
        public bool SnapshotSubmitted { get; private set; }
        public bool CommandResultSubmitted { get; private set; }
        public List<string> HeartbeatBodies { get; } = new();
        public Task HeartbeatSubmittedTask => _heartbeatSubmitted.Task;
        public Task SnapshotSubmittedTask => _snapshotSubmitted.Task;

        private readonly TaskCompletionSource _heartbeatSubmitted =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _snapshotSubmitted =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("/heartbeat", StringComparison.Ordinal))
            {
                HeartbeatBodies.Add(await request.Content!.ReadAsStringAsync(cancellationToken));
                _heartbeatSubmitted.TrySetResult();
                return JsonResponse(
                    """
                    {
                      "pending_commands": [
                        {
                          "id": "cmd-1",
                          "type": "test.command",
                          "idempotency_key": "cmd-1",
                          "payload": {}
                        }
                      ],
                      "next_poll_seconds": 60,
                      "server_time": 1,
                      "server_time_utc": "2026-05-08T00:00:00Z",
                      "command_batch_size": 1,
                      "next_snapshot_seconds": 60,
                      "config_version": "agent-config.v1",
                      "lifecycle_state": "connected",
                      "agent_status": "pending_claim",
                      "version_policy": null,
                      "update": null,
                      "revoke": null,
                      "quarantine": {"active": true}
                    }
                    """);
            }

            if (path.EndsWith("/events", StringComparison.Ordinal))
                return JsonResponse("""{"status":"accepted","accepted":1,"ignored":0,"reason":null,"changed_sections":[]}""");

            if (path.EndsWith("/snapshot", StringComparison.Ordinal))
            {
                _ = await request.Content!.ReadAsStringAsync(cancellationToken);
                SnapshotSubmitted = true;
                _snapshotSubmitted.TrySetResult();
                return JsonResponse("""{"status":"accepted","accepted":1,"ignored":0,"reason":null,"changed_sections":["identity"]}""");
            }

            if (path.EndsWith("/result", StringComparison.Ordinal))
            {
                CommandResultSubmitted = true;
                return JsonResponse("""{"status":"accepted"}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }

        private static HttpResponseMessage JsonResponse(string json)
            => new(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };
    }

    private sealed class RefreshableTelemetryProvider : IAgentTelemetryProvider, IAgentTelemetrySnapshotTrigger
    {
        private int _currentVersion;
        private int _submittedVersion;
        private int _capturedVersion;
        private int _buildCount;
        private int _markSubmittedCount;

        public Action<int>? DuringBuild { get; set; }
        public int BuildCount => Volatile.Read(ref _buildCount);
        public int SubmittedVersion => Volatile.Read(ref _submittedVersion);
        public int MarkSubmittedCount => Volatile.Read(ref _markSubmittedCount);

        public void RequestRefresh() => Interlocked.Increment(ref _currentVersion);

        public bool IsSnapshotRefreshRequired()
            => Volatile.Read(ref _currentVersion) != Volatile.Read(ref _submittedVersion);

        public void MarkSnapshotSubmitted()
        {
            Volatile.Write(ref _submittedVersion, Volatile.Read(ref _capturedVersion));
            Interlocked.Increment(ref _markSubmittedCount);
        }

        public Task<AgentSnapshotRequest> BuildSnapshotAsync(
            AgentBuildMetadata metadata,
            HeartbeatResponse? lastHeartbeat,
            CancellationToken ct)
        {
            var buildNumber = Interlocked.Increment(ref _buildCount);
            var capturedVersion = Volatile.Read(ref _currentVersion);
            Volatile.Write(ref _capturedVersion, capturedVersion);
            DuringBuild?.Invoke(buildNumber);
            return Task.FromResult(AgentSnapshotFactory.Create(
                metadata,
                DateTimeOffset.UtcNow,
                new Dictionary<string, object?>
                {
                    ["identity"] = new { policy_version = capturedVersion },
                }));
        }
    }

    private sealed class SchedulingLoopHandler : HttpMessageHandler
    {
        private readonly Action<int>? _onHeartbeat;
        private readonly int _snapshotFailuresBeforeSuccess;
        private readonly TaskCompletionSource _secondHeartbeat =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _snapshotSubmitted =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _secondSnapshotSubmitted =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _heartbeatAttempts;
        private int _snapshotAttempts;

        public SchedulingLoopHandler(
            Action<int>? onHeartbeat = null,
            int snapshotFailuresBeforeSuccess = 0)
        {
            _onHeartbeat = onHeartbeat;
            _snapshotFailuresBeforeSuccess = snapshotFailuresBeforeSuccess;
        }

        public int SnapshotAttempts => Volatile.Read(ref _snapshotAttempts);
        public Task SecondHeartbeatTask => _secondHeartbeat.Task;
        public Task SnapshotSubmittedTask => _snapshotSubmitted.Task;
        public Task SecondSnapshotSubmittedTask => _secondSnapshotSubmitted.Task;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("/heartbeat", StringComparison.Ordinal))
            {
                var attempt = Interlocked.Increment(ref _heartbeatAttempts);
                _onHeartbeat?.Invoke(attempt);
                if (attempt >= 2)
                    _secondHeartbeat.TrySetResult();
                return Task.FromResult(JsonResponse(
                    """
                    {
                      "pending_commands": [],
                      "next_poll_seconds": 1,
                      "server_time": 1,
                      "server_time_utc": "2026-05-08T00:00:00Z",
                      "command_batch_size": 1,
                      "next_snapshot_seconds": 300,
                      "config_version": "agent-config.v1",
                      "lifecycle_state": "connected",
                      "agent_status": "active",
                      "version_policy": null,
                      "update": null,
                      "revoke": null,
                      "quarantine": null
                    }
                    """));
            }

            if (path.EndsWith("/events", StringComparison.Ordinal))
                return Task.FromResult(JsonResponse("""{"status":"accepted","accepted":1,"ignored":0,"reason":null,"changed_sections":[]}"""));

            if (path.EndsWith("/snapshot", StringComparison.Ordinal))
            {
                var attempt = Interlocked.Increment(ref _snapshotAttempts);
                if (attempt <= _snapshotFailuresBeforeSuccess)
                {
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Conflict)
                    {
                        Content = new StringContent(
                            "{\"detail\":\"snapshot_failure\"}",
                            Encoding.UTF8,
                            "application/json"),
                    });
                }

                _snapshotSubmitted.TrySetResult();
                if (attempt >= 2)
                    _secondSnapshotSubmitted.TrySetResult();
                return Task.FromResult(JsonResponse("""{"status":"accepted","accepted":1,"ignored":0,"reason":null,"changed_sections":["capabilities"]}"""));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private static HttpResponseMessage JsonResponse(string json)
            => new(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };
    }

    private sealed class InvalidHeartbeatPayloadHandler : HttpMessageHandler
    {
        private readonly TaskCompletionSource _secondHeartbeatAttempt =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int HeartbeatAttempts => Volatile.Read(ref _heartbeatAttempts);
        public Task SecondHeartbeatAttemptTask => _secondHeartbeatAttempt.Task;

        private int _heartbeatAttempts;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/heartbeat", StringComparison.Ordinal))
            {
                if (Interlocked.Increment(ref _heartbeatAttempts) >= 2)
                    _secondHeartbeatAttempt.TrySetResult();
                return Task.FromResult(JsonResponse("""{"pending_commands":"""));
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }

        private static HttpResponseMessage JsonResponse(string json)
            => new(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };
    }

    private sealed class CommandFailureLoopHandler : HttpMessageHandler
    {
        public List<string> CommandResults { get; } = new();

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("/heartbeat", StringComparison.Ordinal))
            {
                return JsonResponse(
                    """
                    {
                      "pending_commands": [
                        {
                          "id": "cmd-throw",
                          "type": "test.throw",
                          "idempotency_key": "cmd-throw",
                          "payload": {}
                        },
                        {
                          "id": "cmd-ok",
                          "type": "test.command",
                          "idempotency_key": "cmd-ok",
                          "payload": {}
                        }
                      ],
                      "next_poll_seconds": 60,
                      "server_time": 1,
                      "server_time_utc": "2026-05-08T00:00:00Z",
                      "command_batch_size": 2,
                      "next_snapshot_seconds": 60,
                      "config_version": "agent-config.v1",
                      "lifecycle_state": "connected",
                      "agent_status": "active",
                      "version_policy": null,
                      "update": null,
                      "revoke": null,
                      "quarantine": null
                    }
                    """);
            }

            if (path.EndsWith("/events", StringComparison.Ordinal))
                return JsonResponse("""{"status":"accepted","accepted":1,"ignored":0,"reason":null,"changed_sections":[]}""");

            if (path.EndsWith("/result", StringComparison.Ordinal))
            {
                CommandResults.Add(await request.Content!.ReadAsStringAsync(cancellationToken));
                return JsonResponse("""{"status":"accepted"}""");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }

        private static HttpResponseMessage JsonResponse(string json)
            => new(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json"),
            };
    }

    private sealed class StaticTelemetryProvider : IAgentTelemetryProvider
    {
        public Task<AgentSnapshotRequest> BuildSnapshotAsync(
            AgentBuildMetadata metadata,
            HeartbeatResponse? lastHeartbeat,
            CancellationToken ct)
            => Task.FromResult(AgentSnapshotFactory.Create(
                metadata,
                DateTimeOffset.Parse("2026-05-08T00:00:00Z"),
                new Dictionary<string, object?> { ["identity"] = new { machine = "test-pc" } }));
    }

    private sealed class CaptureCommandHandler : ICommandHandler
    {
        public string Type => "test.command";
        public Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
            => Task.FromResult(new CommandResult("DONE", 0, null, null, null));
    }

    private sealed class ThrowingCommandHandler : ICommandHandler
    {
        public string Type => "test.throw";
        public Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
            => throw new InvalidOperationException("boom");
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

        public Task<(
            AgentIdentity Identity,
            string RefreshToken,
            string PrivateKeyPem,
            string BackendUrl,
            string? TailscaleLoginServer,
            string? TailscaleAuthkey)> LoadAsync(CancellationToken ct)
            => Task.FromResult((
                new AgentIdentity("agent-1", "tenant-1"),
                "refresh",
                "private",
                "http://backend.test",
                (string?)null,
                (string?)null));

        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class StaticTokenManager : ITokenManager
    {
        public Task<string> GetAccessTokenAsync(CancellationToken ct) => Task.FromResult("token");
        public Task RefreshAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class StaticSigner : IRequestSigner
    {
        public string ComputeBodyHash(byte[] bodyBytes) => "hash";
        public string CanonicalString(string method, string path, string nonce, long timestamp, string bodyHash)
            => $"{method}:{path}:{nonce}:{timestamp}:{bodyHash}";
        public string Sign(string canonical) => "signature";
    }
}
