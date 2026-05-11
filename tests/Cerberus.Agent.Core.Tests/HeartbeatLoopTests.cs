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
            log: NullAgentLogger.Instance);

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
        await loop.RunAsync(cts.Token);

        Assert.True(handler.SnapshotSubmitted);
        Assert.False(handler.CommandResultSubmitted);
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

    private sealed class LoopCaptureHandler : HttpMessageHandler
    {
        public bool SnapshotSubmitted { get; private set; }
        public bool CommandResultSubmitted { get; private set; }

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
