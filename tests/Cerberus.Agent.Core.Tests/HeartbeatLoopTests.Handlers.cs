using System.Net;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class HeartbeatLoopTests
{
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
}
