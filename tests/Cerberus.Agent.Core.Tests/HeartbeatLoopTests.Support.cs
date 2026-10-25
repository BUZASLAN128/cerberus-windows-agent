using System.Net;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class HeartbeatLoopTests
{
    private sealed class AdCommandLoopHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _ackStatus;
        private readonly bool _blockAckResponse;
        private readonly Action<string>? _trace;
        private readonly TaskCompletionSource _ackRequested =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _ackResponseRelease =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public AdCommandLoopHandler(
            HttpStatusCode ackStatus = HttpStatusCode.OK,
            bool blockAckResponse = false,
            Action<string>? trace = null)
        {
            _ackStatus = ackStatus;
            _blockAckResponse = blockAckResponse;
            _trace = trace;
        }

        public List<string> Operations { get; } = [];
        public List<string> Leases { get; } = [];
        public Task ResultSubmittedTask => _resultSubmitted.Task;
        public Task AckRequestedTask => _ackRequested.Task;

        public void ReleaseAckResponse() => _ackResponseRelease.TrySetResult();

        private readonly TaskCompletionSource _resultSubmitted =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

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
                          "id": "cmd-ad",
                          "type": "windows.ad_user.disable",
                          "idempotency_key": "idem-ad",
                          "lease_id": "lease-ad",
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
                      "agent_status": "active",
                      "version_policy": null,
                      "update": null,
                      "revoke": null,
                      "quarantine": null
                    }
                    """);
            }

            if (path.EndsWith("/ack", StringComparison.Ordinal))
            {
                Operations.Add("ack");
                Leases.Add(await ReadLeaseAsync(request, cancellationToken));
                _trace?.Invoke("ack");
                _ackRequested.TrySetResult();
                if (_blockAckResponse)
                    await _ackResponseRelease.Task.WaitAsync(cancellationToken);
                return JsonResponse("{}", _ackStatus);
            }

            if (path.EndsWith("/result", StringComparison.Ordinal))
            {
                Operations.Add("result");
                Leases.Add(await ReadLeaseAsync(request, cancellationToken));
                _trace?.Invoke("result");
                _resultSubmitted.TrySetResult();
                return JsonResponse("{}");
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }

        private static async Task<string> ReadLeaseAsync(HttpRequestMessage request, CancellationToken ct)
        {
            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(ct));
            return body.RootElement.GetProperty("lease_id").GetString()!;
        }

        private static HttpResponseMessage JsonResponse(string json, HttpStatusCode status = HttpStatusCode.OK)
            => new(status)
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

    private sealed class AuthoritativeCommandHandler : IAuthoritativeCommandExecutionGate
    {
        private readonly Action? _onAuthorizedDispatch;

        public AuthoritativeCommandHandler(Action? onAuthorizedDispatch = null)
            => _onAuthorizedDispatch = onAuthorizedDispatch;

        public string Type => "windows.ad_user.disable";

        public Task<CommandResult> HandleAsync(AgentCommand command, CancellationToken ct)
            => Task.FromResult(new CommandResult("FAILED", 1, null, "not authorized", null));

        public Task<CommandResult> ExecuteAuthorizedAsync(
            AgentCommand command,
            Func<AgentCommand, CancellationToken, Task<CommandResult>> execute,
            CancellationToken ct)
            => execute(command, ct);

        public Task<CommandResult> HandleAuthorizedAsync(AgentCommand command, CancellationToken ct)
        {
            _onAuthorizedDispatch?.Invoke();
            return Task.FromResult(new CommandResult("DONE", 0, null, null, new { code = "ad_disabled" }));
        }
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
