using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class HeartbeatLoopTests
{
    [Fact]
    public async Task RunAsync_SendsHeartbeatAndObtainsToken_WhenUpdateStatusFails()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-heartbeat-update-" + Guid.NewGuid().ToString("N"));
        try
        {
            var handler = new LoopCaptureHandler();
            using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
            var tokens = new UpdateStatusTokenManager();
            var client = new AgentApiClient(http, new StaticSecretStore(), tokens, new StaticSigner());
            var dispatcher = new CommandDispatcher(Array.Empty<ICommandHandler>(),
                new IdempotencyCache(Path.Combine(root, "idempotency.json"), 10, TimeSpan.FromMinutes(5)));
            var log = new RecordingLogger();
            var loop = new HeartbeatLoop(client, dispatcher, TimeSpan.FromMilliseconds(10),
                adStatusProvider: _ => Task.FromResult<object?>(new { available = true }),
                updateStatusProvider: FailingUpdateStatus, log: log);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            var run = loop.RunAsync(cts.Token);
            try { await handler.HeartbeatSubmittedTask.WaitAsync(cts.Token); }
            finally { cts.Cancel(); await run; }

            Assert.True(tokens.Requests > 0);
            using var body = JsonDocument.Parse(Assert.Single(handler.HeartbeatBodies));
            Assert.Equal(JsonValueKind.Null, body.RootElement.GetProperty("update_status").ValueKind);
            Assert.True(body.RootElement.GetProperty("ad").GetProperty("available").GetBoolean());
            Assert.Contains(log.Lines, line => line.Contains("Update status unavailable: InvalidOperationException") &&
                line.Contains("at=HeartbeatLoopTests.FailingUpdateStatus"));
            Assert.DoesNotContain(log.Lines, line => line.Contains("Heartbeat loop error"));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public async Task RunAsync_DoesNotSendHeartbeat_WhenUpdateStatusCancelsShutdown()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-heartbeat-update-" + Guid.NewGuid().ToString("N"));
        try
        {
            var handler = new LoopCaptureHandler();
            using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
            var tokens = new UpdateStatusTokenManager();
            var client = new AgentApiClient(http, new StaticSecretStore(), tokens, new StaticSigner());
            var dispatcher = new CommandDispatcher(Array.Empty<ICommandHandler>(),
                new IdempotencyCache(Path.Combine(root, "idempotency.json"), 10, TimeSpan.FromMinutes(5)));
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            var log = new RecordingLogger();
            var loop = new HeartbeatLoop(client, dispatcher, TimeSpan.FromMilliseconds(10),
                updateStatusProvider: ct => { cts.Cancel(); ct.ThrowIfCancellationRequested(); return Task.FromResult<object?>(null); },
                log: log);
            await loop.RunAsync(cts.Token);

            Assert.Empty(handler.HeartbeatBodies);
            Assert.Equal(0, tokens.Requests);
            Assert.DoesNotContain(log.Lines, line => line.Contains("Update status unavailable"));
        }
        finally { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    }

    private static Task<object?> FailingUpdateStatus(CancellationToken ct)
        => throw new InvalidOperationException("status fixture failure");

    private sealed class UpdateStatusTokenManager : ITokenManager
    {
        public int Requests { get; private set; }
        public Task<string> GetAccessTokenAsync(CancellationToken ct) { Requests++; return Task.FromResult("token"); }
        public Task RefreshAsync(CancellationToken ct) => Task.CompletedTask;
    }
}
