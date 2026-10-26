using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class HeartbeatLoopTests
{
    private sealed class SecurityTelemetryProvider : IAgentTelemetryProvider
    {
        public Task<AgentSnapshotRequest> BuildSnapshotAsync(AgentBuildMetadata metadata, HeartbeatResponse? lastHeartbeat, CancellationToken ct)
            => Task.FromResult(AgentSnapshotFactory.Create(metadata, DateTimeOffset.Parse("2026-05-08T00:00:00Z"), new Dictionary<string, object?>
            {
                ["security"] = new
                {
                    status = "ok",
                    defender_av = new { status = "ok" },
                    failed_logons = new { status = "ok" },
                    successful_logons = new { status = "ok", count = 1 },
                    local_admins = new { status = "ok", count = 2, changes = new { count = 1 } },
                },
            }));
    }

    [Fact]
    public async Task RunAsync_FailedSnapshotIsBufferedWithoutConsumeOnceSecurityFields()
    {
        var handler = new SchedulingLoopHandler(snapshotFailuresBeforeSuccess: int.MaxValue);
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var root = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
        var dispatcher = new CommandDispatcher(Array.Empty<ICommandHandler>(), new IdempotencyCache(Path.Combine(root, "idempotency.json"), 10, TimeSpan.FromMinutes(5)));
        var buffer = new OfflineTelemetryBuffer(Path.Combine(root, "buffer.json"));
        var loop = new HeartbeatLoop(
            client,
            dispatcher,
            minDelayOnError: TimeSpan.FromMilliseconds(10),
            telemetryProvider: new SecurityTelemetryProvider(),
            telemetryBuffer: buffer,
            log: NullAgentLogger.Instance,
            initialSnapshotDelay: TimeSpan.Zero,
            timingPolicy: ShortPollTiming);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = loop.RunAsync(cts.Token);
        IReadOnlyList<OfflineTelemetryRecord> records = Array.Empty<OfflineTelemetryRecord>();
        while (records.Count == 0)
        {
            await Task.Delay(20, cts.Token);
            records = await buffer.ReadBatchAsync(10, cts.Token);
        }
        cts.Cancel();
        await runTask;

        Assert.True(handler.SnapshotAttempts >= 1);
        var security = JsonDocument.Parse(records[0].Json).RootElement.GetProperty("sections").GetProperty("security");
        Assert.False(security.TryGetProperty("failed_logons", out _));
        Assert.False(security.TryGetProperty("successful_logons", out _));
        var admins = security.GetProperty("local_admins");
        Assert.False(admins.TryGetProperty("changes", out _));
        Assert.Equal(2, admins.GetProperty("count").GetInt32());
        Assert.Equal("ok", security.GetProperty("defender_av").GetProperty("status").GetString());
    }
}
