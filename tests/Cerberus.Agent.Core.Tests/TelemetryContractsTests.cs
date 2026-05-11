using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class TelemetryContractsTests
{
    [Fact]
    public void SnapshotFactory_ComputesHashes_AndRejectsUnknownSections()
    {
        var metadata = Metadata();
        var snapshot = AgentSnapshotFactory.Create(
            metadata,
            DateTimeOffset.Parse("2026-05-07T00:00:00Z"),
            new Dictionary<string, object?>
            {
                ["identity"] = new { status = "ok", machine_name = "host1" },
                ["runtime"] = new { status = "ok", uptime_seconds = 5 },
            });

        Assert.Equal(AgentSchemaVersions.Snapshot, snapshot.SchemaVersion);
        Assert.Equal("1.2.3", snapshot.AgentVersion);
        Assert.Contains("identity", snapshot.SectionHashes.Keys);
        Assert.Contains("runtime", snapshot.SectionHashes.Keys);
        Assert.True(AgentTelemetryLimits.EstimateJsonBytes(snapshot) > 0);

        Assert.Throws<InvalidOperationException>(() =>
            AgentSnapshotFactory.Create(
                metadata,
                DateTimeOffset.UtcNow,
                new Dictionary<string, object?> { ["raw_event_log"] = new { status = "bad" } }));
    }

    [Fact]
    public async Task OfflineTelemetryBuffer_DedupesAndDropsLowestPriorityOldest()
    {
        var path = Path.Combine(Path.GetTempPath(), $"cerberus-offline-{Guid.NewGuid():N}.json");
        try
        {
            var buffer = new OfflineTelemetryBuffer(path, maxEntries: 2, maxBytes: 128 * 1024, ttl: TimeSpan.FromHours(1));

            await buffer.EnqueueAsync(OfflineTelemetryKinds.Events, new { item = 1 }, "same", priority: 1, CancellationToken.None);
            await buffer.EnqueueAsync(OfflineTelemetryKinds.Events, new { item = 2 }, "same", priority: 1, CancellationToken.None);
            await buffer.EnqueueAsync(OfflineTelemetryKinds.Events, new { item = 3 }, "low", priority: 0, CancellationToken.None);
            await buffer.EnqueueAsync(OfflineTelemetryKinds.Events, new { item = 4 }, "high", priority: 10, CancellationToken.None);

            var batch = await buffer.ReadBatchAsync(10, CancellationToken.None);

            Assert.Equal(2, batch.Count);
            Assert.DoesNotContain(batch, r => r.IdempotencyKey == "same" && r.Json.Contains("\"item\":1"));
            Assert.Contains(batch, r => r.IdempotencyKey == "high");
            Assert.DoesNotContain(batch, r => r.IdempotencyKey == "low");
        }
        finally
        {
            if (File.Exists(path))
                File.Delete(path);
        }
    }

    [Fact]
    public async Task OfflineTelemetryBuffer_QuarantinesCorruptStore()
    {
        var dir = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
        var path = Path.Combine(dir, "telemetry-offline.json");
        Directory.CreateDirectory(dir);
        try
        {
            await File.WriteAllTextAsync(path, "{not-json");
            var buffer = new OfflineTelemetryBuffer(path, maxEntries: 2, maxBytes: 128 * 1024, ttl: TimeSpan.FromHours(1));

            var batch = await buffer.ReadBatchAsync(10, CancellationToken.None);

            Assert.Empty(batch);
            Assert.False(File.Exists(path));
            Assert.NotEmpty(Directory.GetFiles(dir, "telemetry-offline.json.corrupt.*"));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task OfflineTelemetryBuffer_PersistsChecksummedEnvelope()
    {
        var path = Path.Combine(Path.GetTempPath(), $"cerberus-offline-{Guid.NewGuid():N}.json");
        try
        {
            var buffer = new OfflineTelemetryBuffer(path, maxEntries: 2, maxBytes: 128 * 1024, ttl: TimeSpan.FromHours(1));

            await buffer.EnqueueAsync(OfflineTelemetryKinds.Events, new { item = 1 }, "event-1", priority: 1, CancellationToken.None);

            var stored = await File.ReadAllTextAsync(path);
            Assert.Contains("\"schema_version\":\"cerberus.offline_telemetry_buffer.v1\"", stored);
            Assert.Contains("\"checksum_sha256\"", stored);
            Assert.Contains("\"records\"", stored);
        }
        finally
        {
            if (File.Exists(path))
                File.Delete(path);
        }
    }

    private static AgentBuildMetadata Metadata() => new(
        AgentVersion: "1.2.3",
        BuildId: "build-1",
        BuildChannel: "dev",
        BootId: "boot-1",
        SupportedSchemaVersions: AgentSchemaVersions.All);
}
