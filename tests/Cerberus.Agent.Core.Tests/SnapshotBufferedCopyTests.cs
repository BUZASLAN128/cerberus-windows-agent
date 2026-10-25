using System.Text.Json;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Support evidence: the copy that goes to the offline buffer drops security.failed_logons only.</summary>
public sealed class SnapshotBufferedCopyTests
{
    [Fact]
    public void BufferedCopy_HasNoFailedLogons_LiveSnapshotUnchanged()
    {
        var metadata = new AgentBuildMetadata("1.2.3", "build-1", "dev", "boot-1", new[] { AgentSchemaVersions.Snapshot });
        var sections = new Dictionary<string, object?>
        {
            ["security"] = new { status = "ok", failed_logons = new { status = "ok", cap = 20 } },
            ["clock"] = new { status = "ok" },
        };
        var live = AgentSnapshotFactory.Create(metadata, DateTimeOffset.UtcNow, sections);
        var liveJson = JsonSerializer.Serialize(live);

        var buffered = AgentSnapshotFactory.WithoutSectionField(live, "security", "failed_logons");

        Assert.DoesNotContain("failed_logons", JsonSerializer.Serialize(buffered));
        Assert.Contains("failed_logons", liveJson);
        Assert.Equal(liveJson, JsonSerializer.Serialize(live));
        Assert.Contains("\"status\":\"ok\"", JsonSerializer.Serialize(buffered.Sections["security"]));
        Assert.Equal(live.SectionHashes["clock"], buffered.SectionHashes["clock"]);
        Assert.Equal(AgentSnapshotFactory.HashSection(buffered.Sections["security"]), buffered.SectionHashes["security"]);
        Assert.Same(live, AgentSnapshotFactory.WithoutSectionField(live, "clock", "failed_logons"));
    }
}
