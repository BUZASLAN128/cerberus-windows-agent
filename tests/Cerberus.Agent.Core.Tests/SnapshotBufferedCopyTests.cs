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

    private static AgentSnapshotRequest SecuritySnapshot()
    {
        var metadata = new AgentBuildMetadata("1.2.3", "build-1", "dev", "boot-1", new[] { AgentSchemaVersions.Snapshot });
        return AgentSnapshotFactory.Create(metadata, DateTimeOffset.UtcNow, new Dictionary<string, object?>
        {
            ["security"] = new
            {
                status = "ok",
                local_admins = new { status = "ok", count = 1, members = new[] { new { name = "a" } }, changes = new { count = 2, items = new[] { new { event_id = 4732 } } } },
                other = new { changes = 1 },
            },
        });
    }

    [Fact]
    public void DottedPath_RemovesOnlyTheNestedFieldAndRecomputesTheHash()
    {
        var live = SecuritySnapshot();
        var liveJson = JsonSerializer.Serialize(live);

        var buffered = AgentSnapshotFactory.WithoutSectionField(live, "security", "local_admins.changes");

        var admins = JsonDocument.Parse(JsonSerializer.Serialize(buffered.Sections["security"])).RootElement.GetProperty("local_admins");
        Assert.False(admins.TryGetProperty("changes", out _));
        Assert.Equal(1, admins.GetProperty("count").GetInt32());
        Assert.Equal(1, admins.GetProperty("members").GetArrayLength());
        Assert.Contains("\"other\":{\"changes\":1}", JsonSerializer.Serialize(buffered.Sections["security"]));
        Assert.NotEqual(live.SectionHashes["security"], buffered.SectionHashes["security"]);
        Assert.Equal(AgentSnapshotFactory.HashSection(buffered.Sections["security"]), buffered.SectionHashes["security"]);
        Assert.Equal(liveJson, JsonSerializer.Serialize(live));
    }

    [Theory]
    [InlineData("security", "missing.changes")]        // missing intermediate
    [InlineData("security", "local_admins.missing")]   // missing leaf
    [InlineData("security", "status.changes")]         // intermediate is not an object
    [InlineData("security", "local_admins.members.x")] // intermediate is an array
    [InlineData("nosuch", "local_admins.changes")]     // missing section
    public void DottedPath_MissingPartReturnsTheSameInstance(string section, string field)
    {
        var live = SecuritySnapshot();

        Assert.Same(live, AgentSnapshotFactory.WithoutSectionField(live, section, field));
    }
}
