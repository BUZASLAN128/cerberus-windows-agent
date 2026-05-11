using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class WindowsTelemetryCollectorTests
{
    [Fact]
    public async Task BuildSnapshotAsync_ReturnsAllowedSectionsOnly()
    {
        var collector = new WindowsTelemetryCollector();
        var snapshot = await collector.BuildSnapshotAsync(
            new AgentBuildMetadata(
                AgentVersion: "1.2.3",
                BuildId: "build-1",
                BuildChannel: "dev",
                BootId: "boot-1",
                SupportedSchemaVersions: AgentSchemaVersions.All),
            lastHeartbeat: null,
            ct: CancellationToken.None);

        var expected = new[]
        {
            "identity",
            "os",
            "resources",
            "network",
            "tailscale",
            "rdp",
            "firewall",
            "security",
            "clock",
            "runtime",
            "capabilities",
        };

        Assert.Equal(expected.OrderBy(x => x), snapshot.Sections.Keys.OrderBy(x => x));
        Assert.Equal(expected.Length, snapshot.SectionHashes.Count);
        Assert.True(AgentTelemetryLimits.EstimateJsonBytes(snapshot) <= AgentTelemetryLimits.MaxJsonBytes);
    }
}
