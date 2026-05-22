using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.Core;
using System.Net;
using System.Net.Sockets;

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

    [Fact]
    public async Task RdpPortProbeAsync_ReturnsReachableForLoopbackListener()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var acceptTask = listener.AcceptTcpClientAsync();

        var result = await RdpTelemetrySectionCollector.ProbeLocalRdpPortAsync(
            port,
            CancellationToken.None);

        using var accepted = await acceptTask.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal("reachable", result.Status);
        Assert.True(result.Reachable);
        Assert.NotNull(result.LatencyMs);
        Assert.Null(result.Error);
    }

    [Fact]
    public async Task RdpPortProbeAsync_SkipsInvalidPort()
    {
        var result = await RdpTelemetrySectionCollector.ProbeLocalRdpPortAsync(
            null,
            CancellationToken.None);

        Assert.Equal("skipped", result.Status);
        Assert.Null(result.Reachable);
        Assert.Null(result.LatencyMs);
        Assert.Equal("missing_or_invalid_port", result.Error);
    }
}
