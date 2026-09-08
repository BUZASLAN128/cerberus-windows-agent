using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.Core;
using Cerberus.Agent.Integrations.Ad;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

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
    public async Task BuildSnapshotAsync_HonorsTelemetrySectionAllowlist()
    {
        var collector = new WindowsTelemetryCollector(
            WindowsTelemetrySectionCatalog.CreateDefault("identity,clock"));
        var snapshot = await collector.BuildSnapshotAsync(
            new AgentBuildMetadata(
                AgentVersion: "1.2.3",
                BuildId: "build-1",
                BuildChannel: "dev",
                BootId: "boot-1",
                SupportedSchemaVersions: AgentSchemaVersions.All),
            lastHeartbeat: null,
            ct: CancellationToken.None);

        Assert.Equal(new[] { "clock", "identity" }, snapshot.Sections.Keys.OrderBy(x => x));
    }

    [Fact]
    public async Task CapabilitiesTelemetry_OmitsLocalUserCreateWhenPolicyDisabled()
    {
        var collector = new CapabilitiesTelemetrySectionCollector(LocalUserCommandPolicy.CreateDisabled);
        var section = await collector.CollectAsync(TelemetryContext(), CancellationToken.None);
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(section));
        var json = document.RootElement.GetRawText();

        Assert.DoesNotContain("windows.local_user.create", json);
        Assert.DoesNotContain("ad.user.", json);
        Assert.Contains("windows.local_user.disable", json);
        Assert.Contains("windows.local_user.delete", json);
        Assert.Equal("disabled", document.RootElement.GetProperty("local_user_create_policy").GetProperty("state").GetString());
        Assert.True(DateTimeOffset.TryParse(
            document.RootElement.GetProperty("local_user_create_policy").GetProperty("observed_at").GetString(),
            out _));
    }

    [Fact]
    public async Task CapabilitiesTelemetry_IncludesLocalUserCreateWhenPolicyEnabled()
    {
        var collector = new CapabilitiesTelemetrySectionCollector(LocalUserCommandPolicy.CreateEnabledPolicy);
        var section = await collector.CollectAsync(TelemetryContext(), CancellationToken.None);
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(section));
        var json = document.RootElement.GetRawText();

        Assert.Contains("windows.local_user.create", json);
        Assert.Equal("enabled", document.RootElement.GetProperty("local_user_create_policy").GetProperty("state").GetString());
    }

    [Fact]
    public async Task CapabilitiesTelemetry_ResolvesLocalPolicyOnEveryCollection()
    {
        var current = LocalUserCommandPolicy.CreateDisabled;
        var collector = new CapabilitiesTelemetrySectionCollector(() => current);

        var disabled = JsonDocument.Parse(JsonSerializer.Serialize(
            await collector.CollectAsync(TelemetryContext(), CancellationToken.None)));
        current = LocalUserCommandPolicy.CreateEnabledPolicy;
        var enabled = JsonDocument.Parse(JsonSerializer.Serialize(
            await collector.CollectAsync(TelemetryContext(), CancellationToken.None)));

        Assert.Equal("disabled", disabled.RootElement.GetProperty("local_user_create_policy").GetProperty("state").GetString());
        Assert.Equal("enabled", enabled.RootElement.GetProperty("local_user_create_policy").GetProperty("state").GetString());
        Assert.DoesNotContain(
            "windows.local_user.create",
            disabled.RootElement.GetProperty("mutation").GetRawText());
        Assert.Contains(
            "windows.local_user.create",
            enabled.RootElement.GetProperty("mutation").GetRawText());
        disabled.Dispose();
        enabled.Dispose();
    }

    [Fact]
    public async Task CapabilitiesTelemetry_ExpectedPolicyReadFailureReportsUnknownAndOmitsCreate()
    {
        var collector = new CapabilitiesTelemetrySectionCollector(
            () => throw new UnauthorizedAccessException("registry denied"));

        using var document = JsonDocument.Parse(JsonSerializer.Serialize(
            await collector.CollectAsync(TelemetryContext(), CancellationToken.None)));

        Assert.Equal("unknown", document.RootElement
            .GetProperty("local_user_create_policy").GetProperty("state").GetString());
        Assert.DoesNotContain(
            "windows.local_user.create",
            document.RootElement.GetProperty("mutation").GetRawText());
    }

    [Fact]
    public void CapabilitiesTelemetry_UnexpectedPolicyResolverFailurePropagates()
    {
        var expected = new InvalidOperationException("resolver contract failed");
        var calls = 0;
        var collector = new CapabilitiesTelemetrySectionCollector(() =>
        {
            if (Interlocked.Increment(ref calls) == 1)
                return LocalUserCommandPolicy.CreateDisabled;
            throw expected;
        });

        var actual = Assert.Throws<InvalidOperationException>(() => collector.IsSnapshotRefreshRequired());

        Assert.Same(expected, actual);
    }

    [Fact]
    public async Task CapabilitiesTelemetry_ServiceWriterReceivesEffectiveObservation()
    {
        LocalUserCommandPolicy? observedPolicy = null;
        DateTimeOffset? observedAt = null;
        var collector = new CapabilitiesTelemetrySectionCollector(
            () => LocalUserCommandPolicy.CreateEnabledPolicy,
            (policy, timestamp) =>
            {
                observedPolicy = policy;
                observedAt = timestamp;
            });

        await collector.CollectAsync(TelemetryContext(), CancellationToken.None);

        Assert.Same(LocalUserCommandPolicy.CreateEnabledPolicy, observedPolicy);
        Assert.NotNull(observedAt);
        Assert.InRange(observedAt!.Value, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));
    }

    [Fact]
    public async Task WindowsTelemetryCollector_RefreshTriggerTracksPolicyUntilSnapshotSubmission()
    {
        var current = LocalUserCommandPolicy.CreateDisabled;
        var capabilities = new CapabilitiesTelemetrySectionCollector(() => current);
        var collector = new WindowsTelemetryCollector(
            new IWindowsTelemetrySectionCollector[] { capabilities });
        var trigger = (IAgentTelemetrySnapshotTrigger)collector;

        Assert.False(trigger.IsSnapshotRefreshRequired());
        current = LocalUserCommandPolicy.CreateEnabledPolicy;
        Assert.True(trigger.IsSnapshotRefreshRequired());

        await collector.BuildSnapshotAsync(
            new AgentBuildMetadata(
                AgentVersion: "1.2.3",
                BuildId: "build-1",
                BuildChannel: "dev",
                BootId: "boot-1",
                SupportedSchemaVersions: AgentSchemaVersions.All),
            lastHeartbeat: null,
            ct: CancellationToken.None);
        trigger.MarkSnapshotSubmitted();

        Assert.False(trigger.IsSnapshotRefreshRequired());
        current = LocalUserCommandPolicy.UnknownPolicy;
        Assert.True(trigger.IsSnapshotRefreshRequired());
    }

    [Theory]
    [InlineData("10.12.13.14")]
    [InlineData("172.16.1.2")]
    [InlineData("192.168.1.10")]
    [InlineData("127.0.0.1")]
    [InlineData("fd00::1")]
    public void NetworkTelemetry_RedactsPrivateAddressValues(string rawAddress)
    {
        var redacted = NetworkTelemetrySectionCollector.RedactAddress(IPAddress.Parse(rawAddress));
        var json = JsonSerializer.Serialize(redacted);

        Assert.DoesNotContain(rawAddress, json);
        Assert.Contains("private", json);
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

    private static WindowsTelemetryContext TelemetryContext()
        => new(
            new AgentBuildMetadata(
                AgentVersion: "1.2.3",
                BuildId: "build-1",
                BuildChannel: "dev",
                BootId: "boot-1",
                SupportedSchemaVersions: AgentSchemaVersions.All),
            LastHeartbeat: null);
}
