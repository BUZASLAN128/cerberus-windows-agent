using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections;
using System.Text.Json;

namespace Cerberus.Agent.Core.Tests;

public sealed class ResourceSamplerAndRdsLicensingTests
{
    private sealed class ManualTime : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan by) => _now += by;
    }

    [Fact]
    public void GetWindow_BeforeFirstSample_IsEmpty()
    {
        var sampler = new ResourceSampler(new ManualTime(), TimeSpan.FromSeconds(5));

        var window = sampler.GetWindow(60);

        Assert.Null(window.CpuAvgPct);
        Assert.Null(window.CpuMaxPct);
        Assert.Null(window.MemUsedAvgMb);
        Assert.Null(window.MemUsedMaxMb);
        Assert.Equal(0, window.SampleCount);
        Assert.Equal(0, window.SampleWindowSeconds);
    }

    [Fact]
    public void GetWindow_ReportsAvgMaxAndSpan_AndIsRepeatable()
    {
        var time = new ManualTime();
        var sampler = new ResourceSampler(time, TimeSpan.FromSeconds(5));
        sampler.AddSample(10.0, 1000);
        time.Advance(TimeSpan.FromSeconds(5));
        sampler.AddSample(20.25, 2000);
        time.Advance(TimeSpan.FromSeconds(5));
        sampler.AddSample(60.0, 3001);

        var window = sampler.GetWindow(60);

        Assert.Equal(30.1, window.CpuAvgPct);
        Assert.Equal(60.0, window.CpuMaxPct);
        Assert.Equal(2000, window.MemUsedAvgMb);
        Assert.Equal(3001, window.MemUsedMaxMb);
        Assert.Equal(3, window.SampleCount);
        Assert.Equal(15, window.SampleWindowSeconds);
        Assert.Equal(window, sampler.GetWindow(60));
    }

    [Fact]
    public void GetWindow_DropsSamplesOlderThanWindow()
    {
        var time = new ManualTime();
        var sampler = new ResourceSampler(time, TimeSpan.FromSeconds(5));
        sampler.AddSample(90.0, 9000);
        time.Advance(TimeSpan.FromSeconds(50));
        sampler.AddSample(10.0, 1000);
        time.Advance(TimeSpan.FromSeconds(5));
        sampler.AddSample(20.0, 2000);

        var recent = sampler.GetWindow(30);
        Assert.Equal(2, recent.SampleCount);
        Assert.Equal(20.0, recent.CpuMaxPct);
        Assert.Equal(10, recent.SampleWindowSeconds);

        Assert.Equal(3, sampler.GetWindow(60).SampleCount);

        time.Advance(TimeSpan.FromSeconds(120));
        Assert.Equal(0, sampler.GetWindow(60).SampleCount);
    }

    [Fact]
    public void AddSample_StaysBounded_AndKeepsNewestSamples()
    {
        var time = new ManualTime();
        var sampler = new ResourceSampler(time, TimeSpan.FromSeconds(5), bufferSeconds: 60);
        for (var i = 0; i < 10_000; i++)
        {
            sampler.AddSample(i % 100, 4096);
            time.Advance(TimeSpan.FromSeconds(5));
        }

        var window = sampler.GetWindow(3600);

        Assert.Equal(sampler.Capacity, window.SampleCount);
        Assert.True(sampler.Capacity <= 16);
        Assert.Equal(99.0, window.CpuMaxPct);
    }

    [Fact]
    public void WindowSeconds_UsesEffectiveSnapshotDelayClampedToMinimumAndCeiling()
    {
        var policy = new AgentTimingPolicy(new AgentTimingBounds(5, 60, 30, 900, 120));

        Assert.Equal(120, ResourceSampler.WindowSeconds(policy, null));
        Assert.Equal(300, ResourceSampler.WindowSeconds(policy, 300));
        Assert.Equal(900, ResourceSampler.WindowSeconds(policy, 5000));
        Assert.Equal(60, ResourceSampler.WindowSeconds(policy, 30));
    }

    [Fact]
    public void CpuPercent_UsesBusyShareOfKernelPlusUser()
    {
        var previous = new ResourceSampler.SystemTimes(Idle: 100, Kernel: 200, User: 100);
        var current = new ResourceSampler.SystemTimes(Idle: 150, Kernel: 300, User: 200);

        // total = 100 + 100 = 200, idle = 50 -> 75% busy
        Assert.Equal(75.0, ResourceSampler.CpuPercent(previous, current));
        Assert.Null(ResourceSampler.CpuPercent(previous, previous));
    }

    [Fact]
    public async Task ResourcesCollector_EmitsContractFieldsFromSampler()
    {
        var sampler = new ResourceSampler(new ManualTime(), TimeSpan.FromSeconds(5));
        var collector = new ResourcesTelemetrySectionCollector(sampler);
        var context = new WindowsTelemetryContext(
            new AgentBuildMetadata("1", "b", "dev", "boot", AgentSchemaVersions.All), null);

        using var empty = JsonDocument.Parse(JsonSerializer.Serialize(await collector.CollectAsync(context, default)));
        Assert.Equal(JsonValueKind.Null, empty.RootElement.GetProperty("cpu_avg_pct").ValueKind);
        Assert.Equal(0, empty.RootElement.GetProperty("sample_count").GetInt32());
        Assert.Equal(0, empty.RootElement.GetProperty("sample_window_s").GetInt32());

        sampler.AddSample(12.34, 2048);
        using var filled = JsonDocument.Parse(JsonSerializer.Serialize(await collector.CollectAsync(context, default)));
        Assert.Equal(12.3, filled.RootElement.GetProperty("cpu_avg_pct").GetDouble());
        Assert.Equal(2048, filled.RootElement.GetProperty("mem_used_max_mb").GetInt32());
        Assert.Equal(1, filled.RootElement.GetProperty("sample_count").GetInt32());
        Assert.True(filled.RootElement.TryGetProperty("memory_total_mb", out _));
    }

    [Theory]
    [InlineData(2, "per_device")]
    [InlineData(4, "per_user")]
    [InlineData(5, "not_configured")]
    [InlineData(0, "not_configured")]
    [InlineData(null, "not_configured")]
    [InlineData(1, "unknown")]
    [InlineData(3, "unknown")]
    public void MapLicensingMode_FollowsLicensingType(int? type, string expected)
        => Assert.Equal(expected, RdsLicensingProbe.MapLicensingMode(type));

    [Fact]
    public void LicensingPayload_NotApplicableAndUnavailableShapes()
    {
        using var na = JsonDocument.Parse(JsonSerializer.Serialize(RdsLicensingInfo.NotApplicable.ToPayload()));
        Assert.Equal("not_applicable", na.RootElement.GetProperty("status").GetString());
        Assert.False(na.RootElement.GetProperty("rdsh_installed").GetBoolean());
        foreach (var name in new[] { "licensing_mode", "license_server_configured", "grace_days_left" })
            Assert.Equal(JsonValueKind.Null, na.RootElement.GetProperty(name).ValueKind);

        using var unavailable = JsonDocument.Parse(JsonSerializer.Serialize(RdsLicensingInfo.Unavailable.ToPayload()));
        Assert.Equal("unavailable", unavailable.RootElement.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, unavailable.RootElement.GetProperty("rdsh_installed").ValueKind);
    }
}
