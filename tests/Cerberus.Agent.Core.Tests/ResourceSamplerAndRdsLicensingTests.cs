using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections.FailedLogons;
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

    [Theory]
    [InlineData(1, null, true)]
    [InlineData(1, 0, true)]
    [InlineData(null, 1, true)]
    [InlineData(0, 0, false)]
    [InlineData(null, null, false)]
    public void IsRdshInstalled_UsesServerManagerInstallStateWithTsAppCompatFallback(object? installState, object? tsAppCompat, bool expected)
        => Assert.Equal(expected, RdsLicensingProbe.IsRdshInstalled(installState, tsAppCompat));

    [Fact]
    public void Read_RdshRoleWithTsAppCompatUnset_IsApplicable()
    {
        const string component = @"SOFTWARE\Microsoft\ServerManager\ServicingStorage\ServerComponentCache\RDS-RD-Server";
        var info = RdsLicensingProbe.Read(Registry((component, "InstallState", 1)));
        Assert.Equal("ok", info.Status);
    }

    [Theory]
    [InlineData(30)]
    [InlineData(10)]
    [InlineData(7200)]
    public void SharedRing_HoldsAtLeastTheMinimumWindow(int snapshotCeiling)
    {
        var seconds = ResourceSampler.SharedBufferSeconds(snapshotCeiling);
        Assert.InRange(seconds, ResourceSampler.MinWindowSeconds, ResourceSampler.MaxBufferSeconds);
        var sampler = new ResourceSampler(TimeProvider.System, ResourceSampler.DefaultInterval, seconds);
        Assert.True(sampler.Capacity >= ResourceSampler.MinWindowSeconds / ResourceSampler.DefaultInterval.TotalSeconds);
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
    public void WindowSeconds_NeverExceedsTheRingLengthWhenTheSnapshotCeilingIsLarger()
    {
        var policy = new AgentTimingPolicy(new AgentTimingBounds(5, 60, 30, 7200, 120));

        Assert.Equal(ResourceSampler.MaxBufferSeconds, ResourceSampler.WindowSeconds(policy, 7200));
        Assert.Equal(3000, ResourceSampler.WindowSeconds(policy, 3000));
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

    private const string Ts = @"SYSTEM\CurrentControlSet\Control\Terminal Server";
    private const string Core = Ts + @"\RCM\Licensing Core";
    private const string Policy = @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services";
    private const string Params = @"SYSTEM\CurrentControlSet\Services\TermService\Parameters\LicenseServers";

    private static Func<string, string, object?> Registry(params (string Key, string Name, object Value)[] values)
        => (key, name) => values.FirstOrDefault(v => v.Key == key && v.Name == name).Value;

    [Theory]
    [InlineData(null)]
    [InlineData(0)]
    public void Read_WithoutRdsh_IsNotApplicable(object? tsAppCompat)
    {
        var info = RdsLicensingProbe.Read(tsAppCompat is null ? Registry() : Registry((Ts, "TSAppCompat", tsAppCompat)));
        Assert.Same(RdsLicensingInfo.NotApplicable, info);
    }

    [Fact]
    public void Read_PolicyLicensingModeWinsOverLocal()
    {
        var info = RdsLicensingProbe.Read(Registry(
            (Ts, "TSAppCompat", 1), (Policy, "LicensingMode", 4), (Core, "LicensingMode", 2)));
        Assert.Equal("ok", info.Status);
        Assert.True(info.RdshInstalled);
        Assert.Equal("per_user", info.LicensingMode);
        Assert.False(info.LicenseServerConfigured);
        Assert.Null(info.GraceDaysLeft);
    }

    [Fact]
    public void Read_FallsBackToLocalLicensingMode()
    {
        var info = RdsLicensingProbe.Read(Registry((Ts, "TSAppCompat", 1), (Core, "LicensingMode", 2)));
        Assert.Equal("per_device", info.LicensingMode);
        Assert.Equal("not_configured", RdsLicensingProbe.Read(Registry((Ts, "TSAppCompat", 1))).LicensingMode);
    }

    [Fact]
    public void Read_LicenseServerConfigured_FromPolicyOrLocalList()
    {
        Assert.True(RdsLicensingProbe.Read(Registry((Ts, "TSAppCompat", 1), (Policy, "LicenseServers", "ls01"))).LicenseServerConfigured);
        Assert.True(RdsLicensingProbe.Read(Registry((Ts, "TSAppCompat", 1), (Params, "SpecifiedLicenseServers", new[] { "ls01" }))).LicenseServerConfigured);
        Assert.False(RdsLicensingProbe.Read(Registry(
            (Ts, "TSAppCompat", 1), (Policy, "LicenseServers", " "), (Params, "SpecifiedLicenseServers", new[] { "" }))).LicenseServerConfigured);
    }


    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    [Fact]
    public void Read_GraceEstimate_MatchesObservedWmiSample()
    {
        var start = new DateTime(2026, 10, 22, 20, 38, 42, DateTimeKind.Utc);
        var now = new DateTimeOffset(2026, 10, 25, 22, 26, 20, TimeSpan.Zero);

        var info = RdsLicensingProbe.Read(Registry((Ts, "TSAppCompat", 1)), () => start, new FixedTime(now));

        Assert.Equal("2026-10-22T20:38:42Z", info.GraceStartedUtc);
        Assert.Equal(116, info.GraceDaysLeftEstimate);
        Assert.Null(info.GraceDaysLeft);
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(info.ToPayload()));
        Assert.Equal("2026-10-22T20:38:42Z", json.RootElement.GetProperty("grace_started_utc").GetString());
        Assert.Equal(116, json.RootElement.GetProperty("grace_days_left_estimate").GetInt32());
    }

    [Fact]
    public void Read_GraceEstimate_ClampsAndIsNullWhenUnknown()
    {
        var now = new FixedTime(new DateTimeOffset(2027, 6, 1, 0, 0, 0, TimeSpan.Zero));
        var old = new DateTime(2026, 10, 22, 0, 0, 0, DateTimeKind.Utc);
        Assert.Equal(0, RdsLicensingProbe.Read(Registry((Ts, "TSAppCompat", 1)), () => old, now).GraceDaysLeftEstimate);
        var future = new DateTime(2027, 7, 1, 0, 0, 0, DateTimeKind.Utc);
        Assert.Equal(120, RdsLicensingProbe.Read(Registry((Ts, "TSAppCompat", 1)), () => future, now).GraceDaysLeftEstimate);

        var unknown = RdsLicensingProbe.Read(Registry((Ts, "TSAppCompat", 1)), () => null, now);
        Assert.Null(unknown.GraceStartedUtc);
        Assert.Null(unknown.GraceDaysLeftEstimate);
        Assert.Null(RdsLicensingProbe.Read(Registry((Ts, "TSAppCompat", 1))).GraceDaysLeftEstimate);
        Assert.Null(RdsLicensingProbe.Read(Registry(), () => old, now).GraceDaysLeftEstimate);
    }

    [Theory]
    [InlineData(0, 1, 3389, true, true, 3389)]
    [InlineData(1, 0, 3390, false, false, 3390)]
    [InlineData(null, null, null, null, null, null)]
    public void RdpPosture_MapsRegistryValues(int? deny, int? nla, int? port, bool? enabled, bool? nlaRequired, int? expectedPort)
    {
        var posture = RdpPosture.From(deny, nla, port);
        Assert.Equal(enabled, posture.RemoteDesktopEnabled);
        Assert.Equal(nlaRequired, posture.NlaRequired);
        Assert.Equal(expectedPort, posture.PortNumber);
    }

    [Theory]
    [InlineData(0u, false)]
    [InlineData(1u, false)]
    [InlineData(2u, true)]
    [InlineData(3u, true)]
    [InlineData(4u, false)]
    public void AuditFailureFlag_FollowsFailureBit(uint flags, bool expected)
        => Assert.Equal(expected, FailedLogonAuditPolicy.MapFailureFlag(flags));

    [Fact]
    public void FailedLogons_CarriesAuditFailureEnabled()
    {
        var t = FailedLogonClassifier.Tally(Array.Empty<FailedLogonEvent>());
        var now = DateTimeOffset.UnixEpoch;
        using var set = JsonDocument.Parse(JsonSerializer.Serialize(
            FailedLogonSection.Build("ok", now, now, false, t, default, default, default, true)));
        Assert.True(set.RootElement.GetProperty("audit_failure_enabled").GetBoolean());
        using var unknown = JsonDocument.Parse(JsonSerializer.Serialize(FailedLogonSection.Unavailable(now)));
        Assert.Equal(JsonValueKind.Null, unknown.RootElement.GetProperty("audit_failure_enabled").ValueKind);
    }

    [Fact]
    public void LicensingPayload_NotApplicableAndUnavailableShapes()
    {
        using var na = JsonDocument.Parse(JsonSerializer.Serialize(RdsLicensingInfo.NotApplicable.ToPayload()));
        Assert.Equal("not_applicable", na.RootElement.GetProperty("status").GetString());
        Assert.False(na.RootElement.GetProperty("rdsh_installed").GetBoolean());
        foreach (var name in new[] { "licensing_mode", "license_server_configured", "grace_days_left", "grace_started_utc", "grace_days_left_estimate" })
            Assert.Equal(JsonValueKind.Null, na.RootElement.GetProperty(name).ValueKind);

        using var unavailable = JsonDocument.Parse(JsonSerializer.Serialize(RdsLicensingInfo.Unavailable.ToPayload()));
        Assert.Equal("unavailable", unavailable.RootElement.GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, unavailable.RootElement.GetProperty("rdsh_installed").ValueKind);
    }

    [Fact]
    public void SessionsSection_CarriesRdsLicensing()
    {
        using var sessions = JsonDocument.Parse(JsonSerializer.Serialize(
            SessionsTelemetrySectionCollector.Build(Array.Empty<SessionsTelemetrySectionCollector.RawSession>(), RdsLicensingInfo.NotApplicable)));
        var licensing = sessions.RootElement.GetProperty("rds_licensing");
        Assert.Equal("not_applicable", licensing.GetProperty("status").GetString());
        Assert.False(licensing.GetProperty("rdsh_installed").GetBoolean());
    }
}
