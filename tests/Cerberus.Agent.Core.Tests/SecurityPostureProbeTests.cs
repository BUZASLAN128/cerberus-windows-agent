using System.Text.Json.Nodes;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.App.Telemetry.Sections.FailedLogons;
using static Cerberus.Agent.Core.Tests.ServerFactJson;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Support evidence: pure mapping helpers of the Defender and SMB1 posture keys of the server security section.</summary>
[Collection("FailedLogonCursor")]
public sealed class SecurityPostureProbeTests
{
    [Theory]
    [InlineData(null, "ok")]
    [InlineData("", "ok")]
    [InlineData("Normal", "ok")]
    [InlineData(" normal ", "ok")]
    [InlineData("Passive", "not_applicable")]
    [InlineData("SxS Passive Mode", "not_applicable")]
    [InlineData("EDR Block Mode", "not_applicable")]
    [InlineData("Not running", "not_applicable")]
    [InlineData("SomethingNew", "not_applicable")]
    public void MapDefenderStatus_OnlyNormalOrUnreportedModeIsDefendersOwnPosture(string? mode, string expected)
        => Assert.Equal(expected, SecurityPostureProbe.MapDefenderStatus(mode));

    [Theory]
    [InlineData("20260301120000.000000+000", "2026-03-01T12:00:00Z")]
    [InlineData("20260301150000.500000+180", "2026-03-01T12:00:00Z")]
    [InlineData("20260301090000.000000-180", "2026-03-01T12:00:00Z")]
    public void ParseDmtf_ConvertsOffsetToUtc(string text, string expected)
        => Assert.Equal(DateTimeOffset.Parse(expected), SecurityPostureProbe.ParseDmtf(text));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not a date")]
    [InlineData("16010101000000.000000+000")]
    [InlineData("20261301120000.000000+000")]   // month 13
    [InlineData("20260230120000.000000+000")]   // 30 Feb
    [InlineData("20260301120000x000000+000")]   // missing '.'
    [InlineData("20260301120000.000000*000")]   // bad offset sign
    [InlineData("2026030112000.0000000+000")]
    public void ParseDmtf_MalformedOrEpochValuesAreNull(string? text)
        => Assert.Null(SecurityPostureProbe.ParseDmtf(text));

    [Fact]
    public void ParseDmtf_AcceptsDateTimeAndRejectsNon1601AndOtherTypes()
    {
        Assert.Equal(new DateTimeOffset(2026, 3, 1, 12, 0, 0, TimeSpan.Zero),
            SecurityPostureProbe.ParseDmtf(new DateTime(2026, 3, 1, 12, 0, 0, DateTimeKind.Utc)));
        Assert.Null(SecurityPostureProbe.ParseDmtf(new DateTime(1601, 1, 1, 0, 0, 0, DateTimeKind.Utc)));
        Assert.Null(SecurityPostureProbe.ParseDmtf(42));
    }

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, true)]
    public void MapSmb1Value_ZeroAndOneAreExplicit(int value, bool expected)
        => Assert.Equal(expected, SecurityPostureProbe.MapSmb1Value(value));

    [Theory]
    [InlineData(null)]
    [InlineData(2)]
    [InlineData(-1)]
    [InlineData("1")]
    [InlineData(1L)]
    public void MapSmb1Value_AbsentOrOtherValuesAreNotConfigured(object? value)
        => Assert.Null(SecurityPostureProbe.MapSmb1Value(value));

    [Theory]
    [InlineData(1, true)]
    [InlineData(1u, true)]
    [InlineData(2, false)]
    [InlineData(3, false)]
    [InlineData(null, false)]
    public void MapOptionalFeatureState_OnlyEnabledCountsAsServerEnabled(object? state, bool expected)
        => Assert.Equal(expected, SecurityPostureProbe.MapOptionalFeatureState(state));

    [Fact]
    public void MapOptionalFeatureState_ShortOneIsEnabled()
        => Assert.True(SecurityPostureProbe.MapOptionalFeatureState((short)1));

    [Theory]
    [InlineData(unchecked((int)0x8004100E), true)]   // WBEM_E_INVALID_NAMESPACE
    [InlineData(unchecked((int)0x80041010), true)]   // WBEM_E_INVALID_CLASS
    [InlineData(unchecked((int)0x80041003), false)]  // WBEM_E_ACCESS_DENIED
    [InlineData(unchecked((int)0x80070005), false)]  // E_ACCESSDENIED
    [InlineData(0, false)]
    public void IsNamespaceOrClassMissing_OnlyTheTwoNotInstalledCodes(int hresult, bool expected)
        => Assert.Equal(expected, SecurityPostureProbe.IsNamespaceOrClassMissing(hresult));

    [Fact]
    public void Read_ReturnsDefenderAvAndSmb1Only_NeverTheServiceShapedDefenderKey()
    {
        var posture = SecurityPostureProbe.Read(CancellationToken.None);

        Assert.Equal(new[] { "defender_av", "smb1" }, posture.Keys.OrderBy(k => k, StringComparer.Ordinal));
        Assert.Contains((string)Obj(posture["defender_av"]!)["status"]!, new[] { "ok", "not_applicable", "unavailable" });
        var smb1 = Obj(posture["smb1"]!);
        Assert.Contains((string)smb1["status"]!, new[] { "ok", "unavailable" });
        if ((string)smb1["status"]! == "ok")
            Assert.Contains(smb1["server_enabled"]!.ToJsonString(), new[] { "true", "false" });
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SecuritySection_ServerFieldsExistOnlyWhenEnabled_AndDefenderServiceShapeIsKept(bool enabled)
    {
        var dir = Path.Combine(Path.GetTempPath(), "fl-sec-" + Guid.NewGuid().ToString("N"));
        try
        {
            // Fake reader: the collector must never reach real WMI from a test.
            using var cache = new SecurityPostureCache(new FakePostureReader(), new ManualTimeProvider(new DateTimeOffset(2026, 3, 1, 12, 0, 0, TimeSpan.Zero)));
            var collector = new SecurityTelemetrySectionCollector(commitFailedLogons: false, enabled, new FailedLogonCursorStore(Path.Combine(dir, "c.json")), cache);
            var node = Obj(await collector.CollectAsync(Context(), CancellationToken.None));

            var added = new[] { "failed_logons", "successful_logons", "log_cleared", "local_admins", "unexpected_shutdowns", "defender_av", "smb1" };
            foreach (var key in added)
                Assert.Equal(enabled, node.ContainsKey(key));
            Assert.NotNull(node["defender"]);
            Assert.False(((JsonObject)node["defender"]!).ContainsKey("am_service_enabled")); // service shape, not the defender_av shape
            if (enabled)
            {
                Assert.Equal(new[] { "changes", "count", "members", "status", "truncated" }, ((JsonObject)node["local_admins"]!).Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal));
                Assert.Equal(new[] { "count_7d", "last_utc", "status" }, ((JsonObject)node["unexpected_shutdowns"]!).Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal));
            }
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, true);
        }
    }
}
