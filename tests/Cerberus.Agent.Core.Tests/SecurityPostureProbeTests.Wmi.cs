using System.Runtime.InteropServices;
using Cerberus.Agent.App.Telemetry;
using static Cerberus.Agent.Core.Tests.ServerFactJson;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Unit evidence: Defender and SMB1 posture reads against a scripted WMI query delegate (no WMI).</summary>
public sealed class SecurityPostureWmiTests
{
    private const int InvalidNamespace = unchecked((int)0x8004100E);
    private const int InvalidClass = unchecked((int)0x80041010);
    private const int AccessDenied = unchecked((int)0x80041003);

    private static IReadOnlyDictionary<string, object?> Row(params (string Key, object? Value)[] values)
        => values.ToDictionary(v => v.Key, v => v.Value, StringComparer.Ordinal);

    private static IReadOnlyList<IReadOnlyDictionary<string, object?>> Rows(params IReadOnlyDictionary<string, object?>[] rows) => rows;

    private static readonly IReadOnlyDictionary<string, object?> NormalStatus = Row(
        ("AMServiceEnabled", true), ("RealTimeProtectionEnabled", true), ("AMRunningMode", "Normal"),
        ("AntivirusSignatureLastUpdated", "20260301120000.000000+000"));

    // ---- Defender ----------------------------------------------------------------------------------------------

    [Theory]
    [InlineData(InvalidNamespace)]
    [InlineData(InvalidClass)]
    public void Defender_MissingNamespaceOrClassOnStatusQueryIsNotApplicable(int hresult)
    {
        var node = Obj(SecurityPostureProbe.ReadDefender((_, _, _) => throw new COMException("missing", hresult), CancellationToken.None));

        Assert.Equal("not_applicable", (string)node["status"]!);
        Assert.Null(node["active_threats"]);
        Assert.Null(node["real_time_protection"]);
    }

    [Theory]
    [InlineData(InvalidNamespace)]
    [InlineData(InvalidClass)]
    public void Defender_MissingThreatClassKeepsStatusOkWithNullActiveThreats(int hresult)
    {
        var node = Obj(SecurityPostureProbe.ReadDefender((_, query, _) =>
            query.Contains("MSFT_MpThreat", StringComparison.Ordinal) && !query.Contains("MpComputerStatus", StringComparison.Ordinal)
                ? throw new COMException("missing", hresult)
                : Rows(NormalStatus), CancellationToken.None));

        Assert.Equal("ok", (string)node["status"]!);
        Assert.True((bool)node["real_time_protection"]!);
        Assert.Equal("2026-03-01T12:00:00Z", (string)node["signature_updated_utc"]!);
        Assert.Null(node["active_threats"]);
    }

    [Fact]
    public void Defender_OtherComErrorsPropagate_OnStatusAndOnThreatQuery()
    {
        Assert.Throws<COMException>(() => SecurityPostureProbe.ReadDefender((_, _, _) => throw new COMException("denied", AccessDenied), CancellationToken.None));
        Assert.Throws<COMException>(() => SecurityPostureProbe.ReadDefender((_, query, _) =>
            query.Contains("MpComputerStatus", StringComparison.Ordinal) ? Rows(NormalStatus) : throw new COMException("denied", AccessDenied), CancellationToken.None));
    }

    [Theory]
    [InlineData("Passive")]
    [InlineData("EDR Block Mode")]
    [InlineData("Not running")]
    public void Defender_NonNormalRunningModeIsNotApplicableAndSkipsThreatQuery(string mode)
    {
        var queries = 0;
        var node = Obj(SecurityPostureProbe.ReadDefender((_, _, _) =>
        {
            queries++;
            return Rows(Row(("AMRunningMode", mode), ("RealTimeProtectionEnabled", false)));
        }, CancellationToken.None));

        Assert.Equal("not_applicable", (string)node["status"]!);
        Assert.Null(node["real_time_protection"]);
        Assert.Equal(1, queries);
    }

    [Fact]
    public void Defender_NoStatusRowIsNotApplicable()
        => Assert.Equal("not_applicable", (string)Obj(SecurityPostureProbe.ReadDefender((_, _, _) => Rows(), CancellationToken.None))["status"]!);

    [Fact]
    public void Defender_ActiveThreatsCountsOnlyIsActiveTrue()
    {
        var node = Obj(SecurityPostureProbe.ReadDefender((_, query, _) => query.Contains("MpComputerStatus", StringComparison.Ordinal)
            ? Rows(NormalStatus)
            : Rows(Row(("IsActive", true)), Row(("IsActive", false)), Row(("IsActive", true)), Row(("IsActive", null))), CancellationToken.None));

        Assert.Equal("ok", (string)node["status"]!);
        Assert.Equal(2, (int)node["active_threats"]!);

        var none = Obj(SecurityPostureProbe.ReadDefender((_, query, _) => query.Contains("MpComputerStatus", StringComparison.Ordinal) ? Rows(NormalStatus) : Rows(), CancellationToken.None));
        Assert.Equal(0, (int)none["active_threats"]!);
    }

    // ---- SMB1 --------------------------------------------------------------------------------------------------

    private static SecurityPostureProbe.WmiQuery Features(IReadOnlyDictionary<string, object?>? child, IReadOnlyDictionary<string, object?>? parent, List<string> asked)
        => (_, query, _) =>
        {
            var name = query.Contains("'SMB1Protocol-Server'", StringComparison.Ordinal) ? "child" : "parent";
            asked.Add(name);
            var row = name == "child" ? child : parent;
            return row is null ? Rows() : Rows(row);
        };

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, true)]
    public void Smb1_RegistryValueDecidesWithoutWmi(int value, bool expected)
    {
        var node = Obj(SecurityPostureProbe.ReadSmb1((_, _, _) => throw new InvalidOperationException("no WMI"), () => value, CancellationToken.None));

        Assert.Equal("ok", (string)node["status"]!);
        Assert.Equal(expected, (bool)node["server_enabled"]!);
    }

    [Theory]
    [InlineData(1, true)]
    [InlineData(2, false)]
    [InlineData(3, false)]
    public void Smb1_ChildServerFeatureIsUsedFirst_ParentIsNotAsked(int installState, bool expected)
    {
        var asked = new List<string>();

        var node = Obj(SecurityPostureProbe.ReadSmb1(
            Features(Row(("InstallState", installState)), Row(("InstallState", expected ? 3 : 1)), asked), () => null, CancellationToken.None));

        Assert.Equal("ok", (string)node["status"]!);
        Assert.Equal(expected, (bool)node["server_enabled"]!);
        Assert.Equal(new[] { "child" }, asked);
    }

    [Theory]
    [InlineData(1, true)]
    [InlineData(2, false)]
    public void Smb1_ParentFeatureOnlyWhenChildHasNoRow(int installState, bool expected)
    {
        var asked = new List<string>();

        var node = Obj(SecurityPostureProbe.ReadSmb1(Features(null, Row(("InstallState", installState)), asked), () => null, CancellationToken.None));

        Assert.Equal("ok", (string)node["status"]!);
        Assert.Equal(expected, (bool)node["server_enabled"]!);
        Assert.Equal(new[] { "child", "parent" }, asked);
    }

    [Fact]
    public void Smb1_NoRegistryAndNoFeatureRowIsUnavailableNeverFalse()
    {
        var node = Obj(SecurityPostureProbe.ReadSmb1(Features(null, null, new List<string>()), () => 2, CancellationToken.None));

        Assert.Equal("unavailable", (string)node["status"]!);
        Assert.Null(node["server_enabled"]);
    }
}
