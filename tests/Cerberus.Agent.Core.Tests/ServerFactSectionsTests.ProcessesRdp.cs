using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.Core;
using static Cerberus.Agent.Core.Tests.ServerFactJson;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Server fact sections: processes, RDP listener certificate and per-user software.</summary>
public sealed partial class ServerFactSectionsTests
{
    // ---- processes -------------------------------------------------------------------------------------------

    private static ProcessesTelemetrySectionCollector.RawProcess Proc(string? path) => new(path);

    [Fact]
    public void Processes_ShapeSortingDedupeByPathAndUnreadableCount()
    {
        var node = Obj(ProcessesTelemetrySectionCollector.Build(new[]
        {
            Proc(@"C:\Windows\System32\svchost.exe"),
            Proc(@"C:\Windows\System32\svchost.exe"),
            Proc(@"c:\windows\system32\SVCHOST.EXE"),
            Proc(@"D:\x\svchost.exe"),
            Proc(@"C:\Apps\Zeta.exe"),
            Proc(@"C:\Apps\alpha.exe"),
            Proc(null),
            Proc("  "),
        }, path => path.StartsWith(@"C:\Apps", StringComparison.Ordinal) ? "Contoso" : null));

        Assert.Equal(Sorted("status", "count", "items", "truncated"), Keys(node));
        Assert.Equal("ok", (string)node["status"]!);
        Assert.Equal(6, (int)node["count"]!); // 4 distinct paths + 2 unreadable
        Assert.False((bool)node["truncated"]!);
        var items = node["items"]!.AsArray();
        Assert.Equal(4, items.Count);
        Assert.Equal(Sorted("name", "path", "signer"), Keys(items[0]));
        Assert.Equal(new[] { "alpha.exe", "svchost.exe", "svchost.exe", "Zeta.exe" }, items.Select(i => (string)i!["name"]!));
        Assert.Equal(new[] { @"C:\Apps\alpha.exe", @"C:\Windows\System32\svchost.exe", @"D:\x\svchost.exe", @"C:\Apps\Zeta.exe" },
            items.Select(i => (string)i!["path"]!));
        Assert.Equal("Contoso", (string)items[0]!["signer"]!);
        Assert.Null(items[1]!["signer"]);
    }

    [Fact]
    public void Processes_EmptyAndAllUnreadableStillOk()
    {
        var node = Obj(ProcessesTelemetrySectionCollector.Build(new[] { Proc(null), Proc(null) }, _ => throw new InvalidOperationException("no signer lookup")));

        Assert.Equal(2, (int)node["count"]!);
        Assert.Empty(node["items"]!.AsArray());
        Assert.False((bool)node["truncated"]!);
    }

    [Fact]
    public void Processes_CapsItemsAtFourHundredCountsAllAndLooksUpSignersOnlyForListedItems()
    {
        var lookups = 0;
        string? Signer(string _)
        {
            lookups++;
            return null;
        }

        var over = Obj(ProcessesTelemetrySectionCollector.Build(Enumerable.Range(0, 401).Select(i => Proc($@"C:\p\app{i:D4}.exe")), Signer));
        Assert.Equal(400, over["items"]!.AsArray().Count);
        Assert.Equal(401, (int)over["count"]!);
        Assert.True((bool)over["truncated"]!);
        Assert.Equal("app0399.exe", (string)over["items"]![399]!["name"]!);
        Assert.Equal(400, lookups);

        var exact = Obj(ProcessesTelemetrySectionCollector.Build(Enumerable.Range(0, 400).Select(i => Proc($@"C:\p\app{i:D4}.exe")), _ => null));
        Assert.Equal(400, exact["items"]!.AsArray().Count);
        Assert.False((bool)exact["truncated"]!);
    }

    [Fact]
    public void Processes_TextFieldsAreCleanedAndTruncated()
    {
        var path = @"C:\" + new string('d', 600) + @"\" + new string('n', 300) + ".exe";
        var node = Obj(ProcessesTelemetrySectionCollector.Build(new[] { Proc(path) }, _ => "S\u0007igner" + new string('s', 300)));

        var item = node["items"]![0]!;
        Assert.Equal(260, ((string)item["name"]!).Length);
        Assert.Equal(520, ((string)item["path"]!).Length);
        Assert.Equal(200, ((string)item["signer"]!).Length);
        Assert.StartsWith("Signer", (string)item["signer"]!);
    }

    [Fact]
    public void Processes_CancellationStopsTheSignerLoop()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        Assert.Throws<OperationCanceledException>(() => ProcessesTelemetrySectionCollector.Build(new[] { Proc(@"C:\a.exe") }, _ => null, cts.Token));
    }

#if CERBERUS_SERVER_PROFILE
    [Fact]
    public void Processes_TryHalveHalvesItemsAfterSoftwareAndMarksTruncated()
    {
        var processes = ProcessesTelemetrySectionCollector.Build(Enumerable.Range(0, 6).Select(i => Proc($@"C:\p\app{i}.exe")), _ => null);

        Assert.True(ServerSnapshotFit.TryHalve(new Dictionary<string, object?> { ["processes"] = processes }, out var halved));
        var node = Obj(halved["processes"]!);
        Assert.Equal(3, node["items"]!.AsArray().Count);
        Assert.True((bool)node["truncated"]!);
        Assert.Equal("app0.exe", (string)node["items"]![0]!["name"]!);

        var software = SoftwareTelemetrySectionCollector.Build(new[] { new SoftwareTelemetrySectionCollector.RawSoftware("a", "1", null, null, "x64"), new SoftwareTelemetrySectionCollector.RawSoftware("b", "1", null, null, "x64") });
        Assert.True(ServerSnapshotFit.TryHalve(new Dictionary<string, object?> { ["processes"] = processes, ["software"] = software }, out var both));
        Assert.Equal(1, Obj(both["software"]!)["software"]!.AsArray().Count);
        Assert.Equal(6, Obj(both["processes"]!)["items"]!.AsArray().Count);

        Assert.False(ServerSnapshotFit.TryHalve(new Dictionary<string, object?> { ["processes"] = ProcessesTelemetrySectionCollector.Build(Array.Empty<ProcessesTelemetrySectionCollector.RawProcess>(), _ => null) }, out _));
    }

    [Fact]
    public void Processes_OversizedSnapshotIsHalvedUntilItFitsTheCap()
    {
        var processes = ProcessesTelemetrySectionCollector.Build(
            Enumerable.Range(0, 400).Select(i => Proc(@"C:\" + new string('d', 250) + $@"\{i:D4}" + new string('n', 250) + ".exe")),
            _ => new string('s', 200));

        var snapshot = AgentSnapshotFactory.Create(Metadata(), T0, new Dictionary<string, object?> { ["processes"] = processes });

        Assert.True(AgentTelemetryLimits.EstimateJsonBytes(snapshot) <= 262144);
        var node = Obj(snapshot.Sections["processes"]!);
        Assert.InRange(node["items"]!.AsArray().Count, 1, 399);
        Assert.True((bool)node["truncated"]!);
        Assert.Equal(400, (int)node["count"]!);
        Assert.Equal(AgentSnapshotFactory.HashSection(snapshot.Sections["processes"]), snapshot.SectionHashes["processes"]);
    }
#endif

    // ---- RDP listener certificate ----------------------------------------------------------------------------

    [Fact]
    public void RdpCertificate_StoreOrderIsListenerStoreThenMachinePersonal()
        => Assert.Equal(new[] { "Remote Desktop", "My" }, RdpCertificate.StoreOrder);

    [Fact]
    public void RdpCertificate_IsSelfSignedComparesEncodedNames()
    {
        Assert.True(RdpCertificate.IsSelfSigned(new byte[] { 1, 2, 3 }, new byte[] { 1, 2, 3 }));
        Assert.False(RdpCertificate.IsSelfSigned(new byte[] { 1, 2, 3 }, new byte[] { 1, 2, 4 }));
        Assert.False(RdpCertificate.IsSelfSigned(new byte[] { 1, 2, 3 }, new byte[] { 1, 2 }));
    }

    [Fact]
    public void RdpCertificate_FromCertificateSeparatesSelfSignedFromIssued()
    {
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootRequest = new CertificateRequest("CN=Test Root", rootKey, HashAlgorithmName.SHA256);
        using var root = rootRequest.CreateSelfSigned(T0.AddDays(-1), T0.AddDays(30));
        using var leafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var leafRequest = new CertificateRequest("CN=rdp.test", leafKey, HashAlgorithmName.SHA256);
        using var leaf = leafRequest.Create(root.SubjectName, X509SignatureGenerator.CreateForECDsa(rootKey), T0.AddDays(-1), T0.AddDays(10), new byte[] { 7, 7, 7, 7 });

        var self = RdpCertificate.FromCertificate(root);
        var issued = RdpCertificate.FromCertificate(leaf);

        Assert.Equal(("ok", true), (self.Status, self.SelfSigned));
        Assert.Equal(("ok", false), (issued.Status, issued.SelfSigned));
        Assert.Equal(T0.AddDays(10), issued.NotAfter);
        Assert.Equal(TimeSpan.Zero, issued.NotAfter!.Value.Offset);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(new byte[0])]
    [InlineData(new byte[] { 0, 0, 0, 0 })]
    public void RdpCertificate_ThumbprintFromHash_MissingEmptyOrZeroIsNull(byte[]? hash)
        => Assert.Null(RdpCertificate.ThumbprintFromHash(hash));

    [Fact]
    public void RdpCertificate_ThumbprintFromHash_ValidIsUpperHexAndAZeroPrefixIsKept()
    {
        Assert.Equal("00AB", RdpCertificate.ThumbprintFromHash(new byte[] { 0x00, 0xAB }));
        Assert.Equal("0000" + "01", RdpCertificate.ThumbprintFromHash(new byte[] { 0, 0, 1 }));
    }

    [Fact]
    public void RdpCertificate_ToPayloadPerStatus()
    {
        var ok = Obj(new RdpCertificate("ok", new DateTimeOffset(2026, 4, 1, 15, 0, 0, TimeSpan.FromHours(3)), false).ToPayload());
        Assert.Equal(Sorted("status", "not_after_utc", "self_signed"), Keys(ok));
        Assert.Equal("ok", (string)ok["status"]!);
        Assert.Equal("2026-04-01T12:00:00Z", (string)ok["not_after_utc"]!);
        Assert.False((bool)ok["self_signed"]!);

        foreach (var (certificate, status) in new[] { (RdpCertificate.NotFound, "not_found"), (RdpCertificate.Unavailable, "unavailable") })
        {
            var node = Obj(certificate.ToPayload());
            Assert.Equal(status, (string)node["status"]!);
            Assert.Null(node["not_after_utc"]);
            Assert.Null(node["self_signed"]);
        }
    }

    [Fact]
    public void RdpPosture_SessionsPayloadCarriesCertificate_RdpSectionPayloadDoesNot()
    {
        var posture = RdpPosture.From(0, 1, 3389) with { Certificate = new RdpCertificate("ok", T0, true) };

        var sessions = Obj(posture.ToSessionsPayload());
        Assert.Equal(Sorted("remote_desktop_enabled", "nla_required", "port_number", "certificate"), Keys(sessions));
        Assert.Equal(Sorted("status", "not_after_utc", "self_signed"), Keys(sessions["certificate"]));
        Assert.Equal("2026-03-01T12:00:00Z", (string)sessions["certificate"]!["not_after_utc"]!);
        Assert.True((bool)sessions["certificate"]!["self_signed"]!);

        Assert.Equal(Sorted("remote_desktop_enabled", "nla_required", "port_number"), Keys(Obj(posture.ToPayload())));
        Assert.Equal("unavailable", (string)Obj(RdpPosture.Unknown.ToSessionsPayload())["certificate"]!["status"]!);
    }

    [Fact]
    public void Sessions_RdpPostureCertificateShape()
    {
        var withCertificate = Obj(SessionsTelemetrySectionCollector.Build(
            Array.Empty<SessionsTelemetrySectionCollector.RawSession>(), null,
            RdpPosture.From(0, 1, 3389) with { Certificate = new RdpCertificate("ok", T0, false) }));
        var posture = withCertificate["rdp_posture"]!;
        Assert.Equal(Sorted("remote_desktop_enabled", "nla_required", "port_number", "certificate"), Keys(posture));
        Assert.Equal(Sorted("status", "not_after_utc", "self_signed"), Keys(posture["certificate"]));
        Assert.Equal("ok", (string)posture["certificate"]!["status"]!);

        var without = Obj(SessionsTelemetrySectionCollector.Build(Array.Empty<SessionsTelemetrySectionCollector.RawSession>()));
        Assert.Equal("unavailable", (string)without["rdp_posture"]!["certificate"]!["status"]!);
        Assert.Null(without["rdp_posture"]!["port_number"]);
    }

    // ---- software scope --------------------------------------------------------------------------------------

    [Fact]
    public void Software_SameProductUnderTwoUserSidsAndMachineScopeStaysSeparate()
    {
        const string sidA = "S-1-5-21-1-2-3-1001";
        const string sidB = "S-1-5-21-1-2-3-1002";
        var node = Obj(SoftwareTelemetrySectionCollector.Build(new[]
        {
            new SoftwareTelemetrySectionCollector.RawSoftware("Tool", "1", "P", null, "x64", "user", sidB),
            new SoftwareTelemetrySectionCollector.RawSoftware("Tool", "1", "P", null, "x64", "user", sidA),
            new SoftwareTelemetrySectionCollector.RawSoftware("Tool", "1", "P", null, "x64", "user", sidA),
            new SoftwareTelemetrySectionCollector.RawSoftware("Tool", "1", "P", null, "x64"),
            new SoftwareTelemetrySectionCollector.RawSoftware("Tool", "1", "P", null, "x64", "machine", sidA), // a machine entry never carries a SID
        }));

        Assert.Equal(3, (int)node["software_count"]!);
        var list = node["software"]!.AsArray();
        Assert.Equal(new[] { "machine", "user", "user" }, list.Select(e => (string)e!["scope"]!));
        Assert.Equal(new string?[] { null, sidA, sidB }, list.Select(e => (string?)e!["user_sid"]));
    }

    [Theory]
    [InlineData("S-1-5-21-1-2-3-1001", true)]
    [InlineData("s-1-5-21-1-2-3-500", true)]
    [InlineData("S-1-12-1-1-2-3-4", true)]
    [InlineData("S-1-12-1-1-2-3-4_Classes", false)]
    [InlineData("S-1-12-2-1-2-3-4", false)]
    [InlineData("S-1-5-21-1-2-3-1001_Classes", false)]
    [InlineData(".DEFAULT", false)]
    [InlineData("S-1-5-18", false)]
    [InlineData("S-1-5-19", false)]
    [InlineData("S-1-5-20", false)]
    [InlineData("", false)]
    public void Software_UserHiveSidFilter(string name, bool expected)
        => Assert.Equal(expected, SoftwareTelemetrySectionCollector.IsUserHiveSid(name));
}
