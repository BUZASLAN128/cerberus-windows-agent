using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections;
using static Cerberus.Agent.Core.Tests.ServerFactJson;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Server fact sections: RDP certificate resolution, software scope cap and security-first pending updates.</summary>
public sealed partial class ServerFactSectionsTests
{
    // ---- RDP certificate resolution ----------------------------------------------------------------------------

    private const string ServerAuth = "1.3.6.1.5.5.7.3.1";
    private const string ClientAuth = "1.3.6.1.5.5.7.3.2";
    private const string RdpAuth = "1.3.6.1.4.1.311.54.1.2";

    /// <summary>Self-signed in-memory certificate; <paramref name="eku"/> null means no EKU extension.</summary>
    private static X509Certificate2 MakeCert(string name, int daysValid, bool privateKey = true, string? eku = null)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=" + name, key, HashAlgorithmName.SHA256);
        if (eku is not null)
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(eku) }, critical: false));
        using var full = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(daysValid));
        return privateKey ? X509CertificateLoader.LoadPkcs12(full.Export(X509ContentType.Pfx), null) : X509CertificateLoader.LoadCertificate(full.RawData);
    }

    private static Func<string, IReadOnlyList<X509Certificate2>> Stores(List<string> asked, IReadOnlyList<X509Certificate2> remoteDesktop, IReadOnlyList<X509Certificate2>? personal = null)
        => store =>
        {
            asked.Add(store);
            return store == "Remote Desktop" ? remoteDesktop : personal ?? Array.Empty<X509Certificate2>();
        };

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RdpCertificate_NoConfiguredHash_PicksLatestServerCapableCertWithPrivateKey(bool zeroHash)
    {
        var serverAuth = MakeCert("srv", 10, eku: ServerAuth);
        var noEku = MakeCert("plain", 30);
        var noKeyLatest = MakeCert("nokey", 90, privateKey: false);
        var clientOnly = MakeCert("client", 60, eku: ClientAuth);
        var expected = noEku.NotAfter.ToUniversalTime();
        var all = new[] { serverAuth, noEku, noKeyLatest, clientOnly };
        var asked = new List<string>();

        var result = RdpCertificate.Resolve(zeroHash ? new byte[20] : null, Stores(asked, all));

        Assert.Equal("ok", result.Status);
        Assert.Equal(new DateTimeOffset(expected, TimeSpan.Zero), result.NotAfter);
        Assert.True(result.SelfSigned);
        Assert.Equal(new[] { "Remote Desktop" }, asked);
        Assert.All(all, c => Assert.Equal(IntPtr.Zero, c.Handle)); // disposed
    }

    [Fact]
    public void RdpCertificate_NoConfiguredHash_RdpAuthEkuCounts()
    {
        var plain = MakeCert("plain", 30);
        var rdp = MakeCert("rdp", 40, eku: RdpAuth);
        var expected = rdp.NotAfter.ToUniversalTime();

        var result = RdpCertificate.Resolve(null, Stores(new List<string>(), new[] { plain, rdp }));

        Assert.Equal(new DateTimeOffset(expected, TimeSpan.Zero), result.NotAfter);
    }

    [Fact]
    public void RdpCertificate_NoConfiguredHash_NothingEligibleIsNotFound_AndEverythingIsDisposed()
    {
        Assert.Equal("not_found", RdpCertificate.Resolve(null, Stores(new List<string>(), Array.Empty<X509Certificate2>())).Status);

        var noKey = MakeCert("nokey", 30, privateKey: false);
        var wrongEku = MakeCert("client", 30, eku: ClientAuth);
        var result = RdpCertificate.Resolve(null, Stores(new List<string>(), new[] { noKey, wrongEku }));

        Assert.Equal("not_found", result.Status);
        Assert.Null(result.NotAfter);
        Assert.All(new[] { noKey, wrongEku }, c => Assert.Equal(IntPtr.Zero, c.Handle));
    }

    [Fact]
    public void RdpCertificate_ConfiguredHashNotInAnyStore_IsNotFoundEvenWhenAnEligibleListenerCertExists()
    {
        var target = MakeCert("target", 20);
        var other = MakeCert("other", 50);
        var otherPersonal = MakeCert("other-my", 60);
        var asked = new List<string>();

        var result = RdpCertificate.Resolve(Convert.FromHexString(target.Thumbprint), Stores(asked, new[] { other }, new[] { otherPersonal }));

        Assert.Equal("not_found", result.Status);
        Assert.Equal(new[] { "Remote Desktop", "My" }, asked);
        Assert.All(new[] { other, otherPersonal }, c => Assert.Equal(IntPtr.Zero, c.Handle));
        target.Dispose();
    }

    [Fact]
    public void RdpCertificate_ConfiguredHashFoundInPersonalStore_IsUsed()
    {
        var listener = MakeCert("listener", 80);
        var target = MakeCert("target", 20);
        var expected = target.NotAfter.ToUniversalTime();
        var hash = Convert.FromHexString(target.Thumbprint);
        var asked = new List<string>();

        var result = RdpCertificate.Resolve(hash, Stores(asked, new[] { listener }, new[] { target }));

        Assert.Equal("ok", result.Status);
        Assert.Equal(new DateTimeOffset(expected, TimeSpan.Zero), result.NotAfter);
        Assert.Equal(new[] { "Remote Desktop", "My" }, asked);
        Assert.Equal(IntPtr.Zero, listener.Handle);
        Assert.Equal(IntPtr.Zero, target.Handle);
    }

    // ---- software cap ------------------------------------------------------------------------------------------

    [Fact]
    public void Software_CapKeepsEveryMachineEntryAndLetsUserEntriesFillTheRest_InSortedOrder()
    {
        // 900 entries, interleaved by name: every third is machine scope (300), the rest per-user (600).
        var raw = Enumerable.Range(0, 900).Select(i => i % 3 == 0
            ? new SoftwareTelemetrySectionCollector.RawSoftware($"app{i:D4}", "1", "P", null, "x64")
            : new SoftwareTelemetrySectionCollector.RawSoftware($"app{i:D4}", "1", "P", null, "x64", "user", "S-1-5-21-1-2-3-1001"));

        var node = Obj(SoftwareTelemetrySectionCollector.Build(raw));

        Assert.Equal(900, (int)node["software_count"]!);
        Assert.True((bool)node["truncated"]!);
        var list = node["software"]!.AsArray();
        Assert.Equal(500, list.Count);
        var machine = list.Where(e => (string)e!["scope"]! == "machine").Select(e => (string)e!["name"]!).ToArray();
        var users = list.Where(e => (string)e!["scope"]! == "user").Select(e => (string)e!["name"]!).ToArray();
        Assert.Equal(300, machine.Length);
        Assert.Equal(200, users.Length);
        Assert.Equal(Enumerable.Range(0, 900).Where(i => i % 3 == 0).Select(i => $"app{i:D4}"), machine);
        Assert.Equal(Enumerable.Range(0, 900).Where(i => i % 3 != 0).Take(200).Select(i => $"app{i:D4}"), users); // earliest users by sort order
        var names = list.Select(e => (string)e!["name"]!).ToArray();
        Assert.Equal(names.OrderBy(n => n, StringComparer.Ordinal), names);
    }

    [Fact]
    public void Software_UnderTheCapNothingIsDroppedOrTruncated()
    {
        var raw = Enumerable.Range(0, 500).Select(i => new SoftwareTelemetrySectionCollector.RawSoftware($"app{i:D4}", "1", null, null, "x64", i % 2 == 0 ? "machine" : "user", "S-1-5-21-1-2-3-1001"));

        var node = Obj(SoftwareTelemetrySectionCollector.Build(raw));

        Assert.Equal(500, node["software"]!.AsArray().Count);
        Assert.False((bool)node["truncated"]!);
    }

    // ---- updates: security first -------------------------------------------------------------------------------

    [Fact]
    public void Updates_SecurityPendingItemsSurviveTheCapEvenWhenTheyComeLast()
    {
        var items = Enumerable.Range(0, 60).Select(i => new WindowsUpdatePending($"KB{i:D7}", $"Pending {i:D2}", i >= 52)).ToArray();

        var node = Obj(UpdatesTelemetrySectionCollector.Build(false, new WindowsUpdateCacheEntry(new WindowsUpdateScan(60, 8, Array.Empty<WindowsUpdateEntry>(), items, true), T0)));

        var pending = node["pending"]!;
        var list = pending["items"]!.AsArray();
        Assert.Equal(50, list.Count);
        Assert.True((bool)pending["truncated"]!);
        Assert.Equal(Enumerable.Range(52, 8).Select(i => $"Pending {i:D2}"), list.Where(e => (bool)e!["security"]!).Select(e => (string)e!["title"]!));
        Assert.All(list.Take(8), e => Assert.True((bool)e!["security"]!));
        Assert.Equal(Enumerable.Range(0, 42).Select(i => $"Pending {i:D2}"), list.Skip(8).Select(e => (string)e!["title"]!)); // non-security keep their order
    }
}
