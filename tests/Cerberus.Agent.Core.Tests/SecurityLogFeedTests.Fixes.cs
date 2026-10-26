using System.Security.Principal;
using System.Text.Json;
using Cerberus.Agent.App.Telemetry.Sections.FailedLogons;
using static Cerberus.Agent.Core.Tests.ServerFactJson;

namespace Cerberus.Agent.Core.Tests;

/// <summary>
/// Support evidence for the review fixes of the server security feeds: local admin kind on domain controllers and Entra
/// accounts, UAC linked-logon dedupe, cursor seed flag and the unexpected-shutdown cache. No event log is read.
/// </summary>
[Collection("FailedLogonCursor")]
public sealed class SecurityLogFeedFixesTests
{
    private static readonly DateTimeOffset T0 = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly SecurityIdentifier Machine = new("S-1-5-21-1-2-3");

    // ---- local admins kind -------------------------------------------------------------------------------------

    [Theory]
    [InlineData("S-1-12-1-1-2-3-4", 1, false, "domain_user")]
    [InlineData("S-1-12-1-1-2-3-4", 2, false, "domain_group")]
    [InlineData("S-1-12-1-1-2-3-4", 1, true, "domain_user")]
    [InlineData("S-1-5-21-1-2-3-1001", 1, true, "domain_user")]    // DC: the account domain is the directory domain, even if equal to "machine"
    [InlineData("S-1-5-21-9-9-9-512", 2, true, "domain_group")]
    [InlineData("S-1-5-21-9-9-9-1001", 9, true, "unknown")]        // computer account on a DC
    [InlineData("S-1-5-32-544", 4, true, "local_group")]           // builtin stays local on a DC
    [InlineData("S-1-5-21-1-2-3-1001", 1, false, "local_user")]    // member host: machine SID matches
    [InlineData("S-1-5-21-9-9-9-500", 1, false, "domain_user")]    // member host: other domain
    public void LocalAdminKind_EntraAndDomainControllerRules(string sid, int usage, bool isDc, string expected)
        => Assert.Equal(expected, LocalAdminsProbe.Kind(new SecurityIdentifier(sid), usage, Machine, isDc));

    [Fact]
    public void LocalAdminKind_NullMachineSid_DomainControllerStillResolvesDomainAndBuiltinStaysLocal()
    {
        Assert.Equal("domain_user", LocalAdminsProbe.Kind(new SecurityIdentifier("S-1-5-21-1-2-3-1001"), 1, null, isDomainController: true));
        Assert.Equal("local_group", LocalAdminsProbe.Kind(new SecurityIdentifier("S-1-5-32-544"), 4, null));
        Assert.Equal("unknown", LocalAdminsProbe.Kind(new SecurityIdentifier("S-1-5-21-1-2-3-1001"), 1, null));
        Assert.Equal("unknown", LocalAdminsProbe.Kind(new SecurityIdentifier("S-1-5-21-1-2-3-1001"), 9, Machine));
    }

    // ---- linked logon dedupe -----------------------------------------------------------------------------------

    private static SuccessfulLogon L(int minute, string id, string link, string user = "alice", string? ip = "203.0.113.5", int type = 2, string domain = "CORP")
        => new(T0.AddMinutes(minute), user, domain, type, ip, "WS", id, link);

    [Fact]
    public void Dedupe_LinkedPairCountsOnce_InEitherDirection()
    {
        var limitedFirst = SecurityLogFields.DedupeLinkedLogons(new[] { L(1, "0x10", "0x11"), L(1, "0x11", "0x10") });
        var elevatedFirst = SecurityLogFields.DedupeLinkedLogons(new[] { L(1, "0x11", "0x10"), L(1, "0x10", "0x11") });
        var oneSidedLink = SecurityLogFields.DedupeLinkedLogons(new[] { L(1, "0x10", "0x11"), L(1, "0x11", "0x0") });
        var otherOneSided = SecurityLogFields.DedupeLinkedLogons(new[] { L(1, "0x10", "0x0"), L(1, "0x11", "0x10") });

        Assert.Single(limitedFirst);
        Assert.Equal("0x10", limitedFirst[0].LogonId);
        Assert.Single(elevatedFirst);
        Assert.Equal("0x11", elevatedFirst[0].LogonId);
        Assert.Single(oneSidedLink);
        Assert.Single(otherOneSided);
    }

    [Theory]
    [InlineData("other", "203.0.113.5", 2, "CORP")]   // different user
    [InlineData("alice", "203.0.113.9", 2, "CORP")]   // different address
    [InlineData("alice", "203.0.113.5", 10, "CORP")]  // different logon type
    [InlineData("alice", "203.0.113.5", 2, "OTHER")]  // different domain
    public void Dedupe_LinkedEventsThatAreNotTheSameSessionStaySeparate(string user, string ip, int type, string domain)
    {
        var result = SecurityLogFields.DedupeLinkedLogons(new[] { L(1, "0x10", "0x11"), L(1, "0x11", "0x10", user, ip, type, domain) });

        Assert.Equal(2, result.Count);
    }

    [Theory]
    [InlineData("0x0")]
    [InlineData("0x00000000")]
    public void Dedupe_ZeroLinksNeverMerge(string zero)
    {
        var result = SecurityLogFields.DedupeLinkedLogons(new[] { L(1, zero, zero), L(2, zero, zero), L(3, "0x5", zero), L(4, "0x6", zero) });

        Assert.Equal(4, result.Count);
    }

    [Fact]
    public void Dedupe_UnlinkedEventsAreUntouchedAndOrderIsKept()
    {
        var input = new[] { L(3, "0x1", "0x2"), L(1, "0x9", "0x0", "bob"), L(2, "0x2", "0x1"), L(0, "0x7", "0x0", "bob") };

        var result = SecurityLogFields.DedupeLinkedLogons(input);

        Assert.Equal(new[] { "0x1", "0x9", "0x7" }, result.Select(l => l.LogonId));
        Assert.Empty(SecurityLogFields.DedupeLinkedLogons(Array.Empty<SuccessfulLogon>()));
        Assert.Equal(2, SecurityLogFields.DedupeLinkedLogons(new[] { new SuccessfulLogon(T0, "a", "D", 2, null, null), new SuccessfulLogon(T0, "a", "D", 2, null, null) }).Count);
    }

    [Fact]
    public void SuccessfulLogons_CountReflectsTheDedupe()
    {
        var node = Obj(SecurityLogFields.SuccessfulLogons("ok", new[] { L(1, "0x10", "0x11"), L(1, "0x11", "0x10"), L(2, "0x20", "0x0", "bob") }));

        Assert.Equal(2, (int)node["count"]!);
        Assert.Equal(2, node["items"]!.AsArray().Count);
    }

    [Fact]
    public void Logon_ParserReadsTargetLogonIdAndLinkedLogonId()
    {
        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["LogonType"] = "2", ["TargetUserName"] = "alice", ["TargetDomainName"] = "CORP", ["IpAddress"] = "-",
            ["TargetLogonId"] = "0x1a2b", ["TargetLinkedLogonId"] = "0x1a2c",
        };

        var logon = Assert.IsType<SuccessfulLogon>(SecurityLogEventParser.Logon(T0, data)!.Detail);

        Assert.Equal("0x1a2b", logon.LogonId);
        Assert.Equal("0x1a2c", logon.LinkedLogonId);
    }

    // ---- cursor ------------------------------------------------------------------------------------------------

    [Fact]
    public void Cursor_LogClearedSeededDefaultsFalseForOldFilesAndRoundTripsAtVersion1()
    {
        var dir = Path.Combine(Path.GetTempPath(), "fl-seed-" + Guid.NewGuid().ToString("N"));
        try
        {
            var path = Path.Combine(dir, "c.json");
            var store = new FailedLogonCursorStore(path);
            Assert.True(store.Save(new FailedLogonCursorState()));
            File.WriteAllText(path, "{\"version\":1,\"last_window_end_utc\":\"2026-03-01T12:00:00+00:00\",\"last_log_cleared_utc\":\"2026-02-01T00:00:00+00:00\",\"channels\":{\"Security\":5}}");

            var old = store.Load(out var invalid);
            Assert.False(invalid);
            Assert.False(old.LogClearedSeeded);

            old.LogClearedSeeded = true;
            Assert.True(store.Save(old));
            using (var json = JsonDocument.Parse(File.ReadAllText(path)))
            {
                Assert.Equal(1, json.RootElement.GetProperty("version").GetInt32());
                Assert.True(json.RootElement.GetProperty("log_cleared_seeded").GetBoolean());
            }

            var again = store.Load(out invalid);
            Assert.False(invalid);
            Assert.True(again.LogClearedSeeded);
            Assert.Equal(1, again.Version);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, true);
        }
    }

    // ---- unexpected shutdown cache -----------------------------------------------------------------------------

    private static readonly DateTimeOffset Boot = T0.AddDays(-2);

    private static Func<IReadOnlyList<DateTimeOffset>> Fetch(Action onCall, params DateTimeOffset[] times)
        => () =>
        {
            onCall();
            return times;
        };

    [Fact]
    public void ShutdownCache_SameBootWithinTtlDoesNotRefetch_NewBootOrExpiredTtlDoes()
    {
        UnexpectedShutdownsProbe.ResetCache();
        try
        {
            var calls = 0;
            var fetch = Fetch(() => calls++, T0.AddHours(-5));

            var first = UnexpectedShutdownsProbe.ReadCached(T0, Boot, fetch);
            UnexpectedShutdownsProbe.ReadCached(T0.AddMinutes(30), Boot.AddSeconds(20), fetch); // boot time jitter within tolerance
            Assert.Equal(1, calls);
            Assert.Equal(1, first.Count7d);

            UnexpectedShutdownsProbe.ReadCached(T0.AddMinutes(31), Boot.AddHours(3), fetch);   // rebooted
            Assert.Equal(2, calls);

            UnexpectedShutdownsProbe.ReadCached(T0.AddMinutes(31 + 61), Boot.AddHours(3), fetch); // TTL expired
            Assert.Equal(3, calls);
        }
        finally
        {
            UnexpectedShutdownsProbe.ResetCache();
        }
    }

    [Fact]
    public void ShutdownCache_ReappliesTheSevenDayWindowToTheCachedList()
    {
        UnexpectedShutdownsProbe.ResetCache();
        try
        {
            var calls = 0;
            var fetch = Fetch(() => calls++, T0.AddDays(-6).AddHours(-12), T0.AddDays(-1));

            Assert.Equal(2, UnexpectedShutdownsProbe.ReadCached(T0, Boot, fetch).Count7d);
            var later = UnexpectedShutdownsProbe.ReadCached(T0.AddHours(1).AddMinutes(-1), Boot, fetch); // same cache, window moved on
            Assert.Equal(1, calls);
            Assert.Equal(2, later.Count7d);

            UnexpectedShutdownsProbe.ResetCache();
            var aged = UnexpectedShutdownsProbe.ReadCached(T0.AddDays(1), Boot, fetch);
            Assert.Equal(2, calls);
            Assert.Equal(1, aged.Count7d); // the 6.5 day old event is outside 7 days a day later
            Assert.Equal(T0.AddDays(-1), aged.LastUtc);

            var cachedAged = UnexpectedShutdownsProbe.ReadCached(T0.AddDays(1).AddMinutes(10), Boot, fetch);
            Assert.Equal(2, calls);
            Assert.Equal(1, cachedAged.Count7d);
        }
        finally
        {
            UnexpectedShutdownsProbe.ResetCache();
        }
    }

    [Fact]
    public void ShutdownCache_ThrowingFetchIsNotCached()
    {
        UnexpectedShutdownsProbe.ResetCache();
        try
        {
            var calls = 0;
            Assert.Throws<InvalidOperationException>(() => UnexpectedShutdownsProbe.ReadCached(T0, Boot, () =>
            {
                calls++;
                throw new InvalidOperationException("log unreadable");
            }));

            var result = UnexpectedShutdownsProbe.ReadCached(T0.AddSeconds(1), Boot, Fetch(() => calls++, T0.AddHours(-1)));

            Assert.Equal(2, calls);
            Assert.Equal(1, result.Count7d);
        }
        finally
        {
            UnexpectedShutdownsProbe.ResetCache();
        }
    }
}
