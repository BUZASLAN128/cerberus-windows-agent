using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using Cerberus.Agent.App.Telemetry.Sections.FailedLogons;
using static Cerberus.Agent.Core.Tests.ServerFactJson;

namespace Cerberus.Agent.Core.Tests;

/// <summary>
/// Support evidence for the successful_logons, local_admins, log_cleared and unexpected_shutdowns fields of the server
/// security section: event parsers and filters, field builders, probe helpers. No event log is read except in the
/// CollectAll test, which accepts the Security log being unreadable.
/// </summary>
[Collection("FailedLogonCursor")]
public sealed class SecurityLogFeedTests
{
    private static readonly DateTimeOffset T0 = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);

    private static Dictionary<string, string> Data(params (string Key, string Value)[] pairs)
        => pairs.ToDictionary(p => p.Key, p => p.Value, StringComparer.OrdinalIgnoreCase);

    private static string[] Sorted(params string[] names) => names.OrderBy(k => k, StringComparer.Ordinal).ToArray();

    private static string[] Keys(JsonNode? node) => ((JsonObject)node!).Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal).ToArray();

    // ---- 4624 parser -------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("2")]
    [InlineData("10")]
    public void Logon_KeepsInteractiveAndRemoteInteractiveWithAllFields(string type)
    {
        var ev = SecurityLogEventParser.Logon(T0, Data(
            ("LogonType", type), ("TargetUserName", "alice"), ("TargetDomainName", "CORP"),
            ("IpAddress", "203.0.113.5"), ("WorkstationName", "WS01")));

        Assert.NotNull(ev);
        Assert.Equal(FailedLogonSource.SuccessfulLogon4624, ev.Source);
        var logon = Assert.IsType<SuccessfulLogon>(ev.Detail);
        Assert.Equal(new SuccessfulLogon(T0, "alice", "CORP", int.Parse(type), "203.0.113.5", "WS01"), logon);
    }

    [Theory]
    [InlineData("3")]
    [InlineData("4")]
    [InlineData("5")]
    [InlineData("7")]
    [InlineData("9")]
    [InlineData("11")]
    [InlineData("")]
    [InlineData("abc")]
    public void Logon_DropsOtherLogonTypes(string type)
        => Assert.Null(SecurityLogEventParser.Logon(T0, Data(("LogonType", type), ("TargetUserName", "alice"))));

    [Fact]
    public void Logon_MissingLogonTypeIsDropped()
        => Assert.Null(SecurityLogEventParser.Logon(T0, Data(("TargetUserName", "alice"))));

    [Theory]
    [InlineData("DWM-1")]
    [InlineData("dwm-12")]
    [InlineData("UMFD-0")]
    [InlineData("umfd-3")]
    [InlineData("-")]
    [InlineData("  ")]
    public void Logon_SkipsSessionHelperAccountsAndEmptyUsers(string user)
        => Assert.Null(SecurityLogEventParser.Logon(T0, Data(("LogonType", "2"), ("TargetUserName", user))));

    [Fact]
    public void Logon_UserOnlyPrefixedLikeAHelperWithoutDashIsKept()
        => Assert.NotNull(SecurityLogEventParser.Logon(T0, Data(("LogonType", "2"), ("TargetUserName", "DWMX"))));

    [Fact]
    public void Logon_PlaceholdersLoopbackAndLongNamesAreCleaned()
    {
        var ev = SecurityLogEventParser.Logon(T0, Data(
            ("LogonType", "2"), ("TargetUserName", new string('u', 300)), ("TargetDomainName", "-"),
            ("IpAddress", "::1"), ("WorkstationName", "-")));

        var logon = Assert.IsType<SuccessfulLogon>(ev!.Detail);
        Assert.Equal(128, logon.User!.Length);
        Assert.Null(logon.Domain);
        Assert.Null(logon.SourceIp);
        Assert.Null(logon.WorkstationName);
    }

    [Fact]
    public void Tally_IgnoresSuccessfulLogonAndGroupChangeEvents()
    {
        var failed = new FailedLogonEvent(FailedLogonSource.Security4625, T0, "203.0.113.5", 3);
        var success = SecurityLogEventParser.Logon(T0, Data(("LogonType", "10"), ("TargetUserName", "a"), ("IpAddress", "203.0.113.5")))!;
        var change = SecurityLogEventParser.GroupChange(4732, T0, Data(("TargetSid", "S-1-5-32-544"), ("MemberSid", "S-1-5-21-1-2-3-1001")))!;

        var plain = FailedLogonClassifier.Tally(new[] { failed });
        var mixed = FailedLogonClassifier.Tally(new[] { failed, success, change });

        Assert.Equal(plain.Counts, mixed.Counts);
        Assert.Equal(plain.Groups, mixed.Groups);
    }

    // ---- group-change parser -----------------------------------------------------------------------------------

    [Theory]
    [InlineData(4732, "added", "S-1-5-32-544")]
    [InlineData(4733, "removed", "S-1-5-32-544")]
    [InlineData(4728, "added", "S-1-5-21-1-2-3-512")]
    [InlineData(4729, "removed", "S-1-5-21-1-2-3-518")]
    [InlineData(4756, "added", "S-1-5-21-1-2-3-519")]
    [InlineData(4757, "removed", "S-1-5-21-1-2-3-512")]
    [InlineData(4728, "added", "S-1-5-32-544")]
    public void GroupChange_KeepsPrivilegedGroups(int eventId, string action, string groupSid)
    {
        var ev = SecurityLogEventParser.GroupChange(eventId, T0, Data(
            ("TargetSid", groupSid), ("MemberName", "CN=bob,DC=corp"), ("MemberSid", "S-1-5-21-1-2-3-1001")));

        Assert.NotNull(ev);
        Assert.Equal(FailedLogonSource.GroupChange, ev.Source);
        Assert.Equal(new AdminGroupChange(eventId, action, "CN=bob,DC=corp", "S-1-5-21-1-2-3-1001", groupSid, T0), ev.Detail);
    }

    [Theory]
    [InlineData(4732, "S-1-5-32-545")]          // builtin Users
    [InlineData(4732, "S-1-5-21-1-2-3-512")]    // local-group event: RID rule is for domain-wide events only
    [InlineData(4733, "S-1-5-21-1-2-3-519")]
    [InlineData(4728, "S-1-5-21-1-2-3-513")]    // Domain Users
    [InlineData(4728, "S-1-5-21-1-2-3-1512")]   // RID 1512, not 512
    [InlineData(4728, "S-1-5-22-1-2-3-512")]    // not a domain SID
    [InlineData(4624, "S-1-5-32-544")]          // not a group-change event
    [InlineData(4731, "S-1-5-32-544")]          // group creation
    public void GroupChange_DropsOtherGroupsAndEvents(int eventId, string groupSid)
        => Assert.Null(SecurityLogEventParser.GroupChange(eventId, T0, Data(("TargetSid", groupSid))));

    [Fact]
    public void GroupChange_MissingTargetSidIsDroppedAndPlaceholderMemberIsNull()
    {
        Assert.Null(SecurityLogEventParser.GroupChange(4732, T0, Data(("MemberSid", "S-1-5-21-1-2-3-1001"))));

        var ev = SecurityLogEventParser.GroupChange(4732, T0, Data(("TargetSid", "S-1-5-32-544"), ("MemberName", "-"), ("MemberSid", "-")));
        var change = Assert.IsType<AdminGroupChange>(ev!.Detail);
        Assert.Null(change.MemberName);
        Assert.Null(change.MemberSid);
    }

    // ---- field builders ----------------------------------------------------------------------------------------

    private static SuccessfulLogon Logon(int i) => new(T0.AddMinutes(i), $"u{i:D3}", "CORP", i % 2 == 0 ? 2 : 10, "203.0.113.5", "WS");

    [Fact]
    public void SuccessfulLogons_ShapeNewestFirstAndCapAtFifty()
    {
        var node = Obj(SecurityLogFields.SuccessfulLogons("ok", Enumerable.Range(0, 60).Select(Logon).ToArray()));

        Assert.Equal(Sorted("status", "count", "truncated", "items"), Keys(node));
        Assert.Equal(60, (int)node["count"]!);
        Assert.True((bool)node["truncated"]!);
        var items = node["items"]!.AsArray();
        Assert.Equal(50, items.Count);
        Assert.Equal("u059", (string)items[0]!["user"]!);
        Assert.Equal("u010", (string)items[49]!["user"]!);
        Assert.Equal(Sorted("time_utc", "user", "domain", "logon_type", "source_ip", "workstation_name"), Keys(items[0]));
        Assert.Equal("2026-03-01T12:59:00Z", (string)items[0]!["time_utc"]!);
        Assert.Equal(10, (int)items[0]!["logon_type"]!);
    }

    [Fact]
    public void SuccessfulLogons_ExactlyFiftyIsNotTruncatedAndEmptyIsOk()
    {
        var full = Obj(SecurityLogFields.SuccessfulLogons("ok", Enumerable.Range(0, 50).Select(Logon).ToArray()));
        Assert.Equal(50, full["items"]!.AsArray().Count);
        Assert.False((bool)full["truncated"]!);

        var empty = Obj(SecurityLogFields.SuccessfulLogons("partial", Array.Empty<SuccessfulLogon>()));
        Assert.Equal("partial", (string)empty["status"]!);
        Assert.Equal(0, (int)empty["count"]!);
        Assert.Empty(empty["items"]!.AsArray());
    }

    private static AdminGroupChange Change(int i) => new(4732, "added", $"m{i:D2}", $"S-1-5-21-1-2-3-{1000 + i}", "S-1-5-32-544", T0.AddMinutes(i));

    [Fact]
    public void AdminChanges_ShapeNewestFirstAndCapAtTwenty()
    {
        var report = SecurityLogFields.AdminChanges("ok", Enumerable.Range(0, 25).Select(Change).ToArray());

        Assert.Equal("ok", report.Status);
        var changes = Obj(report.Changes!);
        Assert.Equal(Sorted("count", "truncated", "items"), Keys(changes));
        Assert.Equal(25, (int)changes["count"]!);
        Assert.True((bool)changes["truncated"]!);
        var items = changes["items"]!.AsArray();
        Assert.Equal(20, items.Count);
        Assert.Equal("m24", (string)items[0]!["member_name"]!);
        Assert.Equal(Sorted("event_id", "action", "member_name", "member_sid", "group_sid", "time_utc"), Keys(items[0]));
        Assert.False((bool)Obj(SecurityLogFields.AdminChanges("ok", Enumerable.Range(0, 20).Select(Change).ToArray()).Changes!)["truncated"]!);
    }

    [Fact]
    public void LogCleared_ShapeWithAndWithoutTime()
    {
        var some = Obj(SecurityLogFields.LogCleared("ok", T0));
        Assert.Equal(Sorted("status", "last_cleared_utc"), Keys(some));
        Assert.Equal("2026-03-01T12:00:00Z", (string)some["last_cleared_utc"]!);
        Assert.Null(Obj(SecurityLogFields.LogCleared("ok", null))["last_cleared_utc"]);
    }

    private static LocalAdminsRead Members(bool truncated = false, bool incomplete = false)
        => new(new[] { new LocalAdminMember("CORP\\Domain Admins", "S-1-5-21-9-9-9-512", "domain_group") }, 130, truncated, incomplete);

    [Fact]
    public void LocalAdmins_ShapeAndStatusMatrix()
    {
        var okChanges = SecurityLogFields.AdminChanges("ok", new[] { Change(1) });
        var node = Obj(SecurityLogFields.LocalAdmins(Members(truncated: true), okChanges));

        Assert.Equal(Sorted("status", "count", "members", "truncated", "changes"), Keys(node));
        Assert.Equal("ok", (string)node["status"]!); // a capped list with a complete scan is still ok
        Assert.Equal(130, (int)node["count"]!);
        Assert.True((bool)node["truncated"]!);
        Assert.Equal(Sorted("name", "sid", "kind"), Keys(node["members"]![0]));
        Assert.Equal(1, (int)node["changes"]!["count"]!);

        Assert.Equal("ok", Status(Members(), okChanges));
        Assert.Equal("partial", Status(Members(incomplete: true), okChanges));
        Assert.Equal("partial", Status(Members(), SecurityLogFields.AdminChanges("partial", Array.Empty<AdminGroupChange>())));
        Assert.Equal("partial", Status(null, okChanges));
        Assert.Equal("partial", Status(Members(), new AdminChangeReport("unavailable", null)));
        Assert.Equal("unavailable", Status(null, new AdminChangeReport("unavailable", null)));
    }

    [Fact]
    public void LocalAdmins_UnavailableKeepsEmptyChangesObject()
    {
        var node = Obj(SecurityLogFields.LocalAdmins(null, new AdminChangeReport("unavailable", null)));

        Assert.Equal(0, (int)node["count"]!);
        Assert.Empty(node["members"]!.AsArray());
        Assert.Equal(0, (int)node["changes"]!["count"]!);
        Assert.Empty(node["changes"]!["items"]!.AsArray());
    }

    private static string Status(LocalAdminsRead? members, AdminChangeReport changes)
        => (string)Obj(SecurityLogFields.LocalAdmins(members, changes))["status"]!;

    // ---- local admins kind mapping -----------------------------------------------------------------------------

    private static readonly SecurityIdentifier Machine = new("S-1-5-21-1-2-3");

    [Theory]
    [InlineData("S-1-5-21-1-2-3-1001", 1, "local_user")]
    [InlineData("S-1-5-21-9-9-9-500", 1, "domain_user")]
    [InlineData("S-1-5-21-9-9-9-512", 2, "domain_group")]
    [InlineData("S-1-5-21-1-2-3-1002", 4, "local_group")]
    [InlineData("S-1-5-32-544", 4, "local_group")]
    [InlineData("S-1-5-18", 5, "local_group")]
    [InlineData("S-1-5-21-9-9-9-1001", 3, "unknown")]   // domain object
    [InlineData("S-1-5-21-9-9-9-1001", 6, "unknown")]   // deleted account
    [InlineData("S-1-5-21-9-9-9-1001", 8, "unknown")]   // unresolved
    [InlineData("S-1-5-21-9-9-9-1001", 9, "unknown")]   // computer
    public void LocalAdminKind_MapsSidDomainAndUsage(string sid, int usage, string expected)
        => Assert.Equal(expected, LocalAdminsProbe.Kind(new SecurityIdentifier(sid), usage, Machine));

    [Fact]
    public void LocalAdminKind_UnknownMachineSidOnlyAffectsAccountsWithADomainPart()
    {
        Assert.Equal("unknown", LocalAdminsProbe.Kind(new SecurityIdentifier("S-1-5-21-1-2-3-1001"), 1, null));
        Assert.Equal("local_group", LocalAdminsProbe.Kind(new SecurityIdentifier("S-1-5-32-544"), 4, null));
    }

    // ---- unexpected shutdowns ----------------------------------------------------------------------------------

    [Fact]
    public void Shutdowns_NoEventsIsZeroWithoutLastTime()
        => Assert.Equal(new UnexpectedShutdowns(0, null), UnexpectedShutdownsProbe.Summarize(Array.Empty<DateTimeOffset>()));

    [Fact]
    public void Shutdowns_Event41And6008OfOneCrashAreOneIncident()
    {
        var result = UnexpectedShutdownsProbe.Summarize(new[] { T0, T0.AddSeconds(40) });

        Assert.Equal(1, result.Count7d);
        Assert.Equal(T0.AddSeconds(40), result.LastUtc);
    }

    [Fact]
    public void Shutdowns_MergeWindowBoundaryIsInclusiveAtFiveMinutes()
    {
        Assert.Equal(1, UnexpectedShutdownsProbe.Summarize(new[] { T0, T0.AddMinutes(5) }).Count7d);
        Assert.Equal(2, UnexpectedShutdownsProbe.Summarize(new[] { T0, T0.AddMinutes(5).AddSeconds(1) }).Count7d);
    }

    [Fact]
    public void Shutdowns_InputOrderDoesNotMatterAndChainsMeasureFromTheCountedEvent()
    {
        // 12:20 / 12:16 merge; 12:12 is 8 minutes from the counted 12:20, so it starts a new incident; 12:10 merges into it.
        var times = new[] { T0.AddMinutes(10), T0.AddMinutes(20), T0.AddMinutes(12), T0.AddMinutes(16), T0.AddDays(-3) };

        var result = UnexpectedShutdownsProbe.Summarize(times);

        Assert.Equal(3, result.Count7d);
        Assert.Equal(T0.AddMinutes(20), result.LastUtc);
    }

    [Theory]
    [InlineData(41, "Microsoft-Windows-Kernel-Power", true)]
    [InlineData(41, "EventLog", false)]
    [InlineData(6008, "EventLog", true)]
    [InlineData(6008, "Microsoft-Windows-Kernel-Power", false)]
    [InlineData(41, null, false)]
    [InlineData(1074, "EventLog", false)]
    public void Shutdowns_OnlyTheExpectedProviderPerEventIdCounts(int id, string? provider, bool expected)
        => Assert.Equal(expected, UnexpectedShutdownsProbe.IsExpectedProvider(id, provider));

    // ---- cursor ------------------------------------------------------------------------------------------------

    [Fact]
    public void Cursor_FileWrittenBeforeLastLogClearedExistedStillLoads_AndNewFieldRoundTripsAtVersion1()
    {
        var dir = Path.Combine(Path.GetTempPath(), "fl-compat-" + Guid.NewGuid().ToString("N"));
        try
        {
            var path = Path.Combine(dir, "c.json");
            var store = new FailedLogonCursorStore(path);
            Assert.True(store.Save(new FailedLogonCursorState()));
            File.WriteAllText(path, "{\"version\":1,\"last_window_end_utc\":\"2026-03-01T12:00:00+00:00\",\"channels\":{\"Security\":5}}");

            var old = store.Load(out var invalid);

            Assert.False(invalid);
            Assert.Equal(1, old.Version);
            Assert.Null(old.LastLogClearedUtc);
            Assert.Equal(T0, old.LastWindowEndUtc);
            Assert.Equal(5, old.Channels["security"]);

            old.LastLogClearedUtc = T0.AddHours(-1);
            Assert.True(store.Save(old));
            using var json = JsonDocument.Parse(File.ReadAllText(path));
            Assert.Equal(1, json.RootElement.GetProperty("version").GetInt32());
            Assert.True(json.RootElement.TryGetProperty("last_log_cleared_utc", out _));
            Assert.Equal(T0.AddHours(-1), store.Load(out invalid).LastLogClearedUtc);
            Assert.False(invalid);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, true);
        }
    }

    // ---- CollectAll --------------------------------------------------------------------------------------------

    [Fact]
    public void CollectAll_ReturnsAllFeedsOnTheSameWindow_PeekLeavesFileUntouchedAndCommitStoresLastCleared()
    {
        var dir = Path.Combine(Path.GetTempPath(), "fl-all-" + Guid.NewGuid().ToString("N"));
        try
        {
            var path = Path.Combine(dir, "c.json");
            var store = new FailedLogonCursorStore(path);
            Assert.True(store.Save(new FailedLogonCursorState { LastWindowEndUtc = T0 }));
            var before = File.ReadAllText(path);

            var peek = FailedLogonSection.CollectAll(store, T0.AddMinutes(5), commit: false, CancellationToken.None);
            FailedLogonSection.CommitPending();

            Assert.Equal(before, File.ReadAllText(path));
            Assert.Equal("2026-03-01T12:00:00Z", (string)Obj(peek.FailedLogons)["window_start_utc"]!);
            AssertFeedConsistency(peek);

            var commit = FailedLogonSection.CollectAll(store, T0.AddMinutes(10), commit: true, CancellationToken.None);
            FailedLogonSection.KeepPendingIfReported(new Dictionary<string, object?> { ["failed_logons"] = commit.FailedLogons });
            FailedLogonSection.CommitPending();

            var stored = store.Load(out var invalid);
            Assert.False(invalid);
            Assert.Equal(T0.AddMinutes(10), stored.LastWindowEndUtc);
            var cleared = (string?)Obj(commit.LogCleared)["last_cleared_utc"];
            Assert.Equal(cleared, stored.LastLogClearedUtc is { } t ? FailedLogonSection.Iso(t) : null);

            // The wrapper keeps its old behaviour: the failed_logons object of the same kind of pass.
            Assert.Equal("2026-03-01T12:10:00Z", (string)Obj(FailedLogonSection.Collect(store, T0.AddMinutes(15), commit: false, CancellationToken.None))["window_start_utc"]!);
        }
        finally
        {
            if (Directory.Exists(dir))
                Directory.Delete(dir, true);
        }
    }

    // With no saved channel position every readable channel is a first run (no reads), so the window has no events:
    // either the Security log is readable and every feed is empty, or it is not and every feed says unavailable.
    private static void AssertFeedConsistency(SecurityLogResult result)
    {
        var logons = Obj(result.SuccessfulLogons);
        if ((string)logons["status"]! == "unavailable")
        {
            Assert.Equal("unavailable", result.AdminChanges.Status);
            Assert.Equal(0, (int)Obj(result.AdminChanges.Changes!)["count"]!);
            return;
        }

        Assert.Equal("ok", (string)logons["status"]!);
        Assert.Equal(0, (int)logons["count"]!);
        Assert.Equal("ok", result.AdminChanges.Status);
        Assert.Equal(0, (int)Obj(result.AdminChanges.Changes!)["count"]!);
        Assert.Contains((string)Obj(result.LogCleared)["status"]!, new[] { "ok", "partial" });
    }
}
