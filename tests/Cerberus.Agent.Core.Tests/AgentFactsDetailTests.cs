using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.App.Telemetry.Sections.FailedLogons;
using static Cerberus.Agent.Core.Tests.ServerFactJson;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Support evidence for optional facts and their uncertainty/PII/cap boundaries; no installed-service acceptance.</summary>
public sealed class AgentFactsDetailTests
{
    private const string MemberSid = "S-1-5-21-1-2-3-1001";
    private static readonly DateTimeOffset Time = new(2026, 11, 3, 12, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(4732)]
    [InlineData(4728)]
    public void AdminAddition_UsesEventActorWithoutAddingActorSid(int eventId)
    {
        var change = Parsed(eventId, "alice", "CORP");
        Assert.Equal("CORP\\alice", change.AddedBy);
        var member = Member(SecurityLogFields.AdminChanges("ok", new[] { change }));
        Assert.Equal("CORP\\alice", (string?)member["added_by"]);
        Assert.Equal("2026-11-03T12:00:00Z", (string?)member["added_at_utc"]);
        Assert.Equal("security_event:" + eventId, (string?)member["addition_source"]);
        Assert.False(member.AsObject().ContainsKey("actor_sid"));
        Assert.False(member.AsObject().ContainsKey("profile_path"));
    }

    [Theory]
    [InlineData(4733)]
    [InlineData(4729)]
    [InlineData(4756)]
    public void OtherGroupEvents_DoNotSupplyAnAdditionActor(int eventId)
        => Assert.Null(Parsed(eventId, "alice", "CORP").AddedBy);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("-")]
    public void MissingActor_IsOmittedInsteadOfInferredFromMember(string? actor)
    {
        var change = Parsed(4732, actor, "CORP");
        var member = Member(SecurityLogFields.AdminChanges("ok", new[] { change }));
        Assert.False(member.AsObject().ContainsKey("added_by"));
        Assert.Equal("security_event:4732", (string?)member["addition_source"]);
    }

    [Theory]
    [InlineData(100, 100)]
    [InlineData(129, 1)]
    [InlineData(1, 129)]
    public void OverlongActorCombination_IsNotTruncatedIntoAnApparentIdentity(int userLength, int domainLength)
        => Assert.Null(Parsed(4732, new string('u', userLength), new string('d', domainLength)).AddedBy);

    [Fact]
    public void ActorWithControlCharacters_IsNotChangedIntoAnotherApparentIdentity()
        => Assert.Null(Parsed(4732, "ali\nce", "CORP").AddedBy);

    [Theory]
    [InlineData("wrong_member")]
    [InlineData("wrong_group")]
    [InlineData("partial")]
    [InlineData("removed")]
    [InlineData("simultaneous")]
    [InlineData("outside_cap")]
    public void CurrentMemberAttribution_RequiresUnambiguousLatestMatchingAddition(string scenario)
    {
        var add = Parsed(4732, "alice", "CORP");
        var changes = new List<AdminGroupChange> { add };
        var status = "ok";
        switch (scenario)
        {
            case "wrong_member": changes[0] = add with { MemberSid = MemberSid + "0" }; break;
            case "wrong_group": changes[0] = add with { GroupSid = "S-1-5-21-1-2-3-512" }; break;
            case "partial": status = "partial"; break;
            case "removed": changes.Add(add with { EventId = 4733, Action = "removed", TimeUtc = Time.AddSeconds(1), RecordId = 101 }); break;
            case "simultaneous": changes.Add(add with { EventId = 4733, Action = "removed" }); break;
            case "outside_cap":
                changes.AddRange(Enumerable.Range(1, SecurityLogFields.MaxChanges)
                    .Select(i => add with { MemberSid = MemberSid + i, TimeUtc = Time.AddMinutes(-i), RecordId = 100 + i }));
                break;
        }
        var member = Member(SecurityLogFields.AdminChanges(status, changes));
        Assert.False(member.AsObject().ContainsKey("added_by"));
        Assert.False(member.AsObject().ContainsKey("added_at_utc"));
        Assert.False(member.AsObject().ContainsKey("addition_source"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void AdminAttribution_UsesRecordOrderAcrossUtcRollback(bool lastWasRemoval)
    {
        var alice = Parsed(4732, "alice", "CORP");
        var removed = alice with { EventId = 4733, Action = "removed", TimeUtc = Time.AddMinutes(-1), RecordId = 101 };
        var bob = Parsed(4732, "bob", "CORP") with { TimeUtc = Time.AddMinutes(-2), RecordId = 102 };
        var feed = lastWasRemoval ? new[] { alice, removed } : new[] { alice, removed, bob };
        var member = Member(SecurityLogFields.AdminChanges("ok", feed));
        if (lastWasRemoval)
            Assert.False(member.AsObject().ContainsKey("added_by"));
        else
        {
            Assert.Equal("CORP\\bob", (string?)member["added_by"]);
            Assert.Equal("2026-11-03T11:58:00Z", (string?)member["added_at_utc"]);
        }
    }

    [Fact]
    public void AdminAttribution_MissingRecordOrderIsOmitted()
    {
        var change = Parsed(4732, "alice", "CORP") with { RecordId = null };
        Assert.False(Member(SecurityLogFields.AdminChanges("ok", new[] { change })).AsObject().ContainsKey("added_by"));
    }

    [Fact]
    public void InstallerMarker_IsMergedAfterExistingIdentityDedupBeforeFiveHundredCap()
    {
        var rows = Enumerable.Range(0, 500).SelectMany(i =>
        {
            var row = new SoftwareTelemetrySectionCollector.RawSoftware($"App{i:D3}", "1", null, null, "x64");
            return new[] { row, row with { WindowsInstaller = true } };
        });
        var node = Obj(SoftwareTelemetrySectionCollector.Build(rows));
        Assert.Equal(500, (int)node["software_count"]!);
        Assert.False((bool)node["truncated"]!);
        var entries = node["software"]!.AsArray();
        Assert.Equal(500, entries.Count);
        Assert.All(entries, entry => Assert.Equal("windows_installer", (string?)entry!["install_source"]));
        Assert.Equal("App499", (string?)entries[^1]!["name"]);
    }

    [Fact]
    public void Updates_PreserveNestedWireShapeSecurityPriorityAndFiftyItemLimit()
    {
        var pending = Enumerable.Range(0, 60).Select(i => new WindowsUpdatePending(
            "KB" + i, "Update " + i, i >= 55, i >= 55 ? "Security Updates" : new string('c', 120))).ToArray();
        var scan = new WindowsUpdateScan(60, 5, Array.Empty<WindowsUpdateEntry>(), pending);
        var node = Obj(UpdatesTelemetrySectionCollector.Build(false, new WindowsUpdateCacheEntry(scan, Time)));
        Assert.False(node.ContainsKey("pending_items"));
        var items = node["pending"]!["items"]!.AsArray();
        Assert.Equal(50, items.Count);
        Assert.True((bool)node["pending"]!["truncated"]!);
        Assert.Equal("KB55", (string?)items[0]!["kb"]);
        Assert.Equal("Security Updates", (string?)items[0]!["classification"]);
        Assert.Equal(96, ((string)items[5]!["classification"]!).Length);
        Assert.Equal(60, (int)node["pending"]!["count"]!);
    }

    [Fact]
    public void UnknownUpdateClassification_RemainsNull()
    {
        var scan = new WindowsUpdateScan(1, 0, Array.Empty<WindowsUpdateEntry>(), new[] { new WindowsUpdatePending(null, "Unknown", false) });
        var node = Obj(UpdatesTelemetrySectionCollector.Build(null, new WindowsUpdateCacheEntry(scan, Time)));
        Assert.Null(node["pending"]!["items"]![0]!["classification"]);
    }

    [Theory]
    [InlineData(false, "machine")]
    [InlineData(false, "user")]
    [InlineData(true, "machine")]
    [InlineData(true, "user")]
    public void Software_OnlyReportsKnownInstallerTechnologyAndNeverTreatsOwnerAsActor(bool msi, string scope)
    {
        var row = new SoftwareTelemetrySectionCollector.RawSoftware("App", "1", "Publisher", "20261103", "x64", scope, MemberSid, msi);
        var node = Obj(SoftwareTelemetrySectionCollector.Build(new[] { row, row }));
        var entries = node["software"]!.AsArray();
        Assert.Single(entries);
        Assert.False(entries[0]!.AsObject().ContainsKey("installed_by"));
        Assert.False(entries[0]!.AsObject().ContainsKey("profile_path"));
        if (msi)
            Assert.Equal("windows_installer", (string?)entries[0]!["install_source"]);
        else
            Assert.False(entries[0]!.AsObject().ContainsKey("install_source"));
    }

    [Theory]
    [InlineData(0, "public")]
    [InlineData(1, "private")]
    [InlineData(2, "domain")]
    [InlineData(3, "unknown")]
    public void Firewall_MapsExactAdapterIdentityAndReportedCategory(int category, string expected)
    {
        var id = Guid.NewGuid();
        var mapped = FirewallAdapterProfiles.Build(new[] { new FirewallAdapterProfiles.Adapter(id.ToString("B"), "Ethernet") },
            new[] { new FirewallAdapterProfiles.Connection(id, category) });
        var node = Obj(mapped[0]);
        Assert.Equal("Ethernet", (string?)node["adapter_name"]);
        Assert.Equal(expected, (string?)node["profile"]);
        Assert.Equal(expected == "unknown" ? "unavailable" : "ok", (string?)node["status"]);
    }

    [Theory]
    [InlineData("unavailable")]
    [InlineData("mismatch")]
    [InlineData("conflict")]
    public void Firewall_NeverInfersProfileFromAdapterNameOrAmbiguousConnections(string scenario)
    {
        var id = Guid.NewGuid();
        var connections = scenario switch
        {
            "mismatch" => new[] { new FirewallAdapterProfiles.Connection(Guid.NewGuid(), 2) },
            "conflict" => new[] { new FirewallAdapterProfiles.Connection(id, 0), new FirewallAdapterProfiles.Connection(id, 1) },
            _ => null,
        };
        var mapped = FirewallAdapterProfiles.Build(new[] { new FirewallAdapterProfiles.Adapter(id.ToString(), "Domain Private Ethernet") }, connections);
        Assert.Equal("unknown", (string?)Obj(mapped[0])["profile"]);
    }

    [Fact]
    public void Firewall_MappingRetainsNetworkSixteenAdapterLimitAndBoundsNames()
    {
        var mapped = FirewallAdapterProfiles.Build(Enumerable.Range(0, 30)
            .Select(i => new FirewallAdapterProfiles.Adapter(Guid.NewGuid().ToString(), new string('n', 200))), null);
        Assert.Equal(16, mapped.Length);
        Assert.All(mapped, row => Assert.Equal(128, ((string)Obj(row)["adapter_name"]!).Length));
    }

    [Fact]
    public async Task Firewall_OrdinaryLocalReadUsesTheExistingSectionBudget()
    {
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var section = new ServerSectionBudget(new FirewallTelemetrySectionCollector(), TimeProvider.System);
        var node = Obj(await section.CollectAsync(Context(), default));
        if (!node.TryGetPropertyValue("adapter_profiles", out var rows))
        {
            Assert.Equal("unavailable", (string?)node["status"]);
            Console.WriteLine("Ordinary local firewall read: unavailable; no installed-service acceptance.");
            return;
        }
        var mapped = rows!.AsArray();
        Assert.InRange(mapped.Count, 0, 16);
        Assert.All(mapped, row => Assert.Contains((string?)row!["profile"], new[] { "domain", "private", "public", "unknown" }));
        var known = mapped.Count(row => (string?)row!["status"] == "ok");
        Console.WriteLine($"Ordinary local firewall read: adapters={mapped.Count}; known={known}; unknown={mapped.Count - known}; elapsedMs={watch.ElapsedMilliseconds}. No installed-service/backend acceptance.");
    }

    private static AdminGroupChange Parsed(int eventId, string? user, string domain)
    {
        var data = new Dictionary<string, string>
        {
            ["TargetSid"] = SecurityLogEventParser.AdministratorsSid, ["MemberSid"] = MemberSid,
            ["MemberName"] = "CORP\\member", ["SubjectDomainName"] = domain,
        };
        if (user is not null)
            data["SubjectUserName"] = user;
        return Assert.IsType<AdminGroupChange>(SecurityLogEventParser.GroupChange(eventId, Time, data, recordId: 100)!.Detail);
    }

    private static System.Text.Json.Nodes.JsonNode Member(AdminChangeReport changes)
    {
        var read = new LocalAdminsRead(new[] { new LocalAdminMember("CORP\\member", MemberSid, "domain_user") }, 1, false, false);
        return Obj(SecurityLogFields.LocalAdmins(read, changes))["members"]![0]!;
    }
}
