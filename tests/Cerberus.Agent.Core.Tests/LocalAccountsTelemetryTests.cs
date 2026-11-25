using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;
using Cerberus.Agent.App.Commands;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.App.Telemetry.Sections.FailedLogons;
using static Cerberus.Agent.Core.Tests.ServerFactJson;

namespace Cerberus.Agent.Core.Tests;

[Collection("FailedLogonCursor")]
public sealed class LocalAccountsTelemetryTests
{
    private const string Section = AgentSnapshotFactory.LocalAccountsSection;
    private static readonly TimeSpan Guard = TimeSpan.FromSeconds(10);
    private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(0L, null)]
    [InlineData(4294967295L, null)]
    [InlineData(1700000000L, "2023-11-14T22:13:20.0000000Z")]
    public void NativeTimesAreUtcZAndNeverValuesAreNull(long seconds, string? expected)
    {
        Assert.Equal(expected, WindowsLocalUsersProbe.FormatTime(seconds));
        Assert.Null(WindowsLocalUsersProbe.PasswordLastSet(1700000000, uint.MaxValue));
        Assert.Null(WindowsLocalUsersProbe.PasswordLastSet(1700000000, 1700000000));
    }
    [Fact]
    public void PasswordAgeSamplesWithinTheSameMinuteProduceTheSameObservation()
    {
        var first = WindowsLocalUsersProbe.PasswordLastSet(1700000100, 100);
        Assert.Equal("2023-11-14T22:13:00.0000000Z", first);
        Assert.Equal(first, WindowsLocalUsersProbe.PasswordLastSet(1700000101, 100));
        Assert.Equal("2023-11-14T22:14:00.0000000Z", WindowsLocalUsersProbe.PasswordLastSet(1700000140, 100));
    }
    [Fact]
    public void DirectGroupCapUsesTheEntireReturnedListInSortOrder()
    {
        var all = Enumerable.Range(0, 40).Select(i => FormattableString.Invariant($"group-{i:D2}")).Reverse().ToArray();
        var capped = WindowsLocalUsersProbe.SortAndCapDirectGroups(all);
        Assert.Equal(LocalAccountsProbe.MaxDirectGroups, capped.Length);
        Assert.Equal("group-00", capped[0]);
        Assert.Equal("group-31", capped[^1]);
    }
    [Fact]
    public void WindowsNativeReadsReturnConsistentCountsAndX64UserInfoLayout()
    {
        if (!OperatingSystem.IsWindows())
            return;

        if (RuntimeInformation.ProcessArchitecture == Architecture.X64)
            Assert.Equal(184, Marshal.SizeOf<WindowsLocalUsersProbe.UserInfo3>());

        var isDc = LocalAdminsProbe.ReadDomainController();
        Assert.NotNull(isDc);
        var machine = LocalAdminsProbe.MachineSid();
        if (isDc == false)
        {
            var users = WindowsLocalUsersProbe.Read(machine, default).Users;
            Assert.NotNull(users.Count);
            Assert.True(users.Count >= users.Items.Count);
        }

        var group = LocalAdminsProbe.ReadGroup(LocalAdminsProbe.AdministratorsSid, machine, isDc == true,
            LocalAdminsProbe.MaxPrivilegedMembers, default);
        Assert.NotNull(group);
        Assert.True(group.Membership.Total >= group.Membership.Members.Count);
    }
    [Fact]
    public void DomainControllerSkipsUsersButReportsExistingGroupsWithCanonicalIdsAndKinds()
    {
        var machine = new SecurityIdentifier("S-1-5-21-1-2-3");
        var memberSid = new SecurityIdentifier("S-1-5-21-1-2-3-1000");
        var builtinSid = new SecurityIdentifier(LocalAdminsProbe.AdministratorsSid);
        var kinds = new[]
        {
            LocalAdminsProbe.Kind(memberSid, 1, machine),
            LocalAdminsProbe.Kind(builtinSid, 4, machine, true),
            LocalAdminsProbe.Kind(memberSid, 1, machine, true),
            LocalAdminsProbe.Kind(memberSid, 2, machine, true),
            LocalAdminsProbe.Kind(memberSid, 9, machine, true),
        };
        Assert.Equal(new[] { "local_user", "local_group", "domain_user", "domain_group", "unknown" }, kinds);
        var sids = new List<string>();
        var result = Obj(LocalAccountsProbe.Collect(true, () => throw new InvalidOperationException(), sid =>
        {
            sids.Add(sid);
            return sid.EndsWith("-578", StringComparison.Ordinal) ? null :
                Group(kinds.Select(kind => new LocalAdminMember("synthetic-member", memberSid.Value, kind)).ToArray());
        }, default));

        Assert.Equal(new[] { "S-1-5-32-544", "S-1-5-32-555", "S-1-5-32-551", "S-1-5-32-580", "S-1-5-32-547", "S-1-5-32-578" }, sids);
        Assert.Equal("domain_controller", (string?)result["status"]);
        AssertEmptyUsers(result);
        Assert.Equal(new[] { "administrators", "remote_desktop_users", "backup_operators", "remote_management_users", "power_users" },
            result["privileged_groups"]!.AsArray().Select(group => (string?)group!["id"]));
        var admin = result["privileged_groups"]![0]!;
        Assert.Equal("Synthetic group", (string?)admin["name"]);
        Assert.Equal(kinds, admin["members"]!.AsArray().Select(member => (string?)member!["kind"]));
    }
    [Fact]
    public async Task DeniedConsentSkipsReadAndFailureReturnsUnavailableWithFullShape()
    {
        var calls = 0;
        object Fail(WindowsTelemetryContext _, CancellationToken __)
        {
            calls++;
            throw new InvalidOperationException("synthetic failure");
        }

        AssertUnavailable(Obj(await new LocalAccountsTelemetrySectionCollector(() => false, Fail).CollectAsync(Context(), default)));
        Assert.Equal(0, calls);
        AssertUnavailable(Obj(await new LocalAccountsTelemetrySectionCollector(() => true, Fail).CollectAsync(Context(), default)));
        Assert.Equal(1, calls);
    }
    [Fact]
    public void AFailedProbeKeepsObservedFactsAndCounts()
    {
        var user = User("synthetic-user");
        var read = new LocalAccountUserRead(new LocalAccountUsers(501, true, [user]), false);
        var section = Obj(LocalAccountsProbe.Collect(false, () => read, sid => sid switch
        {
            LocalAdminsProbe.AdministratorsSid => new LocalGroupRead("Synthetic group",
                new LocalAdminsRead([new LocalAdminMember("synthetic-member", user.Sid, "local_user")], 201, true, false)),
            "S-1-5-32-555" => throw new InvalidOperationException("synthetic failure"),
            "S-1-5-32-551" => new LocalGroupRead("Incomplete synthetic group", new LocalAdminsRead([], 0, false, true)),
            _ => null,
        }, default));
        Assert.Equal("partial", (string?)section["status"]);
        Assert.Equal(501, (int?)section["users"]!["count"]);
        Assert.True((bool?)section["users"]!["truncated"]);
        var row = Assert.Single(section["users"]!["items"]!.AsArray())!;
        Assert.Null(row["locked"]);
        Assert.Null(row["password_last_set_utc"]);
        var group = Assert.Single(section["privileged_groups"]!.AsArray())!;
        Assert.Equal(201, (int?)group["count"]);
        Assert.True((bool?)group["truncated"]);

        var incompleteUsers = read with { Users = read.Users with { Count = null }, Incomplete = true };
        var partial = Obj(LocalAccountsProbe.Collect(false, () => incompleteUsers, _ => null, default));
        Assert.Equal("partial", (string?)partial["status"]);
        Assert.Null(partial["users"]!["count"]);
        Assert.Single(partial["users"]!["items"]!.AsArray());

        var sanitized = LocalAccountsProbe.CleanText("a\0\uD800" + new string('b', 253) + "\U0001F600");
        Assert.Equal(255, sanitized.Length);
        Assert.DoesNotContain('\0', sanitized);
        Assert.DoesNotContain(sanitized, char.IsSurrogate);
    }

    [Fact]
    public async Task OverlappingAccountWaitersShareTheReadAfterAnotherWaiterTimesOut()
    {
        var time = new ManualTimeProvider(T0);
        using var release = new ManualResetEventSlim();
        var began = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        var blocked = new LocalAccountsTelemetrySectionCollector(() => true, (_, _) =>
        {
            Interlocked.Increment(ref calls);
            began.TrySetResult();
            release.Wait(Guard);
            return EmptyRead();
        });
        var context = Context();
        var run = new ServerSectionBudget(blocked, time).CollectAsync(context, default).AsTask();
        Task<object> follower1;
        Task<object> follower2;
        try
        {
            await began.Task.WaitAsync(Guard);
            await WaitFor(() => time.ActiveDueTimes().Contains(T0 + ServerSectionBudget.SectionBudget));
            follower1 = blocked.CollectAsync(Context(), default).AsTask();
            follower2 = blocked.CollectAsync(Context(), default).AsTask();
            Assert.False(follower1.IsCompleted);
            Assert.False(follower2.IsCompleted);
            time.Advance(ServerSectionBudget.SectionBudget);
            AssertUnavailable(Obj(await run.WaitAsync(Guard)));
            Assert.False(follower1.IsCompleted);
            Assert.False(follower2.IsCompleted);
            Assert.Equal(1, calls);

            time.Advance(ServerSectionBudget.TotalBudget);
            AssertUnavailable(Obj(await new ServerSectionBudget(blocked, time).CollectAsync(context, default)));
            Assert.Equal(1, calls);
        }
        finally
        {
            release.Set();
        }

        var result = await follower1.WaitAsync(Guard);
        Assert.Same(result, await follower2.WaitAsync(Guard));
        Assert.Equal("ok", (string?)Obj(result)["status"]);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task OverlappingAdministratorsWaitersShareNativeDataAndKeepTheLegacyProjection()
    {
        using var release = new ManualResetEventSlim();
        using var cancelFirst = new CancellationTokenSource();
        var began = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var calls = 0;
        var member = new LocalAdminMember("synthetic-member", User("synthetic-user").Sid, "local_user");
        var native = Group(Enumerable.Repeat(member, 150).ToArray());
        var reads = new LocalAdminsProbe.ServerAdminRead((_, _) =>
        {
            Interlocked.Increment(ref calls);
            began.TrySetResult();
            release.Wait(Guard);
            return native;
        });
        var context = Context();
        var first = reads.ReadAdminsAsync(context, cancelFirst.Token);
        Task<LocalAdminsRead> follower1;
        Task<LocalAdminsRead> follower2;
        Task<LocalGroupRead?> inventory;
        try
        {
            await began.Task.WaitAsync(Guard);
            follower1 = reads.ReadAdminsAsync(context, default);
            follower2 = reads.ReadAdminsAsync(Context(), default);
            inventory = reads.ReadGroupAsync(context, default);
            Assert.False(follower1.IsCompleted);
            Assert.False(follower2.IsCompleted);
            Assert.False(inventory.IsCompleted);
            cancelFirst.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first.WaitAsync(Guard));
            Assert.Equal(1, calls);
        }
        finally
        {
            release.Set();
        }

        Assert.Same(native, await inventory.WaitAsync(Guard));
        var changes = new AdminChangeReport("ok", null);
        var result = Obj(SecurityLogFields.LocalAdmins(await follower1.WaitAsync(Guard), changes));
        var overlap = Obj(SecurityLogFields.LocalAdmins(await follower2.WaitAsync(Guard), changes));
        Assert.True(JsonNode.DeepEquals(result, overlap));
        Assert.Equal("ok", (string?)result["status"]);
        Assert.Equal(150, (int?)result["count"]);
        Assert.Equal(LocalAdminsProbe.MaxMembers, result["members"]!.AsArray().Count);
        Assert.True((bool?)result["truncated"]);
        Assert.Equal(1, calls);
    }
    [Fact]
    public async Task WorstCaseSectionFitsWithTruthfulCountsAndCompleteNestedObjects()
    {
        var result = await AccountsCollector(WorstCase()).CollectAsync(Context(), default);
        var section = Obj(result);
        Assert.True(AgentTelemetryLimits.EstimateJsonBytes(result) <= ServerSnapshotFit.LocalAccountsMaxBytes);
        AssertTruncatedAccounts(section, LocalAccountsProbe.MaxUsers, LocalAdminsProbe.MaxPrivilegedMembers);
    }

#if CERBERUS_SERVER_PROFILE
    [Theory]
    [InlineData(false, false, true)]
    [InlineData(true, false, false)]
    [InlineData(true, true, true)]
    public async Task PrimaryPeriodicSnapshotAdmitsAccountsOnlyUnderAnApplicableAdvertisement(bool advertised,
        bool includesAccounts, bool expected)
    {
        var catalog = WindowsTelemetrySectionCatalog.CreateDefault(null, false, AccountsCollector(EmptyRead()))
            .Where(section => section.SectionName is "clock" or Section).ToArray();
        var heartbeat = advertised ? AdvertisedHeartbeat(includesAccounts ? ["clock", Section] : ["clock"]) : null;
        var snapshot = await new WindowsTelemetryCollector(catalog).BuildSnapshotAsync(Metadata(), heartbeat, default);
        var accepted = AgentSnapshotFactory.SnapshotSectionsFor(heartbeat?.SnapshotSections);
        var outgoing = AgentSnapshotFactory.ForSections(snapshot, accepted);
        Assert.Equal(expected, snapshot.Sections.ContainsKey(Section));
        Assert.Equal(expected, outgoing.Sections.ContainsKey(Section));
        if (expected)
        {
            Assert.Equal("ok", (string?)Obj(outgoing.Sections[Section]!)["status"]);
            Assert.Equal(AgentSnapshotFactory.HashSection(outgoing.Sections[Section]), outgoing.SectionHashes[Section]);
        }
    }

    [Fact]
    public async Task SecondaryPeriodicSnapshotRetainsCanonicalUnavailableOnCollectionFailure()
    {
        var catalog = WindowsTelemetrySectionCatalog.CreateSignedFacts(localAccounts:
            new LocalAccountsTelemetrySectionCollector(() => true, (_, _) => throw new InvalidOperationException()));
        var accountsOnly = catalog.Where(section => section.SectionName == Section).ToArray();
        var snapshot = await new WindowsTelemetryCollector(accountsOnly, signedFacts: true)
            .BuildSnapshotAsync(Metadata(), null, default);
        var accepted = AgentSnapshotFactory.SnapshotSectionsFor(null, signedFacts: true);
        var outgoing = AgentSnapshotFactory.ForSections(snapshot, accepted);
        AssertUnavailable(Obj(outgoing.Sections[Section]!));
        Assert.Equal(AgentSnapshotFactory.HashSection(outgoing.Sections[Section]), outgoing.SectionHashes[Section]);
    }
    [Fact]
    public async Task WildcardFactsFitsAccountInventoryAndExplicitRequestOmitsIt()
    {
        const int siblingBytes = 210_000;
        var catalog = WindowsTelemetrySectionCatalog.CreateSignedFacts(localAccounts: AccountsCollector(WorstCase()));
        var sections = catalog.Where(section => section.SectionName is Section or "clock").ToList();
        sections.Add(new StubSection("runtime", _ => ValueTask.FromResult<object>(new { info = new string('x', siblingBytes) })));
        var handler = new CollectFactsCommandHandler(Metadata(), sections, TimeProvider.System);
        using var wildcard = JsonDocument.Parse("{}");
        var wildcardResult = await handler.HandleAsync(new AgentCommand("synthetic", handler.Type, "wildcard", wildcard.RootElement), default);
        Assert.Equal("DONE", wildcardResult.Status);
        var post = Obj(wildcardResult.PostVerify!);
        var fitted = post["sections"]![Section]!.AsObject();
        AssertTruncatedAccounts(fitted, LocalAccountsProbe.MaxUsers, LocalAdminsProbe.MaxPrivilegedMembers);
        Assert.True(AgentTelemetryLimits.EstimateJsonBytes(fitted) < CollectFactsCommandHandler.MaxResultBytes - siblingBytes);
        Assert.Equal(siblingBytes, ((string?)post["sections"]!["runtime"]!["info"])!.Length);
        Assert.Equal(AgentSnapshotFactory.HashSection(fitted), (string?)post["section_hashes"]![Section]);

        Assert.DoesNotContain(Section, EnvelopeTypes.ServerFactSections);
        using var explicitList = JsonDocument.Parse("{\"sections\":[\"clock\"]}");
        var explicitResult = await handler.HandleAsync(new AgentCommand("synthetic", handler.Type, "explicit", explicitList.RootElement), default);
        Assert.Equal("DONE", explicitResult.Status);
        Assert.Equal("clock", Assert.Single(Obj(explicitResult.PostVerify!)["sections"]!.AsObject()).Key);
    }

    [Fact]
    public void SnapshotSizeFitRehashesAndPreservesEmptyAccountsWhenNoListsCanShrink()
    {
        var payload = new Dictionary<string, object?> { [Section] = WorstCase(), ["clock"] = new { status = "ok" } };
        var fitted = AgentSnapshotFactory.Create(Metadata(), T0, payload, maxBytes: 16 * 1024);
        AssertTruncatedAccounts(Obj(fitted.Sections[Section]!), LocalAccountsProbe.MaxUsers, LocalAdminsProbe.MaxPrivilegedMembers);
        Assert.Equal(AgentSnapshotFactory.HashSection(fitted.Sections[Section]), fitted.SectionHashes[Section]);

        var emptyAccounts = LocalAccountsProbe.Collect(false,
            () => new LocalAccountUserRead(new LocalAccountUsers(0, false, []), false),
            _ => Group([]), default);
        var runtime = new { info = new string('x', 1024) };
        var emptySnapshot = AgentSnapshotFactory.Create(Metadata(), T0, new Dictionary<string, object?>
        {
            [Section] = emptyAccounts,
            ["runtime"] = runtime,
        });
        var downgraded = AgentSnapshotFactory.Create(Metadata(), T0, new Dictionary<string, object?>
        {
            [Section] = AgentSnapshotFactory.UnavailableLocalAccounts,
            ["runtime"] = runtime,
        });
        var budget = AgentTelemetryLimits.EstimateJsonBytes(downgraded);
        Assert.True(AgentTelemetryLimits.EstimateJsonBytes(emptySnapshot) > budget);
        Assert.False(ServerSnapshotFit.TryHalve(emptySnapshot.Sections, out var unchanged));
        Assert.Same(emptySnapshot.Sections, unchanged);
        Assert.Same(emptyAccounts, unchanged[Section]);
        var error = Assert.Throws<InvalidOperationException>(() => AgentSnapshotFactory.Fit(emptySnapshot, budget));
        Assert.StartsWith("Agent telemetry payload too large:", error.Message);
    }

    [Fact]
    public async Task LargeSoftwareIsFittedBeforeSmallAccountsInBothWireBodies()
    {
        var accounts = LocalAccountsProbe.Collect(false,
            () => new LocalAccountUserRead(new LocalAccountUsers(1, false, [User("synthetic-user")]), false),
            _ => null, default);
        const int softwareCount = 300;
        var software = new { truncated = false, software = Enumerable.Repeat(new string('x', 1024), softwareCount).ToArray() };
        var hash = AgentSnapshotFactory.HashSection(accounts);
        var snapshot = AgentSnapshotFactory.Create(Metadata(), T0, new Dictionary<string, object?>
        {
            [Section] = accounts,
            ["software"] = software,
        });
        Assert.Equal(hash, snapshot.SectionHashes[Section]);
        Assert.Equal(hash, AgentSnapshotFactory.HashSection(snapshot.Sections[Section]));
        Assert.True((bool?)Obj(snapshot.Sections["software"]!)["truncated"]);

        var catalog = WindowsTelemetrySectionCatalog.CreateSignedFacts(localAccounts: AccountsCollector(accounts));
        var sections = catalog.Where(section => section.SectionName == Section).ToList();
        sections.Add(new StubSection("software", _ => ValueTask.FromResult<object>(software)));
        var handler = new CollectFactsCommandHandler(Metadata(), sections, TimeProvider.System);
        using var wildcard = JsonDocument.Parse("{}");
        var result = await handler.HandleAsync(new AgentCommand("synthetic", handler.Type, "wildcard", wildcard.RootElement), default);
        Assert.Equal("DONE", result.Status);
        var post = Obj(result.PostVerify!);
        Assert.Equal(hash, (string?)post["section_hashes"]![Section]);
        Assert.Equal(hash, AgentSnapshotFactory.HashSection(post["sections"]![Section]));
        Assert.True((bool?)post["sections"]!["software"]!["truncated"]);
    }
#else
    [Fact]
    public async Task DesktopCatalogAndSnapshotNeverCollectOrSendAccountInventory()
    {
        var catalog = WindowsTelemetrySectionCatalog.CreateDefault("clock," + Section, false,
            new LocalAccountsTelemetrySectionCollector(() => throw new InvalidOperationException()));
        Assert.DoesNotContain(catalog, section => section.SectionName == Section);
        Assert.DoesNotContain(WindowsTelemetrySectionCatalog.CreateSignedFacts(), section => section.SectionName == Section);
        var heartbeat = AdvertisedHeartbeat("clock", Section);
        var snapshot = await new WindowsTelemetryCollector(catalog).BuildSnapshotAsync(Metadata(), heartbeat, default);
        Assert.DoesNotContain(Section, snapshot.Sections.Keys);
        var staged = snapshot with { Sections = new Dictionary<string, object?> { [Section] = EmptyRead() } };
        foreach (var signedFacts in new[] { false, true })
        {
            var accepted = AgentSnapshotFactory.SnapshotSectionsFor(heartbeat.SnapshotSections, signedFacts);
            Assert.DoesNotContain(Section, AgentSnapshotFactory.ForSections(staged, accepted).Sections.Keys);
        }
        Assert.Throws<InvalidOperationException>(() => AgentSnapshotFactory.Create(Metadata(), T0, staged.Sections));
    }
#endif

    private static LocalGroupRead Group(IReadOnlyList<LocalAdminMember> members)
        => new("Synthetic group", new LocalAdminsRead(members, members.Count, false, false));
    private static LocalAccountItem User(string name)
        => new(name, "S-1-5-21-1-2-3-1000", true, null, null, null, []);
    private static object EmptyRead() => LocalAccountsProbe.Collect(false,
        () => new LocalAccountUserRead(new LocalAccountUsers(0, false, []), false), _ => null, default);
    private static object WorstCase()
    {
        var text = new string('\u4E00', 256);
        var user = User(text) with { Groups = Enumerable.Repeat(text, LocalAccountsProbe.MaxDirectGroups).ToArray() };
        var users = new LocalAccountUsers(LocalAccountsProbe.MaxUsers, false, Enumerable.Repeat(user, LocalAccountsProbe.MaxUsers).ToArray());
        var members = Enumerable.Repeat(new LocalAdminMember(text, user.Sid, "local_user"), LocalAdminsProbe.MaxPrivilegedMembers).ToArray();
        var group = new LocalGroupRead(text, Group(members).Membership);
        return LocalAccountsProbe.Collect(false, () => new LocalAccountUserRead(users, false), _ => group, default);
    }
    private static LocalAccountsTelemetrySectionCollector AccountsCollector(object result) => new(() => true, (_, _) => result);
    private static void AssertUnavailable(JsonObject section)
    {
        Assert.Equal("unavailable", (string?)section["status"]);
        AssertEmptyUsers(section);
        Assert.Empty(section["privileged_groups"]!.AsArray());
    }
    private static void AssertEmptyUsers(JsonObject section)
    {
        var users = section["users"]!.AsObject();
        Assert.True(users.ContainsKey("count"));
        Assert.Null(users["count"]);
        Assert.False((bool?)users["truncated"]);
        Assert.Empty(users["items"]!.AsArray());
    }
    private static void AssertTruncatedAccounts(JsonObject section, int usersCount, int groupCount)
    {
        Assert.Equal("partial", (string?)section["status"]);
        var users = section["users"]!;
        Assert.Equal(usersCount, (int?)users["count"]);
        Assert.True((bool?)users["truncated"]);
        Assert.True(users["items"]!.AsArray().Count < usersCount);
        var groups = section["privileged_groups"]!.AsArray();
        Assert.Equal(6, groups.Count);
        Assert.All(groups, group =>
        {
            Assert.Equal(groupCount, (int?)group!["count"]);
            Assert.True((bool?)group["truncated"]);
            Assert.True(group["members"]!.AsArray().Count < groupCount);
        });
    }

    private static async Task WaitFor(Func<bool> condition)
    {
        using var timeout = new CancellationTokenSource(Guard);
        while (!condition())
            await Task.Delay(10, timeout.Token);
    }
}

#if CERBERUS_SERVER_PROFILE
[CollectionDefinition("LocalAccountsOperatorEnvironment", DisableParallelization = true)]
public sealed class LocalAccountsOperatorEnvironmentCollection { }

[Collection("LocalAccountsOperatorEnvironment")]
public sealed class LocalAccountsOperatorEnvironmentTests
{
    [Theory]
    [InlineData("clock")]
    [InlineData("unknown_section")]
    [InlineData("local_accounts")]
    public async Task OperatorAllowlistSuppressesPeriodicAccountsAndKeepsWildcardFacts(string configured)
    {
        const string section = AgentSnapshotFactory.LocalAccountsSection;
        var variable = AgentSnapshotFactory.SnapshotSectionAllowlistEnv;
        var previous = Environment.GetEnvironmentVariable(variable);
        try
        {
            Environment.SetEnvironmentVariable(variable, configured);
            Assert.DoesNotContain(WindowsTelemetrySectionCatalog.CreateDefault(), item => item.SectionName == section);

            var catalog = WindowsTelemetrySectionCatalog.CreateSignedFacts(localAccounts:
                new LocalAccountsTelemetrySectionCollector(() => true, (_, _) => AgentSnapshotFactory.UnavailableLocalAccounts));
            var sections = catalog.Where(item => item.SectionName is "clock" or section).ToArray();
            var secondary = new WindowsTelemetryCollector(sections, signedFacts: true);
            var heartbeat = AdvertisedHeartbeat("clock", section);
            var snapshot = await secondary.BuildSnapshotAsync(Metadata(), heartbeat, default);
            Assert.Equal("clock", Assert.Single(snapshot.Sections).Key);
            Assert.DoesNotContain(section, AgentSnapshotFactory.SnapshotSectionsFor(null, signedFacts: true));

            var handler = new CollectFactsCommandHandler(Metadata(), sections, TimeProvider.System);
            using var wildcard = JsonDocument.Parse("{}");
            var result = await handler.HandleAsync(new AgentCommand("synthetic", handler.Type, "wildcard", wildcard.RootElement), default);
            Assert.Equal("DONE", result.Status);
            Assert.Equal("unavailable", (string?)Obj(result.PostVerify!)["sections"]![section]!["status"]);
        }
        finally
        {
            Environment.SetEnvironmentVariable(variable, previous);
        }
    }
}
#endif
