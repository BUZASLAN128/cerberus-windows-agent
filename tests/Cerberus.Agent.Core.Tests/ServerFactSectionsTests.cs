using System.ServiceProcess;
using System.Text;
using System.Text.Json.Nodes;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.Core;
using static Cerberus.Agent.Core.Tests.ServerFactJson;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Server fact sections (contract section e): shape, caps, sorting, forbidden fields, budget, cache.</summary>
public sealed partial class ServerFactSectionsTests
{
    private static readonly DateTimeOffset T0 = new(2026, 3, 1, 12, 0, 0, TimeSpan.Zero);
    private static readonly string[] SixSections = { "sessions", "hardware", "services", "listening_ports", "updates", "software" };

    private static string[] Keys(JsonNode? node) => ((JsonObject)node!).Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal).ToArray();

    private static string[] Sorted(params string[] names) => names.OrderBy(k => k, StringComparer.Ordinal).ToArray();

    private static string Fill(string prefix, int length) => prefix.PadRight(length, 'x');

    // ---- sessions --------------------------------------------------------------------------------------------

    [Fact]
    public void Sessions_ShapeSortingExclusionAndCleaning()
    {
        var raw = new[]
        {
            new SessionsTelemetrySectionCollector.RawSession("CORP", "bob", "disconnected", "rdp", T0),
            new SessionsTelemetrySectionCollector.RawSession("CORP", "Alice", "active", "rdp", new DateTimeOffset(2026, 3, 1, 15, 4, 5, TimeSpan.FromHours(3))),
            new SessionsTelemetrySectionCollector.RawSession("CORP", "Alice", "active", "console", null),
            new SessionsTelemetrySectionCollector.RawSession(null, "local\u0000\tuser", "idle", "other", null),
            new SessionsTelemetrySectionCollector.RawSession(null, "  ", "active", "console", null),
            new SessionsTelemetrySectionCollector.RawSession(null, null, "active", "console", null),
        };

        var node = Obj(SessionsTelemetrySectionCollector.Build(raw));

        Assert.Equal(Sorted("status", "session_count", "active_count", "disconnected_count", "truncated", "sessions", "rds_licensing", "rdp_posture"), Keys(node));
        Assert.Equal("unavailable", (string)node["rds_licensing"]!["status"]!);
        Assert.Equal(4, (int)node["session_count"]!);
        Assert.Equal(2, (int)node["active_count"]!);
        Assert.Equal(1, (int)node["disconnected_count"]!);
        Assert.False((bool)node["truncated"]!);

        var sessions = node["sessions"]!.AsArray();
        Assert.Equal(new[] { "CORP\\Alice", "CORP\\Alice", "CORP\\bob", "localuser" }, sessions.Select(s => (string)s!["user"]!));
        Assert.Equal(new[] { "console", "rdp" }, sessions.Take(2).Select(s => (string)s!["kind"]!));
        Assert.Equal(Sorted("user", "state", "kind", "logon_time_utc"), Keys(sessions[0]));
        Assert.Null(sessions[0]!["logon_time_utc"]);
        Assert.Equal("2026-03-01T12:04:05Z", (string)sessions[1]!["logon_time_utc"]!);
    }

    [Fact]
    public void Sessions_CapsListUserLengthAndCutsOnScalarBoundary()
    {
        var many = Enumerable.Range(0, 70)
            .Select(i => new SessionsTelemetrySectionCollector.RawSession("D", $"u{i:D3}", "active", "rdp", null));
        var capped = Obj(SessionsTelemetrySectionCollector.Build(many));
        Assert.Equal(64, capped["sessions"]!.AsArray().Count);
        Assert.Equal(70, (int)capped["session_count"]!);
        Assert.True((bool)capped["truncated"]!);

        var emoji = string.Concat(Enumerable.Repeat("\U0001F600", 200));
        var user = (string)Obj(SessionsTelemetrySectionCollector.Build(new[]
            { new SessionsTelemetrySectionCollector.RawSession("D", emoji, "active", "rdp", null) }))["sessions"]![0]!["user"]!;
        Assert.Equal(104, user.EnumerateRunes().Count());
        _ = new UTF8Encoding(false, true).GetBytes(user);
    }

    [Theory]
    [InlineData(0, "active")]
    [InlineData(4, "disconnected")]
    [InlineData(5, "idle")]
    [InlineData(1, "other")]
    [InlineData(9, "other")]
    public void Sessions_StateMapping(int wts, string expected) => Assert.Equal(expected, SessionsNative.MapState(wts));

    [Theory]
    [InlineData(0, "console")]
    [InlineData(2, "rdp")]
    [InlineData(1, "other")]
    public void Sessions_KindMapping(int protocol, string expected) => Assert.Equal(expected, SessionsNative.MapKind(protocol));

    // ---- services --------------------------------------------------------------------------------------------

    [Fact]
    public void Services_ShapeSortingAndCaps()
    {
        var node = Obj(ServicesTelemetrySectionCollector.Build(new[]
        {
            new ServicesTelemetrySectionCollector.RawService("zeta", "Zeta", "running", "auto"),
            new ServicesTelemetrySectionCollector.RawService("Alpha", Fill("D", 300), "stopped", "auto_delayed"),
            new ServicesTelemetrySectionCollector.RawService("beta\u0007", "B", "paused", "manual"),
            new ServicesTelemetrySectionCollector.RawService(Fill("n", 90), "long", "other", "disabled"),
            new ServicesTelemetrySectionCollector.RawService("  ", "blank", "running", "auto"),
        }));

        Assert.Equal(Sorted("status", "service_count", "truncated", "services"), Keys(node));
        var services = node["services"]!.AsArray();
        Assert.Equal(new[] { "Alpha", "beta", Fill("n", 64), "zeta" }, services.Select(s => (string)s!["name"]!));
        Assert.Equal(Sorted("name", "display_name", "state", "start_type"), Keys(services[0]));
        Assert.Equal(128, ((string)services[0]!["display_name"]!).Length);
        Assert.Equal(4, (int)node["service_count"]!);
        Assert.False((bool)node["truncated"]!);

        var over = Obj(ServicesTelemetrySectionCollector.Build(Enumerable.Range(0, 401)
            .Select(i => new ServicesTelemetrySectionCollector.RawService($"s{i:D4}", "d", "running", "auto"))));
        Assert.Equal(400, over["services"]!.AsArray().Count);
        Assert.Equal(401, (int)over["service_count"]!);
        Assert.True((bool)over["truncated"]!);
        Assert.Equal("s0399", (string)over["services"]![399]!["name"]!);
    }

    [Fact]
    public void Services_PerUserInstancesAreDroppedBeforeTheCap()
    {
        // 0x10 own process, 0x40 user-service template (kept), 0xD0 = 0x10|0x40|0x80 per-logon instance (dropped).
        var raw = new List<ServicesTelemetrySectionCollector.RawService>
        {
            new("Spooler", "Spooler", "running", "auto", 0x10),
            new("CDPUserSvc", "template", "stopped", "manual", 0x50),
            new("CDPUserSvc_1a2b3", "instance", "running", "auto", 0xD0),
            new("OneSyncSvc_9f", "instance", "running", "auto", 0x80),
        };
        raw.AddRange(Enumerable.Range(0, 400).Select(i => new ServicesTelemetrySectionCollector.RawService($"a{i:D4}", "d", "running", "auto", 0xD0)));

        var node = Obj(ServicesTelemetrySectionCollector.Build(raw));

        Assert.Equal(new[] { "CDPUserSvc", "Spooler" }, node["services"]!.AsArray().Select(s => (string)s!["name"]!));
        Assert.Equal(2, (int)node["service_count"]!);
        Assert.False((bool)node["truncated"]!);
    }

    [Theory]
    [InlineData(ServiceControllerStatus.Running, "running")]
    [InlineData(ServiceControllerStatus.Stopped, "stopped")]
    [InlineData(ServiceControllerStatus.StartPending, "start_pending")]
    [InlineData(ServiceControllerStatus.StopPending, "stop_pending")]
    [InlineData(ServiceControllerStatus.Paused, "paused")]
    [InlineData(ServiceControllerStatus.ContinuePending, "other")]
    public void Services_StateMapping(ServiceControllerStatus status, string expected)
        => Assert.Equal(expected, ServicesTelemetrySectionCollector.MapState(status));

    // ---- listening ports -------------------------------------------------------------------------------------

    [Fact]
    public void ListeningPorts_ShapeSortingDuplicatesAndCaps()
    {
        var node = Obj(ListeningPortsTelemetrySectionCollector.Build(new[]
        {
            new ListeningPortsTelemetrySectionCollector.RawPort("udp", "ipv4", 53, "any", "dns"),
            new ListeningPortsTelemetrySectionCollector.RawPort("tcp", "ipv6", 443, "any", "web"),
            new ListeningPortsTelemetrySectionCollector.RawPort("tcp", "ipv4", 443, "any", "web"),
            new ListeningPortsTelemetrySectionCollector.RawPort("tcp", "ipv4", 443, "any", "web"),
            new ListeningPortsTelemetrySectionCollector.RawPort("tcp", "ipv4", 80, "loopback", Fill("p", 100)),
            new ListeningPortsTelemetrySectionCollector.RawPort("tcp", "ipv4", 22, "specific", null),
        }));

        Assert.Equal(Sorted("status", "port_count", "truncated", "ports"), Keys(node));
        var ports = node["ports"]!.AsArray();
        Assert.Equal(5, (int)node["port_count"]!);
        Assert.Equal(new[] { "tcp/22/ipv4", "tcp/80/ipv4", "tcp/443/ipv4", "tcp/443/ipv6", "udp/53/ipv4" },
            ports.Select(p => $"{(string)p!["protocol"]!}/{(int)p["port"]!}/{(string)p["family"]!}"));
        Assert.Equal(Sorted("protocol", "family", "port", "bind_scope", "process_name"), Keys(ports[0]));
        Assert.Null(ports[0]!["process_name"]);
        Assert.Equal(64, ((string)ports[1]!["process_name"]!).Length);

        var over = Obj(ListeningPortsTelemetrySectionCollector.Build(Enumerable.Range(1, 300)
            .Select(i => new ListeningPortsTelemetrySectionCollector.RawPort("tcp", "ipv4", i, "any", null))));
        Assert.Equal(256, over["ports"]!.AsArray().Count);
        Assert.Equal(300, (int)over["port_count"]!);
        Assert.True((bool)over["truncated"]!);
    }

    [Theory]
    [InlineData(new byte[] { 0, 0, 0, 0 }, "any")]
    [InlineData(new byte[] { 127, 0, 0, 1 }, "loopback")]
    [InlineData(new byte[] { 127, 9, 9, 9 }, "loopback")]
    [InlineData(new byte[] { 10, 0, 0, 5 }, "specific")]
    [InlineData(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, "any")]
    [InlineData(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, "loopback")]
    [InlineData(new byte[] { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, "specific")]
    public void ListeningPorts_BindScope(byte[] address, string expected) => Assert.Equal(expected, PortsNative.BindScope(address));

    // ---- software --------------------------------------------------------------------------------------------

    [Fact]
    public void Software_ShapeSortingDuplicatesAndCaps()
    {
        var node = Obj(SoftwareTelemetrySectionCollector.Build(new[]
        {
            new SoftwareTelemetrySectionCollector.RawSoftware("beta", "2.0", "P", "20240229", "x64"),
            new SoftwareTelemetrySectionCollector.RawSoftware("Alpha", "10.0", "P", null, "x86"),
            new SoftwareTelemetrySectionCollector.RawSoftware("alpha", "2.0", null, "bad", "x64"),
            new SoftwareTelemetrySectionCollector.RawSoftware("beta", "2.0", "P", "20240229", "x64"),
            new SoftwareTelemetrySectionCollector.RawSoftware(Fill("n", 200), Fill("v", 100), Fill("p", 200), null, "x64"),
            new SoftwareTelemetrySectionCollector.RawSoftware("", "1", "P", null, "x64"),
        }));

        Assert.Equal(Sorted("status", "software_count", "truncated", "software"), Keys(node));
        var list = node["software"]!.AsArray();
        Assert.Equal(4, (int)node["software_count"]!);
        Assert.Equal(new[] { "Alpha", "alpha", "beta" }, list.Take(3).Select(s => (string)s!["name"]!));
        Assert.Equal(Sorted("name", "version", "publisher", "installed_on", "arch"), Keys(list[0]));
        Assert.Equal("2024-02-29", (string)list[2]!["installed_on"]!);
        Assert.Null(list[1]!["publisher"]);
        Assert.Null(list[1]!["installed_on"]);
        Assert.Equal((128, 64, 128), (((string)list[3]!["name"]!).Length, ((string)list[3]!["version"]!).Length, ((string)list[3]!["publisher"]!).Length));

        var over = Obj(SoftwareTelemetrySectionCollector.Build(Enumerable.Range(0, 501)
            .Select(i => new SoftwareTelemetrySectionCollector.RawSoftware($"app{i:D4}", "1", null, null, "x64"))));
        Assert.Equal(500, over["software"]!.AsArray().Count);
        Assert.Equal(501, (int)over["software_count"]!);
        Assert.True((bool)over["truncated"]!);
    }

    [Theory]
    [InlineData("20240229", "2024-02-29")]
    [InlineData("20240230", null)]
    [InlineData("2024-02-29", null)]
    [InlineData(null, null)]
    public void Software_InstallDateParsing(string? input, string? expected) => Assert.Equal(expected, SoftwareTelemetrySectionCollector.ParseInstallDate(input));

    [Theory]
    [InlineData("KB5001234", null, false, true)]
    [InlineData("{GUID}", "Security Update", false, true)]
    [InlineData("{GUID}", "Hotfix", false, true)]
    [InlineData("{GUID}", null, true, true)]
    [InlineData("{GUID}", "Application", false, false)]
    [InlineData("Contoso", null, false, false)]
    public void Software_UpdateEntriesAreSkipped(string key, string? release, bool hasParent, bool expected)
        => Assert.Equal(expected, SoftwareTelemetrySectionCollector.IsUpdateEntry(key, release, hasParent));

    // ---- updates ---------------------------------------------------------------------------------------------

    [Fact]
    public void Updates_ShapeRecentOrderAndCaps()
    {
        var recent = Enumerable.Range(0, 25)
            .Select(i => new WindowsUpdateEntry($"KB{i:D7}", $"Update {i:D2}", T0.AddDays(-i)))
            .Append(new WindowsUpdateEntry(null, Fill("T", 300), null))
            .Append(new WindowsUpdateEntry(Fill("K", 40), "kb long", T0.AddDays(1)))
            .ToArray();
        var node = Obj(UpdatesTelemetrySectionCollector.Build(true, new WindowsUpdateCacheEntry(new WindowsUpdateScan(3, 1, recent), T0)));

        Assert.Equal(Sorted("status", "reboot_required", "recent", "pending"), Keys(node));
        Assert.True((bool)node["reboot_required"]!);
        var list = node["recent"]!.AsArray();
        Assert.Equal(20, list.Count);
        Assert.Equal(Fill("K", 16), (string)list[0]!["kb"]!);
        Assert.Equal("Update 00", (string)list[1]!["title"]!);
        Assert.Equal(Sorted("kb", "title", "installed_utc"), Keys(list[0]));
        Assert.Equal("2026-03-01T12:00:00Z", (string)list[1]!["installed_utc"]!);
        Assert.All(list, e => Assert.True(((string)e!["title"]!).Length <= 160));

        var pending = node["pending"]!;
        Assert.Equal(Sorted("status", "count", "security_count", "checked_at_utc"), Keys(pending));
        Assert.Equal("ok", (string)pending["status"]!);
        Assert.Equal((3, 1), ((int)pending["count"]!, (int)pending["security_count"]!));
        Assert.Equal("2026-03-01T12:00:00Z", (string)pending["checked_at_utc"]!);
    }

    [Fact]
    public void Updates_UndatedEntriesSortLastAndRebootStaysNullable()
    {
        var scan = new WindowsUpdateScan(0, 0, new[]
        {
            new WindowsUpdateEntry("KB1", "undated", null),
            new WindowsUpdateEntry("KB2", "dated", T0),
        });
        var node = Obj(UpdatesTelemetrySectionCollector.Build(null, new WindowsUpdateCacheEntry(scan, T0)));

        Assert.Null(node["reboot_required"]);
        Assert.Equal(new[] { "dated", "undated" }, node["recent"]!.AsArray().Select(e => (string)e!["title"]!));
        Assert.Null(node["recent"]![1]!["installed_utc"]);
    }

    [Fact]
    public async Task Updates_EmptyCacheIsUnavailableAndNeverSearchesInline()
    {
        var searcher = new FakeUpdateSearcher(_ => Task.FromResult(new WindowsUpdateScan(9, 9, Array.Empty<WindowsUpdateEntry>())));
        using var cache = new WindowsUpdateCache(searcher, new ManualTimeProvider(T0));
        var collector = new UpdatesTelemetrySectionCollector(cache, () => false);

        var node = Obj(await collector.CollectAsync(Context(), CancellationToken.None));

        Assert.Equal(0, searcher.Calls);
        var pending = node["pending"]!;
        Assert.Equal("unavailable", (string)pending["status"]!);
        Assert.Null(pending["count"]);
        Assert.Null(pending["security_count"]);
        Assert.Null(pending["checked_at_utc"]);
        Assert.Empty(node["recent"]!.AsArray());
        Assert.False((bool)node["reboot_required"]!);
    }

    // ---- forbidden fields ------------------------------------------------------------------------------------

    [Theory]
    [InlineData("command_line", true)]
    [InlineData("file_path", true)]
    [InlineData("ip_address", true)]
    [InlineData("client_address", true)]
    [InlineData("owner_sid", true)]
    [InlineData("description", false)]
    [InlineData("zip", false)]
    [InlineData("display_name", false)]
    [InlineData("process_name", false)]
    public void ForbiddenFieldScan_MatchesWholeNameTokensOnly(string name, bool expected)
        => Assert.Equal(expected, HasForbiddenToken(name));

    [Fact]
    public async Task Sections_NeverExposeForbiddenFieldNames()
    {
        var cache = new WindowsUpdateCacheEntry(new WindowsUpdateScan(1, 1, new[] { new WindowsUpdateEntry("KB1", "t", T0) }), T0);
        var outputs = new List<object>
        {
            SessionsTelemetrySectionCollector.Build(new[] { new SessionsTelemetrySectionCollector.RawSession("D", "u", "active", "rdp", T0) }),
            ServicesTelemetrySectionCollector.Build(new[] { new ServicesTelemetrySectionCollector.RawService("n", "d", "running", "auto") }),
            ListeningPortsTelemetrySectionCollector.Build(new[] { new ListeningPortsTelemetrySectionCollector.RawPort("tcp", "ipv4", 1, "any", "p") }),
            SoftwareTelemetrySectionCollector.Build(new[] { new SoftwareTelemetrySectionCollector.RawSoftware("n", "1", "p", "20240101", "x64") }),
            UpdatesTelemetrySectionCollector.Build(false, cache),
            UpdatesTelemetrySectionCollector.Build(null, null),
            ServerFactText.Unavailable("services", "section_timeout"),
            await new HardwareTelemetrySectionCollector().CollectAsync(Context(), CancellationToken.None),
        };

        var names = outputs.SelectMany(o => PropertyNames(Obj(o))).Distinct().ToArray();

        Assert.NotEmpty(names);
        Assert.Empty(names.Where(HasForbiddenToken));
    }


    private static AgentBuildMetadata Metadata() => ServerFactJson.Metadata();

    private static WindowsTelemetryContext Context() => ServerFactJson.Context();

    private static UpdatesTelemetrySectionCollector EmptyCacheUpdates()
        => new(new WindowsUpdateCache(new FakeUpdateSearcher(_ => throw new InvalidOperationException("no search in tests")), TimeProvider.System), () => null);

    // ---- one real, read-only local collection per section ----------------------------------------------------

    [Fact]
    public async Task RealCollection_SessionsServicesPortsSoftwareUpdatesRunWithoutThrowingAndKeepContractShape()
    {
        var sessions = Obj(await new SessionsTelemetrySectionCollector().CollectAsync(Context(), CancellationToken.None));
        Assert.Equal("ok", (string)sessions["status"]!);
        Assert.All(sessions["sessions"]!.AsArray(), s => Assert.Contains((string)s!["state"]!, new[] { "active", "disconnected", "idle", "other" }));

        var services = Obj(await new ServicesTelemetrySectionCollector().CollectAsync(Context(), CancellationToken.None));
        Assert.True((int)services["service_count"]! > 0);
        Assert.All(services["services"]!.AsArray(), s => Assert.Contains((string)s!["start_type"]!,
            new[] { "boot", "system", "auto", "auto_delayed", "manual", "disabled", "other" }));

        var ports = Obj(await new ListeningPortsTelemetrySectionCollector().CollectAsync(Context(), CancellationToken.None));
        Assert.All(ports["ports"]!.AsArray(), p =>
        {
            Assert.InRange((int)p!["port"]!, 0, 65535);
            Assert.Contains((string)p["bind_scope"]!, new[] { "any", "loopback", "specific" });
            Assert.DoesNotContain('\\', (string?)p["process_name"] ?? string.Empty);
            Assert.DoesNotContain('/', (string?)p["process_name"] ?? string.Empty);
        });

        var software = Obj(await new SoftwareTelemetrySectionCollector().CollectAsync(Context(), CancellationToken.None));
        Assert.All(software["software"]!.AsArray(), s => Assert.Contains((string)s!["arch"]!, new[] { "x64", "x86" }));

        var updates = Obj(await EmptyCacheUpdates().CollectAsync(Context(), CancellationToken.None));
        Assert.Equal("unavailable", (string)updates["pending"]!["status"]!);
    }

    [Fact]
    public async Task RealCollection_HardwareReturnsContractFields()
    {
        var node = Obj(await new HardwareTelemetrySectionCollector().CollectAsync(Context(), CancellationToken.None));

        Assert.Equal(Sorted("status", "cpu_model", "cpu_sockets", "cpu_cores", "cpu_logical", "cpu_usage_percent",
            "memory_total_mb", "memory_used_percent", "last_boot_utc", "manufacturer", "model"), Keys(node));
        Assert.True(((string)node["cpu_model"]!).Length <= 128);
        Assert.True((int)node["cpu_logical"]! > 0);
        Assert.InRange((int)node["cpu_usage_percent"]!, 0, 100);
        Assert.InRange((int)node["memory_used_percent"]!, 0, 100);
        Assert.True((int)node["memory_total_mb"]! > 0);
        Assert.EndsWith("Z", (string)node["last_boot_utc"]!);
        Assert.True(DateTimeOffset.Parse((string)node["last_boot_utc"]!) < DateTimeOffset.UtcNow);
        Assert.True(((string?)node["manufacturer"])?.Length <= 64 || node["manufacturer"] is null);
        Assert.True(((string?)node["model"])?.Length <= 64 || node["model"] is null);
    }
}
