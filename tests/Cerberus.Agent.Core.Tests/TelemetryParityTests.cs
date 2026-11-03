using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.Core;
using Cerberus.Agent.Integrations.Ad;

namespace Cerberus.Agent.Core.Tests;

[Collection("FailedLogonCursor")]
public sealed class TelemetryParityTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("unknown_section")]
    public void MissingOrUnknownAllowlist_PreservesAllEighteenBudgetedSections(string? configured)
    {
        var sections = WindowsTelemetrySectionCatalog.CreateDefault(configured);
        Assert.Equal(18, sections.Count);
        Assert.All(sections, s => Assert.IsType<ServerSectionBudget>(s));
        Assert.Equal(TimeSpan.FromSeconds(20), ServerSectionBudget.TotalBudget);
        Assert.Equal(TimeSpan.FromSeconds(5), ServerSectionBudget.SectionBudget);
    }

    [Fact]
    public async Task SharedRunBudget_IsNotExtendedByUtcRollback()
    {
        var clock = new ContactRetryClock();
        var context = ServerFactJson.Context();
        var first = new BudgetProbe("identity");
        await new ServerSectionBudget(first, clock).CollectAsync(context, default);
        clock.UtcOffset = -TimeSpan.FromHours(1);
        clock.Advance(ServerSectionBudget.TotalBudget);
        var next = new BudgetProbe("services");
        var result = await new ServerSectionBudget(next, clock).CollectAsync(context, default);
        Assert.Equal(0, next.Calls);
        Assert.Contains("time_budget_exhausted", JsonSerializer.Serialize(result));
    }

    private sealed class BudgetProbe(string name) : IWindowsTelemetrySectionCollector
    {
        public int Calls;
        public Action? OnCollect;
        public string SectionName => name;
        public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
        {
            Calls++;
            OnCollect?.Invoke();
            return ValueTask.FromResult<object>(new { status = "ok" });
        }
    }

    [Fact]
    public async Task WrappedCapabilities_RefreshOnlyClearsAfterItsCollectedSnapshotWasSubmitted()
    {
        var clock = new ContactRetryClock();
        var current = LocalUserCommandPolicy.CreateDisabled;
        var spendRunBudget = true;
        var first = new BudgetProbe("identity")
        {
            OnCollect = () => { if (spendRunBudget) clock.Advance(ServerSectionBudget.TotalBudget); },
        };
        var capabilities = new CapabilitiesTelemetrySectionCollector(() => current);
        var collector = new WindowsTelemetryCollector(new IWindowsTelemetrySectionCollector[]
        {
            new ServerSectionBudget(first, clock),
            new ServerSectionBudget(capabilities, clock),
        });
        var heartbeat = ServerFactJson.AdvertisedHeartbeat();
        collector.ConfigureSnapshot(heartbeat);
        Assert.False(collector.IsSnapshotRefreshRequired());
        current = LocalUserCommandPolicy.CreateEnabledPolicy;
        Assert.True(collector.IsSnapshotRefreshRequired());
        var skipped = await collector.BuildSnapshotAsync(ServerFactJson.Metadata(), heartbeat, default);
        Assert.Contains("time_budget_exhausted", JsonSerializer.Serialize(skipped.Sections["capabilities"]));
        collector.MarkSnapshotSubmitted();
        Assert.True(collector.IsSnapshotRefreshRequired()); // an unavailable section did not publish the policy
        spendRunBudget = false;
        await collector.BuildSnapshotAsync(ServerFactJson.Metadata(), heartbeat, default);
        Assert.True(collector.IsSnapshotRefreshRequired()); // collection alone is not an acknowledgement
        collector.MarkSnapshotSubmitted();
        Assert.False(collector.IsSnapshotRefreshRequired());
        current = LocalUserCommandPolicy.UnknownPolicy;
        Assert.True(collector.IsSnapshotRefreshRequired());
        collector.ConfigureSnapshot(ServerFactJson.AdvertisedHeartbeat("identity"));
        Assert.False(collector.IsSnapshotRefreshRequired()); // a receiver that excludes capabilities cannot publish this signal
    }

    [Fact]
    public async Task AdvertisedSections_CannotWidenTheLocalOperatorAllowlist()
    {
        var collector = new WindowsTelemetryCollector(WindowsTelemetrySectionCatalog.CreateDefault("identity,clock"));
        var snapshot = await collector.BuildSnapshotAsync(ServerFactJson.Metadata(),
            ServerFactJson.AdvertisedHeartbeat("identity", "services", "raw_event_log"), default);
        Assert.Equal(new[] { "identity" }, snapshot.Sections.Keys);
    }
}

public sealed partial class AgentApiClientTelemetryTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SnapshotSections_UsesAdvertisedIntersectionOrLegacyProfileSet(bool advertised)
    {
        var wire = new SnapshotBudgetWire { Advertised = 262144,
            AdvertisedSections = advertised ? new[] { "identity", "software", "raw_event_log" } : null };
        using var http = new HttpClient(wire) { BaseAddress = new Uri("https://backend.test") };
        var api = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        await api.HeartbeatAsync(new { }, default);
        await api.SubmitSnapshotAsync(AllSectionsSnapshot(), default);
        var expected = advertised ? new[] { "identity", "software" } : LegacySections();
        AssertSentSections(Assert.Single(wire.Snapshots), expected);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SnapshotSections_422FitsTheNextLiveOrOfflineAttemptToLegacySet(bool offline)
    {
        var wire = new SnapshotBudgetWire { Advertised = 262144, RejectNonLegacySections = true };
        using var http = new HttpClient(wire) { BaseAddress = new Uri("https://backend.test") };
        var api = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        await api.HeartbeatAsync(new { }, default);
        var original = AllSectionsSnapshot();
        await Assert.ThrowsAnyAsync<HttpRequestException>(() => api.SubmitSnapshotAsync(original, default));
        await api.HeartbeatAsync(new { }, default);
        if (offline)
            await api.SubmitOfflineTelemetryAsync(new OfflineTelemetryRecord("id", OfflineTelemetryKinds.Snapshot,
                JsonSerializer.Serialize(original, new JsonSerializerOptions(JsonSerializerDefaults.Web)), DateTimeOffset.UtcNow, null, 1), default);
        else await api.SubmitSnapshotAsync(original, default);
        Assert.Equal(2, wire.Snapshots.Count);
        AssertSentSections(wire.Snapshots[0], ServerFactJson.PeriodicSections);
        AssertSentSections(wire.Snapshots[1], LegacySections());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SnapshotSections_SecondaryRetainsItsLocalFifteenSections(bool advertised)
    {
        var wire = new SnapshotBudgetWire { Advertised = 262144,
            AdvertisedSections = advertised ? ServerFactJson.PeriodicSections : null };
        using var http = new HttpClient(wire) { BaseAddress = new Uri("https://backend.test") };
        var api = new AgentApiClient(http, new SecondaryTelemetrySecrets(), new StaticTokenManager(), new StaticSigner());
        await api.HeartbeatAsync(new { }, default);
        await api.SubmitSnapshotAsync(AllSectionsSnapshot(), default);
        AssertSentSections(Assert.Single(wire.Snapshots), EnvelopeTypes.ServerFactSections);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(65536)]
    [InlineData(262144)]
    [InlineData(524288)]
    public async Task SnapshotBudget_UsesAdvertisementOrLegacyDefault_AndNeverWidensLocalCeiling(int? advertised)
    {
        var wire = new SnapshotBudgetWire { Advertised = advertised };
        using var http = new HttpClient(wire) { BaseAddress = new Uri("https://backend.test") };
        var api = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var response = await api.HeartbeatAsync(new { }, default);
        Assert.Equal(advertised, response.SnapshotMaxBytes);
        var expected = advertised is { } limit ? Math.Min(262144, limit) : AgentBuildProfile.IsServer ? 262144 : 65536;
        Assert.Equal(expected, api.SnapshotByteLimit);
        var original = LargeSnapshot();
        await api.SubmitSnapshotAsync(original, default);
        var sent = Assert.Single(wire.Snapshots);
        Assert.InRange(Encoding.UTF8.GetByteCount(sent), 1, expected);
        AssertSnapshotHashes(sent);
        using var doc = JsonDocument.Parse(sent);
        Assert.Equal(expected == 65536, doc.RootElement.GetProperty("sections").GetProperty("services").GetProperty("truncated").GetBoolean());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SnapshotBudget_413FitsTheNextLiveOrOfflineAttempt_DespiteRepeatedAdvertisement(bool offline)
    {
        var wire = new SnapshotBudgetWire { Advertised = 262144, RejectAbove64KiB = true };
        using var http = new HttpClient(wire) { BaseAddress = new Uri("https://backend.test") };
        var api = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        await api.HeartbeatAsync(new { }, default);
        var original = LargeSnapshot();
        await Assert.ThrowsAnyAsync<HttpRequestException>(() => api.SubmitSnapshotAsync(original, default));
        Assert.Equal(65536, api.SnapshotByteLimit);
        await api.HeartbeatAsync(new { }, default);
        Assert.Equal(65536, api.SnapshotByteLimit);
        if (offline)
            await api.SubmitOfflineTelemetryAsync(new OfflineTelemetryRecord("id", OfflineTelemetryKinds.Snapshot,
                JsonSerializer.Serialize(original, new JsonSerializerOptions(JsonSerializerDefaults.Web)), DateTimeOffset.UtcNow, "snapshot", 1), default);
        else
            await api.SubmitSnapshotAsync(original, default);
        Assert.Equal(2, wire.Snapshots.Count);
        Assert.True(Encoding.UTF8.GetByteCount(wire.Snapshots[0]) > 65536);
        Assert.InRange(Encoding.UTF8.GetByteCount(wire.Snapshots[1]), 1, 65536);
        AssertSnapshotHashes(wire.Snapshots[1]);
    }

    [Fact]
    public async Task SnapshotBudget_PrivacyRedactionPrecedesFitForPersistedCopy()
    {
        var consent = true;
        var wire = new SnapshotBudgetWire { Advertised = 65536 };
        using var http = new HttpClient(wire) { BaseAddress = new Uri("https://backend.test") };
        var api = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner(),
            outgoingPolicy: new AgentOutboundPrivacyPolicy(() => consent).Prepare);
        await api.HeartbeatAsync(new { }, default);
        var original = AgentSnapshotFactory.Create(Metadata(), DateTimeOffset.UtcNow,
            new Dictionary<string, object?>
            {
                ["security"] = new { status = "ok", local_admins = new
                {
                    members = Enumerable.Range(0, 100).Select(n => new { name = new string('a', 180) + n }).ToArray(),
                } },
                ["software"] = new { status = "ok", count = 100, truncated = false,
                    software = Enumerable.Range(0, 100).Select(n => new { name = new string('s', 380) + n, version = "1" }).ToArray() },
            });
        var json = JsonSerializer.Serialize(original, new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.InRange(Encoding.UTF8.GetByteCount(json), 50001, 65536);
        var path = Path.Combine(Path.GetTempPath(), "cerberus-privacy-budget", Guid.NewGuid().ToString("N"), "outbox.json");
        await new OfflineTelemetryBuffer(path).EnqueueAsync(OfflineTelemetryKinds.Snapshot, original, "budget", 0, default);
        consent = false;
        wire.Advertised = 50000;
        await api.HeartbeatAsync(new { }, default);
        var persisted = Assert.Single(await new OfflineTelemetryBuffer(path).ReadBatchAsync(10, default));
        await api.SubmitOfflineTelemetryAsync(persisted, default);
        var sent = Assert.Single(wire.Snapshots);
        Assert.InRange(Encoding.UTF8.GetByteCount(sent), 1, 50000);
        AssertSnapshotHashes(sent);
        using var doc = JsonDocument.Parse(sent);
        var sections = doc.RootElement.GetProperty("sections");
        var software = sections.GetProperty("software");
        if (AgentBuildProfile.IsServer)
            Assert.InRange(software.GetProperty("software").GetArrayLength(), 1, 99);
        else
        {
            Assert.False(sections.GetProperty("security").TryGetProperty("local_admins", out _));
            Assert.Equal(100, software.GetProperty("software").GetArrayLength());
            Assert.False(software.GetProperty("truncated").GetBoolean());
        }
        Assert.Equal(persisted.Json, Assert.Single(await new OfflineTelemetryBuffer(path).ReadBatchAsync(10, default)).Json);
    }

    [Theory]
    [InlineData(false, 65536)]
    [InlineData(false, 65537)]
    [InlineData(true, 65536)]
    [InlineData(true, 65537)]
    public async Task ResponseBudget_HeartbeatAndSnapshotAckKeepThe64KiBBoundary(bool heartbeat, int bytes)
    {
        var content = heartbeat ? HeartbeatResponseJson() : """{"status":"accepted","accepted":1,"ignored":0}""";
        var handler = new CaptureHandler(PadToLength(content, bytes));
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://backend.test") };
        var api = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        Task Submit() => heartbeat ? api.HeartbeatAsync(new { }, default) : api.SubmitSnapshotAsync(
            AgentSnapshotFactory.Create(Metadata(), DateTimeOffset.UtcNow, new Dictionary<string, object?>()), default);
        if (bytes <= 65536) await Submit();
        else await Assert.ThrowsAnyAsync<HttpRequestException>(Submit);
    }

    [Fact]
    public async Task RequestBudget_HeartbeatRejectsAbove64KiBBeforeTransport()
    {
        var handler = new CaptureHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://backend.test") };
        var api = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        await Assert.ThrowsAsync<InvalidOperationException>(() => api.HeartbeatAsync(new { blob = new string('x', 65536) }, default));
        Assert.Null(handler.CapturedRequest);
    }

    [Fact]
    public async Task RequestBudget_OfflineEventsUseUtf8BytesRatherThanCharacterCount()
    {
        var handler = new CaptureHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://backend.test") };
        var api = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var json = "{\"blob\":\"" + new string('é', 33000) + "\"}";
        Assert.True(json.Length < 65536);
        await Assert.ThrowsAsync<InvalidOperationException>(() => api.SubmitOfflineTelemetryAsync(
            new OfflineTelemetryRecord("id", OfflineTelemetryKinds.Events, json, DateTimeOffset.UtcNow, null, 1), default));
        Assert.Null(handler.CapturedRequest);
    }

    [Fact]
    public async Task RequestBudget_SnapshotWithoutTrimmableListsRejectsAbove256KiBBeforeTransport()
    {
        var handler = new CaptureHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://backend.test") };
        var api = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var body = LargeSnapshot() with { Sections = new Dictionary<string, object?> { ["identity"] = new { blob = new string('x', 262144) } } };
        await Assert.ThrowsAsync<InvalidOperationException>(() => api.SubmitSnapshotAsync(body, default));
        Assert.Null(handler.CapturedRequest);
    }

    private static AgentSnapshotRequest LargeSnapshot() => AgentSnapshotFactory.Create(Metadata(), DateTimeOffset.UtcNow,
        new Dictionary<string, object?> { ["services"] = new { status = "ok", truncated = false,
            services = Enumerable.Range(0, 400).Select(i => new { name = $"service-{i}", display_name = new string('x', 280) }).ToArray() } });

    private static void AssertSnapshotHashes(string json)
    {
        using var doc = JsonDocument.Parse(json);
        foreach (var section in doc.RootElement.GetProperty("sections").EnumerateObject())
            Assert.Equal(AgentSnapshotFactory.HashSection(section.Value),
                doc.RootElement.GetProperty("section_hashes").GetProperty(section.Name).GetString());
    }

    private static string[] LegacySections() => AgentBuildProfile.IsServer ? EnvelopeTypes.ServerFactSections.ToArray()
        : new[] { "identity", "os", "resources", "network", "tailscale", "rdp", "firewall", "security", "clock", "runtime", "capabilities" };

    private static AgentSnapshotRequest AllSectionsSnapshot() => AgentSnapshotFactory.Create(Metadata(), DateTimeOffset.UtcNow,
        ServerFactJson.PeriodicSections.ToDictionary(name => name, _ => (object?)new { status = "ok" }));

    private static void AssertSentSections(string json, IEnumerable<string> expected)
    {
        using var doc = JsonDocument.Parse(json);
        Assert.Equal(expected.OrderBy(n => n), doc.RootElement.GetProperty("sections").EnumerateObject().Select(p => p.Name).OrderBy(n => n));
        AssertSnapshotHashes(json);
    }

    private sealed class SecondaryTelemetrySecrets : ISecretStore
    {
        private readonly ISecretStore _inner = new StaticSecretStore();
        public async Task<(AgentIdentity, string, string, string, string?, string?)> LoadAsync(CancellationToken ct)
        {
            var value = await _inner.LoadAsync(ct);
            return (value.Item1 with { Product = AgentProducts.Secondary }, value.Item2, value.Item3, value.Item4, value.Item5, value.Item6);
        }
        public Task SaveAsync(AgentIdentity id, string refresh, string key, string url, string? login, string? auth, CancellationToken ct) => Task.CompletedTask;
        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class SnapshotBudgetWire : HttpMessageHandler
    {
        public int? Advertised;
        public IReadOnlyList<string>? AdvertisedSections = ServerFactJson.PeriodicSections;
        public bool RejectAbove64KiB;
        public bool RejectNonLegacySections;
        public List<string> Snapshots { get; } = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/heartbeat", StringComparison.Ordinal))
            {
                var response = JsonNode.Parse(HeartbeatResponseJson())!.AsObject();
                if (Advertised is { } limit) response["snapshot_max_bytes"] = limit;
                if (AdvertisedSections is { } sections) response["snapshot_sections"] = JsonSerializer.SerializeToNode(sections);
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(response.ToJsonString()) };
            }
            var json = await request.Content!.ReadAsStringAsync(ct);
            Snapshots.Add(json);
            if (RejectNonLegacySections)
            {
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.GetProperty("sections").EnumerateObject().Any(p => !LegacySections().Contains(p.Name)))
                    return new HttpResponseMessage(HttpStatusCode.UnprocessableEntity) { Content = new StringContent("{}") };
            }
            return RejectAbove64KiB && Encoding.UTF8.GetByteCount(json) > 65536
                ? new HttpResponseMessage(HttpStatusCode.RequestEntityTooLarge) { Content = new StringContent("{}") }
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("""{"status":"accepted","accepted":1,"ignored":0}""") };
        }
    }
}
