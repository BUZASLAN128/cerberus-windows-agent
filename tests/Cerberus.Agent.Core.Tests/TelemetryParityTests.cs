using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

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
        public string SectionName => name;
        public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
        {
            Calls++;
            return ValueTask.FromResult<object>(new { status = "ok" });
        }
    }
}

public sealed partial class AgentApiClientTelemetryTests
{
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

    private sealed class SnapshotBudgetWire : HttpMessageHandler
    {
        public int? Advertised;
        public bool RejectAbove64KiB;
        public List<string> Snapshots { get; } = [];
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/heartbeat", StringComparison.Ordinal))
            {
                var response = JsonNode.Parse(HeartbeatResponseJson())!.AsObject();
                if (Advertised is { } limit) response["snapshot_max_bytes"] = limit;
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(response.ToJsonString()) };
            }
            var json = await request.Content!.ReadAsStringAsync(ct);
            Snapshots.Add(json);
            return RejectAbove64KiB && Encoding.UTF8.GetByteCount(json) > 65536
                ? new HttpResponseMessage(HttpStatusCode.RequestEntityTooLarge) { Content = new StringContent("{}") }
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("""{"status":"accepted","accepted":1,"ignored":0}""") };
        }
    }
}
