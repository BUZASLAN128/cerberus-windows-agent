using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Cerberus.Agent.App.Commands;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentOutboundPrivacyReplayTests
{
    private static object Security() => new
    {
        status = "ok", defender = new { status = "ok" },
        failed_logons = new { user = "PRIVATE_USER", domain = "PRIVATE_DOMAIN", source_ip = "203.0.113.9" },
        successful_logons = new { user = "PRIVATE_USER" },
        local_admins = new { members = new[] { new { sid = "PRIVATE_SID", added_by = "PRIVATE_ACTOR" } } },
    };

    private sealed class SyntheticSecurity : IWindowsTelemetrySectionCollector
    {
        public string SectionName => "security";
        public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
            => ValueTask.FromResult(Security());
    }

    private static void AssertWire(JsonElement body, string expectedEnvelopeHash)
    {
        Assert.Equal(expectedEnvelopeHash, body.GetProperty("envelope_sha256").GetString());
        var facts = body.GetProperty("post_verify");
        var security = facts.GetProperty("sections").GetProperty("security");
        Assert.Equal(AgentBuildProfile.IsServer, security.TryGetProperty("local_admins", out _));
        Assert.True(security.TryGetProperty("defender", out _));
        if (!AgentBuildProfile.IsServer) Assert.DoesNotContain("PRIVATE_", body.GetRawText());
        Assert.Equal(AgentSnapshotFactory.HashSection(security), facts.GetProperty("section_hashes").GetProperty("security").GetString());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task CollectFacts_FileQueueRestartAnd503_RechecksConsentAndTerminatesLostAckConflict(bool serverStoredFirst)
    {
        var granted = true;
        var policy = new AgentOutboundPrivacyPolicy(() => granted);
        await using var h = EnvelopeHarness.Create(o => o.OutgoingPolicy = policy.Prepare);
        var facts = new CollectFactsCommandHandler(ServerFactJson.Metadata(), new[] { new SyntheticSecurity() }, h.Time);
        h.Facts.Body = facts.HandleAsync;
        var attempts = 0;
        string? serverBody = null;
        h.Backend.ResponseBody = _ => "{\"detail\":\"signed_result_conflict\"}";
        h.Backend.Respond = (request, _) =>
        {
            if (request.Leaf != "result") return Task.FromResult(HttpStatusCode.OK);
            if (Interlocked.Increment(ref attempts) == 1)
            {
                if (serverStoredFirst)
                {
                    serverBody = request.Json.GetRawText();
                    return Task.FromException<HttpStatusCode>(new HttpRequestException("Synthetic ACK loss after server commit."));
                }
                return Task.FromResult(HttpStatusCode.ServiceUnavailable);
            }
            var conflict = serverBody is not null && !JsonNode.DeepEquals(JsonNode.Parse(serverBody), JsonNode.Parse(request.Json.GetRawText()));
            return Task.FromResult(conflict ? HttpStatusCode.Conflict : HttpStatusCode.OK);
        };
        var command = h.Cmd(p => { p.Type = EnvelopeTypes.CollectFacts; p.PayloadJson = "{\"sections\":[\"security\"]}"; });
        await h.Processor.ProcessAsync(new[] { command }, default);
        await Wait.UntilAsync(() => h.Backend.Results.Count == 1 && h.Store.Find(h.AgentId, command.Id)?.State == EnvelopeRecordStates.Done,
            "first private result persisted and failed to deliver");
        await h.Queue.StopAsync();
        var original = h.Store.Find(h.AgentId, command.Id)!;
        Assert.False(original.ResultSubmitted);
        Assert.Contains("PRIVATE_ACTOR", Encoding.UTF8.GetString(Convert.FromBase64String(original.ResultB64!)));
        Assert.Contains("PRIVATE_USER", Encoding.UTF8.GetString(h.Backend.Results[0].Body));

        granted = false;
        await h.RestartAsync(recreateApi: true); // new API policy is ready before outbox startup; no HeartbeatLoop registration.
        await h.Queue.DrainOutboxOnceAsync(default); // the same production pass requested by startup/heartbeat.
        await Wait.UntilAsync(() => h.Store.Find(h.AgentId, command.Id)?.ResultSubmitted == true, "result accepted or terminally refused");
        var last = h.Store.Find(h.AgentId, command.Id)!;
        AssertWire(h.Backend.Results[^1].Json, original.EnvelopeSha256);
        Assert.Equal(original.ResultB64, last.ResultB64); // local immutable evidence is not rewritten or re-sent unchecked.
        Assert.Equal(original.ResultSha256, last.ResultSha256);
        Assert.Equal(1, h.Facts.Calls);
        var refused = serverStoredFirst && !AgentBuildProfile.IsServer;
        Assert.Equal(refused, h.Log.Lines.Any(line => line.Contains("result refused") && line.Contains("409")));
        if (refused) Assert.DoesNotContain(h.Log.Lines, line => line.Contains("Command finished"));
        var sent = h.Backend.Results.Count;
        h.Time.Advance(TimeSpan.FromHours(1));
        await h.Queue.DrainOutboxOnceAsync(default);
        await h.Queue.DrainOutboxOnceAsync(default);
        Assert.Equal(sent, h.Backend.Results.Count); // neither endless conflict retry nor fallback to original PII.
    }

    [Fact]
    public async Task CollectFacts_401Resend_RechecksCurrentConsentBeforeSigning()
    {
        var granted = true;
        await using var h = EnvelopeHarness.Create(o => o.OutgoingPolicy = new AgentOutboundPrivacyPolicy(() => granted).Prepare);
        h.Facts.Body = new CollectFactsCommandHandler(ServerFactJson.Metadata(), new[] { new SyntheticSecurity() }, h.Time).HandleAsync;
        var attempts = 0;
        h.Backend.Respond = (request, _) =>
        {
            if (request.Leaf == "result" && Interlocked.Increment(ref attempts) == 1)
            {
                granted = false;
                return Task.FromResult(HttpStatusCode.Unauthorized);
            }
            return Task.FromResult(HttpStatusCode.OK);
        };
        var command = h.Cmd(p => { p.Type = EnvelopeTypes.CollectFacts; p.PayloadJson = "{\"sections\":[\"security\"]}"; });
        await h.Processor.ProcessAsync(new[] { command }, default);
        await Wait.UntilAsync(() => h.Store.Find(h.AgentId, command.Id)?.ResultSubmitted == true, "401 refreshed result completed");
        Assert.Equal(2, h.Backend.Results.Count);
        Assert.Contains("PRIVATE_ACTOR", Encoding.UTF8.GetString(h.Backend.Results[0].Body));
        AssertWire(h.Backend.Results[1].Json, h.Store.Find(h.AgentId, command.Id)!.EnvelopeSha256);
    }

    [Fact]
    public async Task EveryOfflineTelemetryKind_RechecksPolicyFromActualPersistedRecord()
    {
        var calls = 0;
        var policy = new AgentOutboundPrivacyPolicy(() => false);
        await using var h = EnvelopeHarness.Create(o => o.OutgoingPolicy = json => { Interlocked.Increment(ref calls); return policy.Prepare(json); });
        await h.Queue.StopAsync();
        var path = Path.Combine(Path.GetDirectoryName(h.StorePath)!, "offline-privacy.json");
        var buffer = new OfflineTelemetryBuffer(path);
        foreach (var kind in new[] { OfflineTelemetryKinds.Snapshot, OfflineTelemetryKinds.Events, OfflineTelemetryKinds.ProbeResult })
        {
            var data = AgentSnapshotFactory.Create(ServerFactJson.Metadata(), DateTimeOffset.UtcNow,
                new Dictionary<string, object?> { ["security"] = Security() });
            object body = kind == OfflineTelemetryKinds.Snapshot ? data : new { payload = data };
            await buffer.EnqueueAsync(kind, body, kind, 0, default);
        }
        var restarted = new OfflineTelemetryBuffer(path);
        var records = await restarted.ReadBatchAsync(10, default);
        Assert.Equal(3, records.Count);
        foreach (var record in records) await h.Api.SubmitOfflineTelemetryAsync(record, default);
        Assert.Equal(3, calls);
        Assert.Equal(3, h.Backend.Requests.Count);
        if (!AgentBuildProfile.IsServer)
            foreach (var request in h.Backend.Requests) Assert.DoesNotContain("PRIVATE_", Encoding.UTF8.GetString(request.Body));
    }

    [Fact]
    public async Task LegacyReplayStore_ReloadedResultPassesCommonPolicy()
    {
        var calls = 0;
        var policy = new AgentOutboundPrivacyPolicy(() => false);
        await using var h = EnvelopeHarness.Create(o => o.OutgoingPolicy = json => { Interlocked.Increment(ref calls); return policy.Prepare(json); });
        await h.Queue.StopAsync();
        var dir = Path.GetDirectoryName(h.StorePath)!;
        var path = Path.Combine(dir, "legacy-privacy.json");
        var store = new CommandReplayStore(path);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var pending = new CommandReplayRecord(h.AgentId, Guid.NewGuid().ToString("D"), new string('a', 64),
            Guid.NewGuid().ToString("D"), "agent.health.snapshot", now, now + 300, EnvelopeRecordStates.Reserved, null, null, false);
        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(pending));
        var snapshot = AgentSnapshotFactory.Create(ServerFactJson.Metadata(), DateTimeOffset.UtcNow,
            new Dictionary<string, object?> { ["security"] = Security() });
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new CommandResult("DONE", 0, null, null, snapshot),
            new JsonSerializerOptions(JsonSerializerDefaults.Web));
        Assert.True(store.TryUpdate(pending with { State = EnvelopeRecordStates.Done,
            ResultB64 = Convert.ToBase64String(bytes), ResultSha256 = CommandEnvelope.Sha256Hex(bytes) }));
        var reloaded = new CommandReplayStore(path);
        var handler = new FakeCommandHandler("agent.health.snapshot");
        var dispatcher = new CommandDispatcher(new[] { handler }, new IdempotencyCache(Path.Combine(dir, "legacy-cache.json"), 10, TimeSpan.FromHours(1)));
        await using var legacy = new LegacyAsyncCommandProcessor(h.Api, dispatcher,
            new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromSeconds(5), 1), reloaded, _ => Task.FromResult(h.AgentId));
        await Wait.UntilAsync(() => reloaded.Find(h.AgentId, pending.Id)?.ResultSubmitted == true, "legacy persisted result processed");
        Assert.Equal(1, calls);
        Assert.Equal(0, handler.Calls);
        Assert.Single(h.Backend.Results);
        if (!AgentBuildProfile.IsServer) Assert.DoesNotContain("PRIVATE_", Encoding.UTF8.GetString(h.Backend.Results[0].Body));
    }

    [Fact]
    public async Task IdempotencyCache_ReloadedResultCannotBypassCommonPolicy()
    {
        var calls = 0;
        var policy = new AgentOutboundPrivacyPolicy(() => false);
        await using var h = EnvelopeHarness.Create(o => o.OutgoingPolicy = json => { Interlocked.Increment(ref calls); return policy.Prepare(json); });
        await h.Queue.StopAsync();
        var path = Path.Combine(Path.GetDirectoryName(h.StorePath)!, "idempotency-privacy.json");
        var snapshot = AgentSnapshotFactory.Create(ServerFactJson.Metadata(), DateTimeOffset.UtcNow,
            new Dictionary<string, object?> { ["security"] = Security() });
        var result = new CommandResult("DONE", 0, null, null, snapshot);
        new IdempotencyCache(path, 10, TimeSpan.FromHours(1)).Set("privacy-cache", result);
        var handler = new FakeCommandHandler("agent.health.snapshot");
        var dispatcher = new CommandDispatcher(new[] { handler }, new IdempotencyCache(path, 10, TimeSpan.FromHours(1)));
        var cached = await dispatcher.DispatchAsync(new AgentCommand(Guid.NewGuid().ToString("D"), handler.Type, "privacy-cache", new { }), default);
        await h.Api.SubmitCommandResultAsync(Guid.NewGuid().ToString("D"), cached, default);
        Assert.Equal(1, calls);
        Assert.Equal(0, handler.Calls);
        if (!AgentBuildProfile.IsServer) Assert.DoesNotContain("PRIVATE_", Encoding.UTF8.GetString(h.Backend.Results[0].Body));
    }
}
