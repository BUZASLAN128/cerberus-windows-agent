// Command registry per build profile, ping and collect_facts results (contract v1 (d)).
using System.Text.Json;
using System.Text.Json.Nodes;
using Cerberus.Agent.App;
using Cerberus.Agent.App.Commands;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.Core;
#if !CERBERUS_SERVER_PROFILE
using Cerberus.Agent.App.Diagnostics;
using Cerberus.Agent.App.Updates;
#endif

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentCommandRegistryTests
{
    private static readonly DateTimeOffset Start = DateTimeOffset.Parse("2026-06-02T01:02:03Z");

    private static AgentCommand Command(string type, string payloadJson = "{}")
        => new("cmd-1", type, "idem-1", JsonDocument.Parse(payloadJson).RootElement.Clone());

    private static AgentBuildMetadata Metadata() => ServerFactJson.Metadata();

    // ---- ping (both profiles) -----------------------------------------------------------

    [Fact]
    public async Task Ping_ReturnsPingV1WithAgentTimeFromClock()
    {
        var handler = new PingCommandHandler(Metadata(), new ManualTimeProvider(Start));

        var result = await handler.HandleAsync(Command("ping"), CancellationToken.None);

        Assert.Equal("DONE", result.Status);
        Assert.Equal(0, result.ExitCode);
        var post = ServerFactJson.Obj(result.PostVerify!);
        Assert.Equal("agent.ping.v1", (string?)post["schema"]);
        Assert.Equal("1.2.3", (string?)post["agent_version"]);
        Assert.Equal("build-1", (string?)post["build_id"]);
        Assert.Equal(Start.ToUnixTimeSeconds(), (long?)post["agent_time"]);
        Assert.True((long?)post["uptime_seconds"] >= 0);
    }

#if CERBERUS_SERVER_PROFILE
    // ---- server registry ------------------------------------------------------------------

    [Fact]
    public void ServerRegistry_HoldsExactlyPingCollectFactsAndAgentState()
    {
        var statePath = Path.Combine(Path.GetTempPath(), "u6b-registry-" + Guid.NewGuid().ToString("N") + ".json");
        var agentState = new AgentStateCommandHandler(
            new AgentSignedStateStore(statePath),
            _ => Task.FromResult("agent-1"),
            new AgentLifecycleController(null!),
            () => { });

        var handlers = AgentCommandRegistry.CreateServer(Metadata(), agentState);

        Assert.Equal(
            new[] { "agent_state", "collect_facts", "ping" },
            handlers.Select(h => h.Type).OrderBy(t => t, StringComparer.Ordinal).ToArray());
    }

    // ---- collect_facts --------------------------------------------------------------------

    private sealed class ContextCapturingSection(string name) : IWindowsTelemetrySectionCollector
    {
        public List<WindowsTelemetryContext> Contexts { get; } = new();

        public string SectionName { get; } = name;

        public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
        {
            Contexts.Add(context);
            return ValueTask.FromResult<object>(new { name = SectionName });
        }
    }

    private static CollectFactsCommandHandler Facts(params IWindowsTelemetrySectionCollector[] sections)
        => new(Metadata(), sections, new ManualTimeProvider(Start));

    [Fact]
    public async Task CollectFacts_EmptyPayloadReturnsAllSectionsWithHashesAndCollectedAt()
    {
        var handler = Facts(
            new StubSection("os", _ => ValueTask.FromResult<object>(new { family = "windows" })),
            new StubSection("clock", _ => ValueTask.FromResult<object>(new { utc = "x" })));

        var result = await handler.HandleAsync(Command("collect_facts"), CancellationToken.None);

        Assert.Equal("DONE", result.Status);
        var post = ServerFactJson.Obj(result.PostVerify!);
        Assert.Equal("agent.facts.v1", (string?)post["schema_version"]);
        Assert.Equal(Start.UtcDateTime.ToString("O"), (string?)post["collected_at"]);
        Assert.EndsWith("Z", (string?)post["collected_at"]);
        var sections = post["sections"]!.AsObject().Select(p => p.Key).OrderBy(k => k).ToArray();
        Assert.Equal(new[] { "clock", "os" }, sections);
        var hashes = post["section_hashes"]!.AsObject();
        Assert.Equal(sections, hashes.Select(p => p.Key).OrderBy(k => k).ToArray());
        Assert.Equal(AgentSnapshotFactory.HashSection(new { family = "windows" }), (string?)hashes["os"]);
    }

    [Fact]
    public async Task CollectFacts_RunsOnlyRequestedSections()
    {
        var os = new StubSection("os", _ => ValueTask.FromResult<object>(new { a = 1 }));
        var clock = new StubSection("clock", _ => ValueTask.FromResult<object>(new { b = 2 }));

        var result = await Facts(os, clock).HandleAsync(
            Command("collect_facts", """{"sections":["clock"]}"""), CancellationToken.None);

        var post = ServerFactJson.Obj(result.PostVerify!);
        Assert.Equal(new[] { "clock" }, post["sections"]!.AsObject().Select(p => p.Key).ToArray());
        Assert.Equal(0, os.Calls);
        Assert.Equal(1, clock.Calls);
    }

    [Fact]
    public async Task CollectFacts_UsesAFreshTelemetryContextPerRun()
    {
        var section = new ContextCapturingSection("os");
        var handler = Facts(section);

        await handler.HandleAsync(Command("collect_facts"), CancellationToken.None);
        await handler.HandleAsync(Command("collect_facts"), CancellationToken.None);

        Assert.Equal(2, section.Contexts.Count);
        Assert.NotSame(section.Contexts[0], section.Contexts[1]);
    }

    [Fact]
    public async Task CollectFacts_OversizedListIsHalvedUntilTheBodyFitsTheCap()
    {
        var items = Enumerable.Range(0, 8000).Select(i => new { name = "package-" + i, publisher = new string('p', 60) }).ToArray();
        var handler = Facts(new StubSection("software", _ => ValueTask.FromResult<object>(new { software = items })));

        var result = await handler.HandleAsync(Command("collect_facts"), CancellationToken.None);

        Assert.Equal("DONE", result.Status);
        var body = CommandEnvelope.BuildResultBody("DONE", 0, null, result.PostVerify, new string('0', 64));
        Assert.True(body.Length <= 262144, $"body {body.Length} bytes");
        var software = ServerFactJson.Obj(result.PostVerify!)["sections"]!["software"]!.AsObject();
        Assert.True(software["truncated"]!.GetValue<bool>());
        Assert.InRange(software["software"]!.AsArray().Count, 1, items.Length - 1);
    }

    [Fact]
    public async Task CollectFacts_UntruncatableOversizedBodyFailsWithResultTooLarge()
    {
        var handler = Facts(new StubSection("os", _ => ValueTask.FromResult<object>(new { blob = new string('x', 300_000) })));

        var result = await handler.HandleAsync(Command("collect_facts"), CancellationToken.None);

        Assert.Equal("FAILED", result.Status);
        Assert.Equal("result_too_large", result.Stderr);
        Assert.Null(result.PostVerify);
    }

#else
    // ---- desktop registry -----------------------------------------------------------------

    [Fact]
    public void DesktopRegistry_KeepsTheHandlerSetTheServiceAlwaysRegistered()
    {
        var api = new AgentApiClient(new HttpClient(), null!, null!, null!);
        var tmp = Path.Combine(Path.GetTempPath(), "u6b-registry-" + Guid.NewGuid().ToString("N"));
        var handlers = AgentCommandRegistry.CreateDesktop(
            api,
            new AgentIdentity("agent-1", "tenant-1"),
            null!,
            null!,
            new AgentDiagnosticBundleUploader(api, Metadata()),
            () => null,
            new AgentUpdateStateStore(tmp + "-state.json", tmp + "-result.json"),
            NullAgentLogger.Instance,
            "1.2.3");

        var types = handlers.Select(h => h.Type).OrderBy(t => t, StringComparer.Ordinal).ToArray();

        var expected = new[]
        {
            "agent.health.snapshot", "agent.rdp.quick_test", "tailscale.ensure_connected",
            AgentDiagnosticBundleUploader.CommandType,
            "windows.local_user.create", "windows.local_user.disable", "windows.local_user.delete",
            "windows.ad_user.create", "windows.ad_user.disable", "windows.ad_user.delete",
            "agent.update.request",
        }.OrderBy(t => t, StringComparer.Ordinal).ToArray();
        Assert.Equal(expected, types);
        Assert.DoesNotContain(types, t => t is "ping" or "collect_facts" or "agent_state");
    }
#endif
}
