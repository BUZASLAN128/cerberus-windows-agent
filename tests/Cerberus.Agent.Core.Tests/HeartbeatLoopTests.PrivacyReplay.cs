using System.Net;
using System.Text.Json;
using Cerberus.Agent.App.Telemetry;
using Cerberus.Agent.App.Telemetry.Sections;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class HeartbeatLoopTests
{
    private static object PrivacyReplaySecurity() => new
    {
        status = "ok", defender_av = new { status = "ok" },
        failed_logons = new { status = "ok" }, successful_logons = new { status = "ok" },
        local_admins = new
        {
            status = "ok", count = 1,
            members = new[] { new { name = "PRIVATE_MEMBER", sid = "PRIVATE_SID", added_by = "PRIVATE_ACTOR" } },
            changes = new { count = 1 },
        },
    };

    private sealed class PrivacyReplaySection : IWindowsTelemetrySectionCollector
    {
        public string SectionName => "security";
        public ValueTask<object> CollectAsync(WindowsTelemetryContext context, CancellationToken ct)
            => ValueTask.FromResult(PrivacyReplaySecurity());
    }

    private sealed class RevocablePrivacyProvider : IAgentTelemetryProvider
    {
        public bool MachineConsent = true;
        private readonly WindowsTelemetryCollector _policy;
        public RevocablePrivacyProvider()
            => _policy = new WindowsTelemetryCollector(new[] { new PrivacyReplaySection() },
                hasSnapshotConsent: () => AgentBuildProfile.IsServer || MachineConsent);

        public Task<AgentSnapshotRequest> BuildSnapshotAsync(AgentBuildMetadata metadata, HeartbeatResponse? lastHeartbeat, CancellationToken ct)
            => Task.FromResult(AgentSnapshotFactory.Create(metadata, DateTimeOffset.UtcNow,
                new Dictionary<string, object?> { ["security"] = PrivacyReplaySecurity() }));

        public AgentSnapshotRequest PrepareSnapshotForSubmission(AgentSnapshotRequest snapshot, bool isReplay)
            => _policy.PrepareSnapshotForSubmission(snapshot, isReplay);
    }

    private sealed class PrivacyReplayWire(LoopCaptureHandler accepted) : DelegatingHandler(accepted)
    {
        public bool FailSnapshots = true;
        public List<string> SnapshotBodies { get; } = new();
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/snapshot", StringComparison.Ordinal))
            {
                SnapshotBodies.Add(await request.Content!.ReadAsStringAsync(ct));
                if (FailSnapshots)
                    return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable) { Content = new StringContent("{}") };
            }
            return await base.SendAsync(request, ct);
        }
    }

    [Fact]
    public async Task PrivacyReplay_CurrentConsentIsRecheckedBeforePersistedSnapshotFlush()
    {
        var accepted = new LoopCaptureHandler();
        var wire = new PrivacyReplayWire(accepted);
        using var http = new HttpClient(wire) { BaseAddress = new Uri("http://backend.test") };
        var api = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var root = Path.Combine(Path.GetTempPath(), "cerberus-privacy-replay", Guid.NewGuid().ToString("N"));
        var dispatcher = new CommandDispatcher(Array.Empty<ICommandHandler>(),
            new IdempotencyCache(Path.Combine(root, "idempotency.json"), 10, TimeSpan.FromMinutes(5)));
        var buffer = new OfflineTelemetryBuffer(Path.Combine(root, "buffer.json"));
        var provider = new RevocablePrivacyProvider();
        HeartbeatLoop Loop(TimeSpan initial) => new(api, dispatcher, TimeSpan.FromMilliseconds(10),
            telemetryProvider: provider, telemetryBuffer: buffer, initialSnapshotDelay: initial,
            timingPolicy: ShortPollTiming, log: NullAgentLogger.Instance);

        using (var first = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
        {
            var run = Loop(TimeSpan.Zero).RunAsync(first.Token);
            IReadOnlyList<OfflineTelemetryRecord> records;
            do
            {
                await Task.Delay(20, first.Token);
                records = await buffer.ReadBatchAsync(10, first.Token);
            } while (!records.Any(r => r.Kind == OfflineTelemetryKinds.Snapshot));
            var saved = records.First(r => r.Kind == OfflineTelemetryKinds.Snapshot);
            Assert.Contains("PRIVATE_MEMBER", saved.Json);
            Assert.Contains("PRIVATE_ACTOR", saved.Json);
            first.Cancel();
            await run;
        }

        provider.MachineConsent = false;
        wire.FailSnapshots = false;
        using (var second = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
        {
            var run = Loop(TimeSpan.FromHours(1)).RunAsync(second.Token);
            await accepted.SnapshotSubmittedTask.WaitAsync(second.Token);
            while ((await buffer.ReadBatchAsync(10, second.Token)).Any(r => r.Kind == OfflineTelemetryKinds.Snapshot))
                await Task.Delay(10, second.Token);
            second.Cancel();
            await run;
        }

        using var post = JsonDocument.Parse(wire.SnapshotBodies[^1]);
        var security = post.RootElement.GetProperty("sections").GetProperty("security");
        Assert.Equal(AgentBuildProfile.IsServer, security.TryGetProperty("local_admins", out _));
        Assert.Equal("ok", security.GetProperty("defender_av").GetProperty("status").GetString());
        if (!AgentBuildProfile.IsServer)
        {
            Assert.DoesNotContain("PRIVATE_MEMBER", wire.SnapshotBodies[^1]);
            Assert.DoesNotContain("PRIVATE_SID", wire.SnapshotBodies[^1]);
            Assert.DoesNotContain("PRIVATE_ACTOR", wire.SnapshotBodies[^1]);
        }
        Assert.Equal(AgentSnapshotFactory.HashSection(security),
            post.RootElement.GetProperty("section_hashes").GetProperty("security").GetString());
    }
}
