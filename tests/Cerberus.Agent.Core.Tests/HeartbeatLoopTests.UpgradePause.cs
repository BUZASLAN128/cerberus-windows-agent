using System.Diagnostics;
using System.Net;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class HeartbeatLoopTests
{
#if !CERBERUS_SERVER_PROFILE
    [Fact]
    public async Task UpgradeRequiredPausesFullLegacyQueueAndStillDeliversRunningResult()
    {
        var parent = Path.GetFullPath(Path.GetTempPath());
        var root = Path.Combine(parent, "cerberus-upgrade-pause-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var wire = new UpgradePauseWire();
            using var http = new HttpClient(wire) { BaseAddress = new Uri("http://backend.test") };
            var api = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
            var handler = new FakeCommandHandler("agent.health.snapshot").Block();
            var dispatcher = new CommandDispatcher(new[] { handler }, new IdempotencyCache(Path.Combine(root, "idem.json"), 100, TimeSpan.FromHours(1)));
            var store = new CommandReplayStore(Path.Combine(root, "replay.json"));
            await using var processor = new LegacyAsyncCommandProcessor(api, dispatcher,
                new LegacyHeartbeatCommandProcessor(api, dispatcher, TimeSpan.FromSeconds(5), 1), store, _ => Task.FromResult("agent-1"));
            var observed = new UpgradePauseObserver(processor);
            var commands = Enumerable.Range(0, LegacyAsyncCommandProcessor.MaxPending).Select(i =>
                new AgentCommand(Guid.NewGuid().ToString("D"), handler.Type, "upgrade-pause-" + i, new { },
                    Guid.NewGuid().ToString("D"), null, DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 300)
                { SafeLeaseDeadlineTimestamp = Stopwatch.GetTimestamp() + 240 * Stopwatch.Frequency }).ToArray();
            wire.FirstId = commands[0].Id;
            await processor.ProcessAsync(commands, default);
            await handler.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(LegacyAsyncCommandProcessor.MaxPending, store.Records("agent-1").Count);
            var loop = new HeartbeatLoop(api, dispatcher, TimeSpan.FromSeconds(1), supportsEvents: false,
                commandProcessor: observed, responseHandler: new HeartbeatResponseHandler(new StaticSecretStore()));
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var run = loop.RunAsync(stop.Token);
            try
            {
                await observed.Paused.Task.WaitAsync(stop.Token);
                handler.Gate.TrySetResult();
                await wire.FirstResult.Task.WaitAsync(stop.Token);
                var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                var sentinel = StoreFileWriter.Record("agent-1", Guid.NewGuid().ToString("D"), Guid.NewGuid().ToString("D"),
                    EnvelopeRecordStates.Reserved, now, now + 300, submitted: false) with { Type = handler.Type };
                Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(sentinel));
                var body = JsonSerializer.SerializeToUtf8Bytes(FakeCommandHandler.Done(), new JsonSerializerOptions(JsonSerializerDefaults.Web));
                Assert.Equal(ReplayUpdateOutcome.Updated, store.TryUpdate(sentinel with { State = EnvelopeRecordStates.Done,
                    ResultB64 = Convert.ToBase64String(body), ResultSha256 = CommandEnvelope.Sha256Hex(body) }, sentinel.State));
                wire.ReleaseResult.TrySetResult();
                await Wait.UntilAsync(() => store.Find("agent-1", sentinel.Id)!.ResultSubmitted, "result outbox continues under upgrade pause");
                Assert.True(store.Find("agent-1", commands[0].Id)!.ResultSubmitted);
                Assert.All(commands.Skip(1), command => Assert.Equal(EnvelopeRecordStates.Reserved, store.Find("agent-1", command.Id)!.State));
                Assert.Equal(1, handler.Calls);
            }
            finally { handler.Gate.TrySetResult(); wire.ReleaseResult.TrySetResult(); stop.Cancel(); await run; }
        }
        finally
        {
            var resolved = Path.GetFullPath(root);
            Assert.Equal(parent.TrimEnd(Path.DirectorySeparatorChar), Path.GetDirectoryName(resolved), ignoreCase: true);
            if (Directory.Exists(resolved)) Directory.Delete(resolved, true);
        }
    }

    private sealed class UpgradePauseObserver(IHeartbeatCommandProcessor inner) : IHeartbeatCommandProcessor
    {
        public TaskCompletionSource Paused { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task ProcessAsync(IReadOnlyList<AgentCommand> commands, CancellationToken ct) => inner.ProcessAsync(commands, ct);
        public void SignalOutbox() => inner.SignalOutbox();
        public void SetExecutionPaused(bool paused) { inner.SetExecutionPaused(paused); if (paused) Paused.TrySetResult(); }
    }

    private sealed class UpgradePauseWire : HttpMessageHandler
    {
        public string FirstId = "";
        public TaskCompletionSource FirstResult { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseResult { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("/" + FirstId + "/result", StringComparison.Ordinal))
            {
                FirstResult.TrySetResult();
                await ReleaseResult.Task.WaitAsync(ct);
            }
            var body = path.EndsWith("/heartbeat", StringComparison.Ordinal)
                ? "{\"pending_commands\":[],\"next_poll_seconds\":300,\"server_time\":1,\"version_policy\":{\"decision\":\"upgrade_required\",\"reason\":\"owned-policy\"}}"
                : "{}";
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") };
        }
    }
#endif
}
