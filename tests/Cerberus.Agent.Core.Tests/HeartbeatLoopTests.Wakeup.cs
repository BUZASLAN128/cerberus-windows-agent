using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class HeartbeatLoopTests
{
    [Fact]
    public async Task StaleEnrollmentGenerationCannotSendHeartbeat()
    {
        var state = new InMemoryAgentLifecycleStateStore();
        var initial = await state.LoadAsync(default);
        var wire = new ProductLoopHandler();
        using var http = new HttpClient(wire) { BaseAddress = new Uri("https://backend.test") };
        var api = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner(),
            state, expectedGeneration: initial.Generation);
        await new AgentLifecycleController(state).CompleteEnrollmentAsync(initial.Generation, Guid.NewGuid().ToString("N"), default);

        await Assert.ThrowsAsync<AgentLifecycleDormantException>(() => api.HeartbeatAsync(new { status = "connected" }, default));
        Assert.Empty(wire.Paths);
    }

    [Fact]
    public async Task HeartbeatNegotiatesAndExecutesLeaseBoundAsyncCommand()
    {
        var wire = new AsyncCommandLoopHandler();
        using var http = new HttpClient(wire) { BaseAddress = new Uri("https://backend.test") };
        var api = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var commandHandler = new FakeCommandHandler("agent.health.snapshot");
        var dir = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
        var dispatcher = new CommandDispatcher(new[] { commandHandler },
            new IdempotencyCache(Path.Combine(dir, "idem.json"), 10, TimeSpan.FromMinutes(5)));
        await using var processor = new LegacyAsyncCommandProcessor(api, dispatcher,
            new LegacyHeartbeatCommandProcessor(api, dispatcher, TimeSpan.FromSeconds(5), 1),
            new CommandReplayStore(Path.Combine(dir, "async.json")), _ => Task.FromResult("agent-1"));
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var loop = new HeartbeatLoop(api, dispatcher, TimeSpan.FromSeconds(1), commandProcessor: processor,
            supportsEvents: false, legacyAsyncSupported: true);

        var running = loop.RunAsync(stop.Token);
        await wire.ResultReceived.Task.WaitAsync(stop.Token);
        stop.Cancel();
        await running;

        Assert.Contains(LegacyAsyncCommandProcessor.Capability, wire.HeartbeatBody);
        Assert.Equal(1, commandHandler.Calls);
        using var result = JsonDocument.Parse(wire.ResultBody);
        Assert.Equal("DONE", result.RootElement.GetProperty("status").GetString());
        Assert.Equal("33333333-3333-4333-8333-333333333333", result.RootElement.GetProperty("lease_id").GetString());
    }

    private sealed class AsyncCommandLoopHandler : HttpMessageHandler
    {
        public TaskCompletionSource ResultReceived { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public string HeartbeatBody { get; private set; } = "";
        public string ResultBody { get; private set; } = "";

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            var body = await request.Content!.ReadAsStringAsync(ct);
            if (path.EndsWith("/heartbeat", StringComparison.Ordinal))
            {
                HeartbeatBody = body;
                var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                var payload = JsonSerializer.Serialize(new
                {
                    pending_commands = new[] { new { id = "11111111-1111-4111-8111-111111111111", type = "agent.health.snapshot", idempotency_key = "key-1",
                        payload = new { }, lease_id = "33333333-3333-4333-8333-333333333333", lease_expires_at_unix = now + 300 } },
                    next_poll_seconds = 30, next_snapshot_seconds = 300, server_time = now,
                });
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(payload, Encoding.UTF8, "application/json") };
            }
            ResultBody = body;
            ResultReceived.TrySetResult();
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") };
        }
    }

    [Fact]
    public async Task SignedStateProductIgnoresUnsignedVersionAndDoesNotSendUnsupportedEvents()
    {
        var handler = new ProductLoopHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://backend.test") };
        var api = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var dispatcher = new CommandDispatcher(Array.Empty<ICommandHandler>(),
            new IdempotencyCache(Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"), "idem.json"), 10, TimeSpan.FromMinutes(5)));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var processor = new ProductLoopProcessor(cts);
        var loop = new HeartbeatLoop(api, dispatcher, TimeSpan.FromSeconds(1), commandProcessor: processor,
            signedStateOnly: true, supportsEvents: false, signedCommandMode: true, signedCommandsOnly: true);
        await loop.RunAsync(cts.Token);
        Assert.True(processor.Called);
        Assert.Equal(new[] { "/api/v1/agents/agent-1/heartbeat" }, handler.Paths);
        Assert.Contains(CommandEnvelope.Capability, handler.Body);
        Assert.Contains(CommandEnvelope.SignedOnlyCapability, handler.Body);
    }

    private sealed class ProductLoopProcessor(CancellationTokenSource stop) : IHeartbeatCommandProcessor
    {
        public bool Called;
        public Task ProcessAsync(IReadOnlyList<AgentCommand> commands, CancellationToken ct)
        {
            Called = true;
            stop.Cancel();
            return Task.CompletedTask;
        }
    }

    private sealed class ProductLoopHandler : HttpMessageHandler
    {
        public List<string> Paths { get; } = new();
        public string Body { get; private set; } = "";
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Paths.Add(request.RequestUri!.AbsolutePath);
            Body = await request.Content!.ReadAsStringAsync(ct);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("""
                {"pending_commands":[],"next_poll_seconds":30,"next_snapshot_seconds":300,
                 "server_time":1,"version_policy":{"decision":"upgrade_required"}}
                """, Encoding.UTF8, "application/json") };
        }
    }
    [Fact]
    public async Task WakeupSchedulesOneHeartbeatAfterProfileFloor()
    {
        var handler = new WakeupLoopHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://backend.test") };
        var api = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var signal = new AgentWakeupSignal();
        Task Listen(JsonElement _, AgentWakeupSignal s, CancellationToken ct)
        {
            s.Signal();
            s.Signal();
            return Task.Delay(Timeout.InfiniteTimeSpan, ct);
        }
        await using var wakeup = new AgentWakeupClient(api, signal, Listen);
        var dispatcher = new CommandDispatcher(Array.Empty<ICommandHandler>(),
            new IdempotencyCache(Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"), "idem.json"), 10, TimeSpan.FromMinutes(5)));
        var timing = new AgentTimingPolicy(new AgentTimingBounds(1, 60, 60, 3600, 60));
        var loop = new HeartbeatLoop(api, dispatcher, TimeSpan.FromSeconds(1), timingPolicy: timing,
            wakeupSignal: signal, wakeupClient: wakeup);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        var run = loop.RunAsync(cts.Token);
        await handler.SecondHeartbeat.Task.WaitAsync(cts.Token);
        cts.Cancel();
        await run;
        Assert.True(handler.SecondElapsed >= TimeSpan.FromMilliseconds(850), $"Wakeup bypassed floor: {handler.SecondElapsed}");
        Assert.True(handler.SecondElapsed < TimeSpan.FromSeconds(6), $"Wakeup did not shorten idle polling: {handler.SecondElapsed}");
        Assert.Contains(AgentWakeupProtocol.Capability, handler.FirstBody);
        Assert.DoesNotContain(CommandEnvelope.Capability, handler.FirstBody);
        Assert.Equal(1, handler.MaxConcurrent);
    }

    [Fact]
    public async Task WakeupCannotInterruptRateLimitBackoff()
    {
        var handler = new WakeupLoopHandler(rateLimitSecond: true);
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://backend.test") };
        var api = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var signal = new AgentWakeupSignal();
        Task Listen(JsonElement _, AgentWakeupSignal s, CancellationToken ct)
        {
            s.Signal();
            return Task.Delay(Timeout.InfiniteTimeSpan, ct);
        }
        await using var wakeup = new AgentWakeupClient(api, signal, Listen);
        var dispatcher = new CommandDispatcher(Array.Empty<ICommandHandler>(),
            new IdempotencyCache(Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"), "idem.json"), 10, TimeSpan.FromMinutes(5)));
        var timing = new AgentTimingPolicy(new AgentTimingBounds(1, 60, 60, 3600, 60));
        var loop = new HeartbeatLoop(api, dispatcher, TimeSpan.FromSeconds(1), timingPolicy: timing,
            wakeupSignal: signal, wakeupClient: wakeup);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        var run = loop.RunAsync(cts.Token);
        await handler.SecondHeartbeat.Task.WaitAsync(cts.Token);
        await Task.Delay(200, cts.Token);
        signal.Signal();
        signal.Signal();
        await Task.Delay(1200, cts.Token);
        Assert.Equal(2, handler.HeartbeatCount);
        cts.Cancel();
        await run;
    }

    private sealed class WakeupLoopHandler : HttpMessageHandler
    {
        private readonly bool _rateLimitSecond;
        private readonly Stopwatch _clock = Stopwatch.StartNew();
        private int _count;
        private int _inFlight;
        public int MaxConcurrent { get; private set; }
        public string FirstBody { get; private set; } = "";
        public TimeSpan SecondElapsed { get; private set; }
        public TaskCompletionSource SecondHeartbeat { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public int HeartbeatCount => Volatile.Read(ref _count);

        public WakeupLoopHandler(bool rateLimitSecond = false) => _rateLimitSecond = rateLimitSecond;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            if (!request.RequestUri!.AbsolutePath.EndsWith("/heartbeat", StringComparison.Ordinal))
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{}") };
            var active = Interlocked.Increment(ref _inFlight);
            MaxConcurrent = Math.Max(MaxConcurrent, active);
            try
            {
                var count = Interlocked.Increment(ref _count);
                var body = await request.Content!.ReadAsStringAsync(ct);
                if (count == 1) { FirstBody = body; _clock.Restart(); }
                if (count == 2) { SecondElapsed = _clock.Elapsed; SecondHeartbeat.TrySetResult(); }
                if (count == 2 && _rateLimitSecond)
                {
                    var limited = new HttpResponseMessage(HttpStatusCode.TooManyRequests) { Content = new StringContent("{}") };
                    limited.Headers.TryAddWithoutValidation("Retry-After", "5");
                    return limited;
                }
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent("""
                        {"pending_commands":[],"next_poll_seconds":30,"next_snapshot_seconds":300,
                         "server_time":1,"wakeup":{"version":1,"path":"/api/v1/agents/agent-1/wakeup"}}
                        """, Encoding.UTF8, "application/json")
                };
            }
            finally { Interlocked.Decrement(ref _inFlight); }
        }
    }
}
