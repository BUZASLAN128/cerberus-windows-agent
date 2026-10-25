using System.Net;
using System.Text;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class HeartbeatLoopTests
{
    // The server profile floors polls at 30 s; these tests wait on the second heartbeat, so they use the desktop bounds.
    private static readonly AgentTimingPolicy ShortPollTiming = new(new AgentTimingBounds(1, 3600, 60, 86400, 60));

    [Fact]
    public async Task RunAsync_SubmitsSnapshot_WhenResponseSkipsCommands()
    {
        var handler = new LoopCaptureHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var cachePath = Path.Combine(
            Path.GetTempPath(),
            "cerberus-agent-tests",
            Guid.NewGuid().ToString("N"),
            "idempotency.json");
        var dispatcher = new CommandDispatcher(
            new[] { new CaptureCommandHandler() },
            new IdempotencyCache(cachePath, maxEntries: 10, ttl: TimeSpan.FromMinutes(5)));
        var loop = new HeartbeatLoop(
            client,
            dispatcher,
            minDelayOnError: TimeSpan.FromMilliseconds(10),
            responseHandler: new HeartbeatResponseHandler(new StaticSecretStore(), NullAgentLogger.Instance),
            telemetryProvider: new StaticTelemetryProvider(),
            log: NullAgentLogger.Instance,
            initialSnapshotDelay: TimeSpan.Zero);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = loop.RunAsync(cts.Token);
        await handler.SnapshotSubmittedTask.WaitAsync(cts.Token);
        cts.Cancel();
        await runTask;

        Assert.True(handler.SnapshotSubmitted);
        Assert.Equal(AgentBuildProfile.IsServer, handler.CommandResultSubmitted); // server: the unsigned quarantine does not skip commands
    }

    [Fact]
    public async Task RunAsync_SignalsOutboxWithoutRunningCommands_WhenResponseSkipsCommands()
    {
        var handler = new LoopCaptureHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var dispatcher = new CommandDispatcher(
            Array.Empty<ICommandHandler>(),
            new IdempotencyCache(Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"), "idempotency.json"), 10, TimeSpan.FromMinutes(5)));
        var processor = new OutboxRecordingProcessor();
        var loop = new HeartbeatLoop(
            client,
            dispatcher,
            minDelayOnError: TimeSpan.FromMilliseconds(10),
            responseHandler: new HeartbeatResponseHandler(new StaticSecretStore(), NullAgentLogger.Instance),
            log: NullAgentLogger.Instance,
            commandProcessor: processor);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = loop.RunAsync(cts.Token);
        await processor.FirstCall.WaitAsync(cts.Token);
        cts.Cancel();
        await runTask;

        // Desktop: the quarantine skips commands but still requests the result outbox pass.
        // Server: the unsigned quarantine is not a skip, so commands run as usual.
        if (AgentBuildProfile.IsServer)
        {
            Assert.True(processor.ProcessCalls >= 1);
            Assert.Equal(0, processor.SignalCalls);
        }
        else
        {
            Assert.True(processor.SignalCalls >= 1);
            Assert.Equal(0, processor.ProcessCalls);
        }
    }

#if !CERBERUS_SERVER_PROFILE
    [Fact]
    public async Task RunAsync_SignalsOutboxWithoutRunningCommands_WhenVersionUpgradeRequired()
    {
        using var http = new HttpClient(new UpgradeRequiredHandler()) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var dispatcher = new CommandDispatcher(
            Array.Empty<ICommandHandler>(),
            new IdempotencyCache(Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"), "idempotency.json"), 10, TimeSpan.FromMinutes(5)));
        var processor = new OutboxRecordingProcessor();
        var loop = new HeartbeatLoop(
            client,
            dispatcher,
            minDelayOnError: TimeSpan.FromMilliseconds(10),
            responseHandler: new HeartbeatResponseHandler(new StaticSecretStore(), NullAgentLogger.Instance),
            log: NullAgentLogger.Instance,
            commandProcessor: processor);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = loop.RunAsync(cts.Token);
        await processor.FirstCall.WaitAsync(cts.Token);
        cts.Cancel();
        await runTask;

        // A version-blocked agent runs no commands but must still retry a result whose POST failed earlier.
        Assert.True(processor.SignalCalls >= 1);
        Assert.Equal(0, processor.ProcessCalls);
    }

    private sealed class UpgradeRequiredHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (!request.RequestUri!.AbsolutePath.EndsWith("/heartbeat", StringComparison.Ordinal))
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(
                    """
                    {
                      "pending_commands": [
                        {"id": "cmd-1", "type": "test.command", "idempotency_key": "cmd-1", "payload": {}}
                      ],
                      "next_poll_seconds": 60,
                      "server_time": 1,
                      "server_time_utc": "2026-05-08T00:00:00Z",
                      "command_batch_size": 1,
                      "next_snapshot_seconds": 60,
                      "config_version": "agent-config.v1",
                      "lifecycle_state": "connected",
                      "version_policy": {"decision": "upgrade_required", "reason": "blocked_version"},
                      "update": null,
                      "revoke": null,
                      "quarantine": null
                    }
                    """,
                    Encoding.UTF8,
                    "application/json"),
            });
        }
    }
#endif

    private sealed class OutboxRecordingProcessor : IHeartbeatCommandProcessor
    {
        private int _process;
        private int _signal;
        private readonly TaskCompletionSource _first = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int ProcessCalls => Volatile.Read(ref _process);
        public int SignalCalls => Volatile.Read(ref _signal);
        public Task FirstCall => _first.Task;

        public Task ProcessAsync(IReadOnlyList<AgentCommand> commands, CancellationToken ct)
        {
            Interlocked.Increment(ref _process);
            _first.TrySetResult();
            return Task.CompletedTask;
        }

        public void SignalOutbox()
        {
            Interlocked.Increment(ref _signal);
            _first.TrySetResult();
        }
    }

    [Fact]
    public async Task RunAsync_SubmitsRefreshSnapshotOnNextHeartbeat_AndKeepsChangeMadeDuringCollectionPending()
    {
        var provider = new RefreshableTelemetryProvider();
        provider.DuringBuild = buildNumber =>
        {
            if (buildNumber == 1)
                provider.RequestRefresh();
        };
        var handler = new SchedulingLoopHandler(attempt =>
        {
            if (attempt == 1)
                provider.RequestRefresh();
        });
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var dispatcher = new CommandDispatcher(
            Array.Empty<ICommandHandler>(),
            new IdempotencyCache(Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"), "idempotency.json"), 10, TimeSpan.FromMinutes(5)));
        var loop = new HeartbeatLoop(
            client,
            dispatcher,
            minDelayOnError: TimeSpan.FromMilliseconds(10),
            telemetryProvider: provider,
            log: NullAgentLogger.Instance,
            initialSnapshotDelay: TimeSpan.FromMinutes(5),
            timingPolicy: ShortPollTiming);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = loop.RunAsync(cts.Token);
        await handler.SecondSnapshotSubmittedTask.WaitAsync(cts.Token);
        cts.Cancel();
        await runTask;

        Assert.Equal(2, handler.SnapshotAttempts);
        Assert.Equal(2, provider.BuildCount);
        Assert.Equal(2, provider.SubmittedVersion);
        Assert.False(provider.IsSnapshotRefreshRequired());
    }

    [Fact]
    public async Task RunAsync_DoesNotSubmitSnapshotForStableTelemetryBeforeNormalCadence()
    {
        var provider = new RefreshableTelemetryProvider();
        var handler = new SchedulingLoopHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var dispatcher = new CommandDispatcher(
            Array.Empty<ICommandHandler>(),
            new IdempotencyCache(Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"), "idempotency.json"), 10, TimeSpan.FromMinutes(5)));
        var loop = new HeartbeatLoop(
            client,
            dispatcher,
            minDelayOnError: TimeSpan.FromMilliseconds(10),
            telemetryProvider: provider,
            log: NullAgentLogger.Instance,
            initialSnapshotDelay: TimeSpan.FromMinutes(5),
            timingPolicy: ShortPollTiming);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = loop.RunAsync(cts.Token);
        await handler.SecondHeartbeatTask.WaitAsync(cts.Token);
        cts.Cancel();
        await runTask;

        Assert.Equal(0, handler.SnapshotAttempts);
        Assert.Equal(0, provider.BuildCount);
    }

    [Fact]
    public async Task RunAsync_RetriesRefreshSnapshotAfterSubmissionFailureWithoutAcknowledgingIt()
    {
        var provider = new RefreshableTelemetryProvider();
        provider.RequestRefresh();
        var handler = new SchedulingLoopHandler(snapshotFailuresBeforeSuccess: 1);
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var dispatcher = new CommandDispatcher(
            Array.Empty<ICommandHandler>(),
            new IdempotencyCache(Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"), "idempotency.json"), 10, TimeSpan.FromMinutes(5)));
        var loop = new HeartbeatLoop(
            client,
            dispatcher,
            minDelayOnError: TimeSpan.FromMilliseconds(10),
            telemetryProvider: provider,
            log: NullAgentLogger.Instance,
            initialSnapshotDelay: TimeSpan.FromMinutes(5),
            timingPolicy: ShortPollTiming);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = loop.RunAsync(cts.Token);
        await handler.SnapshotSubmittedTask.WaitAsync(cts.Token);
        cts.Cancel();
        await runTask;

        Assert.Equal(2, handler.SnapshotAttempts);
        Assert.Equal(2, provider.BuildCount);
        Assert.Equal(1, provider.MarkSubmittedCount);
        Assert.False(provider.IsSnapshotRefreshRequired());
    }

    [Fact]
    public async Task RunAsync_IncludesUpdateStatusProviderPayload()
    {
        var handler = new LoopCaptureHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var cachePath = Path.Combine(
            Path.GetTempPath(),
            "cerberus-agent-tests",
            Guid.NewGuid().ToString("N"),
            "idempotency.json");
        var dispatcher = new CommandDispatcher(
            new[] { new CaptureCommandHandler() },
            new IdempotencyCache(cachePath, maxEntries: 10, ttl: TimeSpan.FromMinutes(5)));
        var loop = new HeartbeatLoop(
            client,
            dispatcher,
            minDelayOnError: TimeSpan.FromMilliseconds(10),
            updateStatusProvider: _ => Task.FromResult<object?>(new
            {
                schema_version = "agent.update.status.v1",
                state = "staged",
                target_version = "0.2.0",
            }),
            responseHandler: new HeartbeatResponseHandler(new StaticSecretStore(), NullAgentLogger.Instance),
            log: NullAgentLogger.Instance);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = loop.RunAsync(cts.Token);
        await handler.HeartbeatSubmittedTask.WaitAsync(cts.Token);
        cts.Cancel();
        await runTask;

        Assert.Contains(handler.HeartbeatBodies, body => body.Contains("\"update_status\""));
        Assert.Contains(handler.HeartbeatBodies, body => body.Contains("\"state\":\"staged\""));
    }

    [Fact]
    public async Task RunAsync_SubmitsFailedResultAndContinues_WhenCommandHandlerThrows()
    {
        var handler = new CommandFailureLoopHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var cachePath = Path.Combine(
            Path.GetTempPath(),
            "cerberus-agent-tests",
            Guid.NewGuid().ToString("N"),
            "idempotency.json");
        var dispatcher = new CommandDispatcher(
            new ICommandHandler[] { new ThrowingCommandHandler(), new CaptureCommandHandler() },
            new IdempotencyCache(cachePath, maxEntries: 10, ttl: TimeSpan.FromMinutes(5)));
        var loop = new HeartbeatLoop(
            client,
            dispatcher,
            minDelayOnError: TimeSpan.FromMilliseconds(10),
            responseHandler: new HeartbeatResponseHandler(new StaticSecretStore(), NullAgentLogger.Instance),
            log: NullAgentLogger.Instance,
            commandTimeout: TimeSpan.FromMilliseconds(100));

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(350));
        await loop.RunAsync(cts.Token);

        Assert.Equal(2, handler.CommandResults.Count);
        Assert.Contains(handler.CommandResults, body => body.Contains("\"status\":\"FAILED\""));
        Assert.Contains(handler.CommandResults, body => body.Contains("\"status\":\"DONE\""));
    }

    [Fact]
    public async Task RunAsync_AcknowledgesAdLeaseBeforeDispatchAndReportsSameLease()
    {
        var trace = new List<string>();
        var handler = new AdCommandLoopHandler(blockAckResponse: true, trace: trace.Add);
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var cachePath = Path.Combine(
            Path.GetTempPath(),
            "cerberus-agent-tests",
            Guid.NewGuid().ToString("N"),
            "idempotency.json");
        var dispatcher = new CommandDispatcher(
            new ICommandHandler[] { new AuthoritativeCommandHandler(() => trace.Add("dispatch")) },
            new IdempotencyCache(cachePath, maxEntries: 10, ttl: TimeSpan.FromMinutes(5)));
        var loop = new HeartbeatLoop(
            client,
            dispatcher,
            minDelayOnError: TimeSpan.FromMilliseconds(10),
            log: NullAgentLogger.Instance);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = loop.RunAsync(cts.Token);
        await handler.AckRequestedTask.WaitAsync(cts.Token);
        Assert.Equal(new[] { "ack" }, trace);
        handler.ReleaseAckResponse();
        await handler.ResultSubmittedTask.WaitAsync(cts.Token);
        cts.Cancel();
        await runTask;

        Assert.Equal(new[] { "ack", "dispatch", "result" }, trace);
        Assert.Equal(new[] { "ack", "result" }, handler.Operations);
        Assert.Equal("lease-ad", handler.Leases[0]);
        Assert.Equal("lease-ad", handler.Leases[1]);
    }

    [Fact]
    public async Task RunAsync_DoesNotDispatchOrReportAdCommand_WhenAckIsRejected()
    {
        var handler = new AdCommandLoopHandler(HttpStatusCode.Conflict);
        var dispatches = new List<string>();
        var failureObserved = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var cachePath = Path.Combine(
            Path.GetTempPath(),
            "cerberus-agent-tests",
            Guid.NewGuid().ToString("N"),
            "idempotency.json");
        var dispatcher = new CommandDispatcher(
            new ICommandHandler[] { new AuthoritativeCommandHandler(() => dispatches.Add("dispatch")) },
            new IdempotencyCache(cachePath, maxEntries: 10, ttl: TimeSpan.FromMinutes(5)));
        var loop = new HeartbeatLoop(
            client,
            dispatcher,
            minDelayOnError: TimeSpan.FromMilliseconds(10),
            log: NullAgentLogger.Instance,
            backoffResetRequested: _ =>
            {
                failureObserved.TrySetResult();
                return Task.FromResult(false);
            });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var runTask = loop.RunAsync(cts.Token);
        await failureObserved.Task.WaitAsync(cts.Token);
        cts.Cancel();
        await runTask;

        Assert.Empty(dispatches);
        Assert.Equal(new[] { "ack" }, handler.Operations);
        Assert.Single(handler.Leases);
        Assert.Equal("lease-ad", handler.Leases[0]);
    }

    [Fact]
    public void CalculateErrorDelay_BacksOffAndCaps_WhenBackendStaysUnavailable()
    {
        var min = TimeSpan.FromSeconds(10);
        var max = TimeSpan.FromMinutes(10);

        Assert.Equal(TimeSpan.FromSeconds(10), HeartbeatLoop.CalculateErrorDelay(min, max, 1));
        Assert.Equal(TimeSpan.FromSeconds(20), HeartbeatLoop.CalculateErrorDelay(min, max, 2));
        Assert.Equal(TimeSpan.FromSeconds(40), HeartbeatLoop.CalculateErrorDelay(min, max, 3));
        Assert.Equal(max, HeartbeatLoop.CalculateErrorDelay(min, max, 20));
    }

    [Fact]
    public async Task RunAsync_RetriesImmediately_WhenBackoffResetRequested()
    {
        var handler = new InvalidHeartbeatPayloadHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("http://backend.test") };
        var client = new AgentApiClient(http, new StaticSecretStore(), new StaticTokenManager(), new StaticSigner());
        var cachePath = Path.Combine(
            Path.GetTempPath(),
            "cerberus-agent-tests",
            Guid.NewGuid().ToString("N"),
            "idempotency.json");
        var dispatcher = new CommandDispatcher(
            Array.Empty<ICommandHandler>(),
            new IdempotencyCache(cachePath, maxEntries: 10, ttl: TimeSpan.FromMinutes(5)));
        var resetChecks = 0;
        var loop = new HeartbeatLoop(
            client,
            dispatcher,
            minDelayOnError: TimeSpan.FromSeconds(30),
            maxDelayOnError: TimeSpan.FromMinutes(10),
            backoffResetRequested: _ =>
                Task.FromResult(Interlocked.Increment(ref resetChecks) == 1),
            log: NullAgentLogger.Instance);

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var runTask = loop.RunAsync(cts.Token);
        await handler.SecondHeartbeatAttemptTask.WaitAsync(cts.Token);
        cts.Cancel();
        await runTask;

        Assert.True(handler.HeartbeatAttempts >= 2);
        Assert.True(resetChecks >= 1);
    }
}
