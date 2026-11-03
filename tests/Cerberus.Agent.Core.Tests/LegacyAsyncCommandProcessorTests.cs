using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class LegacyAsyncCommandProcessorTests
{
    [Theory]
    [InlineData(EnvelopeRecordStates.Done, "DONE")]
    [InlineData(EnvelopeRecordStates.Started, "OUTCOME_UNKNOWN")]
    public async Task SentReplayRecordsDoNotStarvePendingOrRecoveredResult(string state, string expectedStatus)
    {
        await using var h = EnvelopeHarness.Create();
        var handler = new FakeCommandHandler("agent.health.snapshot");
        var dispatcher = Dispatcher(h, handler);
        var store = NewStore(h);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var resultBytes = JsonSerializer.SerializeToUtf8Bytes(FakeCommandHandler.Done(), new JsonSerializerOptions(JsonSerializerDefaults.Web));
        var resultB64 = Convert.ToBase64String(resultBytes);
        var resultHash = Convert.ToHexString(SHA256.HashData(resultBytes)).ToLowerInvariant();
        for (var index = 0; index < 16; index++)
        {
            var sent = new CommandReplayRecord(h.AgentId, Guid.NewGuid().ToString("D"), new string('a', 64),
                Guid.NewGuid().ToString("D"), handler.Type, now, now + 100 + index,
                EnvelopeRecordStates.Reserved, null, null, false);
            Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(sent));
            Assert.True(store.TryUpdate(sent with { State = EnvelopeRecordStates.Done, ResultB64 = resultB64,
                ResultSha256 = resultHash, ResultSubmitted = true }));
        }
        var pending = new CommandReplayRecord(h.AgentId, Guid.NewGuid().ToString("D"), new string('b', 64),
            Guid.NewGuid().ToString("D"), handler.Type, now, now + 300,
            EnvelopeRecordStates.Reserved, null, null, false);
        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(pending));
        Assert.True(store.TryUpdate(pending with { State = state,
            ResultB64 = state == EnvelopeRecordStates.Done ? resultB64 : null,
            ResultSha256 = state == EnvelopeRecordStates.Done ? resultHash : null }));
        await using var processor = new LegacyAsyncCommandProcessor(h.Api, dispatcher,
            new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromSeconds(5), 1),
            store, _ => Task.FromResult(h.AgentId));

        await Wait.UntilAsync(() => store.Find(h.AgentId, pending.Id)?.ResultSubmitted == true, "pending result after retained replay records");
        Assert.Equal(expectedStatus, Assert.Single(h.Backend.Results).Json.GetProperty("status").GetString());
        Assert.Equal(17, store.Records(h.AgentId).Count);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task LongCommandReturnsToHeartbeatAndPostsLeaseBoundResult()
    {
        await using var h = EnvelopeHarness.Create();
        var handler = new FakeCommandHandler("agent.health.snapshot");
        handler.Body = async (_, _) =>
        {
            handler.Started.TrySetResult();
            await handler.Gate.Task;
            return FakeCommandHandler.Done();
        };
        var dispatcher = Dispatcher(h, handler);
        var store = NewStore(h);
        await using var processor = new LegacyAsyncCommandProcessor(h.Api, dispatcher,
            new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromSeconds(5), 1),
            store, _ => Task.FromResult(h.AgentId), h.Log, h.Time);
        var command = Command();

        await processor.ProcessAsync(new[] { command }, default).WaitAsync(TimeSpan.FromSeconds(10));
        await handler.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Empty(h.Backend.Results);
        handler.Gate.TrySetResult();
        await Wait.UntilAsync(() => h.Backend.Results.Count == 1, "lease-bound result");
        Assert.Equal("33333333-3333-4333-8333-333333333333", h.Backend.Results[0].Json.GetProperty("lease_id").GetString());
        Assert.Equal("DONE", h.Backend.Results[0].Json.GetProperty("status").GetString());
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task RestartReportsUnknownWithoutRerunningAndRetriesUnsentResult()
    {
        await using var h = EnvelopeHarness.Create();
        var handler = new FakeCommandHandler("agent.health.snapshot");
        var dispatcher = Dispatcher(h, handler);
        var store = NewStore(h);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var record = new CommandReplayRecord(h.AgentId, "11111111-1111-4111-8111-111111111111", new string('a', 64), "33333333-3333-4333-8333-333333333333",
            handler.Type, now, now + 300, EnvelopeRecordStates.Reserved, null, null, false);
        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(record));
        Assert.Equal(ReplayUpdateOutcome.Updated, store.TryUpdate(record with { State = EnvelopeRecordStates.Started },
            EnvelopeRecordStates.Reserved));
        h.Backend.Respond = (_, _) => Task.FromResult(HttpStatusCode.ServiceUnavailable);
        await using var processor = new LegacyAsyncCommandProcessor(h.Api, dispatcher,
            new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromSeconds(5), 1),
            store, _ => Task.FromResult(h.AgentId), h.Log, h.Time);

        await Wait.UntilAsync(() => h.Log.Lines.Any(line => line.Contains("result retained")), "first outbox failure recorded");
        Assert.Equal("OUTCOME_UNKNOWN", h.Backend.Results[0].Json.GetProperty("status").GetString());
        Assert.Equal(0, handler.Calls);
        Assert.False(store.Find(h.AgentId, "11111111-1111-4111-8111-111111111111")!.ResultSubmitted);
        h.Backend.Respond = (_, _) => Task.FromResult(HttpStatusCode.OK);
        h.Time.Advance(TimeSpan.FromSeconds(10));
        processor.SignalOutbox();
        await Wait.UntilAsync(() => h.Backend.Results.Count == 2, "retried outbox result");
        Assert.Equal("33333333-3333-4333-8333-333333333333", h.Backend.Results[1].Json.GetProperty("lease_id").GetString());
        await Wait.UntilAsync(() => store.Find(h.AgentId, "11111111-1111-4111-8111-111111111111")!.ResultSubmitted, "outbox acknowledged");
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task ExpiredOrMissingLeaseDeadlineNeverExecutes()
    {
        await using var h = EnvelopeHarness.Create();
        var handler = new FakeCommandHandler("agent.health.snapshot");
        var dispatcher = Dispatcher(h, handler);
        await using var processor = new LegacyAsyncCommandProcessor(h.Api, dispatcher,
            new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromSeconds(5), 1),
            NewStore(h), _ => Task.FromResult(h.AgentId));
        await processor.ProcessAsync(new[] { Command() with { SafeLeaseDeadlineTimestamp = Stopwatch.GetTimestamp() - 1 } }, default);
        await processor.ProcessAsync(new[] { Command() with { SafeLeaseDeadlineTimestamp = null } }, default);
        Assert.Equal(0, handler.Calls);
        Assert.Empty(h.Backend.Results);
    }

    [Fact]
    public async Task OutboxHonorsRateLimitRetryAfter()
    {
        await using var h = EnvelopeHarness.Create();
        var handler = new FakeCommandHandler("agent.health.snapshot");
        var dispatcher = Dispatcher(h, handler);
        var store = NewStore(h);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var record = new CommandReplayRecord(h.AgentId, "11111111-1111-4111-8111-111111111111", new string('a', 64), "33333333-3333-4333-8333-333333333333",
            handler.Type, now, now + 300, EnvelopeRecordStates.Reserved, null, null, false);
        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(record));
        h.Backend.Respond = (_, _) => Task.FromResult(HttpStatusCode.TooManyRequests);
        h.Backend.RetryAfter = "3600";
        await using var processor = new LegacyAsyncCommandProcessor(h.Api, dispatcher,
            new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromSeconds(5), 1),
            store, _ => Task.FromResult(h.AgentId), h.Log, h.Time);
        await Wait.UntilAsync(() => h.Log.Lines.Any(line => line.Contains("result retained")), "rate limit recorded");
        Assert.Equal(h.Time.GetTimestamp() + AgentTimingPolicy.Current.Bounds.PollCeiling * h.Time.TimestampFrequency, processor.OutboxNotBefore);
        Assert.False(store.Find(h.AgentId, "11111111-1111-4111-8111-111111111111")!.ResultSubmitted);
    }

    [Fact]
    public async Task ReplacingWorkerDoesNotStartAnotherHandlerWhileOldOneIgnoresCancellation()
    {
        await using var h = EnvelopeHarness.Create();
        var handler = new FakeCommandHandler("agent.health.snapshot");
        handler.Body = async (_, _) =>
        {
            handler.Started.TrySetResult();
            await handler.Gate.Task;
            return FakeCommandHandler.Done();
        };
        var dispatcher = Dispatcher(h, handler);
        var firstStore = NewStore(h);
        var first = new LegacyAsyncCommandProcessor(h.Api, dispatcher,
            new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromSeconds(5), 1),
            firstStore, _ => Task.FromResult(h.AgentId));
        try
        {
            await first.ProcessAsync(new[] { Command() }, default);
            await handler.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await first.DisposeAsync();

            var nextStore = NewStore(h);
            await using var second = new LegacyAsyncCommandProcessor(h.Api, dispatcher,
                new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromSeconds(5), 1),
                nextStore, _ => Task.FromResult(h.AgentId));
            var next = Command() with { Id = "22222222-2222-4222-8222-222222222222", IdempotencyKey = "key-2", LeaseId = "44444444-4444-4444-8444-444444444444" };
            await second.ProcessAsync(new[] { next }, default);
            await Wait.UntilAsync(() => nextStore.Find(h.AgentId, "22222222-2222-4222-8222-222222222222")?.State == EnvelopeRecordStates.Started,
                "replacement waiting for the prior handler");
            Assert.Equal(1, handler.Calls);
            handler.Gate.TrySetResult();
            await Wait.UntilAsync(() => handler.Calls == 2, "replacement handler started");
        }
        finally { handler.Gate.TrySetResult(); }
    }

    [Fact]
    public async Task RevokeCancellationStopsAcceptingWorkAndKeepsStartedEvidence()
    {
        await using var h = EnvelopeHarness.Create();
        var handler = new FakeCommandHandler("agent.health.snapshot").Block();
        var dispatcher = Dispatcher(h, handler);
        var store = NewStore(h);
        await using var processor = new LegacyAsyncCommandProcessor(h.Api, dispatcher,
            new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromSeconds(5), 1),
            store, _ => Task.FromResult(h.AgentId));
        await processor.ProcessAsync(new[] { Command() }, default);
        await handler.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));

        processor.CancelAll();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => processor.ProcessAsync(new[] { Command() }, default));
        await Wait.UntilAsync(() => store.Find(h.AgentId, "11111111-1111-4111-8111-111111111111")?.State == EnvelopeRecordStates.Started,
            "durable started evidence");
    }

    [Fact]
    public async Task SynchronouslyBlockedHandlerDoesNotBlockWorkerShutdown()
    {
        await using var h = EnvelopeHarness.Create();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var completed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var handler = new FakeCommandHandler("agent.health.snapshot");
        handler.Body = (_, _) =>
        {
            started.TrySetResult();
            release.Task.GetAwaiter().GetResult();
            completed.TrySetResult();
            return Task.FromResult(FakeCommandHandler.Done());
        };
        var dispatcher = Dispatcher(h, handler);
        await using var processor = new LegacyAsyncCommandProcessor(h.Api, dispatcher,
            new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromSeconds(5), 1),
            NewStore(h), _ => Task.FromResult(h.AgentId));
        try
        {
            await processor.ProcessAsync(new[] { Command() }, default);
            await started.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await processor.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        }
        finally
        {
            release.TrySetResult();
            if (started.Task.IsCompleted) await completed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    [Fact]
    public void LeaseDeadlineUsesPreRequestMonotonicTimeAndServerDuration()
    {
        var command = Command() with { LeaseExpiresAtUnix = 1300, SafeLeaseDeadlineTimestamp = null };
        var bound = HeartbeatLoop.BindLeaseDeadlines(new[] { command }, 1000, 1234).Single();
        Assert.Equal(1234 + 298 * Stopwatch.Frequency, bound.SafeLeaseDeadlineTimestamp);
        Assert.Null(HeartbeatLoop.BindLeaseDeadlines(new[] { command }, 0, 1234).Single().SafeLeaseDeadlineTimestamp);
    }

    private static AgentCommand Command()
        => new("11111111-1111-4111-8111-111111111111", "agent.health.snapshot", "key-1", new { }, "33333333-3333-4333-8333-333333333333", null,
            DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 300)
        { SafeLeaseDeadlineTimestamp = Stopwatch.GetTimestamp() + 240 * Stopwatch.Frequency };

    private static CommandReplayStore NewStore(EnvelopeHarness h)
        => new(Path.Combine(Path.GetDirectoryName(h.StorePath)!, "legacy-async.json"));

    private static CommandDispatcher Dispatcher(EnvelopeHarness h, ICommandHandler handler)
        => new(new[] { handler }, new IdempotencyCache(Path.Combine(Path.GetDirectoryName(h.StorePath)!, "legacy-idem.json"),
            100, TimeSpan.FromHours(1)));
}
