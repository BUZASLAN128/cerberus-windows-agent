using System.Net;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class LegacyAsyncCommandProcessorTests
{
    [Fact]
    public async Task PauseAfterAdmissionWhileWaitingForHandlerGateHoldsActualDispatch()
    {
        await using var first = EnvelopeHarness.Create(o => o.StartQueue = false);
        await using var second = EnvelopeHarness.Create(o => o.StartQueue = false);
        var running = new FakeCommandHandler(Command().Type).Block();
        var held = new FakeCommandHandler(Command().Type);
        var firstDispatcher = Dispatcher(first, running);
        var secondDispatcher = Dispatcher(second, held);
        var firstStore = NewStore(first);
        var secondStore = NewStore(second);
        await using var p1 = new LegacyAsyncCommandProcessor(first.Api, firstDispatcher,
            new LegacyHeartbeatCommandProcessor(first.Api, firstDispatcher, TimeSpan.FromSeconds(5), 1),
            firstStore, _ => Task.FromResult(first.AgentId));
        await using var p2 = new LegacyAsyncCommandProcessor(second.Api, secondDispatcher,
            new LegacyHeartbeatCommandProcessor(second.Api, secondDispatcher, TimeSpan.FromSeconds(5), 1),
            secondStore, _ => Task.FromResult(second.AgentId));
        var command = Command();
        try
        {
            await p1.ProcessAsync(new[] { command }, default);
            await running.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await p2.ProcessAsync(new[] { command }, default);
            await Wait.UntilAsync(() => secondStore.Find(second.AgentId, command.Id)?.State == EnvelopeRecordStates.Started,
                "second command admitted behind the shared handler gate");
            p2.SetExecutionPaused(true);
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var sentinel = StoreFileWriter.Record(second.AgentId, Guid.NewGuid().ToString("D"), Guid.NewGuid().ToString("D"),
                EnvelopeRecordStates.Reserved, now, now + 300, submitted: false) with { Type = command.Type };
            Assert.Equal(ReplayReserveOutcome.Reserved, secondStore.TryReserve(sentinel));
            var bytes = JsonSerializer.SerializeToUtf8Bytes(FakeCommandHandler.Done(), new JsonSerializerOptions(JsonSerializerDefaults.Web));
            Assert.Equal(ReplayUpdateOutcome.Updated, secondStore.TryUpdate(sentinel with { State = EnvelopeRecordStates.Done,
                ResultB64 = Convert.ToBase64String(bytes), ResultSha256 = CommandEnvelope.Sha256Hex(bytes) }, sentinel.State));
            running.Gate.TrySetResult();
            await Wait.UntilAsync(() => secondStore.Find(second.AgentId, sentinel.Id)!.ResultSubmitted,
                "paused invocation reached the final handler gate and drained existing results");
            Assert.Equal(0, held.Calls);
            Assert.DoesNotContain(second.Backend.Results, result => result.CommandId == command.Id);
            p2.SetExecutionPaused(false);
            await Wait.UntilAsync(() => secondStore.Find(second.AgentId, command.Id)!.ResultSubmitted, "dispatch resumes after pause clears");
            Assert.Equal(1, held.Calls);
            Assert.Equal("DONE", second.Backend.Results.Single(result => result.CommandId == command.Id).Json.GetProperty("status").GetString());
        }
        finally { running.Gate.TrySetResult(); p2.SetExecutionPaused(false); }
    }

    [Fact]
    public async Task HeartbeatPauseHoldsNextCommandWithoutCancellingRunningWorkOrResultDelivery()
    {
        await using var h = EnvelopeHarness.Create(o => o.StartQueue = false);
        var first = Command();
        var second = Command() with { Id = Guid.NewGuid().ToString("D"), IdempotencyKey = "second",
            LeaseId = Guid.NewGuid().ToString("D") };
        var handler = new FakeCommandHandler(first.Type);
        handler.Body = async (command, ct) =>
        {
            if (command.Id == first.Id)
            {
                handler.Started.TrySetResult();
                await handler.Gate.Task.WaitAsync(ct);
            }
            return FakeCommandHandler.Done();
        };
        var dispatcher = Dispatcher(h, handler);
        var store = NewStore(h);
        await using var processor = new LegacyAsyncCommandProcessor(h.Api, dispatcher,
            new LegacyHeartbeatCommandProcessor(h.Api, dispatcher, TimeSpan.FromSeconds(5), 1),
            store, _ => Task.FromResult(h.AgentId), h.Log, h.Time);
        IHeartbeatCommandProcessor front = processor;
#if !CERBERUS_SERVER_PROFILE
        front = new EnvelopeCommandProcessor(h.Api, new[] { h.Signer.Anchor }, h.Queue, legacy: processor);
#endif
        var posting = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        h.Backend.Respond = async (request, ct) =>
        {
            if (request.CommandId == first.Id && request.Leaf == "result")
            {
                posting.TrySetResult();
                await release.Task.WaitAsync(ct);
            }
            return HttpStatusCode.OK;
        };
        try
        {
            await front.ProcessAsync(new[] { first, second }, default);
            await handler.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
            front.SetExecutionPaused(true);
            handler.Gate.TrySetResult();
            await posting.Task.WaitAsync(TimeSpan.FromSeconds(5));

            // This result is added after the first drain selected its batch. Its delivery proves the
            // worker reached the next queue boundary while paused, without dispatching the second job.
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            var sentinel = StoreFileWriter.Record(h.AgentId, Guid.NewGuid().ToString("D"), Guid.NewGuid().ToString("D"),
                EnvelopeRecordStates.Reserved, now, now + 300, submitted: false) with { Type = first.Type };
            Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(sentinel));
            var bytes = JsonSerializer.SerializeToUtf8Bytes(FakeCommandHandler.Done(), new JsonSerializerOptions(JsonSerializerDefaults.Web));
            Assert.Equal(ReplayUpdateOutcome.Updated, store.TryUpdate(sentinel with { State = EnvelopeRecordStates.Done,
                ResultB64 = Convert.ToBase64String(bytes), ResultSha256 = CommandEnvelope.Sha256Hex(bytes) }, sentinel.State));
            release.TrySetResult();
            await Wait.UntilAsync(() => store.Find(h.AgentId, sentinel.Id)!.ResultSubmitted, "result delivery during heartbeat pause");

            Assert.True(store.Find(h.AgentId, first.Id)!.ResultSubmitted);
            Assert.Equal("DONE", h.Backend.Results.Single(r => r.CommandId == first.Id).Json.GetProperty("status").GetString());
            Assert.Equal(EnvelopeRecordStates.Reserved, store.Find(h.AgentId, second.Id)!.State);
            Assert.Equal(1, handler.Calls);
            Assert.DoesNotContain(h.Backend.Results, r => r.CommandId == second.Id);

            front.SetExecutionPaused(false);
            await Wait.UntilAsync(() => store.Find(h.AgentId, second.Id)!.ResultSubmitted, "queued work resumes after heartbeat pause");
            Assert.Equal(2, handler.Calls);
            Assert.Equal("DONE", h.Backend.Results.Single(r => r.CommandId == second.Id).Json.GetProperty("status").GetString());
        }
        finally { handler.Gate.TrySetResult(); release.TrySetResult(); }
    }
}
