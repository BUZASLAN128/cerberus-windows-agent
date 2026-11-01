using System.Net;
using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class LegacyAsyncCommandProcessorTests
{
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
