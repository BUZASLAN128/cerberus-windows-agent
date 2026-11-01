using System.Net;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

/// <summary>
/// Liveness (B1): the heartbeat loop is never held by command work. Time-dependent cases use
/// the fake clock or a blocked task; none asserts on wall-clock duration.
/// </summary>
public sealed partial class CommandEnvelopeProcessorTests
{
    [Fact]
    public async Task BlockedHandler_DoesNotHoldProcessAsyncPastTheAck()
    {
        await using var h = EnvelopeHarness.Create();
        h.Facts.Block();
        var cmd = h.Cmd(p => p.Type = "collect_facts");

        await h.Process(cmd);

        await h.Facts.Started.Task.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Single(h.Backend.Acks);
        Assert.Empty(h.Backend.Results);

        h.Facts.Gate.SetResult();
        await Wait.UntilAsync(() => h.Backend.Results.Count == 1, "result after release");
        Assert.Equal("DONE", h.Backend.Results[0].Json.GetProperty("status").GetString());
    }

    [Fact]
    public async Task InlinePhase_StartsNoEntryOnceTwentySecondsHavePassed()
    {
        await using var h = EnvelopeHarness.Create(o => o.StartQueue = false);
        h.Backend.Respond = (r, _) =>
        {
            if (r.Leaf == "ack")
                h.Time.Advance(TimeSpan.FromSeconds(7));
            return Status(HttpStatusCode.OK);
        };
        var commands = Enumerable.Range(0, 5).Select(_ => h.Cmd(p => p.Expires = p.Issued + 300)).ToArray();

        await h.Process(commands);

        Assert.Equal(commands.Take(3).Select(c => c.Id), h.Backend.Acks.Select(a => a.CommandId));
        Assert.All(commands.Take(3), c => Assert.NotNull(h.Record(c)));
        Assert.All(commands.Skip(3), c => Assert.Null(h.Record(c)));

        await h.Process(commands.Skip(3).ToArray());
        Assert.Equal(commands.Select(c => c.Id), h.Backend.Acks.Select(a => a.CommandId));
    }

    [Fact]
    public async Task FullQueue_LeavesTheNinthEntryUnackedAndUnreservedUntilThereIsRoom()
    {
        await using var h = EnvelopeHarness.Create(o => o.StartQueue = false);
        var first = Enumerable.Range(0, EnvelopeExecutionQueue.MaxQueued).Select(_ => h.Cmd()).ToArray();
        var ninth = h.Cmd();
        await h.Process(first);

        await h.Process(ninth);

        Assert.Equal(EnvelopeExecutionQueue.MaxQueued, h.Backend.Acks.Count);
        Assert.DoesNotContain(h.Backend.Acks, a => a.CommandId == ninth.Id);
        Assert.Null(h.Record(ninth));
        Assert.Equal(0, h.Rejections("replay_store_full"));

        h.Queue.Start();
        await Wait.UntilAsync(() => h.Backend.Results.Count == EnvelopeExecutionQueue.MaxQueued && h.Queue.QueuedCount == 0, "queue drained");
        await h.Process(ninth);
        await Wait.UntilAsync(() => h.Backend.Results.Count == EnvelopeExecutionQueue.MaxQueued + 1, "ninth result");
        Assert.Contains(h.Backend.Acks, a => a.CommandId == ninth.Id);
    }

    [Fact]
    public async Task QueuedEntryPastItsWindow_FailsWithExpiredBeforeStartWithoutRunning()
    {
        await using var h = EnvelopeHarness.Create(o => o.StartQueue = false);
        var live = h.Cmd(p => p.Expires = p.Issued + 300);
        var shortLived = h.Cmd(p => p.Expires = p.Issued + 30);
        await h.Process(live, shortLived);
        h.Time.Advance(TimeSpan.FromSeconds(200));

        h.Queue.Start();
        await Wait.UntilAsync(() => h.Backend.Results.Count == 2, "both results");

        var byId = h.Backend.Results.ToDictionary(r => r.CommandId, r => r.Json);
        Assert.Equal("DONE", byId[live.Id].GetProperty("status").GetString());
        Assert.Equal("FAILED", byId[shortLived.Id].GetProperty("status").GetString());
        Assert.Equal("expired_before_start", byId[shortLived.Id].GetProperty("stderr").GetString());
        Assert.Equal(1, h.Ping.Calls);
    }

    [Fact]
    public async Task HandlerThatNeverReturns_ReportsUnknownOnceItsBoundPasses()
    {
        await using var h = EnvelopeHarness.Create();
        h.Facts.Block();
        var cmd = h.Cmd(p => p.Type = "collect_facts");
        await h.Process(cmd);
        await h.Facts.Started.Task.WaitAsync(TimeSpan.FromSeconds(30));

        h.Time.Advance(TimeSpan.FromSeconds(120));
        await Wait.UntilAsync(() => h.Backend.Results.Count == 1, "timeout result");

        var result = h.Backend.Results[0].Json;
        Assert.Equal("OUTCOME_UNKNOWN", result.GetProperty("status").GetString());
        Assert.Equal("command_timeout", result.GetProperty("stderr").GetString());
        await h.Process(cmd);
        Assert.Equal(1, h.Facts.Calls);
        Assert.Single(h.Backend.Results);
    }

    [Fact]
    public async Task TimedOutHandlerIgnoringCancellation_BlocksAnotherFactsHandlerUntilItActuallyReturns()
    {
        await using var h = EnvelopeHarness.Create();
        h.Facts.Body = async (_, _) =>
        {
            h.Facts.Started.TrySetResult();
            await h.Facts.Gate.Task;
            return FakeCommandHandler.Done();
        };
        var first = h.Cmd(p => p.Type = "collect_facts");
        var second = h.Cmd(p => p.Type = "collect_facts");
        await h.Process(first, second);
        await h.Facts.Started.Task.WaitAsync(TimeSpan.FromSeconds(30));

        h.Time.Advance(TimeSpan.FromSeconds(120));
        await Wait.UntilAsync(() => h.Backend.Results.Count == 1, "first timeout result");
        await Wait.UntilAsync(() => h.Record(second)?.State == EnvelopeRecordStates.Started,
            "second command waiting at the execution gate");
        Assert.Equal("OUTCOME_UNKNOWN", h.Backend.Results[0].Json.GetProperty("status").GetString());
        Assert.Equal(1, h.Facts.Calls);

        h.Facts.Gate.TrySetResult();
        await Wait.UntilAsync(() => h.Backend.Results.Count == 2, "second result after first returns");
        Assert.Equal(2, h.Facts.Calls);
        Assert.Equal("DONE", h.Backend.Results[1].Json.GetProperty("status").GetString());
    }

    [Fact]
    public async Task StuckFactsHandlerDoesNotBlockSignedStateControl()
    {
        await using var h = EnvelopeHarness.Create();
        h.Facts.Body = async (_, _) =>
        {
            h.Facts.Started.TrySetResult();
            await h.Facts.Gate.Task;
            return FakeCommandHandler.Done();
        };
        await h.Process(h.Cmd(p => p.Type = "collect_facts"));
        await h.Facts.Started.Task.WaitAsync(TimeSpan.FromSeconds(30));
        var state = h.Cmd(p =>
        {
            p.Type = "agent_state";
            p.PayloadJson = "{\"state_seq\":1,\"quarantine\":{\"active\":true}}";
        });

        await h.Process(state);

        Assert.Equal(1, h.State.Calls);
        Assert.Contains(h.Backend.Acks, ack => ack.CommandId == state.Id);
        h.Facts.Gate.TrySetResult();
    }

    [Fact]
    public async Task SynchronouslyBlockedSignedHandlerReportsUnknownAtTimeout()
    {
        await using var h = EnvelopeHarness.Create();
        var finished = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        h.Facts.Body = (_, _) =>
        {
            h.Facts.Started.TrySetResult();
            h.Facts.Gate.Task.GetAwaiter().GetResult();
            finished.TrySetResult();
            return Task.FromResult(FakeCommandHandler.Done());
        };
        try
        {
            await h.Process(h.Cmd(p => p.Type = "collect_facts"));
            await h.Facts.Started.Task.WaitAsync(TimeSpan.FromSeconds(10));
            h.Time.Advance(TimeSpan.FromSeconds(120));
            await Wait.UntilAsync(() => h.Backend.Results.Count == 1, "synchronous handler timeout");
            Assert.Equal("OUTCOME_UNKNOWN", h.Backend.Results[0].Json.GetProperty("status").GetString());
        }
        finally
        {
            h.Facts.Gate.TrySetResult();
            if (h.Facts.Started.Task.IsCompleted) await finished.Task.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }

    [Fact]
    public async Task AckThatHangs_IsCutAtTenSecondsLeavingTheRecordReserved()
    {
        await using var h = EnvelopeHarness.Create();
        h.Backend.Respond = async (_, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            return HttpStatusCode.OK;
        };
        var cmd = h.Cmd();

        var processing = h.Process(cmd);
        await Wait.UntilAsync(() => h.Backend.Acks.Count == 1, "ack request");
        h.Time.Advance(EnvelopeCommandProcessor.AckTimeout);
        await processing;

        Assert.Equal(EnvelopeRecordStates.Reserved, h.Record(cmd)!.State);
        Assert.Equal(0, h.Ping.Calls);
        Assert.Empty(h.Backend.Results);
    }
}
