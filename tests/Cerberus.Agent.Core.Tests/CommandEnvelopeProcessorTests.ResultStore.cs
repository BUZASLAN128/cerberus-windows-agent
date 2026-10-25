using System.Net;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Result storage races, non-durable results, refused results and the outbox pass (unit/support tier).</summary>
public sealed partial class CommandEnvelopeProcessorTests
{
    private static byte[] ResultBody(string status, string code)
        => CommandEnvelope.BuildResultBody(status, null, code, null, new string('a', 64));

    private static string StoreWithPendingResults(int count, out string[] ids)
    {
        var path = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"), CommandReplayStore.FileName);
        ids = Enumerable.Range(0, count).Select(i => $"pending-{i}").ToArray();
        var names = ids;
        StoreFileWriter.Write(path, 0, names.Select(id =>
            StoreFileWriter.Record(EnvelopeHarness.DefaultAgent, id, "n-" + id, EnvelopeRecordStates.Done, EnvelopeHarness.T0,
                EnvelopeHarness.T0 + 120, Convert.ToBase64String(ResultBody("DONE", id)), submitted: false)));
        return path;
    }

    [Fact]
    public async Task ResultAlreadyStoredByAnotherWriter_IsDeliveredAndNeverOverwrittenByTheLateResult()
    {
        await using var h = EnvelopeHarness.Create();
        var winner = ResultBody("FAILED", "winner");
        h.Ping.Body = (command, _) =>
        {
            var started = h.Store.Find(h.AgentId, command.Id)!;
            Assert.Equal(ReplayUpdateOutcome.Updated, h.Store.TryUpdate(started with
            {
                State = EnvelopeRecordStates.Done,
                ResultB64 = Convert.ToBase64String(winner),
                ResultSha256 = CommandEnvelope.Sha256Hex(winner),
            }, EnvelopeRecordStates.Started));
            return Task.FromResult(FakeCommandHandler.Done());
        };
        var cmd = h.Cmd();

        await h.Process(cmd);
        await Wait.UntilAsync(() => h.Record(cmd)?.ResultSubmitted == true, "stored result submitted");

        Assert.Equal(winner, Assert.Single(h.Backend.Results).Body);
        Assert.Equal(CommandEnvelope.Sha256Hex(winner), h.Record(cmd)!.ResultSha256);
    }

    [Fact]
    public async Task InlineAgentStateResult_WhoseWriteFails_IsDeliveredOnceFromMemoryAndNeverReportedUnknown()
    {
        await using var h = EnvelopeHarness.Create();
        FileStream? lockFile = null;
        h.State.Body = (_, _) =>
        {
            // Holding the store file open makes every replace fail: the started write already succeeded.
            lockFile = new FileStream(h.StorePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            return Task.FromResult(FakeCommandHandler.Done());
        };
        var state = h.Cmd(p => { p.Type = "agent_state"; p.PayloadJson = "{\"state_seq\":1,\"quarantine\":{\"active\":true}}"; });

        try
        {
            await h.Process(state);
            await Wait.UntilAsync(() => h.Backend.Results.Count >= 1, "in-memory result delivered");
        }
        finally
        {
            lockFile?.Dispose();
        }

        await h.Queue.DrainOutboxOnceAsync(CancellationToken.None);

        var result = Assert.Single(h.Backend.Results);
        Assert.Equal("DONE", result.Json.GetProperty("status").GetString());
        Assert.DoesNotContain(h.Backend.Results, r => r.Json.GetProperty("status").GetString() == EnvelopeExecutionQueue.OutcomeUnknown);
    }

    [Fact]
    public async Task ResultRefusedWithA4xx_IsLoggedAsRefusedAndNotAsFinished()
    {
        await using var h = EnvelopeHarness.Create();
        h.Backend.Respond = (r, _) => Status(r.Leaf == "result" ? HttpStatusCode.BadRequest : HttpStatusCode.OK);
        var cmd = h.Cmd();

        await h.Process(cmd);
        await Wait.UntilAsync(() => h.Record(cmd)?.ResultSubmitted == true, "refused result marked final");

        Assert.Contains(h.Log.Lines, l => l.StartsWith("WARN Command result refused", StringComparison.Ordinal) && l.Contains("http=400"));
        Assert.DoesNotContain(h.Log.Lines, l => l.Contains("Command finished", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AcceptedCommandDroppedBeforeItStarts_LeavesNoInFlightEntry()
    {
        await using var h = EnvelopeHarness.Create(o => o.StartQueue = false);
        var cmd = h.Cmd();
        await h.Process(cmd);
        Assert.True(h.Queue.IsInFlight(h.AgentId, cmd.Id));
        var original = h.AgentId;
        h.AgentId = "agent-rebound";

        h.Queue.Start();
        await Wait.UntilAsync(() => h.Queue.QueuedCount == 0, "queued entry dropped");

        Assert.False(h.Queue.IsInFlight(original, cmd.Id));
        Assert.Equal(0, h.Ping.Calls);
        Assert.Empty(h.Backend.Results);
    }

    [Fact]
    public async Task DrainOutboxOnce_DeliversEveryStoredResultWithoutRunningACommand()
    {
        var path = StoreWithPendingResults(3, out var ids);
        await using var h = EnvelopeHarness.Create(o => { o.StorePath = path; o.StartQueue = false; });

        await h.Queue.DrainOutboxOnceAsync(CancellationToken.None);

        Assert.Equal(ids.OrderBy(i => i), h.Backend.Results.Select(r => r.CommandId).OrderBy(i => i));
        Assert.All(ids, id => Assert.True(h.Store.Find(h.AgentId, id)!.ResultSubmitted));
        Assert.Equal(0, h.Ping.Calls + h.Facts.Calls + h.State.Calls);
        Assert.Empty(h.Backend.Acks);
    }

    [Fact]
    public async Task OutboxPassRunningWhenCancelAllFires_PostsNoFurtherResult()
    {
        var path = StoreWithPendingResults(3, out _);
        await using var h = EnvelopeHarness.Create(o => { o.StorePath = path; o.StartQueue = false; });
        var firstPosted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        h.Backend.Respond = async (_, ct) =>
        {
            firstPosted.TrySetResult();
            await release.Task.WaitAsync(TimeSpan.FromSeconds(30), ct);
            return HttpStatusCode.OK;
        };

        var drain = h.Queue.DrainOutboxOnceAsync(CancellationToken.None);
        await firstPosted.Task.WaitAsync(TimeSpan.FromSeconds(30));
        h.Queue.CancelAll();
        release.SetResult();
        await drain.WaitAsync(TimeSpan.FromSeconds(30));

        Assert.Single(h.Backend.Results);
    }
}
