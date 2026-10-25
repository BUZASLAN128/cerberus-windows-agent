using System.Net;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Re-delivery states, ack failure, restart recovery and the result outbox.</summary>
public sealed partial class CommandEnvelopeProcessorTests
{
    private static Task<HttpStatusCode> Status(HttpStatusCode code) => Task.FromResult(code);

    [Fact]
    public async Task AckFailure_LeavesTheRecordReservedAndRunsNothingUntilRedelivery()
    {
        await using var h = EnvelopeHarness.Create();
        h.Backend.Respond = (_, _) => Status(HttpStatusCode.ServiceUnavailable);
        var cmd = h.Cmd();

        await h.Process(cmd);

        Assert.Equal(EnvelopeRecordStates.Reserved, h.Record(cmd)!.State);
        Assert.Equal(0, h.Ping.Calls);
        Assert.Empty(h.Backend.Results);

        h.Backend.Respond = (_, _) => Status(HttpStatusCode.OK);
        await h.Process(cmd);
        await Wait.UntilAsync(() => h.Backend.Results.Count == 1, "result after redelivery");

        Assert.Equal(1, h.Ping.Calls);
        Assert.Equal(2, h.Backend.Acks.Count);
        Assert.Equal(h.Backend.Acks[0].Body, h.Backend.Acks[1].Body);
    }

    [Fact]
    public async Task ReservedRecordPastItsWindow_BecomesRejectedAfterReserveAndLaterRedeliveriesOnlyResendTheRejectedAck()
    {
        await using var h = EnvelopeHarness.Create();
        h.Backend.Respond = (_, _) => Status(HttpStatusCode.ServiceUnavailable);
        var cmd = h.Cmd();
        await h.Process(cmd);
        h.Backend.Respond = (_, _) => Status(HttpStatusCode.OK);
        h.Time.Advance(TimeSpan.FromSeconds(400));

        await h.Process(cmd);

        Assert.Equal(EnvelopeRecordStates.RejectedAfterReserve, h.Record(cmd)!.State);
        var rejection = h.Backend.Acks.Last().Json;
        Assert.Equal("rejected", rejection.GetProperty("decision").GetString());
        Assert.Equal("expired", rejection.GetProperty("reason").GetString());

        var acks = h.Backend.Acks.Count;
        await h.Process(cmd);
        Assert.Equal(acks + 1, h.Backend.Acks.Count);
        Assert.Equal(rejection.ToString(), h.Backend.Acks.Last().Json.ToString());
        Assert.Empty(h.Backend.Results);
        Assert.Equal(0, h.Ping.Calls);
    }

    [Fact]
    public async Task RejectedAckLostToATransientError_IsSentAgainWithTheSameReasonOnRedeliveryAndNothingRuns()
    {
        await using var h = EnvelopeHarness.Create();
        h.Backend.Respond = (_, _) => Status(HttpStatusCode.ServiceUnavailable);
        var cmd = h.Cmd();
        await h.Process(cmd);
        h.Time.Advance(TimeSpan.FromSeconds(400));
        await h.Process(cmd);
        Assert.Equal(EnvelopeRecordStates.RejectedAfterReserve, h.Record(cmd)!.State);
        Assert.Equal("expired", h.Record(cmd)!.RejectReason);
        var lost = h.Backend.Acks.Last();
        Assert.Equal("rejected", lost.Json.GetProperty("decision").GetString());

        h.Backend.Respond = (_, _) => Status(HttpStatusCode.OK);
        var before = h.Backend.Acks.Count;
        await h.Process(cmd);

        Assert.Equal(before + 1, h.Backend.Acks.Count);
        Assert.Equal(lost.Body, h.Backend.Acks.Last().Body);
        Assert.Equal(0, h.Ping.Calls);
        Assert.Empty(h.Backend.Results);

        await h.Process(cmd);

        Assert.Equal(before + 2, h.Backend.Acks.Count);
        Assert.Equal(lost.Body, h.Backend.Acks.Last().Body);
        Assert.All(h.Backend.Acks.Skip(1), a => Assert.Equal("rejected", a.Json.GetProperty("decision").GetString()));
        Assert.Equal(0, h.Ping.Calls);
        Assert.Empty(h.Backend.Results);
    }

    [Fact]
    public async Task RejectedAfterReserveRecordWithoutAStoredReason_StaysANoOpOnRedelivery()
    {
        await using var h = EnvelopeHarness.Create();
        var cmd = h.Cmd();
        var record = StoreFileWriter.Record(h.AgentId, cmd.Id, "legacy-nonce", EnvelopeRecordStates.RejectedAfterReserve, T0, T0 + 120, null, false)
            with { EnvelopeSha256 = EnvelopeHarness.ShaOf(cmd), Type = "ping" };
        Assert.Equal(ReplayReserveOutcome.Reserved, h.Store.TryReserve(record));
        Assert.True(h.Store.TryUpdate(record));

        await h.Process(cmd);

        Assert.Empty(h.Backend.Requests);
        Assert.Equal(0, h.Ping.Calls);
    }

    [Fact]
    public async Task InFlightRedeliveryIsANoOp_ThenDoneResendsOnlyTheStoredAck()
    {
        await using var h = EnvelopeHarness.Create();
        h.Facts.Block();
        var cmd = h.Cmd(p => p.Type = "collect_facts");
        await h.Process(cmd);
        await h.Facts.Started.Task.WaitAsync(TimeSpan.FromSeconds(30));

        await h.Process(cmd);

        Assert.Single(h.Backend.Acks);
        Assert.Equal(1, h.Facts.Calls);

        h.Facts.Gate.SetResult();
        await Wait.UntilAsync(() => h.Record(cmd)?.ResultSubmitted == true && h.Queue.QueuedCount == 0, "result submitted");
        await h.Process(cmd);

        Assert.Equal(2, h.Backend.Acks.Count);
        Assert.Equal(h.Backend.Acks[0].Body, h.Backend.Acks[1].Body);
        Assert.Equal(1, h.Facts.Calls);
        Assert.Single(h.Backend.Results);
    }

    [Fact]
    public async Task StartedRecordFromAnEarlierProcess_ReportsOutcomeUnknownOnceAndNeverRunsAgain()
    {
        await using var h = EnvelopeHarness.Create();
        var cmd = await CrashWhileRunningAsync(h);

        await h.Process(cmd);
        await Wait.UntilAsync(() => h.Backend.Results.Count == 1, "OUTCOME_UNKNOWN result");

        Assert.Equal("OUTCOME_UNKNOWN", h.Backend.Results[0].Json.GetProperty("status").GetString());
        Assert.Empty(h.Backend.Acks);
        await Wait.UntilAsync(() => h.Record(cmd)?.ResultSubmitted == true, "result confirmed");
        await h.Process(cmd);
        Assert.Equal("accepted", Assert.Single(h.Backend.Acks).Json.GetProperty("decision").GetString());
        Assert.Single(h.Backend.Results);
        Assert.Equal(0, h.Facts.Calls);
    }

    [Fact]
    public async Task Startup_GivesEveryStartedRecordWithoutAResultAnOutcomeUnknownResult()
    {
        await using var h = EnvelopeHarness.Create();
        var cmd = await CrashWhileRunningAsync(h);

        await h.Process();
        await Wait.UntilAsync(() => h.Backend.Results.Count == 1, "OUTCOME_UNKNOWN result");

        var body = h.Backend.Results[0];
        Assert.Equal(cmd.Id, body.CommandId);
        Assert.Equal("OUTCOME_UNKNOWN", body.Json.GetProperty("status").GetString());
        Assert.Equal(EnvelopeHarness.ShaOf(cmd), body.Json.GetProperty("envelope_sha256").GetString());
        Assert.Equal(0, h.Facts.Calls);
    }

    [Theory]
    [InlineData(HttpStatusCode.BadRequest, true)]
    [InlineData(HttpStatusCode.TooManyRequests, false)]
    [InlineData(HttpStatusCode.RequestTimeout, false)]
    [InlineData(HttpStatusCode.InternalServerError, false)]
    public async Task ResultRefusal_IsFinalOnlyForA4xxOtherThan408And429(HttpStatusCode status, bool final)
    {
        await using var h = EnvelopeHarness.Create();
        h.Backend.Respond = (r, _) => Status(r.Leaf == "result" ? status : HttpStatusCode.OK);
        var cmd = h.Cmd();

        await h.Process(cmd);
        await Wait.UntilAsync(() => h.Backend.Results.Count >= 1 && h.Queue.QueuedCount == 0, "first result attempt");
        if (final)
            await Wait.UntilAsync(() => h.Record(cmd)!.ResultSubmitted, "refused result marked final");

        Assert.Equal(final, h.Record(cmd)!.ResultSubmitted);
        Assert.Equal(EnvelopeRecordStates.Done, h.Record(cmd)!.State);
        if (final)
            Assert.Single(h.Backend.Results);
    }

    [Fact]
    public async Task FailedResult_IsResentByteIdenticalWithTheNextHeartbeatAndARedeliveredEntry()
    {
        await using var h = EnvelopeHarness.Create();
        h.Backend.Respond = (r, _) => Status(r.Leaf == "result" ? HttpStatusCode.ServiceUnavailable : HttpStatusCode.OK);
        var cmd = h.Cmd();
        await h.Process(cmd);
        await Wait.UntilAsync(() => h.Backend.Results.Count >= 1 && h.Queue.QueuedCount == 0, "first attempt");

        await h.Process(cmd);
        Assert.Equal(2, h.Backend.Acks.Count);
        Assert.Equal(h.Backend.Acks[0].Body, h.Backend.Acks[1].Body);

        h.Backend.Respond = (_, _) => Status(HttpStatusCode.OK);
        await h.Process();
        await Wait.UntilAsync(() => h.Record(cmd)!.ResultSubmitted, "result confirmed");

        var results = h.Backend.Results;
        Assert.True(results.Count >= 2);
        Assert.All(results, r => Assert.Equal(results[0].Body, r.Body));
        Assert.Equal(CommandEnvelope.Sha256Hex(results[0].Body), h.Record(cmd)!.ResultSha256);
        Assert.Equal(1, h.Ping.Calls);
    }

    /// <summary>Leaves a <c>started</c> record on disk, as a process killed mid-run would, then restarts.</summary>
    private static async Task<AgentCommand> CrashWhileRunningAsync(EnvelopeHarness h)
    {
        var cmd = h.Cmd(p => { p.Type = "collect_facts"; p.Nonce = "crash-nonce"; });
        var started = StoreFileWriter.Record(h.AgentId, cmd.Id, "crash-nonce", EnvelopeRecordStates.Started, T0, T0 + 120, null, false)
            with { EnvelopeSha256 = EnvelopeHarness.ShaOf(cmd), Type = "collect_facts" };
        Assert.Equal(ReplayReserveOutcome.Reserved, h.Store.TryReserve(started));
        Assert.True(h.Store.TryUpdate(started));
        await h.RestartAsync();
        Assert.Equal(EnvelopeRecordStates.Started, h.Record(cmd)!.State);
        return cmd;
    }
}
