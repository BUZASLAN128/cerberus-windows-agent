using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Compare-and-set updates and the per-agent, agent_state-aware unsubmitted budget (unit/support tier).</summary>
public sealed class CommandReplayStoreUpdateTests : IDisposable
{
    private const long T0 = EnvelopeHarness.T0;
    private const string Agent = "agent-A";
    private const string Body = "AAAA";

    // 349524 base64 characters hold 262143 bytes, just under the 262144-byte result body cap.
    private static readonly string Big = new('A', 349524);

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
    private readonly FakeTime _time = new(T0);

    private string StorePath => Path.Combine(_dir, CommandReplayStore.FileName);

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, recursive: true);
    }

    private static CommandReplayRecord Rec(string id, string state, string? body = null, bool submitted = false, string agent = Agent)
        => StoreFileWriter.Record(agent, id, "n-" + id, state, T0, T0 + 120, body, submitted);

    private CommandReplayStore ReservedStore(string id)
    {
        var store = new CommandReplayStore(StorePath, _time);
        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(Rec(id, EnvelopeRecordStates.Reserved)));
        return store;
    }

    [Fact]
    public void TryUpdate_MovesReservedToStartedOnceAndPersistsIt()
    {
        var store = ReservedStore("c1");

        Assert.Equal(ReplayUpdateOutcome.Updated, store.TryUpdate(Rec("c1", EnvelopeRecordStates.Started), EnvelopeRecordStates.Reserved));
        Assert.Equal(ReplayUpdateOutcome.Conflict, store.TryUpdate(Rec("c1", EnvelopeRecordStates.Started), EnvelopeRecordStates.Reserved));

        Assert.Equal(EnvelopeRecordStates.Started, new CommandReplayStore(StorePath, _time).Find(Agent, "c1")!.State);
    }

    [Fact]
    public void TryUpdate_NeverOverwritesAStoredResultOrASubmittedRecord()
    {
        var store = ReservedStore("c1");
        Assert.Equal(ReplayUpdateOutcome.Updated, store.TryUpdate(Rec("c1", EnvelopeRecordStates.Started), EnvelopeRecordStates.Reserved));
        var first = Rec("c1", EnvelopeRecordStates.Done, Body);
        Assert.Equal(ReplayUpdateOutcome.Updated, store.TryUpdate(first, EnvelopeRecordStates.Started));

        // A second writer that still believes the record is started must not replace the stored result.
        var other = Rec("c1", EnvelopeRecordStates.Done, "BBBB") with { ResultSha256 = new string('c', 64) };
        Assert.Equal(ReplayUpdateOutcome.Conflict, store.TryUpdate(other, EnvelopeRecordStates.Started));
        // Marking submitted needs the stored result itself.
        Assert.Equal(ReplayUpdateOutcome.Conflict, store.TryUpdate(other with { ResultSubmitted = true }, EnvelopeRecordStates.Done));
        Assert.Equal(Body, store.Find(Agent, "c1")!.ResultB64);

        Assert.Equal(ReplayUpdateOutcome.Updated, store.TryUpdate(first with { ResultSubmitted = true }, EnvelopeRecordStates.Done));
        // A submitted record is final.
        Assert.Equal(ReplayUpdateOutcome.Conflict, store.TryUpdate(first, EnvelopeRecordStates.Done));
        Assert.True(new CommandReplayStore(StorePath, _time).Find(Agent, "c1")!.ResultSubmitted);
    }

    [Fact]
    public void TryUpdate_OfAnUnknownRecordIsAConflict()
    {
        var store = ReservedStore("c1");

        Assert.Equal(ReplayUpdateOutcome.Conflict, store.TryUpdate(Rec("missing", EnvelopeRecordStates.Started), EnvelopeRecordStates.Reserved));
        Assert.Equal(ReplayUpdateOutcome.Conflict, store.TryUpdate(Rec("c1", EnvelopeRecordStates.Started, agent: "agent-B"), EnvelopeRecordStates.Reserved));
    }

    [Fact]
    public void TryUpdate_ReportsFailedAndKeepsTheStoredRecordWhenTheWriteFails()
    {
        var store = ReservedStore("c1");
        using (new FileStream(StorePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            Assert.Equal(ReplayUpdateOutcome.Failed, store.TryUpdate(Rec("c1", EnvelopeRecordStates.Started), EnvelopeRecordStates.Reserved));

        Assert.Equal(EnvelopeRecordStates.Reserved, store.Find(Agent, "c1")!.State);
        Assert.Equal(ReplayUpdateOutcome.Updated, store.TryUpdate(Rec("c1", EnvelopeRecordStates.Started), EnvelopeRecordStates.Reserved));
    }

    [Fact]
    public void ResultBytesOfAnotherAgentId_DoNotCountTowardTheBudgetAndAreDropped()
    {
        // 24 unsubmitted maximal results of an earlier agent id would fill the budget for the current one.
        StoreFileWriter.Write(StorePath, 0, Enumerable.Range(0, 24).Select(i => Rec($"old-{i}", EnvelopeRecordStates.Done, Big, agent: "agent-OLD")));
        var store = new CommandReplayStore(StorePath, _time);

        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(Rec("new", EnvelopeRecordStates.Reserved)));

        Assert.Null(store.Find("agent-OLD", "old-0")!.ResultB64);
        Assert.NotNull(store.Find("agent-OLD", "old-0"));
        Assert.True(new FileInfo(StorePath).Length < 1_000_000);
    }

    [Fact]
    public void ReservedAgentStateRecordsWithoutResults_DoNotConsumeTheBudgetOfQueuedTypes()
    {
        StoreFileWriter.Write(StorePath, 0, Enumerable.Range(0, 24)
            .Select(i => Rec($"as-{i}", EnvelopeRecordStates.Reserved) with { Type = EnvelopeTypes.AgentState }));
        var store = new CommandReplayStore(StorePath, _time);

        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(Rec("q", EnvelopeRecordStates.Reserved) with { Type = EnvelopeTypes.CollectFacts }));
    }

    [Fact]
    public void FileStaysUnderTheReadCap_WithTheBudgetFilledAndManyReservedAgentStateRecords()
    {
        var unsubmitted = Enumerable.Range(0, 23).Select(i => Rec($"u-{i}", EnvelopeRecordStates.Done, Big));
        var submitted = Enumerable.Range(0, 20).Select(i => Rec($"s-{i}", EnvelopeRecordStates.Done, Big, submitted: true));
        var states = Enumerable.Range(0, 900).Select(i => Rec($"as-{i}", EnvelopeRecordStates.Reserved) with { Type = EnvelopeTypes.AgentState });
        StoreFileWriter.Write(StorePath, 0, unsubmitted.Concat(submitted).Concat(states));
        var store = new CommandReplayStore(StorePath, _time);

        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(Rec("q", EnvelopeRecordStates.Reserved)));
        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(Rec("as-new", EnvelopeRecordStates.Reserved) with { Type = EnvelopeTypes.AgentState }));

        Assert.True(new FileInfo(StorePath).Length <= CommandReplayStore.MaxFileBytes);
        var reloaded = new CommandReplayStore(StorePath, _time);
        Assert.Equal(0, reloaded.ResetAt);
        Assert.NotNull(reloaded.Find(Agent, "as-new"));
    }
}
