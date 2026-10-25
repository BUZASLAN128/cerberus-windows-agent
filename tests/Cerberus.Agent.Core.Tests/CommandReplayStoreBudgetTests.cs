using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Unsubmitted-result budget and the read-cap write guard of the replay store (unit/support tier).</summary>
public sealed class CommandReplayStoreBudgetTests : IDisposable
{
    private const long T0 = EnvelopeHarness.T0;
    private const string Agent = "agent-A";

    // 349524 base64 characters hold 262143 bytes (divisible by 3), just under the 262144-byte result body cap.
    private static readonly string Result = new('A', 349524);

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
    private readonly FakeTime _time = new(T0);

    private string StorePath => Path.Combine(_dir, CommandReplayStore.FileName);

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, recursive: true);
    }

    private static CommandReplayRecord Held(int i, bool submitted = false, string? body = null)
        => StoreFileWriter.Record(Agent, $"id-{i}", $"n-{i}", EnvelopeRecordStates.Done, T0, T0 + 120, body ?? Result, submitted);

    private static CommandReplayRecord Fresh() => StoreFileWriter.Record(Agent, "id-new", "n-new", EnvelopeRecordStates.Reserved, T0, T0 + 120);

    private CommandReplayStore StoreWithUnsubmitted(int count)
    {
        StoreFileWriter.Write(StorePath, 0, Enumerable.Range(0, count).Select(i => Held(i)));
        return new CommandReplayStore(StorePath, _time);
    }

    private static CommandReplayRecord InFlight(int i, string state, long expiresAt = T0 + 120)
        => StoreFileWriter.Record(Agent, $"id-{i}", $"n-{i}", state, T0, expiresAt, submitted: false);

    private CommandReplayStore StoreWithInFlight(int reserved, int started, long reservedExpiresAt = T0 + 120)
    {
        StoreFileWriter.Write(StorePath, 0,
            Enumerable.Range(0, reserved).Select(i => InFlight(i, EnvelopeRecordStates.Reserved, reservedExpiresAt))
                .Concat(Enumerable.Range(100, started).Select(i => InFlight(i, EnvelopeRecordStates.Started))));
        return new CommandReplayStore(StorePath, _time);
    }

    [Fact]
    public void InFlightRecordsWithoutResults_CountAsMaximalResultsAndRejectANewEnvelope()
    {
        // 16 reserved + 8 started = 24 future maximal results; with the new envelope that exceeds 6 MiB although no bytes are held.
        var store = StoreWithInFlight(reserved: 16, started: 8);

        Assert.Equal(ReplayReserveOutcome.Full, store.TryReserve(Fresh()));

        Assert.Null(store.Find(Agent, "id-new"));
        Assert.Null(new CommandReplayStore(StorePath, _time).Find(Agent, "id-new"));
        Assert.Equal(24, store.Records(Agent).Count);
    }

    [Fact]
    public void OneInFlightRecordFewer_StillReserves()
    {
        var store = StoreWithInFlight(reserved: 15, started: 8);

        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(Fresh()));
        Assert.NotNull(new CommandReplayStore(StorePath, _time).Find(Agent, "id-new"));
    }

    [Fact]
    public void ReservedRecordsPastTheirWindow_NoLongerCountBecauseTheyNeverRun()
    {
        var store = StoreWithInFlight(reserved: 24, started: 0);
        Assert.Equal(ReplayReserveOutcome.Full, store.TryReserve(Fresh()));

        _time.Advance(TimeSpan.FromSeconds(120 + CommandEnvelopeVerifier.SkewSeconds + 1));

        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(Fresh()));
    }

    [Fact]
    public void UnsubmittedBytesAtTheBudget_RejectANewEnvelopeAsFullAndReserveNothing()
    {
        // 24 held results leave no room for one more maximal result (24 * 262143 + 262144 > 6 MiB).
        var store = StoreWithUnsubmitted(24);

        Assert.Equal(ReplayReserveOutcome.Full, store.TryReserve(Fresh()));

        Assert.Null(store.Find(Agent, "id-new"));
        Assert.Null(new CommandReplayStore(StorePath, _time).Find(Agent, "id-new"));
        Assert.Equal(24, store.Records(Agent).Count);
    }

    [Fact]
    public void UnsubmittedBytesAtTheBudget_StillReserveAnAgentStateAndRefuseAQueuedType()
    {
        var store = StoreWithUnsubmitted(24);

        Assert.Equal(ReplayReserveOutcome.Full, store.TryReserve(Fresh() with { Type = EnvelopeTypes.CollectFacts }));
        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(Fresh() with { Type = EnvelopeTypes.AgentState }));

        Assert.Equal(EnvelopeRecordStates.Reserved, new CommandReplayStore(StorePath, _time).Find(Agent, "id-new")!.State);
        Assert.Equal(25, store.Records(Agent).Count);
    }

    [Fact]
    public void StoreAtMaxRecordsOfUnsubmittedResults_StillReservesAnAgentStateAndRefusesAQueuedType()
    {
        // Unexpired done records with an unsubmitted result are never evictable; the small bodies keep the byte budget out of play.
        StoreFileWriter.Write(StorePath, 0, Enumerable.Range(0, CommandReplayStore.MaxRecords).Select(i => Held(i, body: "AAAA")));
        var store = new CommandReplayStore(StorePath, _time);
        Assert.Equal(CommandReplayStore.MaxRecords, store.Records(Agent).Count);

        Assert.Equal(ReplayReserveOutcome.Full, store.TryReserve(Fresh() with { Type = EnvelopeTypes.CollectFacts }));
        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(Fresh() with { Type = EnvelopeTypes.AgentState }));

        Assert.Equal(CommandReplayStore.MaxRecords + 1, new CommandReplayStore(StorePath, _time).Records(Agent).Count);
    }

    [Fact]
    public void OneResultBelowTheBudget_StillReserves()
    {
        // 23 * 262143 + 262144 fits in 6 MiB.
        var store = StoreWithUnsubmitted(23);

        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(Fresh()));
    }

    [Fact]
    public void AfterAResultIsSubmitted_NewEnvelopesAreAcceptedAgain()
    {
        var store = StoreWithUnsubmitted(24);
        Assert.Equal(ReplayReserveOutcome.Full, store.TryReserve(Fresh()));

        Assert.True(store.TryUpdate(Held(0, submitted: true)));

        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(Fresh()));
        Assert.NotNull(new CommandReplayStore(StorePath, _time).Find(Agent, "id-new"));
    }

    [Fact]
    public void StoreFilledToTheBudgetAndTheSubmittedCap_ReloadsAfterARestartWithoutAReset()
    {
        var unsubmitted = Enumerable.Range(0, 23).Select(i => Held(i));
        var submitted = Enumerable.Range(100, 20).Select(i => Held(i, submitted: true));
        StoreFileWriter.Write(StorePath, 0, unsubmitted.Concat(submitted));
        var store = new CommandReplayStore(StorePath, _time);
        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(Fresh()));
        Assert.True(store.TryUpdate(Held(0, submitted: false)));

        var size = new FileInfo(StorePath).Length;
        var reloaded = new CommandReplayStore(StorePath, _time);

        Assert.True(size <= CommandReplayStore.MaxFileBytes);
        Assert.Equal(0, reloaded.ResetAt);
        Assert.Equal(44, reloaded.Records(Agent).Count);
        Assert.Empty(Directory.GetFiles(_dir, "*.corrupt-*"));
    }

    [Fact]
    public void WriteAboveTheReadCap_FailsClosedAndLeavesTheReadableFileUntouched()
    {
        // 45 held results load (under 16 MiB); growing one of them past the cap must not be written.
        var store = StoreWithUnsubmitted(45);
        var before = File.ReadAllBytes(StorePath);
        Assert.True(before.LongLength < CommandReplayStore.MaxFileBytes);

        var grown = Held(0, body: new string('A', 1_500_000) + Result);
        Assert.False(store.TryUpdate(grown));

        Assert.Equal(before, File.ReadAllBytes(StorePath));
        Assert.Equal(Result.Length, store.Find(Agent, "id-0")!.ResultB64!.Length);
        var reloaded = new CommandReplayStore(StorePath, _time);
        Assert.Equal(0, reloaded.ResetAt);
        Assert.Equal(45, reloaded.Records(Agent).Count);
    }

    [Fact]
    public void Base64PlusSigns_AreWrittenUnescapedSoTheFileStaysWithinTheBound()
    {
        var store = new CommandReplayStore(StorePath, _time);
        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(Fresh()));

        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(Held(1, body: "++++++++") with { State = EnvelopeRecordStates.Reserved }));
        Assert.True(store.TryUpdate(Held(1, body: "++++++++")));

        var text = File.ReadAllText(StorePath);
        Assert.Contains("++++++++", text);
        Assert.DoesNotContain("u002B", text, StringComparison.OrdinalIgnoreCase);
    }
}
