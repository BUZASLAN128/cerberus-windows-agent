using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

/// <summary>Replay store bounds, eviction, durability and per-agent scoping (unit/support tier).</summary>
public sealed class CommandReplayStoreTests : IDisposable
{
    private const long T0 = EnvelopeHarness.T0;
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
    private readonly FakeTime _time = new(T0);

    private string StorePath => Path.Combine(_dir, CommandReplayStore.FileName);

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, recursive: true);
    }

    private static CommandReplayRecord Rec(string agent, string id, string nonce, string state = EnvelopeRecordStates.Reserved,
        long expiresAt = T0 + 120, string? resultB64 = null, bool submitted = false)
        => StoreFileWriter.Record(agent, id, nonce, state, T0, expiresAt, resultB64, submitted);

    [Fact]
    public void RecordOfAgentA_GivesNoIdHitAndNoNonceHitForAgentB()
    {
        var store = new CommandReplayStore(StorePath, _time);
        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(Rec("agent-A", "id-1", "n")));

        Assert.NotNull(store.Find("agent-A", "id-1"));
        Assert.Null(store.Find("agent-B", "id-1"));
        Assert.True(store.IsNonceUsed("agent-A", "n", "other-id"));
        Assert.False(store.IsNonceUsed("agent-B", "n", "other-id"));
        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(Rec("agent-B", "id-1", "n")));
        Assert.Empty(store.Records("agent-C"));
    }

    [Fact]
    public void Records_SurviveAReloadAndANewStoreStartsWithResetAtZero()
    {
        var store = new CommandReplayStore(StorePath, _time);
        Assert.Equal(0, store.ResetAt);
        store.TryReserve(Rec("agent-A", "id-1", "n"));
        Assert.True(store.TryUpdate(Rec("agent-A", "id-1", "n", EnvelopeRecordStates.Done, resultB64: "e30=")));

        var reloaded = new CommandReplayStore(StorePath, _time);

        var record = reloaded.Find("agent-A", "id-1")!;
        Assert.Equal(EnvelopeRecordStates.Done, record.State);
        Assert.Equal("e30=", record.ResultB64);
        Assert.Equal(0, reloaded.ResetAt);
    }

    [Fact]
    public void CorruptFile_IsSetAsideAndTheNewStoreRemembersItsResetAcrossReloads()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(StorePath, "{broken");

        var store = new CommandReplayStore(StorePath, _time);

        Assert.Equal(T0, store.ResetAt);
        Assert.Empty(store.Records("agent-A"));
        Assert.Single(Directory.GetFiles(_dir, $"{CommandReplayStore.FileName}.corrupt-{T0}"));
        _time.Advance(TimeSpan.FromSeconds(50));
        Assert.Equal(T0, new CommandReplayStore(StorePath, _time).ResetAt);
    }

    [Fact]
    public void FullOfLiveRecords_NeverEvictsOne()
    {
        StoreFileWriter.Write(StorePath, 0, Enumerable.Range(0, CommandReplayStore.MaxRecords)
            .Select(i => Rec("agent-A", $"id-{i}", $"n-{i}")));
        var store = new CommandReplayStore(StorePath, _time);

        Assert.Equal(ReplayReserveOutcome.Full, store.TryReserve(Rec("agent-A", "id-new", "n-new")));
        Assert.Equal(CommandReplayStore.MaxRecords, store.Records("agent-A").Count);
    }

    [Fact]
    public void FullStore_EvictsOnlyRecordsPastTheirWindowWithoutAPendingResult()
    {
        StoreFileWriter.Write(StorePath, 0, Enumerable.Range(0, CommandReplayStore.MaxRecords).Select(i => i switch
        {
            0 => Rec("agent-A", "id-pending", "n-0", EnvelopeRecordStates.Started, expiresAt: T0 + 10),
            1 => Rec("agent-A", "id-old", "n-1", EnvelopeRecordStates.Done, expiresAt: T0 + 11, resultB64: "e30=", submitted: true),
            _ => Rec("agent-A", $"id-{i}", $"n-{i}", expiresAt: T0 + 5000),
        }));
        var store = new CommandReplayStore(StorePath, _time);
        _time.Advance(TimeSpan.FromSeconds(100));

        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(Rec("agent-A", "id-new", "n-new", expiresAt: T0 + 5000)));

        Assert.NotNull(store.Find("agent-A", "id-pending"));
        Assert.Null(store.Find("agent-A", "id-old"));
        Assert.NotNull(store.Find("agent-A", "id-new"));
        Assert.Equal(CommandReplayStore.MaxRecords, store.Records("agent-A").Count);
    }

    [Fact]
    public void Record_IsKeptUntilTwentyFourHoursAfterExpiryAndThenAgesOut()
    {
        var store = new CommandReplayStore(StorePath, _time);
        store.TryReserve(Rec("agent-A", "id-1", "n"));

        _time.Advance(TimeSpan.FromSeconds(120 + CommandReplayStore.RetentionSeconds));
        Assert.NotNull(new CommandReplayStore(StorePath, _time).Find("agent-A", "id-1"));

        _time.Advance(TimeSpan.FromSeconds(1));
        Assert.Null(new CommandReplayStore(StorePath, _time).Find("agent-A", "id-1"));
    }

    [Fact]
    public void HeldResultBytesAboveFourMiB_DropTheOldestSubmittedBytesAndKeepTheirHash()
    {
        var big = Convert.ToBase64String(new byte[1_500_000]);
        StoreFileWriter.Write(StorePath, 0, new[]
        {
            Rec("agent-A", "id-1", "n-1", EnvelopeRecordStates.Done, T0 + 100, big, submitted: true),
            Rec("agent-A", "id-2", "n-2", EnvelopeRecordStates.Done, T0 + 101, big, submitted: true),
            Rec("agent-A", "id-3", "n-3", EnvelopeRecordStates.Done, T0 + 102, big, submitted: true),
            Rec("agent-A", "id-4", "n-4"),
        });
        var store = new CommandReplayStore(StorePath, _time);

        Assert.True(store.TryUpdate(Rec("agent-A", "id-4", "n-4", EnvelopeRecordStates.Started)));

        var oldest = store.Find("agent-A", "id-1")!;
        Assert.Null(oldest.ResultB64);
        Assert.Equal(new string('b', 64), oldest.ResultSha256);
        Assert.NotNull(store.Find("agent-A", "id-2")!.ResultB64);
        Assert.NotNull(store.Find("agent-A", "id-3")!.ResultB64);
    }

    [Fact]
    public void UnwritableLocation_FailsClosedWithUnavailable()
    {
        Directory.CreateDirectory(_dir);
        var blocker = Path.Combine(_dir, "blocker");
        File.WriteAllText(blocker, "x");
        var store = new CommandReplayStore(Path.Combine(blocker, CommandReplayStore.FileName), _time);

        Assert.Equal(ReplayReserveOutcome.Unavailable, store.TryReserve(Rec("agent-A", "id-1", "n")));
        Assert.Null(store.Find("agent-A", "id-1"));
    }
}
