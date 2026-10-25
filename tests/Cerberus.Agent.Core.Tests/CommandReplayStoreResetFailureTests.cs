using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

/// <summary>
/// Corrupt store whose reset cannot be written and whose original cannot be put back (unit/support tier, real
/// file system). The write fails because the temp name exceeds the file-name limit; the move-back fails because the
/// logger hook occupies the store path with a directory once the write failure is logged.
/// </summary>
public sealed class CommandReplayStoreResetFailureTests : IDisposable
{
    private const long T0 = EnvelopeHarness.T0;
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
    private readonly FakeTime _time = new(T0);

    // A 230-character name fits the 255-character component limit with the 18-character ".corrupt-<unix>" suffix
    // (set-aside works) but not with the 37-character ".<guid>.tmp" suffix (the reset write fails).
    private string LongStorePath => Path.Combine(_dir, new string('s', 225) + ".json");
    private string StorePath => Path.Combine(_dir, CommandReplayStore.FileName);

    public void Dispose()
    {
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, recursive: true);
    }

    private static CommandReplayRecord Rec(string id)
        => StoreFileWriter.Record("agent-A", id, "n", EnvelopeRecordStates.Reserved, T0, T0 + 120, null, false);

    [Fact]
    public void ResetWriteFailsAndMoveBackFails_SameStoreRefusesReplay()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(LongStorePath, "{broken");
        var store = new CommandReplayStore(LongStorePath, _time, new OccupyStorePathOnWriteError(LongStorePath));

        Assert.Equal(T0, store.ResetAt);
        Assert.False(store.IsAvailable);
        Assert.Equal(ReplayReserveOutcome.Unavailable, store.TryReserve(Rec("id-1")));
        Assert.Null(store.Find("agent-A", "id-1"));
    }

    [Fact]
    public void ResetWriteSucceeds_StoreIsAvailableWithTheResetTime()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(StorePath, "{broken");
        var store = new CommandReplayStore(StorePath, _time);

        Assert.Equal(T0, store.ResetAt);
        Assert.True(store.IsAvailable);
        Assert.Equal(ReplayReserveOutcome.Reserved, store.TryReserve(Rec("id-1")));
    }

    [Fact]
    public void StoreFileMissingNextToCorruptSibling_ResetsAndPersists()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText($"{StorePath}.corrupt-{T0 - 500}", "{broken");

        var store = new CommandReplayStore(StorePath, _time);

        Assert.Equal(T0, store.ResetAt);
        Assert.True(store.IsAvailable);
        Assert.True(File.Exists(StorePath));
        Assert.Equal(T0, new CommandReplayStore(StorePath, new FakeTime(T0 + 60)).ResetAt);
    }

    [Fact]
    public void StoreFileMissingWithoutCorruptSibling_IsAFreshInstall()
    {
        Directory.CreateDirectory(_dir);

        var store = new CommandReplayStore(StorePath, _time);

        Assert.Equal(0, store.ResetAt);
        Assert.True(store.IsAvailable);
    }

    private sealed class OccupyStorePathOnWriteError(string path) : IAgentLogger
    {
        public void Info(string message) { }

        public void Warn(string message) { }

        public void Error(string message, Exception? ex = null)
        {
            if (message.Contains("write failed", StringComparison.Ordinal))
                Directory.CreateDirectory(path);
        }
    }
}
