using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateJournalPatchTests : IDisposable
{
    private const string AttemptId = "7d73b7509a8247239ed692065d55801d";
    private const long InitialRevision = 17;
    private readonly string _root = Path.Combine(Path.GetTempPath(), "cerberus-journal-patch-" + Guid.NewGuid().ToString("N"));

    [Fact]
    public void MatchedPatchPreservesUnknownMembersAndRetriesIoFailure()
    {
        var store = CreateJournal();
        var calls = 0;

        Assert.True(AgentUpdateJournalPatch.TryApply(store, AttemptId, AgentUpdateStates.HealthPending, before =>
        {
            if (++calls == 1)
                throw new IOException("Synthetic transient I/O failure.");
            return before with { Phase = AgentUpdateStates.Installed };
        }));

        var after = store.Read();
        Assert.Equal(2, calls);
        Assert.Equal(InitialRevision + 1, after.Revision);
        Assert.Equal(AgentUpdateStates.Installed, after.Phase);
        Assert.Equal(AttemptId, after.AttemptId);
        Assert.Equal("future", after.Extra!["newerUpdaterField"].GetProperty("binding").GetString());
        AssertLockReleased();
    }

    [Theory]
    [InlineData(AttemptId, AgentUpdateStates.Installed)]
    [InlineData("a7b90f5088074f15a8293d165be587c8", AgentUpdateStates.HealthPending)]
    public void StalePatchLeavesJournalBytesUntouched(string attemptId, string phase)
    {
        var store = CreateJournal();
        var bytes = File.ReadAllBytes(JournalPath);

        Assert.False(AgentUpdateJournalPatch.TryApply(store, attemptId, phase, _ =>
            throw new InvalidOperationException("A stale patch must not be evaluated.")));

        Assert.Equal(bytes, File.ReadAllBytes(JournalPath));
        AssertLockReleased();
    }

    [Fact]
    public void DeclinedPatchLeavesJournalBytesUntouched()
    {
        var store = CreateJournal();
        var bytes = File.ReadAllBytes(JournalPath);
        var calls = 0;

        Assert.False(AgentUpdateJournalPatch.TryApply(store, AttemptId, AgentUpdateStates.HealthPending, _ =>
        {
            calls++;
            return null;
        }));

        Assert.Equal(1, calls);
        Assert.Equal(bytes, File.ReadAllBytes(JournalPath));
        AssertLockReleased();
    }

    [Theory]
    [InlineData("committed_watch")]
    [InlineData("rolling_back")]
    public void WatchAndRollbackPhasesRoundTripAsUnfinishedInstallation(string phase)
    {
        var now = new DateTimeOffset(2026, 11, 18, 10, 0, 0, TimeSpan.Zero);
        var before = CreateJournal().Read();
        var expected = before with
        {
            Phase = phase,
            WatchRequestedUtc = now,
            WatchAttemptId = AttemptId,
            WatchOutcomeCode = "watch_unavailable",
            WatchOutcomeAttemptId = AttemptId,
            RollbackAttemptId = new string('r', 64),
            RollbackStartedUtc = now,
            RollbackAttemptCount = 3,
            RollbackFirstUtc = now.AddMinutes(-30),
        };
        AgentUpdateDurableFile.Write(JournalPath, _root, expected);

        var actual = new AgentUpdateJournalStore(_root).Read();
        Assert.True(actual.MayHaveStartedInstallation);
        Assert.True(actual.HasUnfinishedAttempt);
        Assert.Equal(expected with { Extra = null }, actual with { Extra = null });
        Assert.Equal("future", actual.Extra!["newerUpdaterField"].GetProperty("binding").GetString());
        using var json = JsonDocument.Parse(File.ReadAllBytes(JournalPath));
        Assert.Equal("watch_unavailable", json.RootElement.GetProperty("watchOutcomeCode").GetString());
        Assert.Equal(3, json.RootElement.GetProperty("rollbackAttemptCount").GetInt32());
    }

    [Theory]
    [InlineData("watchRequestedUtc", "\"2026-11-18T10:00:00+03:00\"")]
    [InlineData("watchAttemptId", "\"../unsafe\"")]
    [InlineData("watchOutcomeCode", "\"Open\"")]
    [InlineData("watchOutcomeAttemptId", "\"../unsafe\"")]
    [InlineData("rollbackAttemptId", "\"\"")]
    [InlineData("rollbackStartedUtc", "\"0001-01-01T00:00:00+00:00\"")]
    [InlineData("rollbackAttemptCount", "4")]
    [InlineData("rollbackAttemptCount", "-1")]
    [InlineData("rollbackFirstUtc", "\"2026-11-18T10:00:00+03:00\"")]
    public void JournalReadRejectsOutOfBoundsWatchOrRollbackMember(string member, string jsonValue)
    {
        AgentUpdateSecurity.EnsureProtectedRoot(_root);
        File.WriteAllText(JournalPath, $$"""{"phase":"rolling_back","{{member}}":{{jsonValue}}}""");
        var store = new AgentUpdateJournalStore(_root);

        Assert.Throws<InvalidOperationException>(store.Read);
    }

    [Fact]
    public void JournalWithoutWatchMembersReadsWithDefaultsAndPreservesExtensionData()
    {
        AgentUpdateSecurity.EnsureProtectedRoot(_root);
        File.WriteAllText(JournalPath, """{"phase":"health_pending","futureMember":42}""");
        var store = new AgentUpdateJournalStore(_root);

        var journal = store.Read();

        Assert.Equal(AgentUpdateStates.HealthPending, journal.Phase);
        Assert.Null(journal.WatchRequestedUtc);
        Assert.Null(journal.WatchAttemptId);
        Assert.Null(journal.WatchOutcomeCode);
        Assert.Null(journal.WatchOutcomeAttemptId);
        Assert.Null(journal.RollbackAttemptId);
        Assert.Null(journal.RollbackStartedUtc);
        Assert.Equal(0, journal.RollbackAttemptCount);
        Assert.Null(journal.RollbackFirstUtc);
        Assert.Equal(42, journal.Extra!["futureMember"].GetInt32());
    }

    [Theory]
    [InlineData("committed_watch")]
    [InlineData("rolling_back")]
    public void ReturningWatchPhaseInputKeepsJournalBytesAndRevisionButMutationCommits(string phase)
    {
        var root = _root;
        var path = Path.Combine(root, "transaction.json");
        var store = new AgentUpdateJournalStore(root);
        var original = store.Change(before => before with { AttemptId = AttemptId, Phase = phase });
        var bytes = File.ReadAllBytes(path);

        var unchanged = store.Change(before => before);

        Assert.Equal(original.Revision, unchanged.Revision);
        Assert.Equal(bytes, File.ReadAllBytes(path));

        var nextCheck = new DateTimeOffset(2026, 11, 19, 10, 0, 0, TimeSpan.Zero);
        var changed = store.Change(before => before with { NextCheckUtc = nextCheck });

        Assert.Equal(original.Revision + 1, changed.Revision);
        Assert.Equal(changed, new AgentUpdateJournalStore(root).Read());
        Assert.Equal(nextCheck, changed.NextCheckUtc);
        Assert.False(bytes.SequenceEqual(File.ReadAllBytes(path)));
    }

    [Theory]
    [InlineData("health_pending", true)]
    [InlineData("committed_watch", false)]
    [InlineData("rolling_back", false)]
    public void OnlyReturningExactWatchPhaseInputSuppressesJournalRevision(string phase, bool returnInput)
    {
        var store = new AgentUpdateJournalStore(_root);
        var original = store.Change(before => before with { AttemptId = AttemptId, Phase = phase });

        var changed = store.Change(before => returnInput ? before : before with { });

        Assert.Equal(original.Revision + 1, changed.Revision);
        Assert.Equal(changed, store.Read());
    }

    private string JournalPath => Path.Combine(_root, "transaction.json");

    private AgentUpdateJournalStore CreateJournal()
    {
        Assert.False(AgentUpdateSecurity.IsUnderDirectory(_root, Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)));
        // A directory created with the default temp ACL would fail the journal's provenance guard.
        AgentUpdateSecurity.EnsureProtectedRoot(_root);
        var journal = new AgentUpdateJournal
        {
            AttemptId = AttemptId,
            Phase = AgentUpdateStates.HealthPending,
            Revision = InitialRevision,
            Extra = new AgentUpdateJsonExtra { ["newerUpdaterField"] = JsonSerializer.SerializeToElement(new { binding = "future" }) },
        };
        AgentUpdateDurableFile.Write(JournalPath, _root, journal);
        return new AgentUpdateJournalStore(_root);
    }

    private void AssertLockReleased()
    {
        var path = Path.Combine(_root, AgentUpdateSecurity.GlobalLockFileName);
        using var gate = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
    }

    public void Dispose()
    {
        if (Directory.Exists(_root))
            Directory.Delete(_root, recursive: true);
    }
}
