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
