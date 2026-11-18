using System.Text.Json;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateJournalPatchTests : IDisposable
{
    private const string AttemptId = "7d73b7509a8247239ed692065d55801d";
    private readonly DirectoryInfo _root = Directory.CreateTempSubdirectory("cerberus-journal-patch-");

    [Fact]
    public void MatchedPatchPreservesUnknownMembersAndRetriesIoFailure()
    {
        var store = CreateJournal();
        var calls = 0;

        Assert.True(AgentUpdateJournalPatch.TryApply(ChangeFixture, AttemptId, AgentUpdateStates.HealthPending, before =>
        {
            if (++calls == 1)
                throw new IOException("Synthetic transient I/O failure.");
            return before with { Phase = AgentUpdateStates.Installed };
        }));

        var after = store.Read();
        Assert.Equal(2, calls);
        Assert.Equal(18, after.Revision);
        Assert.Equal(AgentUpdateStates.Installed, after.Phase);
        Assert.Equal("future", after.Extra!["newerUpdaterField"].GetProperty("binding").GetString());
    }

    [Theory]
    [InlineData(AttemptId, AgentUpdateStates.Installed)]
    [InlineData("a7b90f5088074f15a8293d165be587c8", AgentUpdateStates.HealthPending)]
    public void StalePatchLeavesJournalBytesUntouched(string attemptId, string phase)
    {
        CreateJournal();
        var bytes = File.ReadAllBytes(JournalPath);

        Assert.False(AgentUpdateJournalPatch.TryApply(ChangeFixture, attemptId, phase, _ =>
            throw new InvalidOperationException("A stale patch must not be evaluated.")));

        Assert.Equal(bytes, File.ReadAllBytes(JournalPath));
    }

    private string JournalPath => Path.Combine(_root.FullName, "transaction.json");

    private AgentUpdateJournal ChangeFixture(Func<AgentUpdateJournal, AgentUpdateJournal> change)
    {
        var root = _root.FullName;
        var before = new AgentUpdateJournalStore(root).Read();
        var after = change(before) with { Revision = before.Revision + 1 };
        AgentUpdateDurableFile.Write(JournalPath, root, after);
        return after;
    }

    private AgentUpdateJournalStore CreateJournal()
    {
        var root = _root.FullName;
        var journal = new AgentUpdateJournal
        {
            AttemptId = AttemptId,
            Phase = AgentUpdateStates.HealthPending,
            Revision = 17,
            Extra = new AgentUpdateJsonExtra { ["newerUpdaterField"] = JsonSerializer.SerializeToElement(new { binding = "future" }) },
        };
        AgentUpdateDurableFile.Write(JournalPath, root, journal);
        return new AgentUpdateJournalStore(root);
    }

    public void Dispose() => _root.Delete(recursive: true);
}
