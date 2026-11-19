using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

/// <summary>A record write must survive another process briefly reading the record it replaces.</summary>
public sealed class AgentUpdateRecordReplaceTests
{
    private sealed record Record(int Value);

    [Fact]
    public async Task Write_WaitsForAReaderThatClosesWithinTheRetryWindow()
    {
        var root = NewRoot();
        try
        {
            var path = Path.Combine(root, "transaction.json");
            AgentUpdateDurableFile.Write(path, root, new Record(1));
            var reader = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
            var release = Task.Run(async () => { await Task.Delay(80); reader.Dispose(); });

            AgentUpdateDurableFile.Write(path, root, new Record(2));
            await release;

            Assert.Equal(new Record(2), AgentUpdateDurableFile.Read<Record>(path, root));
            Assert.Empty(Directory.GetFiles(root, "*.tmp"));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void Write_FailsAndKeepsTheRecordWhenTheReaderStaysOpen()
    {
        var root = NewRoot();
        try
        {
            var path = Path.Combine(root, "transaction.json");
            AgentUpdateDurableFile.Write(path, root, new Record(1));
            using (new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                Assert.Throws<UnauthorizedAccessException>(() => AgentUpdateDurableFile.Write(path, root, new Record(2)));

            Assert.Equal(new Record(1), AgentUpdateDurableFile.Read<Record>(path, root));
            Assert.Empty(Directory.GetFiles(root, "*.tmp"));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static string NewRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-update-record-replace-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        return root;
    }
}
