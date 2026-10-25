using Cerberus.Agent.Observability;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentFileLoggerTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_dir))
                Directory.Delete(_dir, recursive: true);
        }
        catch (IOException)
        {
            // Best-effort cleanup of the per-test temp directory.
        }
    }

    [Fact]
    public void TwoLoggersOnOnePath_KeepEveryLineInWriteOrder()
    {
        var path = Path.Combine(_dir, "agent.log");
        using (var a = new AgentFileLogger(path, alsoConsole: false))
        using (var b = new AgentFileLogger(path, alsoConsole: false))
        {
            a.Info("A1 first line");
            b.Info("B1 second line");
            a.Info("A2 third line");
            b.Info("B2 fourth line");
        }

        var lines = File.ReadAllLines(path);
        Assert.Equal(4, lines.Length);
        Assert.EndsWith("INFO A1 first line", lines[0]);
        Assert.EndsWith("INFO B1 second line", lines[1]);
        Assert.EndsWith("INFO A2 third line", lines[2]);
        Assert.EndsWith("INFO B2 fourth line", lines[3]);
    }

    [Fact]
    public void OneLogger_AppendsToAnExistingFileWithoutTruncating()
    {
        Directory.CreateDirectory(_dir);
        var path = Path.Combine(_dir, "agent.log");
        File.WriteAllText(path, "existing line" + Environment.NewLine);

        using (var logger = new AgentFileLogger(path, alsoConsole: false))
            logger.Warn("new line");

        var lines = File.ReadAllLines(path);
        Assert.Equal(2, lines.Length);
        Assert.Equal("existing line", lines[0]);
        Assert.EndsWith("WARN new line", lines[1]);
    }
}
