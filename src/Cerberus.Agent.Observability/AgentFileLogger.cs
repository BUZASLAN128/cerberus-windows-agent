using Cerberus.Agent.Core;

namespace Cerberus.Agent.Observability;

public sealed class AgentFileLogger : IAgentLogger, IDisposable
{
    private readonly object _gate = new();
    private readonly StreamWriter _writer;
    private readonly bool _alsoConsole;

    public AgentFileLogger(string logFilePath, bool alsoConsole = true)
    {
        var dir = Path.GetDirectoryName(logFilePath);
        if (!string.IsNullOrWhiteSpace(dir))
            Directory.CreateDirectory(dir);

        var stream = new FileStream(
            logFilePath,
            FileMode.Append,
            FileAccess.Write,
            FileShare.ReadWrite);

        _writer = new StreamWriter(stream) { AutoFlush = true };
        _alsoConsole = alsoConsole;
    }

    public static AgentFileLogger CreateDefault(bool alsoConsole = true)
    {
        var baseDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "CerberusAgent",
            "logs");
        var path = Path.Combine(baseDir, "agent.log");
        return new AgentFileLogger(path, alsoConsole);
    }

    public void Info(string message) => Write("INFO", message, null);
    public void Warn(string message) => Write("WARN", message, null);
    public void Error(string message, Exception? ex = null) => Write("ERROR", message, ex);

    private void Write(string level, string message, Exception? ex)
    {
        var ts = DateTimeOffset.Now.ToString("yyyy-MM-dd HH:mm:ss.fff zzz");
        var line = $"[{ts}] {level} {Sanitizer.Redact(message)}";
        if (ex is not null)
            line += $" | {ex.GetType().Name}: {Sanitizer.Redact(ex.Message)}";

        lock (_gate)
        {
            _writer.WriteLine(line);
            if (_alsoConsole && Environment.UserInteractive)
                Console.WriteLine(line);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _writer.Dispose();
        }
    }
}

