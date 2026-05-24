using Cerberus.Agent.Core;

namespace Cerberus.Agent.Observability;

public sealed class AgentFileLogger : IAgentLogger, IDisposable
{
    private const long DefaultMaxBytes = 2 * 1024 * 1024;
    private const int DefaultRetentionFiles = 5;

    private readonly object _gate = new();
    private readonly string _logFilePath;
    private readonly bool _alsoConsole;
    private readonly long _maxBytes;
    private readonly int _retentionFiles;
    private StreamWriter _writer;

    public AgentFileLogger(
        string logFilePath,
        bool alsoConsole = true,
        long maxBytes = DefaultMaxBytes,
        int retentionFiles = DefaultRetentionFiles)
    {
        var dir = Path.GetDirectoryName(logFilePath);
        if (!string.IsNullOrWhiteSpace(dir))
            Directory.CreateDirectory(dir);

        _logFilePath = logFilePath;
        _alsoConsole = alsoConsole;
        _maxBytes = Math.Max(64 * 1024, maxBytes);
        _retentionFiles = Math.Clamp(retentionFiles, 1, 20);
        _writer = OpenWriter(logFilePath);
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
            RotateIfNeeded();
            _writer.WriteLine(line);
        }

        if (_alsoConsole && Environment.UserInteractive)
            Console.WriteLine(line);
    }

    private void RotateIfNeeded()
    {
        try
        {
            var stream = _writer.BaseStream;
            if (stream.Length < _maxBytes)
                return;

            _writer.Dispose();
            var rotatedPath = $"{_logFilePath}.{DateTimeOffset.UtcNow:yyyyMMddHHmmssfff}.log";
            if (File.Exists(_logFilePath))
                File.Move(_logFilePath, rotatedPath, overwrite: false);
            PruneOldRotatedLogs();
            _writer = OpenWriter(_logFilePath);
        }
        catch (IOException)
        {
            _writer = OpenWriter(_logFilePath);
        }
        catch (UnauthorizedAccessException)
        {
            _writer = OpenWriter(_logFilePath);
        }
    }

    private void PruneOldRotatedLogs()
    {
        var dir = Path.GetDirectoryName(_logFilePath);
        if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
            return;

        var prefix = Path.GetFileName(_logFilePath) + ".";
        var oldLogs = Directory
            .EnumerateFiles(dir, $"{Path.GetFileName(_logFilePath)}.*.log")
            .OrderByDescending(File.GetCreationTimeUtc)
            .Skip(_retentionFiles)
            .ToArray();
        foreach (var path in oldLogs)
        {
            if (Path.GetFileName(path).StartsWith(prefix, StringComparison.Ordinal))
                File.Delete(path);
        }
    }

    private static StreamWriter OpenWriter(string logFilePath)
    {
        var stream = new FileStream(
            logFilePath,
            FileMode.Append,
            FileAccess.Write,
            FileShare.ReadWrite);

        return new StreamWriter(stream) { AutoFlush = true };
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _writer.Dispose();
        }
    }
}
