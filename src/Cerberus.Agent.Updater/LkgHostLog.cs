using System.Globalization;
using System.IO;
using System.Text;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Updater;

internal sealed class LkgHostLog(string updatesRoot)
{
    internal const long MaximumBytes = 1024 * 1024;

    public void Write(string code) => Write(code, null);

    internal void WriteRestartFailure(int win32Error) => Write("watch_restart_failed", win32Error);

    private void Write(string code, int? win32Error)
    {
        if (!AgentUpdateErrorCodes.IsCode(code))
            throw new ArgumentException("The watch host log requires a bounded event code.", nameof(code));

        try
        {
            var root = AgentUpdateSecurity.NormalizeRoot(updatesRoot);
            AgentUpdateSecurity.ValidateTrustedPath(root, root, allowMissing: false);
            var directory = Path.Combine(root, "logs");
            var current = Path.Combine(directory, "lkg-host.log");
            var previous = Path.Combine(directory, "lkg-host.1.log");
            AgentUpdateSecurity.ValidateTrustedPath(current, root, allowMissing: true);
            AgentUpdateSecurity.ValidateTrustedPath(previous, root, allowMissing: true);
            Directory.CreateDirectory(directory);

            var detail = win32Error is { } error ? " win32=" + error.ToString(CultureInfo.InvariantCulture) : "";
            var entry = Encoding.UTF8.GetBytes(DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture) + " " + code + detail + "\n");
            using (var log = Open(current))
            {
                if (AppendIfFits(log, entry))
                    return;
            }

            File.Move(current, previous, overwrite: true);
            using var next = Open(current);
            AppendIfFits(next, entry);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            // Logging cannot block recovery or turn an unsafe path into a writable one.
        }
    }

    private static FileStream Open(string path) => new(path, FileMode.Append, FileAccess.Write, FileShare.Read);

    private static bool AppendIfFits(FileStream stream, byte[] entry)
    {
        if (stream.Length > MaximumBytes - entry.Length)
            return false;
        stream.Write(entry);
        stream.Flush(flushToDisk: true);
        return true;
    }
}
