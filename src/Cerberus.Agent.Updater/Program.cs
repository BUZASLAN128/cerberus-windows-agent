using System.ComponentModel;
using System.Diagnostics;
using Cerberus.Agent.App;

namespace Cerberus.Agent.Updater;

internal static class Program
{
    public static int Main(string[] args)
    {
        var msi = args.Length > 0 ? args[0] : null;
        var log = UpdaterLog.Create();
        log.Write("Cerberus Agent updater starting.");
        if (string.IsNullOrWhiteSpace(msi) || !File.Exists(msi))
        {
            Console.Error.WriteLine("Usage: Cerberus.Agent.Updater.exe <path-to-msi>");
            log.Write("Updater failed: MSI path is missing or does not exist.");
            return 2;
        }

        try
        {
            var fullMsiPath = Path.GetFullPath(msi);
            log.Write($"MSI artifact: {fullMsiPath}");
            TryStopService();
            CloseTrayAndSetup();
            var msiLogPath = log.CreateSiblingLogPath("msiexec");
            var exitCode = RunMsiexec(
                $"/i \"{fullMsiPath}\" /qn /norestart CERBERUS_EULA_ACCEPTED=1 /l*v \"{msiLogPath}\"",
                log);
            log.Write($"msiexec exit code: {exitCode}; msi log: {msiLogPath}");
            if (exitCode != 0)
            {
                TryStartService();
                return exitCode;
            }

            TryStartService();
            log.Write("Cerberus Agent updater completed.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            log.Write($"Updater failed: {ex}");
            TryStartService();
            return 1;
        }
    }

    private static void TryStopService()
    {
        try { ServiceInstaller.StopOrThrow(); } catch { }
    }

    private static void TryStartService()
    {
        try { ServiceInstaller.StartOrThrow(); } catch { }
    }

    private static void CloseTrayAndSetup()
    {
        foreach (var name in new[] { "Cerberus.Agent.Tray", "Cerberus.Agent.Setup", "Cerberus.Agent.App" })
        {
            foreach (var process in Process.GetProcessesByName(name))
            {
                try
                {
                    if (!process.CloseMainWindow())
                        process.Kill(entireProcessTree: true);
                }
                catch
                {
                    // Best-effort shutdown; msiexec validates locked files.
                }
            }
        }
    }

    private static int RunMsiexec(string arguments, UpdaterLog log)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "msiexec.exe",
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using var process = Process.Start(psi) ?? throw new Win32Exception("Failed to start msiexec.exe");
        log.Write($"msiexec started: {arguments}");
        process.WaitForExit();
        var stdout = process.StandardOutput.ReadToEnd();
        var stderr = process.StandardError.ReadToEnd();
        if (!string.IsNullOrWhiteSpace(stdout))
            log.Write($"msiexec stdout: {stdout.Trim()}");
        if (!string.IsNullOrWhiteSpace(stderr))
            log.Write($"msiexec stderr: {stderr.Trim()}");
        return process.ExitCode;
    }

    private sealed class UpdaterLog
    {
        private readonly string _path;

        private UpdaterLog(string path)
        {
            _path = path;
        }

        public static UpdaterLog Create()
        {
            var root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "CerberusAgent",
                "updates",
                "logs");
            Directory.CreateDirectory(root);
            var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss");
            var path = Path.Combine(root, $"Cerberus.Agent.Updater-{stamp}-{Environment.ProcessId}.log");
            return new UpdaterLog(path);
        }

        public string CreateSiblingLogPath(string prefix)
        {
            var dir = Path.GetDirectoryName(_path) ?? AppContext.BaseDirectory;
            var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss");
            return Path.Combine(dir, $"{prefix}-{stamp}-{Environment.ProcessId}.log");
        }

        public void Write(string message)
        {
            try
            {
                File.AppendAllText(
                    _path,
                    $"[{DateTimeOffset.UtcNow:O}] {message}{Environment.NewLine}");
            }
            catch
            {
                // Updater logging must never prevent service recovery.
            }
        }
    }
}
