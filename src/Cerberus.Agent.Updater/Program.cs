using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Cerberus.Agent.App;
using Microsoft.Win32;

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

        ClosedApplications closedApplications = new(false, []);
        try
        {
            var fullMsiPath = Path.GetFullPath(msi);
            log.Write($"MSI artifact: {fullMsiPath}");
            TryStopService();
            closedApplications = CloseAgentUiApplications();
            var msiLogPath = log.CreateSiblingLogPath("msiexec");
            var exitCode = RunMsiexec(
                $"/i \"{fullMsiPath}\" /qn /norestart CERBERUS_EULA_ACCEPTED=1 /l*v \"{msiLogPath}\"",
                log);
            log.Write($"msiexec exit code: {exitCode}; msi log: {msiLogPath}");
            if (exitCode != 0)
            {
                TryStartService();
                TryRestartAgentUi(closedApplications, log);
                return exitCode;
            }

            TryStartService();
            TryRestartAgentUi(closedApplications, log);
            log.Write("Cerberus Agent updater completed.");
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
            log.Write($"Updater failed: {ex}");
            TryStartService();
            TryRestartAgentUi(closedApplications, log);
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

    private static ClosedApplications CloseAgentUiApplications()
    {
        var uiSessions = new HashSet<int>();
        var uiWasRunning = false;
        foreach (var name in new[] { "Cerberus.Agent", "Cerberus.Agent.Tray", "Cerberus.Agent.Setup", "Cerberus.Agent.App" })
        {
            foreach (var process in Process.GetProcessesByName(name))
            {
                try
                {
                    if (string.Equals(name, "Cerberus.Agent", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(name, "Cerberus.Agent.Tray", StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(name, "Cerberus.Agent.Setup", StringComparison.OrdinalIgnoreCase))
                    {
                        uiWasRunning = true;
                        try
                        {
                            if (process.SessionId > 0)
                                uiSessions.Add(process.SessionId);
                        }
                        catch (InvalidOperationException)
                        {
                        }
                    }

                    if (!process.CloseMainWindow())
                        process.Kill(entireProcessTree: true);
                }
                catch
                {
                    // Best-effort shutdown; msiexec validates locked files.
                }
            }
        }

        return new ClosedApplications(uiWasRunning, uiSessions.ToArray());
    }

    private static void TryRestartAgentUi(ClosedApplications closedApplications, UpdaterLog log)
    {
        if (!closedApplications.UiWasRunning)
        {
            log.Write("Agent UI restart skipped: UI was not running before update.");
            return;
        }

        var agentUiPath = ResolveInstalledAgentUiPath();
        if (string.IsNullOrWhiteSpace(agentUiPath) || !File.Exists(agentUiPath))
        {
            log.Write("Agent UI restart skipped: installed executable was not found.");
            return;
        }

        var sessionIds = closedApplications.UiSessionIds.Count > 0
            ? closedApplications.UiSessionIds
            : ActiveSessionProcessLauncher.GetActiveConsoleSessionIds();

        if (!IsRunningAsLocalSystem())
        {
            StartAgentUiInCurrentSession(agentUiPath, log);
            return;
        }

        var started = 0;
        foreach (var sessionId in sessionIds.Distinct().Where(id => id > 0))
        {
            if (ActiveSessionProcessLauncher.TryLaunch(agentUiPath, sessionId, log))
                started++;
        }

        log.Write(started > 0
            ? $"Agent UI restart requested for {started} user session(s)."
            : "Agent UI restart was not requested for any user session.");
    }

    private static void StartAgentUiInCurrentSession(string agentUiPath, UpdaterLog log)
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = agentUiPath,
                WorkingDirectory = Path.GetDirectoryName(agentUiPath) ?? AppContext.BaseDirectory,
                UseShellExecute = true,
            });
            log.Write("Agent UI restart requested in the current user session.");
        }
        catch (Exception ex)
        {
            log.Write($"Agent UI restart failed in current user session: {ex.GetType().Name}: {ex.Message}");
        }
    }

    private static bool IsRunningAsLocalSystem()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.IsSystem;
    }

    private static string? ResolveInstalledAgentUiPath()
    {
        var installRoot = ReadRegistryString(@"Software\Cerberus\WindowsAgent", "installRoot");
        if (!string.IsNullOrWhiteSpace(installRoot))
            return Path.Combine(installRoot.Trim(), "Cerberus.Agent.exe");

        var serviceImagePath = ReadRegistryString(
            $@"SYSTEM\CurrentControlSet\Services\{ServiceInstaller.ServiceName}",
            "ImagePath");
        var servicePath = ServiceInstaller.ExtractExecutablePathFromServiceImagePath(serviceImagePath);
        var serviceDir = string.IsNullOrWhiteSpace(servicePath) ? null : Path.GetDirectoryName(servicePath);
        if (!string.IsNullOrWhiteSpace(serviceDir))
            return Path.Combine(serviceDir, "Cerberus.Agent.exe");

        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Cerberus",
            "Windows Agent",
            "Cerberus.Agent.exe");
    }

    private static string? ReadRegistryString(string subKey, string valueName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(subKey);
            return key?.GetValue(valueName) as string;
        }
        catch
        {
            return null;
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

    private sealed record ClosedApplications(bool UiWasRunning, IReadOnlyCollection<int> UiSessionIds);

    private static class ActiveSessionProcessLauncher
    {
        private const uint CreateUnicodeEnvironment = 0x00000400;
        private const uint InvalidSessionId = 0xFFFFFFFF;

        public static IReadOnlyCollection<int> GetActiveConsoleSessionIds()
        {
            var sessionId = WTSGetActiveConsoleSessionId();
            return sessionId == InvalidSessionId || sessionId == 0
                ? Array.Empty<int>()
                : new[] { checked((int)sessionId) };
        }

        public static bool TryLaunch(string agentUiPath, int sessionId, UpdaterLog log)
        {
            if (sessionId <= 0)
                return false;

            IntPtr token = IntPtr.Zero;
            IntPtr environment = IntPtr.Zero;
            PROCESS_INFORMATION processInfo = default;
            try
            {
                if (!WTSQueryUserToken((uint)sessionId, out token))
                {
                    log.Write($"Agent UI restart skipped for session {sessionId}: WTSQueryUserToken failed with {Marshal.GetLastWin32Error()}.");
                    return false;
                }

                if (!CreateEnvironmentBlock(out environment, token, false))
                {
                    log.Write($"Agent UI restart skipped for session {sessionId}: CreateEnvironmentBlock failed with {Marshal.GetLastWin32Error()}.");
                    return false;
                }

                var startupInfo = new STARTUPINFO
                {
                    cb = Marshal.SizeOf<STARTUPINFO>(),
                    lpDesktop = @"winsta0\default",
                    dwFlags = 1,
                    wShowWindow = 1,
                };
                var commandLine = new StringBuilder($"\"{agentUiPath}\"");
                var started = CreateProcessAsUser(
                    token,
                    null,
                    commandLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    CreateUnicodeEnvironment,
                    environment,
                    Path.GetDirectoryName(agentUiPath),
                    ref startupInfo,
                    out processInfo);
                if (!started)
                {
                    log.Write($"Agent UI restart skipped for session {sessionId}: CreateProcessAsUser failed with {Marshal.GetLastWin32Error()}.");
                    return false;
                }

                log.Write($"Agent UI restart requested for session {sessionId}.");
                return true;
            }
            catch (Exception ex)
            {
                log.Write($"Agent UI restart failed for session {sessionId}: {ex.GetType().Name}: {ex.Message}");
                return false;
            }
            finally
            {
                if (processInfo.hThread != IntPtr.Zero)
                    CloseHandle(processInfo.hThread);
                if (processInfo.hProcess != IntPtr.Zero)
                    CloseHandle(processInfo.hProcess);
                if (environment != IntPtr.Zero)
                    DestroyEnvironmentBlock(environment);
                if (token != IntPtr.Zero)
                    CloseHandle(token);
            }
        }

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);

        [DllImport("userenv.dll", SetLastError = true)]
        private static extern bool DestroyEnvironmentBlock(IntPtr environment);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessAsUser(
            IntPtr token,
            string? applicationName,
            StringBuilder commandLine,
            IntPtr processAttributes,
            IntPtr threadAttributes,
            bool inheritHandles,
            uint creationFlags,
            IntPtr environment,
            string? currentDirectory,
            ref STARTUPINFO startupInfo,
            out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string? lpReserved;
            public string? lpDesktop;
            public string? lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
    }
}
