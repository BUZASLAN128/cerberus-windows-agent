using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Cerberus.Agent.Core;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace Cerberus.Agent.Updater;

internal static partial class LkgWatchHostWindows
{
    internal static void Restart(bool invokedByScm, Func<AgentUpdateJournal?> readJournal)
    {
        AgentUpdateWatchRestart Decide()
        {
            var journal = readJournal();
            var owner = HasInstallerProcess(journal);
            var sample = ReadStatus(bootId: "", includeProcessStart: false);
            return AgentUpdateWatchPolicy.RestartDecision(sample, invokedByScm, owner, InstallerOwnsService());
        }

        var decision = Decide();
        if (decision == AgentUpdateWatchRestart.WaitThenStart)
        {
            Thread.Sleep(TimeSpan.FromSeconds(60));
            decision = Decide();
        }
        if (decision != AgentUpdateWatchRestart.None)
        {
            using var manager = OpenManager();
            using var service = OpenService(manager, Start);
            if (!StartServiceW(service, 0, IntPtr.Zero))
            {
                var error = Marshal.GetLastWin32Error();
                if (error != ServiceAlreadyRunning) throw new Win32Exception(error);
            }
        }
    }

    internal static bool HasInstallerProcess(AgentUpdateJournal? journal)
        => IsAlive(journal?.RunnerProcessId, journal?.RunnerStartedUtc) || IsAlive(journal?.InstallerProcessId, journal?.InstallerStartedUtc);

    internal static bool NoInstallerActivity(AgentUpdateJournal journal)
        => NoInstallerActivity(journal, IsProvenInactive, InstallerOwnsService, ReadMsiInProgress);

    internal static bool NoInstallerActivity(AgentUpdateJournal journal,
        Func<int?, DateTimeOffset?, bool> isInactive, Func<bool> ownsInstallerMutex, Func<bool> readMsiInProgress)
    {
        try
        {
            return isInactive(journal.RunnerProcessId, journal.RunnerStartedUtc) &&
                isInactive(journal.InstallerProcessId, journal.InstallerStartedUtc) &&
                !ownsInstallerMutex() && !readMsiInProgress();
        }
        catch (Exception ex) when (LkgWatchHost.IsHostFailure(ex)) { return false; }
    }

    private static bool ReadMsiInProgress()
    {
        const string inProgress = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\InProgress";
        const int queryValue = 0x0001;
        const int wow64View64 = 0x0100;
        const int wow64View32 = 0x0200;
        const int fileNotFound = 2;
        const int pathNotFound = 3;
        var views = Environment.Is64BitOperatingSystem ? new[] { wow64View64, wow64View32 } : new[] { 0 };
        foreach (var view in views)
        {
            var status = RegOpenKeyExW(Registry.LocalMachine.Handle, inProgress, 0, queryValue | view, out var marker);
            using (marker)
            {
                if (status == 0) return true;
                if (status is not (fileNotFound or pathNotFound)) throw new Win32Exception(status);
            }
        }
        return false;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int RegOpenKeyExW(SafeRegistryHandle root, string subkey, int options, int desiredAccess,
        out SafeRegistryHandle result);

    private static bool IsProvenInactive(int? pid, DateTimeOffset? startedUtc)
    {
        if (pid is null && startedUtc is null) return true;
        if (pid is not > 0 || startedUtc is null) return false;
        try
        {
            using var process = Process.GetProcessById(pid.Value);
            return process.HasExited || new DateTimeOffset(process.StartTime.ToUniversalTime()) != startedUtc;
        }
        catch (ArgumentException) { return true; } // No process currently has the recorded PID.
        catch (Exception ex) when (LkgWatchHost.IsHostFailure(ex)) { return false; }
    }

    internal static bool InstallerOwnsService()
    {
        try
        {
            using var mutex = Mutex.OpenExisting(@"Global\_MSIExecute");
            return true;
        }
        catch (WaitHandleCannotBeOpenedException) { return false; }
        catch (UnauthorizedAccessException) { return true; }
    }

    private static bool IsAlive(int? pid, DateTimeOffset? startedUtc)
    {
        if (pid is not > 0 || startedUtc is null) return false;
        try
        {
            using var process = Process.GetProcessById(pid.Value);
            return !process.HasExited && new DateTimeOffset(process.StartTime.ToUniversalTime()) == startedUtc;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or Win32Exception) { return false; }
    }
}
