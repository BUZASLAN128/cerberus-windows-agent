using System.ComponentModel;
using System.Diagnostics;
using Cerberus.Agent.App;

namespace Cerberus.Agent.Updater;

internal static class Program
{
    public static int Main(string[] args)
    {
        var msi = args.Length > 0 ? args[0] : null;
        if (string.IsNullOrWhiteSpace(msi) || !File.Exists(msi))
        {
            Console.Error.WriteLine("Usage: Cerberus.Agent.Updater.exe <path-to-msi>");
            return 2;
        }

        try
        {
            TryStopService();
            CloseTrayAndSetup();
            var exitCode = RunMsiexec($"/i \"{Path.GetFullPath(msi)}\" /qn /norestart");
            if (exitCode != 0)
            {
                TryStartService();
                return exitCode;
            }

            TryStartService();
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(ex.Message);
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

    private static int RunMsiexec(string arguments)
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
        process.WaitForExit();
        return process.ExitCode;
    }
}
