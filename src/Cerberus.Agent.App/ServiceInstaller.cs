using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using System.ServiceProcess;

namespace Cerberus.Agent.App;

internal static class ServiceInstaller
{
    public const string ServiceName = "CerberusAgent";
    private const string ServiceDisplayName = "CERBERUS Windows Agent";
    private const string ServiceDescription = "CERBERUS Windows Agent (polling orchestrator).";

    public static void InstallOrThrow()
    {
        RequireAdminOrThrow();

        var exePath = Process.GetCurrentProcess().MainModule?.FileName
                      ?? throw new InvalidOperationException("Could not determine executable path.");

        // If already exists, no-op.
        if (ServiceExists())
            return;

        // sc.exe requires a space after '=' in key=value pairs.
        RunSc($"create \"{ServiceName}\" binPath= \"\\\"{exePath}\\\" --service\" start= auto DisplayName= \"{ServiceDisplayName}\"");
        RunSc($"description \"{ServiceName}\" \"{ServiceDescription}\"");

        // Service recovery: restart on failure 3 times with 60s delay.
        RunSc($"failure \"{ServiceName}\" reset= 86400 actions= restart/60000/restart/60000/restart/60000");
        RunSc($"failureflag \"{ServiceName}\" 1");

        // Start now.
        RunSc($"start \"{ServiceName}\"");
    }

    public static void UninstallOrThrow()
    {
        RequireAdminOrThrow();

        if (!ServiceExists())
            return;

        try
        {
            using var sc = new ServiceController(ServiceName);
            if (sc.Status != ServiceControllerStatus.Stopped && sc.Status != ServiceControllerStatus.StopPending)
            {
                sc.Stop();
                sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20));
            }
        }
        catch
        {
            // Best effort; deletion below.
        }

        RunSc($"delete \"{ServiceName}\"");
    }

    public static void StartOrThrow()
    {
        RequireAdminOrThrow();
        if (!ServiceExists())
            throw new InvalidOperationException("Service is not installed.");

        using var sc = new ServiceController(ServiceName);
        if (sc.Status == ServiceControllerStatus.Running || sc.Status == ServiceControllerStatus.StartPending)
            return;
        sc.Start();
        sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(20));
    }

    public static void StopOrThrow()
    {
        RequireAdminOrThrow();
        if (!ServiceExists())
            throw new InvalidOperationException("Service is not installed.");

        using var sc = new ServiceController(ServiceName);
        if (sc.Status == ServiceControllerStatus.Stopped || sc.Status == ServiceControllerStatus.StopPending)
            return;
        sc.Stop();
        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(20));
    }

    private static bool ServiceExists()
    {
        try
        {
            _ = new ServiceController(ServiceName).Status;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void RequireAdminOrThrow()
    {
        using var id = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(id);
        if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
            throw new InvalidOperationException("Administrator privileges are required for service install/uninstall.");
    }

    private static void RunSc(string args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = "sc.exe",
            Arguments = args,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start sc.exe");
        p.WaitForExit(30000);

        var stdout = p.StandardOutput.ReadToEnd();
        var stderr = p.StandardError.ReadToEnd();

        if (p.ExitCode != 0)
            throw new Win32Exception($"sc.exe failed ({p.ExitCode}). stdout={stdout} stderr={stderr}");
    }
}
