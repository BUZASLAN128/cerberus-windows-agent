using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.ServiceProcess;
using Microsoft.Win32;

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

        if (ServiceExists())
        {
            var installedExePath = GetInstalledExecutablePath();
            if (ServiceExecutableMatches(installedExePath, exePath))
            {
                StartOrThrow();
                return;
            }

            UninstallOrThrow();
            WaitForServiceDeleted();
        }

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
        WaitForServiceDeleted();
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

    internal static string? ExtractExecutablePathFromServiceImagePath(string? imagePath)
    {
        if (string.IsNullOrWhiteSpace(imagePath))
            return null;

        var value = imagePath.Trim();
        if (value.StartsWith("\"", StringComparison.Ordinal))
        {
            var endQuote = value.IndexOf('"', startIndex: 1);
            return endQuote > 1 ? value[1..endQuote] : null;
        }

        var serviceArg = value.IndexOf(" --service", StringComparison.OrdinalIgnoreCase);
        if (serviceArg > 0)
            return value[..serviceArg].Trim();

        var firstSpace = value.IndexOf(' ');
        return firstSpace > 0 ? value[..firstSpace].Trim() : value;
    }

    internal static bool ServiceExecutableMatches(string? installedExePath, string currentExePath)
    {
        if (string.IsNullOrWhiteSpace(installedExePath) || string.IsNullOrWhiteSpace(currentExePath))
            return false;

        try
        {
            installedExePath = Path.GetFullPath(installedExePath.Trim());
            currentExePath = Path.GetFullPath(currentExePath.Trim());
        }
        catch
        {
            installedExePath = installedExePath.Trim();
            currentExePath = currentExePath.Trim();
        }

        return string.Equals(installedExePath, currentExePath, StringComparison.OrdinalIgnoreCase);
    }

    private static string? GetInstalledExecutablePath()
    {
        using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{ServiceName}");
        var imagePath = key?.GetValue("ImagePath") as string;
        return ExtractExecutablePathFromServiceImagePath(imagePath);
    }

    private static void WaitForServiceDeleted()
    {
        var deadline = DateTime.UtcNow.AddSeconds(30);
        while (DateTime.UtcNow < deadline)
        {
            if (!ServiceExists())
                return;

            Thread.Sleep(250);
        }

        throw new InvalidOperationException("Service deletion did not complete in time.");
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
