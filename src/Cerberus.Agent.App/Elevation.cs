using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;

namespace Cerberus.Agent.App;

internal static class Elevation
{
    public static bool IsAdministrator()
    {
        using var id = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(id);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static bool TryRunElevated(string arguments)
    {
        var exePath = Process.GetCurrentProcess().MainModule?.FileName;
        if (string.IsNullOrWhiteSpace(exePath))
            return false;

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = arguments,
                UseShellExecute = true,
                Verb = "runas",
            });
            return true;
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            // The operation was canceled by the user.
            return false;
        }
    }

    public static async Task<int?> RunElevatedAndWaitAsync(string arguments, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var exePath = Process.GetCurrentProcess().MainModule?.FileName;
        if (string.IsNullOrWhiteSpace(exePath))
            return null;

        try
        {
            using var child = Process.Start(new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = arguments,
                UseShellExecute = true,
                Verb = "runas",
            });
            return child is null ? null : await WaitForCompletionAsync(child, ct).ConfigureAwait(false);
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode == 1223) { return null; }
    }

    internal static async Task<int> WaitForCompletionAsync(Process child, CancellationToken ct)
    {
        // Cancelling the wait must not kill a privileged provisioning transaction mid-commit.
        await child.WaitForExitAsync(ct).ConfigureAwait(false);
        return child.ExitCode;
    }
}

