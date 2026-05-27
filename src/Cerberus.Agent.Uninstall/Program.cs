using System.ComponentModel;
using System.Diagnostics;
using System.Windows.Forms;
using Cerberus.Agent.App;
using Cerberus.Agent.App.Actions;
using Cerberus.Agent.App.Localization;
using Cerberus.Agent.Security;
using Microsoft.Win32;

namespace Cerberus.Agent.Uninstall;

internal static class Program
{
    [STAThread]
    public static int Main()
    {
        AgentLocalizer.ApplyThreadCulture();
        ApplicationConfiguration.Initialize();
        var answer = MessageBox.Show(
            AgentLocalizer.Get("UninstallPrompt"),
            AgentLocalizer.Get("UninstallTitle"),
            MessageBoxButtons.OKCancel,
            MessageBoxIcon.Warning);
        if (answer != DialogResult.OK)
            return 1;

        TryDeactivateAndClearLocalRegistration();
        try { ServiceInstaller.StopOrThrow(); } catch { }

        var productCode = ReadProductCode();
        if (string.IsNullOrWhiteSpace(productCode))
        {
            MessageBox.Show(AgentLocalizer.Get("InstallerRegistrationMissing"), "Cerberus Agent", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return 2;
        }

        var exitCode = RunMsiexec($"/x {productCode} /passive /norestart");
        return exitCode;
    }

    private static string? ReadProductCode()
    {
        using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Cerberus\WindowsAgent");
        return key?.GetValue("ProductCode")?.ToString();
    }

    private static void TryDeactivateAndClearLocalRegistration()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        foreach (var scope in new[] { SecretStoreScope.Machine, SecretStoreScope.User })
        {
            try
            {
                var store = new DpapiSecretStore(scope);
                _ = AgentBackendLifecycle.TrySelfDeactivateAsync(
                        store,
                        AgentBackendLifecycle.UnregisterReasonCode,
                        AgentBackendLifecycle.UnregisterReason,
                        cts.Token)
                    .GetAwaiter()
                    .GetResult();
                store.ClearAsync(cts.Token).GetAwaiter().GetResult();
            }
            catch
            {
                // Uninstall must continue even when the portal is unreachable or a scope is unreadable.
            }
        }

        try
        {
            AgentServiceLocalState.ClearMachineStateAsync(cts.Token).GetAwaiter().GetResult();
        }
        catch
        {
            // MSI removal is still the source of truth for local uninstall.
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
