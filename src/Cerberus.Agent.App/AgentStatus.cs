using Cerberus.Agent.Integrations.Tailscale;
using Cerberus.Agent.Security;
using System.IO;
using System.ServiceProcess;

namespace Cerberus.Agent.App;

internal static class AgentStatus
{
    public static (string Text, string Short, bool CanStart, bool CanStop, bool Installed) GetService()
    {
        try
        {
            using var sc = new ServiceController(ServiceInstaller.ServiceName);
            var st = sc.Status;
            return st switch
            {
                ServiceControllerStatus.Running => ("running", "svc:up", CanStart: false, CanStop: true, Installed: true),
                ServiceControllerStatus.Stopped => ("stopped", "svc:down", CanStart: true, CanStop: false, Installed: true),
                ServiceControllerStatus.StartPending => ("starting", "svc:...", CanStart: false, CanStop: false, Installed: true),
                ServiceControllerStatus.StopPending => ("stopping", "svc:...", CanStart: false, CanStop: false, Installed: true),
                _ => ($"{st}", "svc:?", CanStart: false, CanStop: false, Installed: true),
            };
        }
        catch
        {
            return ("not installed", "svc:none", CanStart: false, CanStop: false, Installed: false);
        }
    }

    public static bool IsRegistered()
    {
        try
        {
            // IMPORTANT: Do not block on async secret loading from the UI thread (deadlock risk).
            var userPath = DpapiSecretStore.GetDefaultSecretsPath(SecretStoreScope.User);
            var machinePath = DpapiSecretStore.GetDefaultSecretsPath(SecretStoreScope.Machine);

            return IsRegisteredFromSecretPaths(userPath, machinePath);
        }
        catch
        {
            return false;
        }
    }

    internal static bool IsRegisteredFromSecretPaths(string userPath, string machinePath)
    {
        // If user-scope secrets exist, the interactive tray/UI is registered.
        if (File.Exists(userPath))
            return true;

        // Machine-scope secrets are intentionally unreadable to normal interactive users after
        // service install. File existence is enough for UI readiness; do not open the secret.
        return File.Exists(machinePath);
    }

    public static bool IsSetupComplete()
    {
        var service = GetService();
        return IsSetupCompleteFromSignals(
            registered: IsRegistered(),
            serviceInstalled: service.Installed,
            serviceText: service.Text);
    }

    internal static bool IsSetupCompleteFromSignals(bool registered, bool serviceInstalled, string serviceText)
        => registered &&
           serviceInstalled &&
           string.Equals(serviceText, "running", StringComparison.OrdinalIgnoreCase);

    public static async Task<(string Text, string Short)> GetTailscaleAsync(CancellationToken ct)
    {
        try
        {
            var (installed, connected, _, err) = await TailscaleStatusProbe.ProbeAsync(
                timeout: TimeSpan.FromSeconds(2),
                ct: ct);
            if (!installed)
                return ("not installed", "ts:none");
            if (connected)
                return ("connected", "ts:up");
            if (!string.IsNullOrWhiteSpace(err))
                return ("not connected", "ts:down");
            return ("not connected", "ts:down");
        }
        catch
        {
            return ("unknown", "ts:?");
        }
    }
}
