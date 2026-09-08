using Cerberus.Agent.Integrations.Tailscale;
using Cerberus.Agent.App.Control;
using Cerberus.Agent.Core;
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

        // This is only a registration-file hint. Setup readiness separately requires
        // the service's non-secret lifecycle response; never open machine secrets here.
        return File.Exists(machinePath);
    }

    public static async Task<bool> IsSetupCompleteAsync(CancellationToken ct = default)
    {
        var service = await Task.Run(GetService, ct).ConfigureAwait(false);
        var registered = await Task.Run(IsRegistered, ct).ConfigureAwait(false);
        return await IsSetupCompleteAsync(registered, service.Installed, service.Text, ct).ConfigureAwait(false);
    }

    internal static async Task<bool> IsSetupCompleteAsync(
        bool registered, bool serviceInstalled, string serviceText, CancellationToken ct = default)
    {
        if (!registered || !serviceInstalled || !string.Equals(serviceText, "running", StringComparison.OrdinalIgnoreCase))
            return false;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(2));
        try
        {
            var status = await AgentLocalControlClient.SendAsync(new("status"), timeout.Token).ConfigureAwait(false);
            return IsSetupCompleteFromSignals(registered, serviceInstalled, serviceText, status);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            return false;
        }
    }

    internal static bool IsSetupCompleteFromSignals(
        bool registered, bool serviceInstalled, string serviceText, AgentLocalControlResponse? status)
        => registered &&
           serviceInstalled &&
           string.Equals(serviceText, "running", StringComparison.OrdinalIgnoreCase) &&
           status is { Success: true, LifecycleState: "Active" or "Degraded" } &&
           status.Code is not ("cleanup_pending" or "enrollment_proof_required");

    public static async Task<(string Text, string Short)> GetTailscaleAsync(CancellationToken ct)
    {
        try
        {
            var (installed, connected, _, err) = await TailscaleStatusProbe.ProbeAsync(
                timeout: TimeSpan.FromSeconds(2),
                ct: ct);
            if (!installed)
                return ("not installed", "net:none");
            if (connected)
                return ("connected", "net:up");
            if (!string.IsNullOrWhiteSpace(err))
                return ("not connected", "net:down");
            return ("not connected", "net:down");
        }
        catch
        {
            return ("unknown", "net:?");
        }
    }
}
