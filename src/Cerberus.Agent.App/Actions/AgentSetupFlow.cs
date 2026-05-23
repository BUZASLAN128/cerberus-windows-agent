using Cerberus.Agent.App.Legal;
using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;

namespace Cerberus.Agent.App.Actions;

internal sealed record AgentSetupResult(
    bool RegisteredBeforeSetup,
    bool RegisteredDuringSetup,
    bool ServiceChangedDuringSetup,
    string ServiceStatus,
    string Message);

internal sealed class AgentSetupFlow
{
    private static readonly TimeSpan ServiceReadyTimeout = TimeSpan.FromSeconds(120);
    private static readonly TimeSpan ServicePollInterval = TimeSpan.FromSeconds(2);

    public async Task<AgentSetupResult> RunAsync(
        RuntimeUiConfig cfg,
        IAgentLogger log,
        Action<string>? progress,
        CancellationToken ct)
    {
        AgentLegalConsent.RequireCurrentUserConsent();

        if (!AgentOnboardingFlow.IsConfigReady(cfg))
            throw new InvalidOperationException("Device onboarding is not configured.");

        var registeredBefore = AgentStatus.IsRegistered();
        var registeredNow = false;
        if (!registeredBefore)
        {
            progress?.Invoke("Opening browser for SSO sign-in...");
            var onboarding = await new AgentOnboardingFlow()
                .RunAsync(cfg, log, progress, ct)
                .ConfigureAwait(false);
            registeredNow = true;
            progress?.Invoke($"Registered agent {onboarding.Identity.AgentId}.");
            if (onboarding.TailscaleCommandPath is not null)
                progress?.Invoke($"Wrote private mesh command: {onboarding.TailscaleCommandPath}");
        }
        else
        {
            progress?.Invoke("Device is already registered. Checking service...");
        }

        var serviceChanged = EnsureServiceInstallOrStart(progress);
        var service = await WaitForServiceRunningAsync(ServiceReadyTimeout, progress, ct).ConfigureAwait(false);
        if (!service.Installed)
        {
            throw new InvalidOperationException(
                "Windows service was not installed. Complete the UAC prompt or run the setup as administrator.");
        }

        if (!string.Equals(service.Text, "running", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"Windows service is installed but not running (status={service.Text}).");
        }

        return new AgentSetupResult(
            registeredBefore,
            registeredNow,
            serviceChanged,
            service.Text,
            "Agent setup completed. The service is running.");
    }

    private static bool EnsureServiceInstallOrStart(Action<string>? progress)
    {
        var service = AgentStatus.GetService();
        if (!service.Installed)
        {
            progress?.Invoke("Installing Windows service (UAC may prompt)...");
            var result = ServiceControlAction.Run(ServiceControlCommand.Install);
            progress?.Invoke(result.Message);
            if (!result.Succeeded)
                throw new InvalidOperationException(result.Message);
            return true;
        }

        if (service.CanStart)
        {
            progress?.Invoke("Starting Windows service...");
            var result = ServiceControlAction.Run(ServiceControlCommand.Start);
            progress?.Invoke(result.Message);
            if (!result.Succeeded)
                throw new InvalidOperationException(result.Message);
            return true;
        }

        progress?.Invoke($"Windows service status: {service.Text}.");
        return false;
    }

    private static async Task<(string Text, string Short, bool CanStart, bool CanStop, bool Installed)> WaitForServiceRunningAsync(
        TimeSpan timeout,
        Action<string>? progress,
        CancellationToken ct)
    {
        var deadline = DateTimeOffset.UtcNow.Add(timeout);
        var lastText = "";
        while (DateTimeOffset.UtcNow < deadline)
        {
            ct.ThrowIfCancellationRequested();
            var service = AgentStatus.GetService();
            if (!string.Equals(service.Text, lastText, StringComparison.OrdinalIgnoreCase))
            {
                progress?.Invoke($"Windows service status: {service.Text}.");
                lastText = service.Text;
            }

            if (service.Installed && string.Equals(service.Text, "running", StringComparison.OrdinalIgnoreCase))
                return service;

            await Task.Delay(ServicePollInterval, ct).ConfigureAwait(false);
        }

        return AgentStatus.GetService();
    }
}
