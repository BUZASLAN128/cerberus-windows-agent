using Cerberus.Agent.App.Legal;
using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;
using Cerberus.Agent.Security;
using Cerberus.Agent.App.Control;

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
        var requiresEnrollment = false;
        if (AgentStatus.GetService().Installed)
        {
            var status = await AgentLocalControlClient.SendAsync(new("status"), ct).ConfigureAwait(false);
            if (status.Code == AgentLifecycleStatePolicy.AgentRevokedCode)
                throw new InvalidOperationException("This registration was revoked. Contact your administrator.");
            requiresEnrollment = status.LifecycleState == nameof(AgentLifecycleState.NeedsReenrollment) ||
                (status.LifecycleState == nameof(AgentLifecycleState.Retired) && status.Code == AgentLifecycleStatePolicy.AgentDeactivatedCode);
        }
        var userStore = new DpapiSecretStore(SecretStoreScope.User);
        var lifecycleState = new InMemoryAgentLifecycleStateStore();
        if (!registeredBefore || requiresEnrollment)
        {
            var onboarding = await new AgentOnboardingFlow()
                .RunAsync(cfg, log, progress, ct, replaceExistingRegistration: requiresEnrollment)
                .ConfigureAwait(false);
            registeredNow = true;
            progress?.Invoke($"Registered agent {onboarding.Identity.AgentId}.");
            if (onboarding.TailscaleCommandPath is not null)
                progress?.Invoke($"Wrote private mesh command: {onboarding.TailscaleCommandPath}");
        }
        else
        {
            progress?.Invoke("Device is already registered. Checking portal claim...");
        }

        var currentService = AgentStatus.GetService();
        if (!currentService.Installed)
        {
            try
            {
                await AgentClaimGate
                    .WaitForClaimedAsync(userStore, progress, ct, lifecycleState)
                    .ConfigureAwait(false);
            }
            catch (AgentRegistrationInactiveException ex) when (registeredBefore && ex.CanReenroll)
            {
                progress?.Invoke("Stored device registration is inactive. Signing in again...");
                var onboarding = await new AgentOnboardingFlow()
                    .RunAsync(cfg, log, progress, ct, replaceExistingRegistration: true)
                    .ConfigureAwait(false);
                registeredNow = true;
                progress?.Invoke($"Registered agent {onboarding.Identity.AgentId}.");
                if (onboarding.TailscaleCommandPath is not null)
                    progress?.Invoke($"Wrote private mesh command: {onboarding.TailscaleCommandPath}");

                await AgentClaimGate
                    .WaitForClaimedAsync(userStore, progress, ct, lifecycleState)
                    .ConfigureAwait(false);
            }
        }

        var serviceChanged = EnsureServiceInstallOrStart(progress, registeredNow);
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

        var health = await AgentLocalControlClient.SendAsync(new("status"), ct).ConfigureAwait(false);
        if (!health.Success || health.LifecycleState is not (nameof(AgentLifecycleState.Active) or nameof(AgentLifecycleState.Degraded)))
            throw new InvalidOperationException("The service is running but requires registration or administrator recovery.");

        return new AgentSetupResult(
            registeredBefore,
            registeredNow,
            serviceChanged,
            service.Text,
            "Agent setup completed. The service is running.");
    }

    private static bool EnsureServiceInstallOrStart(Action<string>? progress, bool promoteRegistration)
    {
        var service = AgentStatus.GetService();
        if (!service.Installed || promoteRegistration)
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
