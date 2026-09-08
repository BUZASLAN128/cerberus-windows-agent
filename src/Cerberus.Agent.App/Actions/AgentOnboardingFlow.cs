using System.Net.Http;
using Cerberus.Agent.App.Legal;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;
using Cerberus.Agent.App.Control;

namespace Cerberus.Agent.App.Actions;

internal sealed record AgentOnboardingResult(
    AgentIdentity Identity,
    string? TailscaleCommandPath);

internal sealed class AgentOnboardingFlow
{
    // Eligibility is consumed only by explicit setup/SSO, never service startup.
    internal static bool RequiresEnrollment(string? state, string? code)
        => code != AgentLifecycleStatePolicy.AgentRevokedCode &&
           (state == nameof(AgentLifecycleState.NeedsReenrollment) ||
            (state == nameof(AgentLifecycleState.Retired) && code == AgentLifecycleStatePolicy.AgentDeactivatedCode) ||
            (state == nameof(AgentLifecycleState.BlockedConfig) && code == "backend_environment_mismatch"));

    public static bool IsConfigReady(RuntimeUiConfig cfg)
    {
        var ssoBase = (cfg.CasdoorEndpoint ?? "").Trim().TrimEnd('/');
        var backend = (cfg.BackendUrl ?? "").Trim().TrimEnd('/');
        return UiConfigStore.MatchesBuildRouting(cfg) &&
               Uri.TryCreate(ssoBase, UriKind.Absolute, out _) &&
               Uri.TryCreate(backend, UriKind.Absolute, out _) &&
               !string.IsNullOrWhiteSpace(cfg.CasdoorClientId);
    }

    public async Task<AgentOnboardingResult> RunAsync(
        RuntimeUiConfig cfg,
        IAgentLogger log,
        Action<string>? progress,
        CancellationToken ct,
        bool replaceExistingRegistration = false)
    {
        AgentLegalConsent.RequireCurrentUserConsent();

        if (!IsConfigReady(cfg))
            throw new InvalidOperationException("Device onboarding is not configured.");

        var replaceExisting = replaceExistingRegistration;
        if (AgentStatus.GetService().Installed)
        {
            var status = await AgentLocalControlClient.SendAsync(new("status"), ct).ConfigureAwait(false);
            if (!status.Success)
                throw new InvalidOperationException("Agent service status is unavailable; existing registration was preserved.");
            if (status.Code == AgentLifecycleStatePolicy.AgentRevokedCode)
                throw new InvalidOperationException("This registration was revoked. Contact your administrator.");
            replaceExisting = RequiresEnrollment(status.LifecycleState, status.Code);
        }

        var ssoBase = new Uri(cfg.CasdoorEndpoint.Trim().TrimEnd('/'));
        var bootstrap = await BootstrapResolver.ResolveAsync(cfg, ssoBase, ct).ConfigureAwait(false);

        progress?.Invoke("Opening browser for SSO sign-in...");
        var oauth = new CasdoorOAuthClient(
            ssoBase,
            cfg.CasdoorClientId.Trim(),
            string.IsNullOrWhiteSpace(cfg.CasdoorClientSecret) ? null : cfg.CasdoorClientSecret,
            cfg.CasdoorScope);
        var token = await oauth.LoginWithPkceAsync(cfg.OAuthRedirectPort, ct).ConfigureAwait(false);

        progress?.Invoke("Login ok. Registering agent...");
        using var http = new HttpClient
        {
            BaseAddress = bootstrap.Backend,
            Timeout = TimeSpan.FromSeconds(30),
        };
        var secrets = new DpapiSecretStore(SecretStoreScope.User);
        var lifecycleState = new InMemoryAgentLifecycleStateStore();
        var registrar = new AgentRegistrar(
            http,
            secrets,
            keyPairs: null,
            log: log,
            lifecycleState: lifecycleState);

        var identity = await registrar.RegisterAsync(
            token.AccessToken,
            backendUrlForStorage: bootstrap.BackendUrl,
            deviceFingerprint: WindowsDeviceInfo.ComputeDeviceFingerprint(),
            agentVersion: WindowsDeviceInfo.GetAgentVersion(),
            buildId: WindowsDeviceInfo.GetBuildId(),
            buildChannel: WindowsDeviceInfo.GetBuildChannel(),
            ct: ct,
            replaceExisting: replaceExisting).ConfigureAwait(false);

        var export = await VpnCommandExportService
            .ExportAsync(bootstrap.Backend, progress, ct)
            .ConfigureAwait(false);
        return new AgentOnboardingResult(identity, export.CommandPath);
    }
}
