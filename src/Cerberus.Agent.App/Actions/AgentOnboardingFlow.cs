using System.Net.Http;
using Cerberus.Agent.App.Legal;
using Cerberus.Agent.Core;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App.Actions;

internal sealed record AgentOnboardingResult(
    AgentIdentity Identity,
    string? TailscaleCommandPath);

internal sealed class AgentOnboardingFlow
{
    public static bool IsConfigReady(RuntimeUiConfig cfg)
    {
        var ssoBase = (cfg.CasdoorEndpoint ?? "").Trim().TrimEnd('/');
        var backend = (cfg.BackendUrl ?? "").Trim().TrimEnd('/');
        return Uri.TryCreate(ssoBase, UriKind.Absolute, out _) &&
               Uri.TryCreate(backend, UriKind.Absolute, out _) &&
               !string.IsNullOrWhiteSpace(cfg.CasdoorClientId);
    }

    public async Task<AgentOnboardingResult> RunAsync(
        RuntimeUiConfig cfg,
        IAgentLogger log,
        Action<string>? progress,
        CancellationToken ct)
    {
        AgentLegalConsent.RequireCurrentUserConsent();

        if (!IsConfigReady(cfg))
            throw new InvalidOperationException("Device onboarding is not configured.");

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
        var registrar = new AgentRegistrar(http, secrets, keyPairs: null, log: log);

        var identity = await registrar.RegisterAsync(
            token.AccessToken,
            backendUrlForStorage: bootstrap.BackendUrl,
            deviceFingerprint: WindowsDeviceInfo.ComputeDeviceFingerprint(),
            agentVersion: WindowsDeviceInfo.GetAgentVersion(),
            buildId: WindowsDeviceInfo.GetBuildId(),
            buildChannel: WindowsDeviceInfo.GetBuildChannel(),
            ct: ct).ConfigureAwait(false);

        var export = await VpnCommandExportService
            .ExportAsync(bootstrap.Backend, progress, ct)
            .ConfigureAwait(false);
        return new AgentOnboardingResult(identity, export.CommandPath);
    }
}
