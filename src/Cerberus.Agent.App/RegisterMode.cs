using Cerberus.Agent.Core;
using Cerberus.Agent.App.Legal;
using Cerberus.Agent.Observability;
using Cerberus.Agent.Security;
using System.Net.Http;

namespace Cerberus.Agent.App;

internal static class RegisterMode
{
    public static async Task<int> RunAsync(AgentArgs args, CancellationToken ct)
    {
        using var log = AgentFileLogger.CreateDefault(alsoConsole: true);

        try
        {
            AgentLegalConsent.RequireCurrentUserConsent();

            var uiConfig = UiConfigStore.LoadMergedWithEnv();
            // Single onboarding flow: PKCE via loopback redirect.
            // We intentionally do not support token env/file in this mode to avoid dual paths.
            if (!string.IsNullOrWhiteSpace(args.CasdoorTokenFile) ||
                !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("CERBERUS_CASDOOR_TOKEN")) ||
                !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("CERBERUS_CASDOOR_TOKEN_FILE")))
            {
                log.Error("Token env/file based register flow is disabled. Use PKCE login flow (--register opens browser).");
                return 2;
            }

            var casdoorEndpoint = uiConfig.CasdoorEndpoint.Trim().TrimEnd('/');
            if (!Uri.TryCreate(casdoorEndpoint, UriKind.Absolute, out var casdoorBase))
            {
                log.Error("Invalid SSO endpoint (CERBERUS_SSO_BASE_URL / CERBERUS_CASDOOR_ENDPOINT).");
                return 2;
            }

            var bootstrap = await BootstrapResolver.ResolveAsync(uiConfig, casdoorBase, ct);

            var clientId = uiConfig.CasdoorClientId.Trim();
            if (string.IsNullOrWhiteSpace(clientId))
            {
                log.Error("SSO client_id missing (CERBERUS_SSO_CLIENT_ID / CERBERUS_CASDOOR_CLIENT_ID).");
                return 2;
            }

            var clientSecret = uiConfig.CasdoorClientSecret ?? "";
            var scope = uiConfig.CasdoorScope;
            var redirectPort = uiConfig.OAuthRedirectPort;

            log.Info("Starting SSO sign-in (browser will open)...");
            var oauth = new CasdoorOAuthClient(
                casdoorBase,
                clientId,
                string.IsNullOrWhiteSpace(clientSecret) ? null : clientSecret,
                scope);
            var token = await oauth.LoginWithPkceAsync(redirectPort, ct);
            var oauthToken = token.AccessToken;
            log.Info("SSO sign-in ok. Registering agent...");

            // Store secrets in user-scope so onboarding does not require admin/UAC.
            // Service-mode (LocalSystem) uses machine-scope secrets separately.
            var secrets = new DpapiSecretStore(SecretStoreScope.User);
            using var http = new HttpClient
            {
                BaseAddress = bootstrap.Backend,
                Timeout = TimeSpan.FromSeconds(30),
            };

            var registrar = new AgentRegistrar(http, secrets, keyPairs: null, log: log);
            var fingerprint = WindowsDeviceInfo.ComputeDeviceFingerprint();
            var version = WindowsDeviceInfo.GetAgentVersion();
            var buildId = WindowsDeviceInfo.GetBuildId();
            var buildChannel = WindowsDeviceInfo.GetBuildChannel();

            await registrar.RegisterAsync(
                oauthToken,
                backendUrlForStorage: bootstrap.BackendUrl,
                deviceFingerprint: fingerprint,
                agentVersion: version,
                buildId: buildId,
                buildChannel: buildChannel,
                bootstrapDescriptor: bootstrap.RawDescriptor,
                ct);

            var cmdPath = await TailscaleUpExporter.ExportAsync(ct);
            if (cmdPath is not null)
                log.Info($"Wrote tailscale up command file: {cmdPath}");

            log.Info("Secrets stored via DPAPI (CurrentUser).");
            return 0;
        }
        catch (Exception ex)
        {
            // Avoid printing token by never including request content / headers in logs.
            log.Error("Register failed.", ex);
            return 2;
        }
    }

}
