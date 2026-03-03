using Cerberus.Agent.Core;
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
            var backendUrl = (Environment.GetEnvironmentVariable("CERBERUS_BACKEND_URL") ?? "http://127.0.0.1:8000")
                .Trim()
                .TrimEnd('/');
            if (!Uri.TryCreate(backendUrl, UriKind.Absolute, out var backend))
            {
                log.Error("Invalid backend URL (CERBERUS_BACKEND_URL).");
                return 2;
            }

            // Single onboarding flow: PKCE via loopback redirect.
            // We intentionally do not support token env/file in this mode to avoid dual paths.
            if (!string.IsNullOrWhiteSpace(args.CasdoorTokenFile) ||
                !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("CERBERUS_CASDOOR_TOKEN")) ||
                !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("CERBERUS_CASDOOR_TOKEN_FILE")))
            {
                log.Error("Token env/file based register flow is disabled. Use PKCE login flow (--register opens browser).");
                return 2;
            }

            var casdoorEndpoint = (Environment.GetEnvironmentVariable("CERBERUS_SSO_BASE_URL")
                                   ?? Environment.GetEnvironmentVariable("CERBERUS_CASDOOR_ENDPOINT")
                                   ?? "http://100.101.130.51:31080").Trim().TrimEnd('/');
            if (!Uri.TryCreate(casdoorEndpoint, UriKind.Absolute, out var casdoorBase))
            {
                log.Error("Invalid SSO endpoint (CERBERUS_SSO_BASE_URL / CERBERUS_CASDOOR_ENDPOINT).");
                return 2;
            }

            var clientId = (Environment.GetEnvironmentVariable("CERBERUS_SSO_CLIENT_ID")
                            ?? Environment.GetEnvironmentVariable("CERBERUS_CASDOOR_CLIENT_ID")
                            ?? UiConfigStore.Load().CasdoorClientId
                            ?? "").Trim();
            if (string.IsNullOrWhiteSpace(clientId))
            {
                log.Error("SSO client_id missing (CERBERUS_SSO_CLIENT_ID / CERBERUS_CASDOOR_CLIENT_ID).");
                return 2;
            }

            var clientSecret = (Environment.GetEnvironmentVariable("CERBERUS_SSO_CLIENT_SECRET")
                                ?? Environment.GetEnvironmentVariable("CERBERUS_CASDOOR_CLIENT_SECRET")
                                ?? "").Trim();
            var scope = (Environment.GetEnvironmentVariable("CERBERUS_SSO_SCOPE")
                         ?? Environment.GetEnvironmentVariable("CERBERUS_CASDOOR_SCOPE")
                         ?? "openid profile email").Trim();
            var redirectPortStr = Environment.GetEnvironmentVariable("CERBERUS_OAUTH_REDIRECT_PORT") ?? "19823";
            var redirectPort = int.TryParse(redirectPortStr, out var p) ? p : 19823;

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
                BaseAddress = backend,
                Timeout = TimeSpan.FromSeconds(30),
            };

            var registrar = new AgentRegistrar(http, secrets, keyPairs: null, log: log);
            var fingerprint = WindowsDeviceInfo.ComputeDeviceFingerprint();
            var version = WindowsDeviceInfo.GetAgentVersion();

            await registrar.RegisterAsync(
                oauthToken,
                backendUrlForStorage: backendUrl,
                deviceFingerprint: fingerprint,
                agentVersion: version,
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
