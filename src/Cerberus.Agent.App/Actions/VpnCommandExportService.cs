using System.IO;
using System.Net.Http;
using Cerberus.Agent.Core;
using Cerberus.Agent.Observability;
using Cerberus.Agent.Security;

namespace Cerberus.Agent.App.Actions;

internal sealed record VpnCommandExportResult(string? CommandPath, bool PreauthFetched);

internal static class VpnCommandExportService
{
    public static async Task<VpnCommandExportResult> ExportAsync(
        Uri? backend,
        Action<string>? log,
        CancellationToken ct)
    {
        var path = await TailscaleUpExporter.ExportAsync(ct).ConfigureAwait(false);
        if (path is not null)
            return new VpnCommandExportResult(path, PreauthFetched: false);

        var targetBackend = backend ?? await TryLoadStoredBackendAsync(ct).ConfigureAwait(false);
        if (targetBackend is null)
            return new VpnCommandExportResult(null, PreauthFetched: false);

        var fetched = await TryFetchPreauthAsync(targetBackend, log, ct).ConfigureAwait(false);
        if (!fetched)
            return new VpnCommandExportResult(null, PreauthFetched: false);

        path = await TailscaleUpExporter.ExportAsync(ct).ConfigureAwait(false);
        return new VpnCommandExportResult(path, PreauthFetched: true);
    }

    public static Uri? TryGetConfiguredBackend(RuntimeUiConfig cfg)
    {
        var backendUrl = (cfg.BackendUrl ?? "").Trim().TrimEnd('/');
        return Uri.TryCreate(backendUrl, UriKind.Absolute, out var backend)
            ? backend
            : null;
    }

    private static async Task<Uri?> TryLoadStoredBackendAsync(CancellationToken ct)
    {
        try
        {
            var secrets = new DpapiSecretStore(SecretStoreScope.User);
            var (_, _, _, backendUrl, _, _) = await secrets.LoadAsync(ct).ConfigureAwait(false);
            return Uri.TryCreate(backendUrl?.Trim().TrimEnd('/'), UriKind.Absolute, out var backend)
                ? backend
                : null;
        }
        catch (FileNotFoundException)
        {
            return null;
        }
    }

    private static async Task<bool> TryFetchPreauthAsync(
        Uri backend,
        Action<string>? log,
        CancellationToken ct)
    {
        try
        {
            var secrets = new DpapiSecretStore(SecretStoreScope.User);
            var (_, _, privateKeyPem, _, _, _) = await secrets.LoadAsync(ct).ConfigureAwait(false);

            using var http = new HttpClient { BaseAddress = backend, Timeout = TimeSpan.FromSeconds(30) };
            var tokens = new AgentTokenManager(http, secrets);
            var signer = new RequestSigner(privateKeyPem);
            var api = new AgentApiClient(http, secrets, tokens, signer);

            var (loginServer, authKey) = await api.GetTailscalePreauthAsync(ct).ConfigureAwait(false);

            var (id, refresh, privateKey, backendUrl, _, _) = await secrets.LoadAsync(ct).ConfigureAwait(false);
            await secrets.SaveAsync(id, refresh, privateKey, backendUrl, loginServer, authKey, ct).ConfigureAwait(false);

            log?.Invoke("Fetched VPN preauth key.");
            return true;
        }
        catch (FileNotFoundException)
        {
            return false;
        }
        catch (Exception ex)
        {
            log?.Invoke($"Preauth fetch failed: {Sanitizer.Redact(ex.Message)}");
            return false;
        }
    }
}
