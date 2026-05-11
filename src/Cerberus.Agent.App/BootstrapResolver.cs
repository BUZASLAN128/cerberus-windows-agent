using Cerberus.Agent.Core;
using System.Net.Http;

namespace Cerberus.Agent.App;

internal sealed record BootstrapResolution(Uri Backend, string BackendUrl, string RawDescriptor);

internal static class BootstrapResolver
{
    public static async Task<BootstrapResolution> ResolveAsync(
        RuntimeUiConfig uiConfig,
        Uri casdoorBase,
        CancellationToken ct)
    {
        var descriptorUrl = uiConfig.BootstrapDescriptorUrl;
        var backendUrlFromDev = uiConfig.BackendUrl.Trim().TrimEnd('/');
        if (descriptorUrl is null &&
            IsExplicitDevBootstrap() &&
            Uri.TryCreate(backendUrlFromDev, UriKind.Absolute, out var devBackend))
        {
            descriptorUrl = new Uri(devBackend, "/api/v1/agents/bootstrap/descriptor").ToString();
        }

        var descriptorUri = BootstrapDescriptorValidator.ResolveDescriptorUri(casdoorBase, descriptorUrl);
        using var descriptorHttp = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        var descriptorClient = new BootstrapDescriptorClient(descriptorHttp);
        var (descriptorEnvelope, rawDescriptor) = await descriptorClient.FetchAsync(descriptorUri, ct);

        var backendUrl = descriptorEnvelope.Payload.BootstrapApiBaseUrl.Trim().TrimEnd('/');
        if (!Uri.TryCreate(backendUrl, UriKind.Absolute, out var backend))
            throw new InvalidOperationException("Bootstrap descriptor returned an invalid backend URL.");

        return new BootstrapResolution(backend, backendUrl, rawDescriptor);
    }

    private static bool IsExplicitDevBootstrap()
    {
        var raw = Environment.GetEnvironmentVariable("CERBERUS_AGENT_DEV_BOOTSTRAP");
        return string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase)
               || string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase)
               || string.Equals(raw, "yes", StringComparison.OrdinalIgnoreCase);
    }
}
