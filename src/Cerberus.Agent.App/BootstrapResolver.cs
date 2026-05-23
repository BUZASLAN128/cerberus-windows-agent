namespace Cerberus.Agent.App;

internal sealed record BootstrapResolution(Uri Backend, string BackendUrl);

internal static class BootstrapResolver
{
    public static Task<BootstrapResolution> ResolveAsync(
        RuntimeUiConfig uiConfig,
        Uri casdoorBase,
        CancellationToken ct)
    {
        _ = casdoorBase;
        _ = ct;
        var resolution = ResolveConfiguredBackend(uiConfig)
            ?? throw new InvalidOperationException("Backend URL is not configured.");
        return Task.FromResult(resolution);
    }

    internal static BootstrapResolution? ResolveConfiguredBackend(RuntimeUiConfig uiConfig)
    {
        var backendUrl = (uiConfig.BackendUrl ?? "").Trim().TrimEnd('/');
        if (!Uri.TryCreate(backendUrl, UriKind.Absolute, out var backend))
            return null;

        return new BootstrapResolution(backend, backendUrl);
    }
}
