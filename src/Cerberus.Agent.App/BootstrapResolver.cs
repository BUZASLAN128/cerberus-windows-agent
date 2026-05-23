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

        if (!IsAllowedBackendUri(backend))
            throw new InvalidOperationException("Backend URL must use HTTPS. Loopback HTTP is allowed only for dev builds.");

        return new BootstrapResolution(backend, backendUrl);
    }

    internal static bool IsAllowedBackendUri(Uri backend)
    {
        if (string.Equals(backend.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            return true;

        if (!string.Equals(backend.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
            return false;

        return IsDevBuildChannel() && IsLoopbackHost(backend);
    }

    private static bool IsDevBuildChannel()
    {
        var channel = (WindowsDeviceInfo.GetBuildChannel() ?? "").Trim();
        return string.Equals(channel, "dev", StringComparison.OrdinalIgnoreCase)
               || string.Equals(channel, "local", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsLoopbackHost(Uri backend)
    {
        if (backend.IsLoopback)
            return true;
        var host = backend.Host.Trim();
        return string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
               || string.Equals(host, "127.0.0.1", StringComparison.OrdinalIgnoreCase)
               || string.Equals(host, "::1", StringComparison.OrdinalIgnoreCase);
    }
}
