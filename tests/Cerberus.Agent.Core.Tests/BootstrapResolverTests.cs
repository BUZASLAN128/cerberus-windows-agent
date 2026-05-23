using Cerberus.Agent.App;

namespace Cerberus.Agent.Core.Tests;

public sealed class BootstrapResolverTests
{
    [Fact]
    public void ResolveConfiguredBackend_UsesConfiguredBackendWithoutDescriptor()
    {
        var cfg = new RuntimeUiConfig(
            BackendUrl: "http://127.0.0.1:8000",
            CasdoorEndpoint: "http://localhost:18000",
            CasdoorClientId: "client",
            CasdoorScope: "openid profile email groups",
            OAuthRedirectPort: 19823,
            CasdoorClientSecret: null);

        var resolution = BootstrapResolver.ResolveConfiguredBackend(cfg);

        Assert.NotNull(resolution);
        Assert.Equal("http://127.0.0.1:8000", resolution!.BackendUrl);
        Assert.Equal(new Uri("http://127.0.0.1:8000"), resolution.Backend);
    }

    [Fact]
    public async Task ResolveAsync_RequiresBackendUrl()
    {
        var cfg = new RuntimeUiConfig(
            BackendUrl: "",
            CasdoorEndpoint: "https://sso.example",
            CasdoorClientId: "client",
            CasdoorScope: "openid profile email groups",
            OAuthRedirectPort: 19823,
            CasdoorClientSecret: null);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => BootstrapResolver.ResolveAsync(cfg, new Uri("https://sso.example"), CancellationToken.None));
        Assert.Equal("Backend URL is not configured.", ex.Message);
    }
}
