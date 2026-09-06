using Cerberus.Agent.App;
using Cerberus.Agent.App.Actions;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentBuildRoutingTests
{
    [Theory]
    [InlineData("BlockedConfig", "backend_environment_mismatch", true)]
    [InlineData("BlockedConfig", "backend_url_invalid", false)]
    [InlineData("Active", "backend_environment_mismatch", false)]
    [InlineData("NeedsReenrollment", "agent_reenroll_required", true)]
    [InlineData("Retired", "agent_deactivated", true)]
    [InlineData("Retired", "agent_revoked", false)]
    [InlineData("NeedsReenrollment", "agent_revoked", false)]
    [InlineData(null, null, false)]
    public void ExplicitSetupCanRecoverOnlySupportedRegistrationStates(string? state, string? code, bool expected)
        => Assert.Equal(expected, AgentOnboardingFlow.RequiresEnrollment(state, code));

    private static readonly PersistedUiConfig LocalBuild = new(
        "http://127.0.0.1:8000", "http://localhost:18000", "local-client", "openid profile email groups", 19823);

    [Theory]
    [InlineData("http://127.0.0.1:8000/", "http://localhost:18000/", "local-client", true)]
    [InlineData("https://app.cerberusd.com", "http://localhost:18000", "local-client", false)]
    [InlineData("http://127.0.0.1:8000", "https://auth.cerberusd.com", "local-client", false)]
    [InlineData("http://127.0.0.1:8000", "http://localhost:18000", "other-client", false)]
    [InlineData("http://127.0.0.1:8000", "http://localhost:18000", "", false)]
    public void PackageRejectsDifferentDeployment(string backend, string sso, string client, bool expected)
    {
        var config = new RuntimeUiConfig(backend, sso, client, LocalBuild.CasdoorScope, 19823, null);
        Assert.Equal(expected, UiConfigStore.MatchesBuildRouting(config, LocalBuild));
    }

    [Theory]
    [InlineData("https://app.example", "https://APP.example/", true)]
    [InlineData("https://app.example", "https://other.example", false)]
    [InlineData("http://127.0.0.1:8000", "http://127.0.0.1:8001", false)]
    [InlineData("https://app.example/tenant", "https://app.example/Tenant", false)]
    [InlineData("https://app.example", "https://user@app.example", false)]
    [InlineData("https://app.example", "https://app.example/#other", false)]
    [InlineData("", "", false)]
    public void CredentialEndpointComparisonPreservesDeployment(string stored, string requested, bool expected)
        => Assert.Equal(expected, UiConfigStore.SameEndpoint(stored, requested));
}
