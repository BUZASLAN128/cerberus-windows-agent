using Cerberus.Agent.Integrations.Tailscale;
using Xunit;

namespace Cerberus.Agent.Core.Tests;

public sealed class TailscaleUpCommandTests
{
    [Fact]
    public void Build_IncludesLoginServerAndRequiresAuthKeyEnvironment()
    {
        var cmd = TailscaleUpCommand.Build("https://headscale.example", "tskey-auth-123");
        Assert.Contains("tailscale up", cmd);
        Assert.Contains("--login-server=\"https://headscale.example\"", cmd);
        Assert.Contains("CERBERUS_TAILSCALE_AUTHKEY", cmd);
        Assert.Contains("--authkey=\"%CERBERUS_TAILSCALE_AUTHKEY%\"", cmd);
        Assert.DoesNotContain("tskey-auth-123", cmd);
    }
}
