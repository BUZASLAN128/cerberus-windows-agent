using Cerberus.Agent.App;

namespace Cerberus.Agent.Core.Tests;

public sealed class CasdoorOAuthClientTests
{
    [Fact]
    public void WriteManualBrowserUrl_WritesUrlToRequestedFile()
    {
        var dir = Path.Combine(Path.GetTempPath(), "cerberus-agent-tests", Guid.NewGuid().ToString("N"));
        var path = Path.Combine(dir, "oauth-url.txt");
        var url = new Uri("https://sso.example/login/oauth/authorize?client_id=agent-client");

        CasdoorOAuthClient.WriteManualBrowserUrl(url, path);

        Assert.Equal(url.ToString(), File.ReadAllText(path));
    }

    [Fact]
    public void WriteManualBrowserUrl_NoopsWhenPathMissing()
    {
        var url = new Uri("https://sso.example/login/oauth/authorize");

        CasdoorOAuthClient.WriteManualBrowserUrl(url, null);
        CasdoorOAuthClient.WriteManualBrowserUrl(url, "");

        Assert.True(true);
    }

    [Fact]
    public void BuildTokenExchangeForm_DoesNotIncludeClientSecretForPublicPkce()
    {
        var form = CasdoorOAuthClient.BuildTokenExchangeForm(
            "agent-public-client",
            "oauth-code",
            new Uri("http://127.0.0.1:19823/callback"),
            "pkce-verifier");

        Assert.Equal("authorization_code", form["grant_type"]);
        Assert.Equal("agent-public-client", form["client_id"]);
        Assert.Equal("oauth-code", form["code"]);
        Assert.Equal("pkce-verifier", form["code_verifier"]);
        Assert.False(form.ContainsKey("client_secret"));
    }
}
