using System.Net;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentProxySettingsTests
{
    [Theory]
    [InlineData("HTTP://Proxy.Example:8080/", "http://proxy.example:8080/")]
    [InlineData("https://proxy.example:443", "https://proxy.example/")]
    [InlineData("http://[2001:db8::1]:8080", "http://[2001:db8::1]:8080/")]
    public void ParsesOnlyAnAuthorityAndCanonicalizesTheHost(string input, string expected)
        => Assert.Equal(expected, AgentProxySettings.Parse(input)!.AbsoluteUri);

    [Theory]
    [InlineData("socks5://proxy.example:1080")]
    [InlineData("proxy.example:8080")]
    [InlineData("http://proxy.example")]
    [InlineData("https://proxy.example")]
    [InlineData("http://[2001:db8::1]")]
    [InlineData("http://user:example@proxy.example:8080")]
    [InlineData("http://@proxy.example:8080")]
    [InlineData("http://proxy.example:0")]
    [InlineData("http://proxy.example:65536")]
    [InlineData("http://proxy.example:8080/path")]
    [InlineData("http://proxy.example:8080/a/..")]
    [InlineData("http://proxy.example:8080/?query=1")]
    [InlineData("http://proxy.example:8080/#fragment")]
    [InlineData(" http://proxy.example:8080")]
    [InlineData("http://proxy.example:8080\r\nother")]
    [InlineData("http://proxy.example:8080;https://other.example:8443")]
    public void InvalidOrCredentialBearingConfigurationFailsClosed(string value)
        => Assert.Throws<InvalidOperationException>(() => AgentProxySettings.Read(() => value));

    [Fact]
    public void MissingConfigurationKeepsExistingHandlerAndSystemDefaults()
    {
        Assert.Null(AgentProxySettings.Read(() => null));
        Assert.Null(AgentProxySettings.Read(() => ""));
        using var defaults = new HttpClientHandler();
        AgentProxySettings.Apply(defaults, null);
        Assert.True(defaults.UseProxy);
        Assert.Null(defaults.Proxy);
        var existing = new WebProxy("http://already-configured.example");
        using var custom = new HttpClientHandler { UseProxy = false, Proxy = existing };
        AgentProxySettings.Apply(custom, null);
        Assert.False(custom.UseProxy);
        Assert.Same(existing, custom.Proxy);
    }

    [Fact]
    public void UnreadableOrWrongTypeConfigurationDoesNotBecomeSystemDefault()
    {
        Assert.Throws<InvalidOperationException>(() => AgentProxySettings.Read(() => 123));
        Assert.Throws<InvalidOperationException>(() => AgentProxySettings.Read(() => throw new UnauthorizedAccessException()));
    }

    [Fact]
    public void ExplicitProxyChangesOnlyTransportRoutingAndKeepsTlsValidation()
    {
        var proxy = AgentProxySettings.Parse("https://proxy.example:8443")!;
        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => false;
        var callback = handler.ServerCertificateCustomValidationCallback;
        Assert.Same(handler, AgentProxySettings.Apply(handler, proxy));
        Assert.True(handler.UseProxy);
        Assert.Equal(proxy, handler.Proxy!.GetProxy(new Uri("https://collector.example/api/v1/agents/token")));
        Assert.Null(handler.Proxy.Credentials);
        Assert.Same(callback, handler.ServerCertificateCustomValidationCallback);
        Assert.False(handler.AllowAutoRedirect);
    }

    [Theory]
    [InlineData("http://proxy.example:8080", "http://proxy.example:8080")]
    [InlineData("https://proxy.example:443", "https://proxy.example:443")]
    [InlineData("http://[2001:db8::1]:8080", "http://[2001:db8::1]:8080")]
    public void BitsReceivesTheSameProxySchemeAuthorityAndPort(string input, string expected)
    {
        var calls = 0;
        AgentProxySettings.ApplyBits((usage, proxy, bypass) =>
        {
            calls++;
            Assert.Equal(2u, usage);
            Assert.Equal(expected, proxy);
            Assert.Null(bypass);
            return 0;
        }, AgentProxySettings.Parse(input));
        Assert.Equal(1, calls);
    }

    [Fact]
    public void BitsUnsetDoesNotOverridePreconfigAndNativeFailureIsNotIgnored()
    {
        AgentProxySettings.ApplyBits((_, _, _) => throw new InvalidOperationException("must not be called"), null);
        var failure = Assert.Throws<InvalidOperationException>(() => AgentProxySettings.ApplyBits(
            (_, _, _) => unchecked((int)0x80004005), AgentProxySettings.Parse("http://proxy.example:8080")));
        Assert.Equal(unchecked((int)0x80004005), failure.InnerException!.HResult);
    }
}
