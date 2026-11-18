using System.IO;
using System.Text.Json;
using Cerberus.Agent.Updater;
using Xunit;

namespace Cerberus.Agent.Updater.Tests;

public sealed class LkgProbeTests
{
    private const string Nonce = "aabbccdd";
    private const string Version = "1.2.3";

    [Theory]
    [InlineData("1")]
    [InlineData("2")]
    public void ResponseMatchesTheWireContractAndSupportsNewerVersions(string contract)
    {
        using var output = new StringWriter();
        Assert.Equal(0, LkgProbe.WriteResponse(Nonce, Version, contract, output));
        var json = output.ToString();
        using var parsed = JsonDocument.Parse(json);
        var response = parsed.RootElement;
        Assert.Equal(new[] { "schema", "nonce", "version", "modes", "contract" }, response.EnumerateObject().Select(p => p.Name));
        Assert.Equal("agent.update.probe.v1", response.GetProperty("schema").GetString());
        Assert.Equal(new[] { "attempt", "watch", "scm-failure", "probe" }, response.GetProperty("modes")
            .EnumerateArray().Select(mode => mode.GetString()));
        Assert.Equal(JsonValueKind.Number, response.GetProperty("contract").ValueKind);
        Assert.True(LkgProbe.Accepts(json, 0, Nonce, Version, 1));
    }

    [Theory]
    [InlineData("1.0")]
    [InlineData("v1")]
    [InlineData("0")]
    [InlineData("-1")]
    public void InvalidCompiledContractWritesNothing(string contract)
    {
        using var output = new StringWriter();
        Assert.Equal(2, LkgProbe.WriteResponse(Nonce, Version, contract, output));
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public void ExactProbeResponseFailsClosedOnInvalidProcessOrWireEvidence()
    {
        using var output = new StringWriter();
        Assert.Equal(0, LkgProbe.WriteResponse(Nonce, Version, "1", output));
        var json = output.ToString();
        Assert.False(LkgProbe.Accepts(json, 2, Nonce, Version, 1));
        Assert.False(LkgProbe.Accepts(json, 0, "wrong-nonce", Version, 1));
        Assert.False(LkgProbe.Accepts(json, 0, Nonce, "1.2.4", 1));
        Assert.False(LkgProbe.Accepts(json, 0, Nonce, Version, 2));
        Assert.False(LkgProbe.Accepts(json + json, 0, Nonce, Version, 1));
        Assert.False(LkgProbe.Accepts(json.Replace("\"scm-failure\",", ""), 0, Nonce, Version, 1));
        Assert.False(LkgProbe.Accepts(json.Replace("\"contract\":1", "\"contract\":\"1\""), 0, Nonce, Version, 1));
        Assert.False(LkgProbe.Accepts(json.Replace("\"contract\":1", "\"contract\":1.0"), 0, Nonce, Version, 1));
        Assert.False(LkgProbe.Accepts(json.Replace("\"contract\":1", "\"contract\":0,\"contract\":1"), 0, Nonce, Version, 1));
        Assert.True(LkgProbe.Accepts(json.Replace("\"scm-failure\",", "\"future-mode\",\"scm-failure\","), 0, Nonce, Version, 1));
    }
}
