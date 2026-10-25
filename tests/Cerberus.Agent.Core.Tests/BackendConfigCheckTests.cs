// Pure local backend-address check shared by the service start and the recovery supervisor.
using Cerberus.Agent.App;
using Cerberus.Agent.App.Control;

namespace Cerberus.Agent.Core.Tests;

public sealed class BackendConfigCheckTests
{
    private const string Stored = "https://old-collector.example.test:8443";
    private const string Compiled = "https://new-collector.example.test:8443";

    [Theory]
    // environment, stored, compiled, expected reason
    [InlineData(null, Stored, Stored, null)]
    [InlineData(null, Stored, "", null)]
    [InlineData(null, Stored, "  ", null)]
    [InlineData(" https://old-collector.example.test:8443/ ", Stored, Stored, null)]
    [InlineData(Stored, Stored, "", null)]
    [InlineData(null, "not a url", Compiled, "backend_url_invalid")]
    [InlineData(null, "", Compiled, "backend_url_invalid")]
    [InlineData("", Stored, Stored, "backend_url_invalid")]
    [InlineData("ftp://old-collector.example.test", Stored, Stored, "backend_url_invalid")]
    [InlineData("not a url", Stored, Compiled, "backend_url_invalid")]
    [InlineData(Compiled, Stored, "", "backend_environment_mismatch")]
    [InlineData(Compiled, Stored, Compiled, "backend_environment_mismatch")]
    [InlineData(null, Stored, Compiled, "backend_environment_mismatch")]
    [InlineData(null, Stored, "http://old-collector.example.test:8443", "backend_environment_mismatch")]
    [InlineData("https://user@old-collector.example.test:8443", Stored, Stored, "backend_environment_mismatch")]
    public void BlockReason_ReturnsExpectedCode(string? environment, string stored, string compiled, string? expected)
        => Assert.Equal(expected, BackendConfigCheck.BlockReason(environment, stored, compiled));

    [Fact]
    public void BlockReason_MatchesTheFormerInlineServiceStartRules()
    {
        string?[] environments = { null, "", Stored, Compiled, "not a url", "ftp://x.example.test", "http://old-collector.example.test:8443" };
        string[] storedValues = { Stored, Compiled, "", "garbage", "http://old-collector.example.test:8443/" };
        string[] compiledValues = { "", Stored, Compiled, "http://new-collector.example.test" };

        foreach (var environment in environments)
            foreach (var stored in storedValues)
                foreach (var compiled in compiledValues)
                    Assert.True(FormerRules(environment, stored, compiled) == BackendConfigCheck.BlockReason(environment, stored, compiled),
                        $"env={environment ?? "<null>"} stored={stored} compiled={compiled}");
    }

    // Copy of the checks that ran inline in ServiceMode.RunAutomaticAsync before the extraction.
    private static string? FormerRules(string? environment, string stored, string compiled)
    {
        var backendUrl = environment ?? stored;
        if (!Uri.TryCreate(backendUrl.Trim().TrimEnd('/'), UriKind.Absolute, out var baseAddress) ||
            (baseAddress.Scheme != Uri.UriSchemeHttp && baseAddress.Scheme != Uri.UriSchemeHttps))
            return "backend_url_invalid";
        if (!AgentBuildConfig.SameEndpoint(backendUrl, stored) ||
            (!string.IsNullOrWhiteSpace(compiled) && !AgentBuildConfig.SameEndpoint(stored, compiled)))
            return "backend_environment_mismatch";
        return null;
    }
}
