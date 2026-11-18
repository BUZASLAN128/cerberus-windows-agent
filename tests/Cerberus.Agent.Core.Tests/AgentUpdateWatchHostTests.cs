using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateWatchHostTests
{
    [Theory]
    [InlineData("--watch", null, true, "Watch")]
    [InlineData("--scm-failure", null, true, "ScmFailure")]
    [InlineData("--probe", "aB23-d_", true, "Probe")]
    [InlineData("--probe", null, false, "None")]
    [InlineData("--probe", "../a", false, "None")]
    [InlineData("--watch", "extra", false, "None")]
    [InlineData("--attempt", "aB23", false, "None")]
    [InlineData("--WATCH", null, false, "None")]
    public void HostModesHaveExactArguments(string flag, string? value, bool allowed, string mode)
    {
        string[] args = value is null ? [flag] : [flag, value];
        Assert.Equal(allowed, AgentUpdateWatchHostArgs.TryParse(args, out var parsed));
        Assert.Equal(mode, parsed.Mode.ToString());
        Assert.Equal(allowed ? value : null, parsed.Nonce);
    }
}
