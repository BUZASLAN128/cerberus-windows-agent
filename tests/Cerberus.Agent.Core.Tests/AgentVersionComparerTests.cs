using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentVersionComparerTests
{
    [Theory]
    [InlineData("0.2.118-dev.118", "0.2.118.0", 0)]
    [InlineData("0.2.119-dev.119", "0.2.118.0", 1)]
    [InlineData("0.2.117-dev.117", "0.2.118.0", -1)]
    [InlineData("0.2.1003-dev.1003", "0.2.131.0", 1)]
    [InlineData("0.2.131-dev.131", "0.2.1003.0", -1)]
    [InlineData("1.2.0+build.7", "1.2.0.0", 0)]
    public void CompareReleaseCore_IgnoresPrereleaseAndBuildMetadata(
        string left,
        string right,
        int expectedSign)
    {
        var compare = AgentVersionComparer.CompareReleaseCore(left, right);

        Assert.NotNull(compare);
        Assert.Equal(expectedSign, Math.Sign(compare.Value));
    }
}
