using Cerberus.Agent.App;

namespace Cerberus.Agent.Core.Tests;

public sealed class ServiceInstallerTests
{
    [Theory]
    [InlineData("\"C:\\Program Files\\Cerberus\\Cerberus.Agent.App.exe\" --service", "C:\\Program Files\\Cerberus\\Cerberus.Agent.App.exe")]
    [InlineData("C:\\Cerberus\\Cerberus.Agent.App.exe --service", "C:\\Cerberus\\Cerberus.Agent.App.exe")]
    [InlineData("C:\\Cerberus\\Cerberus.Agent.App.exe", "C:\\Cerberus\\Cerberus.Agent.App.exe")]
    public void ExtractExecutablePathFromServiceImagePath_ReturnsExecutablePath(string imagePath, string expected)
    {
        Assert.Equal(expected, ServiceInstaller.ExtractExecutablePathFromServiceImagePath(imagePath));
    }

    [Fact]
    public void ServiceExecutableMatches_NormalizesEquivalentPaths()
    {
        Assert.True(ServiceInstaller.ServiceExecutableMatches(
            "C:\\Cerberus\\Cerberus.Agent.App.exe",
            "c:\\cerberus\\Cerberus.Agent.App.exe"));
    }

    [Fact]
    public void ServiceExecutableMatches_ReturnsFalseForStalePath()
    {
        Assert.False(ServiceInstaller.ServiceExecutableMatches(
            "C:\\Old\\Cerberus.Agent.App.exe",
            "C:\\New\\Cerberus.Agent.App.exe"));
    }
}
