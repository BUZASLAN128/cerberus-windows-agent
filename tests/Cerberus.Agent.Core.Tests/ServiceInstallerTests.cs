using Cerberus.Agent.App;

namespace Cerberus.Agent.Core.Tests;

public sealed class ServiceInstallerTests
{
    [Theory]
    [InlineData("\"C:\\Program Files\\Cerberus\\Cerberus.Agent.exe\" --service", "C:\\Program Files\\Cerberus\\Cerberus.Agent.exe")]
    [InlineData("\"C:\\Program Files\\Cerberus\\Windows Agent\\Cerberus.Agent.Service.exe\"", "C:\\Program Files\\Cerberus\\Windows Agent\\Cerberus.Agent.Service.exe")]
    [InlineData("C:\\Cerberus\\Cerberus.Agent.exe --service", "C:\\Cerberus\\Cerberus.Agent.exe")]
    [InlineData("C:\\Cerberus\\Cerberus.Agent.exe", "C:\\Cerberus\\Cerberus.Agent.exe")]
    public void ExtractExecutablePathFromServiceImagePath_ReturnsExecutablePath(string imagePath, string expected)
    {
        Assert.Equal(expected, ServiceInstaller.ExtractExecutablePathFromServiceImagePath(imagePath));
    }

    [Fact]
    public void ServiceExecutableMatches_NormalizesEquivalentPaths()
    {
        Assert.True(ServiceInstaller.ServiceExecutableMatches(
            "C:\\Cerberus\\Cerberus.Agent.exe",
            "c:\\cerberus\\Cerberus.Agent.exe"));
    }

    [Fact]
    public void ServiceExecutableMatches_ReturnsFalseForStalePath()
    {
        Assert.False(ServiceInstaller.ServiceExecutableMatches(
            "C:\\Old\\Cerberus.Agent.exe",
            "C:\\New\\Cerberus.Agent.exe"));
    }

    [Fact]
    public void ResolveServiceExecutablePath_PrefersSiblingServiceExe()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-service-path-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var setupPath = Path.Combine(root, "Cerberus.Agent.exe");
        var servicePath = Path.Combine(root, "Cerberus.Agent.Service.exe");
        File.WriteAllText(setupPath, "");
        File.WriteAllText(servicePath, "");

        Assert.Equal(servicePath, ServiceInstaller.ResolveServiceExecutablePath(setupPath));
    }
}
