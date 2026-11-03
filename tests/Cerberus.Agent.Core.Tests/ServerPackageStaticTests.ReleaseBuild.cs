using System.Text.RegularExpressions;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class ServerPackageStaticTests
{
    [Fact]
    public void ReleaseScript_SharesTheProfileArgumentsWithEveryBuildStep()
    {
        var script = File.ReadAllText(Path.Combine(FindRepoRoot(), "scripts", "build-agent-public-release.ps1"));

        var runtimePublish = File.ReadAllText(Path.Combine(FindRepoRoot(), "scripts", "release-runtime-publish-lib.ps1"));
        // The shared runtime publish, the Helper publish and the MSI build all receive the profile.
        Assert.Contains("release-runtime-publish-lib.ps1", script);
        Assert.Equal(1, Regex.Matches(runtimePublish, Regex.Escape("$releaseProfile.MsBuildArgs")).Count);
        Assert.Equal(2, Regex.Matches(script, Regex.Escape("$releaseProfile.MsBuildArgs")).Count);
        Assert.Contains("@($releaseProfile.MsiArgs)", script);
        Assert.Contains("Publish-AgentProject \"src/Cerberus.Agent.App/Cerberus.Agent.App.csproj\"", script);
        Assert.Contains("Publish-AgentProject \"src/Cerberus.Agent.Service/Cerberus.Agent.Service.csproj\"", script);
        Assert.Contains("Publish-AgentProject \"src/Cerberus.Agent.Updater/Cerberus.Agent.Updater.csproj\"", script);
        Assert.Matches(@"if \(\$BuildProfile -ne ""server""\) \{ Publish-AgentProject ""src/Cerberus\.Agent\.Uninstall/", script);
        Assert.True(script.Split('\n').Length < 500, "build-agent-public-release.ps1 must stay under 500 lines.");
    }

}
