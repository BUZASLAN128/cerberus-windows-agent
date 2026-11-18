using System.IO;
using System.Runtime.CompilerServices;
using System.Xml.Linq;
using Xunit;

namespace Cerberus.Agent.Updater.Tests;

public sealed class UpdaterLabReleaseSourceTests
{
    [Fact]
    public void ReleaseBuildKeepsTheFixedWatchDurationAndExcludesTheLabOverride()
    {
        var updater = Path.Combine(RepositoryRoot(), "src", "Cerberus.Agent.Updater");
        var release = File.ReadAllText(Path.Combine(updater, "UpdaterLab.Release.cs"));
        Assert.Contains("internal static int WatchMinutes => 30;", release);
        Assert.DoesNotContain("WatchMinutesOverride", release, StringComparison.OrdinalIgnoreCase);

        var project = XDocument.Load(Path.Combine(updater, "Cerberus.Agent.Updater.csproj"));
        Assert.Contains(project.Descendants("Compile"), item => (string?)item.Attribute("Remove") == "UpdaterLab.Runtime.cs" &&
            (string?)item.Attribute("Condition") == "'$(AgentUpdateLabPolicyB64)' == ''");
        Assert.Contains(project.Descendants("Compile"), item => (string?)item.Attribute("Remove") == "UpdaterLab.Release.cs" &&
            (string?)item.Attribute("Condition") == "'$(AgentUpdateLabPolicyB64)' != ''");
    }

    private static string RepositoryRoot([CallerFilePath] string source = "") => new FileInfo(source).Directory!.Parent!.Parent!.FullName;
}
