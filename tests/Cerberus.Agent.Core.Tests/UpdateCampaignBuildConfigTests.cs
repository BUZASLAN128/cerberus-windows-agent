using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace Cerberus.Agent.Core.Tests;

// -p:ExcludeUpdateCampaignCode=true removes the development update campaign code from App, Runtime and the
// installer Helper and swaps each campaign hook file for its release variant.
public sealed class UpdateCampaignBuildConfigTests
{
    private const string Excluded = "'$(ExcludeUpdateCampaignCode)' == 'true'";
    private const string Included = "'$(ExcludeUpdateCampaignCode)' != 'true'";
    private static readonly string[] CampaignFiles = [@"Updates\AgentUpdateLab*.cs", @"Updates\AgentUpdateLocalService.Lab.cs",
        @"Updates\AgentUpdateLocalService.LabRecovery.cs", @"Updates\UpdateCampaignHooks.cs"];

    [Fact]
    public void AppAndRuntimeRemoveTheCampaignFilesOnlyUnderTheExclusion()
    {
        AssertSwap(Project("Cerberus.Agent.App", "Cerberus.Agent.App.csproj"), "");
        var runtime = Project("Cerberus.Agent.Runtime", "Cerberus.Agent.Runtime.csproj");
        AssertSwap(runtime, @"..\Cerberus.Agent.App\");
        var include = runtime.Descendants("Compile").Single(c => (string?)c.Attribute("Include") == @"..\Cerberus.Agent.App\Updates\**\*.cs");
        Assert.All(runtime.Descendants("Compile").Where(c => c.Attribute("Remove") is not null),
            remove => Assert.True(include.IsBefore(remove)));
    }

    [Fact]
    public void HelperLinksTheCampaignAdmissionOnlyWithoutTheExclusion()
    {
        var helper = Project(Path.Combine("Cerberus.Agent.Installer", "Helper"), "Cerberus.Agent.Installer.Helper.csproj");
        var included = Group(helper, Included);
        Assert.Equal([@"..\..\Cerberus.Agent.App\Updates\AgentUpdateLabPolicy.cs", @"..\..\Cerberus.Agent.App\Updates\AgentUpdateLabRuntimeAdmission.cs"],
            included.Elements("Compile").Select(c => (string?)c.Attribute("Include")).OfType<string>());
        Assert.Equal(["InstallerCampaignHooks.Release.cs"], Removes(included));
        Assert.Equal(["InstallerCampaignHooks.cs"], Removes(Group(helper, Excluded)));
        Assert.DoesNotContain(helper.Descendants("Compile"), c => ((string?)c.Attribute("Include"))?.Contains("AgentUpdateLab") == true &&
            (string?)c.Parent!.Attribute("Condition") != Included);
    }

    [Fact]
    public void CampaignPolicyWithTheExclusionFailsTheBuild()
    {
        var props = XDocument.Load(Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "Directory.Build.props"));
        var target = props.Descendants("Target").Single(t => (string?)t.Attribute("Name") == "RejectExcludedUpdateCampaignPolicy");
        Assert.Equal(Excluded + " and '$(AgentUpdateLabPolicyB64)' != ''", (string?)target.Attribute("Condition"));
        Assert.Equal("CERBAGENT007", (string?)target.Element("Error")!.Attribute("Code"));
    }

    [Fact]
    public void OnlyTheExcludedFilesAndForwardingHooksNameCampaignTypes()
    {
        var updates = Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "src", "Cerberus.Agent.App", "Updates");
        var excluded = CampaignFiles.SelectMany(pattern => Directory.GetFiles(updates, Path.GetFileName(pattern)))
            .Select(Path.GetFileName).ToHashSet(StringComparer.Ordinal);
        Assert.Equal(Directory.GetFiles(updates, "*Lab*.cs").Select(Path.GetFileName).Order(),
            excluded.Where(name => name!.Contains("Lab", StringComparison.Ordinal)).Order());
        var labMembers = new[] { "AgentUpdateLocalService.Lab.cs", "AgentUpdateLocalService.LabRecovery.cs" }
            .SelectMany(name => Regex.Matches(File.ReadAllText(Path.Combine(updates, name)), @"static [\w<>?.,\s]+?\b(\w+)\(")
                .Select(match => match.Groups[1].Value)).ToArray();
        Assert.Contains("ReconcileUnstartedLabRunnerAsync", labMembers);
        var roots = new[] { Path.Combine("Cerberus.Agent.App"), Path.Combine("Cerberus.Agent.Installer", "Helper") };
        foreach (var file in roots.SelectMany(root => Directory.GetFiles(Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "src", root),
                     "*.cs", SearchOption.AllDirectories)))
        {
            var name = Path.GetFileName(file);
            if (excluded.Contains(name) || name is "InstallerCampaignHooks.cs" || file.Contains(@"\obj\") || file.Contains(@"\bin\")) continue;
            // Metadata keys such as "AgentUpdateLabPolicyB64" are string literals, not campaign types.
            var source = Regex.Replace(File.ReadAllText(file), "\"[^\"\\n]*\"", "\"\"");
            Assert.DoesNotMatch(@"\bAgentUpdateLab\w*|\bAgentInstalledProductVersion\b", source);
            Assert.DoesNotContain(labMembers, member => Regex.IsMatch(source, $@"\b{member}\b"));
        }
    }

    private static XDocument Project(string directory, string file)
        => XDocument.Load(Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "src", directory, file));

    private static XElement Group(XDocument project, string condition)
        => project.Descendants("ItemGroup").Single(group => (string?)group.Attribute("Condition") == condition);

    private static string[] Removes(XElement group)
        => group.Elements("Compile").Select(c => (string?)c.Attribute("Remove")).OfType<string>().ToArray();

    private static void AssertSwap(XDocument project, string prefix)
    {
        Assert.Equal(CampaignFiles.Select(file => prefix + file), Removes(Group(project, Excluded)));
        Assert.Equal([prefix + @"Updates\UpdateCampaignHooks.Release.cs"], Removes(Group(project, Included)));
    }
}
