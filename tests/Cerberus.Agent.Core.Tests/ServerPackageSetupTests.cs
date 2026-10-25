using System.Xml.Linq;

namespace Cerberus.Agent.Core.Tests;

// Support tier: preprocessed Package.wxs per profile. Install-time DACL and rollback behaviour need a real MSI run.
public sealed class ServerPackageSetupTests
{
    private static readonly XNamespace Wix = "http://wixtoolset.org/schemas/v4/wxs";

    [Theory]
    [InlineData("dev")]
    [InlineData("stable")]
    public void ServerDataFolder_IsCreatedWithProtectedSystemAndAdminsOnlyDacl(string channel)
    {
        var doc = XDocument.Parse(ServerPackageStaticTests.Evaluate("server", channel));
        var component = doc.Descendants(Wix + "Component").Single(c => (string?)c.Attribute("Id") == "ServerDataFolderComponent");

        Assert.Equal("SERVERDATADIR", (string?)component.Attribute("Directory"));
        var permission = component.Descendants(Wix + "PermissionEx").Single();
        Assert.NotNull(component.Descendants(Wix + "CreateFolder").Single());
        var sddl = (string)permission.Attribute("Sddl")!;

        // Protected DACL (no inheritance from ProgramData), exactly SYSTEM and Administrators with full control.
        Assert.StartsWith("D:P", sddl);
        var aces = System.Text.RegularExpressions.Regex.Matches(sddl, @"\(([^)]*)\)").Select(m => m.Groups[1].Value).ToArray();
        Assert.Equal(new[] { "A;OICI;FA;;;SY", "A;OICI;FA;;;BA" }, aces);

        Assert.Contains(doc.Descendants(Wix + "ComponentRef"), r => (string?)r.Attribute("Id") == "ServerDataFolderComponent");
    }

    [Fact]
    public void DesktopPackage_DoesNotSecureOrReferenceTheServerDataFolder()
    {
        var text = ServerPackageStaticTests.Evaluate("desktop", "stable");

        Assert.DoesNotContain("ServerDataFolderComponent", text);
        Assert.DoesNotContain("PermissionEx", text);
    }

    [Fact]
    public void ServerEnroll_HasRollbackActionScheduledAfterTheEnrollAction()
    {
        var text = ServerPackageStaticTests.Evaluate("server", "stable");
        var doc = XDocument.Parse(text);

        var rollback = doc.Descendants(Wix + "CustomAction").Single(a => (string?)a.Attribute("Id") == "ServerEnrollRollback");
        Assert.Equal("rollback", (string?)rollback.Attribute("Execute"));
        Assert.Equal("no", (string?)rollback.Attribute("Impersonate"));
        Assert.Equal("ignore", (string?)rollback.Attribute("Return"));
        Assert.Equal("yes", (string?)rollback.Attribute("HideTarget"));
        Assert.Equal("\"[APPFOLDER]Cerberus.Agent.exe\" --enroll-rollback", (string?)rollback.Attribute("ExeCommand"));

        var sequence = doc.Descendants(Wix + "Custom").ToArray();
        var enroll = sequence.Single(c => (string?)c.Attribute("Action") == "ServerEnrollFromInstaller");
        var scheduled = sequence.Single(c => (string?)c.Attribute("Action") == "ServerEnrollRollback");
        Assert.Equal("ServerEnrollFromInstaller", (string?)scheduled.Attribute("After"));
        Assert.Equal((string?)enroll.Attribute("Condition"), (string?)scheduled.Attribute("Condition"));
    }

    [Fact]
    public void DesktopPackage_HasNoEnrollRollbackAction()
    {
        Assert.DoesNotContain("ServerEnrollRollback", ServerPackageStaticTests.Evaluate("desktop", "stable"));
    }

    [Fact]
    public void BothPackages_NoLongerWriteTheUnusedArtifactPrefixRegistryValue()
    {
        foreach (var profile in new[] { "server", "desktop" })
        {
            var text = ServerPackageStaticTests.Evaluate(profile, "stable");
            Assert.DoesNotContain("updateAllowedArtifactPrefixes", text);
            Assert.DoesNotContain("UpdateAllowedArtifactPrefixes", text);
            Assert.DoesNotContain("CERBERUS_AGENT_UPDATE_ALLOWED_ARTIFACT_PREFIXES", text);
        }
    }

    [Fact]
    public void TrustFactory_DoesNotReadTheRemovedRegistryValue()
    {
        var source = File.ReadAllText(Path.Combine(FindRoot(), "src", "Cerberus.Agent.App", "Updates", "AgentUpdateTrustFactory.cs"));

        Assert.DoesNotContain("updateAllowedArtifactPrefixes", source);
    }

    private static string FindRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "src", "Cerberus.Agent.Installer", "Package.wxs"))) dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("repo root not found");
    }
}
