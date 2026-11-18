using System.Xml.Linq;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class ServerPackageStaticTests
{
    [Theory]
    [InlineData("dev")]
    [InlineData("stable")]
    public void ServerBranch_DowngradeRequiresRollbackGrant(string channel)
    {
        var package = XDocument.Parse(Evaluate("server", channel));
        var fragment = XDocument.Parse(Evaluate("server", channel, "ServerRollback.wxs"));
        var majorUpgrade = package.Descendants(Wix + "MajorUpgrade").Single();
        Assert.Equal("yes", (string?)majorUpgrade.Attribute("AllowDowngrades"));
        Assert.Null(majorUpgrade.Attribute("DowngradeErrorMessage"));
        Assert.Equal("RequireRollbackGrant", (string?)package.Descendants(Wix + "CustomActionRef").Single().Attribute("Id"));

        var upgrade = fragment.Descendants(Wix + "Upgrade").Single();
        Assert.Equal(ServerUpgradeCode, (string?)upgrade.Attribute("Id"));
        var row = upgrade.Element(Wix + "UpgradeVersion")!;
        Assert.Equal("$(var.MsiProductVersion)", (string?)row.Attribute("Minimum"));
        Assert.Equal("no", (string?)row.Attribute("IncludeMinimum"));
        Assert.Equal("yes", (string?)row.Attribute("OnlyDetect"));
        Assert.Equal("CERBERUS_NEWER_DETECTED", (string?)row.Attribute("Property"));
        var secure = fragment.Descendants(Wix + "Property").Where(p => (string?)p.Attribute("Secure") == "yes");
        Assert.Equal(new[] { "CERBERUS_NEWER_DETECTED", "CERBERUS_ROLLBACK_ATTEMPT" }, secure.Select(p => (string?)p.Attribute("Id")));
        var properties = fragment.Descendants(Wix + "Property").ToDictionary(p => (string)p.Attribute("Id")!, p => (string?)p.Attribute("Value"));
        Assert.Equal("$(var.ServiceExeSha256)", properties["RollbackServiceExeSha256"]);
        Assert.Equal("$(var.ServiceAssemblySha256)", properties["RollbackServiceAssemblySha256"]);

        var action = fragment.Descendants(Wix + "CustomAction").Single(e => (string?)e.Attribute("Id") == "RequireRollbackGrant");
        Assert.Equal("CerberusInstallerHelper", (string?)action.Attribute("BinaryRef"));
        Assert.Equal("deferred", (string?)action.Attribute("Execute"));
        Assert.Equal("no", (string?)action.Attribute("Impersonate"));
        Assert.Equal("check", (string?)action.Attribute("Return"));
        Assert.Equal("yes", (string?)action.Attribute("HideTarget"));
        Assert.Equal("""
            require-rollback-grant "[ProductCode]" "[APPFOLDER]." "$(var.ReleaseVersion)" "[RollbackServiceExeSha256]" "[RollbackServiceAssemblySha256]" "[CERBERUS_NEWER_DETECTED]" "[CERBERUS_ROLLBACK_ATTEMPT]" "[OriginalDatabase]"
            """, (string?)action.Attribute("ExeCommand"));
        var sequence = fragment.Descendants(Wix + "Custom").Single(e => (string?)e.Attribute("Action") == "RequireRollbackGrant");
        Assert.Equal("InstallInitialize", (string?)sequence.Attribute("After"));
        Assert.Equal("CERBERUS_NEWER_DETECTED AND NOT REMOVE", (string?)sequence.Attribute("Condition"));
        var removal = fragment.Descendants(Wix + "Custom").Single(e => (string?)e.Attribute("Action") == "BlockNewServerDowngradeWithRemoval");
        Assert.Equal("InstallInitialize", (string?)removal.Attribute("Before"));
        Assert.Equal("CERBERUS_NEWER_DETECTED AND REMOVE AND NOT Installed", (string?)removal.Attribute("Condition"));
    }

    [Theory]
    [InlineData("dev", "yes", null)]
    [InlineData("stable", null, "A newer version of Cerberus Windows Agent is already installed.")]
    public void DesktopBranch_DowngradeAuthoringUnchanged(string channel, string? allow, string? error)
    {
        var package = Evaluate("desktop", channel);
        var fragment = XDocument.Parse(Evaluate("desktop", channel, "ServerRollback.wxs"));
        var majorUpgrade = XDocument.Parse(package).Descendants(Wix + "MajorUpgrade").Single();
        Assert.Equal(allow, (string?)majorUpgrade.Attribute("AllowDowngrades"));
        Assert.Equal(error, (string?)majorUpgrade.Attribute("DowngradeErrorMessage"));
        Assert.DoesNotContain("RequireRollbackGrant", package);
        Assert.Empty(fragment.Root!.Elements());
    }
}
