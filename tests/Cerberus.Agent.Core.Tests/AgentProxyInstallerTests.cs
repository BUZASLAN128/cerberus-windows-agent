using System.Security.AccessControl;
using System.Security.Principal;
using System.Xml.Linq;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentProxyInstallerTests
{
    private static readonly XNamespace Wix = "http://wixtoolset.org/schemas/v4/wxs";
    private static string InstallerPath => Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "src", "Cerberus.Agent.Installer");
    private static XDocument Fragment() => XDocument.Load(Path.Combine(InstallerPath, "Proxy.wxs"));

    [Fact]
    public void BothProfilesInstallTheMachineSettingAndRetainAnOmittedUpgradeProperty()
    {
        var fragment = Fragment();
        var property = fragment.Descendants(Wix + "Property").Single(p => (string?)p.Attribute("Id") == "CERBERUS_PROXY_URL");
        Assert.Equal("yes", (string?)property.Attribute("Secure"));
        Assert.Equal("yes", (string?)property.Attribute("Hidden"));
        var search = Assert.Single(fragment.Descendants(Wix + "RegistrySearch"));
        Assert.Equal("HKLM", (string?)search.Attribute("Root"));
        Assert.Equal("always64", (string?)search.Attribute("Bitness"));
        var retain = Assert.Single(fragment.Descendants(Wix + "SetProperty"));
        Assert.Equal("NOT CERBERUS_PROXY_URL AND CERBERUS_EXISTING_PROXY_URL", (string?)retain.Attribute("Condition"));
        var package = XDocument.Load(Path.Combine(InstallerPath, "Package.wxs"));
        Assert.All(package.Descendants(Wix + "Feature"), feature => Assert.Contains(feature.Elements(Wix + "ComponentGroupRef"),
            reference => (string?)reference.Attribute("Id") == "AgentProxyConfiguration"));
    }

    [Fact]
    public void ProxyRegistryAclAllowsOnlySystemAndAdministratorsToWrite()
    {
        var permissions = Assert.Single(Fragment().Descendants(Wix + "PermissionEx"));
        var descriptor = new RawSecurityDescriptor((string)permissions.Attribute("Sddl")!);
        Assert.Equal(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), descriptor.Owner);
        Assert.True(descriptor.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclProtected));
        var privileged = new[] { new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null) };
        Assert.All(descriptor.DiscretionaryAcl!.Cast<CommonAce>(), ace =>
        {
            Assert.Equal(AceQualifier.AccessAllowed, ace.AceQualifier);
            // Set/create/delete/ACL/owner rights; READ_CONTROL permits inspection, not modification.
            if (!privileged.Contains(ace.SecurityIdentifier)) Assert.Equal(0, ace.AccessMask & 0xD0026);
        });
    }

    [Fact]
    public void UnsetPropertySkipsValidationAndTheEntireRegistryComponent()
    {
        var fragment = Fragment();
        var property = fragment.Descendants(Wix + "Property").Single(p => (string?)p.Attribute("Id") == "CERBERUS_PROXY_URL");
        Assert.Null(property.Attribute("Value"));
        var validation = fragment.Descendants(Wix + "Custom").Single(a => (string?)a.Attribute("Action") == "ValidateAgentProxyUrl");
        Assert.Equal("NOT REMOVE AND CERBERUS_PROXY_URL", (string?)validation.Attribute("Condition"));
        var component = Assert.Single(fragment.Descendants(Wix + "Component"));
        Assert.Equal("CERBERUS_PROXY_URL", (string?)component.Attribute("Condition"));
    }

    [Fact]
    public void ValidationPrecedesRegistryWritesAndKeepsThePrivilegedHelperGate()
    {
        var fragment = Fragment();
        var action = fragment.Descendants(Wix + "CustomAction").Single(a => (string?)a.Attribute("Id") == "ValidateAgentProxyUrl");
        Assert.Equal("deferred", (string?)action.Attribute("Execute"));
        Assert.Equal("no", (string?)action.Attribute("Impersonate"));
        Assert.Equal("check", (string?)action.Attribute("Return"));
        Assert.Equal("yes", (string?)action.Attribute("HideTarget"));
        var validation = fragment.Descendants(Wix + "Custom").Single(a => (string?)a.Attribute("Action") == "ValidateAgentProxyUrl");
        Assert.Equal("WriteRegistryValues", (string?)validation.Attribute("Before"));
        var quoting = fragment.Descendants(Wix + "Custom").Single(a => (string?)a.Attribute("Action") == "RejectQuotedAgentProxyUrl");
        Assert.Equal("InstallInitialize", (string?)quoting.Attribute("Before"));
        Assert.Equal("NOT REMOVE AND (CERBERUS_PROXY_URL >< AgentProxyForbiddenQuote)", (string?)quoting.Attribute("Condition"));
        var helper = File.ReadAllText(Path.Combine(InstallerPath, "Helper", "Program.cs"));
        var guard = helper.IndexOf("!AgentUpdateSecurity.IsLocalSystem()", StringComparison.Ordinal);
        var parse = helper.IndexOf("AgentProxySettings.Parse(args[2])", StringComparison.Ordinal);
        Assert.True(guard >= 0 && parse > guard);
    }
}
