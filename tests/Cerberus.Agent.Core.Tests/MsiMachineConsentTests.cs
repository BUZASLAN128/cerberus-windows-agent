using System.Security.AccessControl;
using System.Xml.Linq;
using Cerberus.Agent.App.Legal;

namespace Cerberus.Agent.Core.Tests;

public sealed class MsiMachineConsentTests
{
    private static Dictionary<string, string?> Current() => new(StringComparer.OrdinalIgnoreCase)
    {
        ["accepted"] = "1",
        ["product"] = AgentLegalConsent.ProductName,
        ["eulaVersion"] = AgentLegalConsent.EulaVersion,
        ["privacyNoticeVersion"] = AgentLegalConsent.PrivacyNoticeVersion,
        ["securityDisclosureVersion"] = AgentLegalConsent.SecurityDisclosureVersion,
        ["acceptedVia"] = "msi_explicit",
        ["acceptanceEvidence"] = "explicit-v1",
    };

    [Fact]
    public void Machine_record_requires_explicit_evidence_and_every_current_document_version()
    {
        Assert.True(AgentLegalConsent.IsCurrentMachineMsiConsent(Current()));
        foreach (var name in new[] { "accepted", "product", "eulaVersion", "privacyNoticeVersion", "securityDisclosureVersion", "acceptedVia", "acceptanceEvidence" })
        {
            var values = Current();
            values.Remove(name);
            Assert.False(AgentLegalConsent.IsCurrentMachineMsiConsent(values));
            values[name] = "stale";
            Assert.False(AgentLegalConsent.IsCurrentMachineMsiConsent(values));
        }
    }

    [Theory]
    [InlineData("O:SYG:SYD:(A;;0xF003F;;;SY)(A;;0xF003F;;;BA)(A;;0x20019;;;BU)", true)]
    [InlineData("O:BAG:SYD:(A;;0xF003F;;;SY)(A;;0xF003F;;;BA)(A;;0x2001B;;;BU)", false)]
    [InlineData("O:BUG:SYD:(A;;0xF003F;;;SY)(A;;0xF003F;;;BA)(A;;0x20019;;;BU)", false)]
    [InlineData("O:SYG:SYD:(A;;0xF003F;;;SY)(A;;0xF003F;;;BA)(A;;0x2001D;;;BU)", false)]
    public void Registry_owner_and_write_rights_gate_every_key(string sddl, bool trusted)
        => Assert.Equal(trusted, MsiMachineConsent.IsTrusted(new RawSecurityDescriptor(sddl)));

    [Fact]
    public void Registry_chain_rejects_untrusted_parent_before_reading_leaf_values()
    {
        var checkedPaths = new List<string>();
        var read = false;
        bool Trusted(string p) { checkedPaths.Add(p); return p != @"Software\Cerberus"; }
        IReadOnlyDictionary<string, string?> Read(string _) { read = true; return Current(); }
        Assert.False(MsiMachineConsent.CheckChainAndRead(@"Software\Cerberus\ServerAgent\LegalConsent", Trusted, Read, AgentLegalConsent.IsCurrentMachineMsiConsent));
        Assert.Equal(new[] { "Software", @"Software\Cerberus" }, checkedPaths);
        Assert.False(read);
        Assert.True(MsiMachineConsent.CheckChainAndRead(@"Software\Cerberus\ServerAgent\LegalConsent", _ => true, Read, AgentLegalConsent.IsCurrentMachineMsiConsent));
        Assert.True(read);
    }

    [Fact]
    public void Installer_only_marks_explicit_fresh_acceptance_and_preserves_silent_upgrade_boundary()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Cerberus.WindowsAgent.slnx"))) dir = dir.Parent;
        Assert.NotNull(dir);
        var package = XDocument.Load(Path.Combine(dir!.FullName, "src", "Cerberus.Agent.Installer", "Package.wxs"));
        XNamespace wix = "http://wixtoolset.org/schemas/v4/wxs";
        var publish = package.Descendants(wix + "Publish").Single(x => (string?)x.Attribute("Property") == "CERBERUS_EXPLICIT_CONSENT");
        Assert.Equal("LicenseAgreementDlg", (string?)publish.Attribute("Dialog"));
        Assert.Equal("LicenseAccepted = \"1\"", (string?)publish.Attribute("Condition"));
        foreach (var id in new[] { "ServerLegalConsentRegistryComponent", "LegalConsentRegistryComponent" })
        {
            var component = package.Descendants(wix + "Component").Single(x => (string?)x.Attribute("Id") == id);
            Assert.Equal("CERBERUS_EXPLICIT_CONSENT = 1 AND NOT WIX_UPGRADE_DETECTED AND NOT Installed", (string?)component.Attribute("Condition"));
            Assert.Contains(component.Elements(wix + "RegistryValue"), x => (string?)x.Attribute("Name") == "acceptanceEvidence" && (string?)x.Attribute("Value") == "explicit-v1");
        }
        var updater = File.ReadAllText(Path.Combine(dir.FullName, "src", "Cerberus.Agent.Updater", "Program.cs"));
        Assert.DoesNotContain("CERBERUS_EXPLICIT_CONSENT", updater);
    }
}
