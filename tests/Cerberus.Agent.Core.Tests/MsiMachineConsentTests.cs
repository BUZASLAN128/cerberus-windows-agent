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
    [InlineData("explicit-v1", true)]
    [InlineData("1", true)]
    [InlineData("0", false)]
    [InlineData("", false)]
    [InlineData("msi_eula_dialog", false)]
    public void Machine_record_only_accepts_explicit_evidence(string marker, bool expected)
    {
        var values = Current();
        values["acceptanceEvidence"] = marker;
        Assert.Equal(expected, AgentLegalConsent.IsCurrentMachineMsiConsent(values));
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
        var reset = package.Descendants(wix + "SetProperty").Single(x => (string?)x.Attribute("Id") == "CERBERUS_EXPLICIT_CONSENT");
        Assert.Equal("0", (string?)reset.Attribute("Value"));
        Assert.Equal("WIX_UPGRADE_DETECTED", (string?)reset.Attribute("Condition"));
        Assert.Equal("FindRelatedProducts", (string?)reset.Attribute("After"));
        Assert.Equal("execute", (string?)reset.Attribute("Sequence"));
        foreach (var (id, guid) in new[] {
            ("ServerLegalConsentRegistryComponent", "{D3741C30-B58B-4F95-940E-F51B5BA80F84}"),
            ("LegalConsentRegistryComponent", "{6FD72DD1-B76B-4E07-94A2-4355A5FB403D}") })
        {
            var component = package.Descendants(wix + "Component").Single(x => (string?)x.Attribute("Id") == id);
            Assert.Equal(guid, (string?)component.Attribute("Guid"));
            Assert.Equal("yes", (string?)component.Attribute("NeverOverwrite"));
            Assert.Equal("(CERBERUS_EXPLICIT_CONSENT = 1 AND NOT Installed AND NOT WIX_UPGRADE_DETECTED) OR WIX_UPGRADE_DETECTED", (string?)component.Attribute("Condition"));
            Assert.Contains(component.Elements(wix + "RegistryValue"), x => (string?)x.Attribute("Name") == "accepted" && (string?)x.Attribute("KeyPath") == "yes");
            Assert.Contains(component.Elements(wix + "RegistryValue"), x => (string?)x.Attribute("Name") == "acceptanceEvidence" && (string?)x.Attribute("Value") == "[CERBERUS_EXPLICIT_CONSENT]");
        }
        var updater = File.ReadAllText(Path.Combine(dir.FullName, "src", "Cerberus.Agent.Updater", "Program.cs"));
        Assert.DoesNotContain("CERBERUS_EXPLICIT_CONSENT", updater);
    }
}
