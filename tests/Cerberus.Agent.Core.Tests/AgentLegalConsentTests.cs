using Cerberus.Agent.App;
using Cerberus.Agent.App.Legal;
using System.Text.RegularExpressions;
using System.Text.Json;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentLegalConsentTests
{
    [Fact]
    public void ArgsParse_SupportsAcceptEulaWithoutDefaultingToTray()
    {
        var args = Args.Parse(["--accept-eula"]);

        Assert.True(args.AcceptEula);
        Assert.False(args.Tray);
    }

    [Fact]
    public void ArgsParse_SupportsOneClickSetupWithoutDefaultingToTray()
    {
        var args = Args.Parse(["--setup"]);

        Assert.True(args.Setup);
        Assert.False(args.Tray);
    }

    [Fact]
    public void AgentStatus_TreatsMachineScopeSecretFileAsRegisteredForInteractiveUi()
    {
        var root = NewTempDir();
        Directory.CreateDirectory(root);
        var userPath = Path.Combine(root, "user-secrets.json");
        var machinePath = Path.Combine(root, "machine-secrets.json");
        File.WriteAllText(machinePath, "not-readable-by-contract");

        Assert.True(AgentStatus.IsRegisteredFromSecretPaths(userPath, machinePath));
    }

    [Fact]
    public void AgentStatus_SetupCompleteRequiresRegistrationAndRunningService()
    {
        Assert.True(AgentStatus.IsSetupCompleteFromSignals(
            registered: true,
            serviceInstalled: true,
            serviceText: "running"));

        Assert.False(AgentStatus.IsSetupCompleteFromSignals(
            registered: true,
            serviceInstalled: true,
            serviceText: "stopped"));
        Assert.False(AgentStatus.IsSetupCompleteFromSignals(
            registered: true,
            serviceInstalled: false,
            serviceText: "running"));
        Assert.False(AgentStatus.IsSetupCompleteFromSignals(
            registered: false,
            serviceInstalled: true,
            serviceText: "running"));
    }

    [Fact]
    public void InstallerPackage_UsesCurrentLegalVersionsAndMsiRegistryConsent()
    {
        var repoRoot = FindRepoRoot();

        var project = File.ReadAllText(Path.Combine(
            repoRoot,
            "src",
            "Cerberus.Agent.Installer",
            "Cerberus.Agent.Installer.wixproj"));
        Assert.Contains("WixToolset.Sdk/7.0.0", project);
        Assert.Contains("<AcceptEula>wix7</AcceptEula>", project);
        Assert.Contains($"EulaVersion={AgentLegalConsent.EulaVersion}", project);
        Assert.Contains($"PrivacyNoticeVersion={AgentLegalConsent.PrivacyNoticeVersion}", project);
        Assert.Contains($"SecurityDisclosureVersion={AgentLegalConsent.SecurityDisclosureVersion}", project);
        Assert.Contains("MsiProductVersion=$(MsiProductVersion)", project);

        var package = File.ReadAllText(Path.Combine(
            repoRoot,
            "src",
            "Cerberus.Agent.Installer",
            "Package.wxs"));
        Assert.Contains("Version=\"$(var.MsiProductVersion)\"", package);
        Assert.Contains("WixUILicenseRtf", package);
        Assert.Contains("Assets\\EULA.rtf", package);
        Assert.Contains("WIXUI_ACCEPT_LICENSE_AGREEMENT", package);
        Assert.Contains("CERBERUS_EULA_ACCEPTED", package);
        Assert.Contains("BlockInstallWithoutEula", package);
        Assert.Contains("UILevel &lt; 5", package);
        Assert.Contains("CERBERUS_EULA_ACCEPTED = 1", package);
        Assert.DoesNotContain("WIXUI_ACCEPT_LICENSE_AGREEMENT = 1", package);
        Assert.DoesNotContain("LicenseAccepted = 1", package);
        Assert.Contains(@"Software\Cerberus\WindowsAgent\LegalConsent", package);
        Assert.Contains("msi_eula_dialog", package);
        Assert.Contains("Cerberus.Agent.App.exe\" --tray", package);
        Assert.DoesNotContain("--accept-eula", package, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("powershell.exe", package, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ExecutionPolicy", package, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void InstallerPackage_EulaGateDoesNotBlockFullUiAfterLicenseDialog()
    {
        var repoRoot = FindRepoRoot();
        var package = File.ReadAllText(Path.Combine(
            repoRoot,
            "src",
            "Cerberus.Agent.Installer",
            "Package.wxs"));

        var match = Regex.Match(
            package,
            @"Action=""BlockInstallWithoutEula""\s+Before=""InstallValidate""\s+Condition=""(?<condition>[^""]+)""");

        Assert.True(match.Success, "BlockInstallWithoutEula execute-sequence condition was not found.");

        var condition = match.Groups["condition"].Value;
        Assert.Equal(
            "NOT Installed AND NOT REMOVE AND UILevel &lt; 5 AND NOT CERBERUS_EULA_ACCEPTED = 1",
            condition);

        Assert.DoesNotContain("WIXUI_ACCEPT_LICENSE_AGREEMENT", condition);
        Assert.DoesNotContain("LicenseAccepted", condition);
    }

    [Fact]
    public void TryImportCurrentMsiConsentFromValues_WritesCanonicalUserConsentRecord()
    {
        var root = NewTempDir();
        var values = new Dictionary<string, string?>
        {
            ["accepted"] = "1",
            ["product"] = AgentLegalConsent.ProductName,
            ["eulaVersion"] = AgentLegalConsent.EulaVersion,
            ["privacyNoticeVersion"] = AgentLegalConsent.PrivacyNoticeVersion,
            ["securityDisclosureVersion"] = AgentLegalConsent.SecurityDisclosureVersion,
            ["acceptedVia"] = "msi_eula_dialog",
        };

        Assert.True(AgentLegalConsent.TryImportCurrentMsiConsentFromValues(values, root, out var imported));
        Assert.NotNull(imported);
        Assert.Equal("msi_eula_dialog", imported.AcceptedVia);
        Assert.True(AgentLegalConsent.TryLoadCurrent(LegalConsentScope.User, root, out var loaded));
        Assert.NotNull(loaded);
        Assert.Equal("msi_eula_dialog", loaded.AcceptedVia);
    }

    [Fact]
    public void TryImportCurrentMsiConsentFromValues_RejectsStaleRegistryVersions()
    {
        var root = NewTempDir();
        var values = new Dictionary<string, string?>
        {
            ["accepted"] = "1",
            ["product"] = AgentLegalConsent.ProductName,
            ["eulaVersion"] = "old-eula",
            ["privacyNoticeVersion"] = AgentLegalConsent.PrivacyNoticeVersion,
            ["securityDisclosureVersion"] = AgentLegalConsent.SecurityDisclosureVersion,
            ["acceptedVia"] = "msi_eula_dialog",
        };

        Assert.False(AgentLegalConsent.TryImportCurrentMsiConsentFromValues(values, root, out var imported));
        Assert.Null(imported);
        Assert.False(File.Exists(AgentLegalConsent.GetPath(LegalConsentScope.User, root)));
    }

    [Fact]
    public void Accept_WritesCurrentUserConsentRecord()
    {
        var root = NewTempDir();

        var record = AgentLegalConsent.Accept(
            LegalConsentScope.User,
            acceptedVia: "unit_test",
            baseDir: root);

        Assert.True(AgentLegalConsent.TryLoadCurrent(LegalConsentScope.User, root, out var loaded));
        Assert.NotNull(loaded);
        Assert.Equal(AgentLegalConsent.ProductName, loaded.Product);
        Assert.Equal(AgentLegalConsent.EulaVersion, loaded.EulaVersion);
        Assert.Equal(AgentLegalConsent.PrivacyNoticeVersion, loaded.PrivacyNoticeVersion);
        Assert.Equal(AgentLegalConsent.SecurityDisclosureVersion, loaded.SecurityDisclosureVersion);
        Assert.Equal("unit_test", loaded.AcceptedVia);
        Assert.Equal(record.EulaVersion, loaded.EulaVersion);
    }

    [Fact]
    public void TryLoadCurrent_RejectsOutdatedConsentVersion()
    {
        var root = NewTempDir();
        Directory.CreateDirectory(root);
        var path = AgentLegalConsent.GetPath(LegalConsentScope.User, root);
        var stale = new AgentLegalConsentRecord(
            "cerberus-agent-legal-consent.v1",
            AgentLegalConsent.ProductName,
            "old-eula",
            AgentLegalConsent.PrivacyNoticeVersion,
            AgentLegalConsent.SecurityDisclosureVersion,
            DateTimeOffset.UtcNow,
            "user",
            "machine",
            "unit_test");
        File.WriteAllText(path, JsonSerializer.Serialize(stale, new JsonSerializerOptions(JsonSerializerDefaults.Web)));

        Assert.False(AgentLegalConsent.TryLoadCurrent(LegalConsentScope.User, root, out var loaded));
        Assert.Null(loaded);
    }

    [Fact]
    public void TryLoadCurrent_RejectsMalformedConsentRecord()
    {
        var root = NewTempDir();
        Directory.CreateDirectory(root);
        File.WriteAllText(AgentLegalConsent.GetPath(LegalConsentScope.User, root), "{not-json");

        Assert.False(AgentLegalConsent.TryLoadCurrent(LegalConsentScope.User, root, out _));
    }

    private static string NewTempDir()
        => Path.Combine(Path.GetTempPath(), "cerberus-agent-legal-tests", Guid.NewGuid().ToString("N"));

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Cerberus.WindowsAgent.slnx")))
                return dir.FullName;
            dir = dir.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate cerberus-windows-agent repository root.");
    }
}
