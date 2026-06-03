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
        Assert.False(args.Service);
    }

    [Fact]
    public void ArgsParse_SupportsOneClickSetupWithoutDefaultingToTray()
    {
        var args = Args.Parse(["--setup"]);

        Assert.True(args.Setup);
        Assert.False(args.Service);
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
        Assert.Contains("WixToolset.Util.wixext", project);
        Assert.Contains("<AcceptEula>wix7</AcceptEula>", project);
        Assert.Contains("<InstallerPlatform>x64</InstallerPlatform>", project);
        Assert.Contains("<SuppressIces>ICE91</SuppressIces>", project);
        Assert.Contains("<SuppressIces Condition=\"'$(Channel)' == 'dev'\">$(SuppressIces);ICE61</SuppressIces>", project);
        Assert.Contains("UpdateManifestPublicKeyB64", project);
        Assert.Contains("UpdateAllowedArtifactPrefixes", project);
        Assert.Contains($"EulaVersion={AgentLegalConsent.EulaVersion}", project);
        Assert.Contains($"PrivacyNoticeVersion={AgentLegalConsent.PrivacyNoticeVersion}", project);
        Assert.Contains($"SecurityDisclosureVersion={AgentLegalConsent.SecurityDisclosureVersion}", project);
        Assert.Contains("MsiProductVersion=$(MsiProductVersion)", project);
        Assert.Contains("UpdateManifestUrl", project);
        Assert.Contains("releases/download/$(Channel)-latest", project);

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
        Assert.Contains("Scope=\"perMachine\"", package);
        Assert.Contains("ProgramFiles64Folder", package);
        Assert.DoesNotContain("ProgramFilesFolder", package);
        Assert.DoesNotContain("RemoveLegacyAppDataInstallFolder", package);
        Assert.DoesNotContain("LegacyAppDataCleanupComponent", package);
        Assert.Contains("<Directory Id=\"APPFOLDER\" Name=\"app\" />", package);
        Assert.Contains("<ComponentGroup Id=\"AgentComponents\" Directory=\"APPFOLDER\">", package);
        Assert.Contains("<Files Include=\"$(var.AgentPublishDir)\\**\">", package);
        Assert.Contains("<Exclude Files=\"$(var.AgentPublishDir)\\**\\*.pdb\" />", package);
        Assert.Contains("Cerberus.Agent.exe", package);
        Assert.Contains("Cerberus.Agent.Uninstall.exe", package);
        Assert.Contains("LaunchAgentUi", package);
        Assert.Contains("ExeCommand='\"[APPFOLDER]Cerberus.Agent.exe\" --open'", package);
        Assert.DoesNotContain("Cerberus.Agent.App.exe\" --tray", package);
        Assert.Contains("CloseRunningAgentTray", package);
        Assert.Contains("CloseRunningAgentSetup", package);
        Assert.Contains("CloseRunningAgentUi", package);
        Assert.Contains("Target=\"Cerberus.Agent.exe\"", package);
        Assert.Contains("Target=\"Cerberus.Agent.Tray.exe\"", package);
        Assert.Contains("Target=\"Cerberus.Agent.Setup.exe\"", package);
        Assert.Contains("Cerberus.Agent.Uninstall.exe", package);
        Assert.Contains("CERBERUS_BACKEND_URL", package);
        Assert.Contains("CERBERUS_SSO_BASE_URL", package);
        Assert.Contains("CERBERUS_SSO_CLIENT_ID", package);
        Assert.Contains("CERBERUS_CHANNEL", package);
        Assert.Contains("CERBERUS_LANGUAGE", package);
        Assert.Contains("CERBERUS_AGENT_UPDATE_MANIFEST_URL", package);
        Assert.Contains("CERBERUS_AGENT_UPDATE_MANIFEST_PUBLIC_KEY_B64", package);
        Assert.Contains("CERBERUS_AGENT_UPDATE_ALLOWED_ARTIFACT_PREFIXES", package);
        Assert.Contains("Value=\"$(var.UpdateManifestUrl)\"", package);
        Assert.Contains("Value=\"$(var.UpdateManifestPublicKeyB64)\"", package);
        Assert.Contains("Value=\"$(var.UpdateAllowedArtifactPrefixes)\"", package);
        Assert.Contains("CREATE_DESKTOP_SHORTCUT", package);
        Assert.Contains("START_TRAY_ON_LOGIN", package);
        Assert.Contains("Name=\"backendUrl\"", package);
        Assert.Contains("Name=\"runtimeRoot\"", package);
        Assert.Contains("Value=\"[APPFOLDER]\"", package);
        Assert.Contains("Name=\"ssoBaseUrl\"", package);
        Assert.Contains("Name=\"ssoClientId\"", package);
        Assert.Contains("Name=\"language\"", package);
        Assert.Contains("Name=\"updateManifestUrl\"", package);
        Assert.Contains("Name=\"updateManifestPublicKeyB64\"", package);
        Assert.Contains("Name=\"updateAllowedArtifactPrefixes\"", package);
        Assert.Contains("DesktopAgentShortcutComponent", package);
        Assert.Contains("DesktopFolder", package);
        Assert.Contains("DesktopAgentShortcut", package);
        Assert.Contains("desktopAgentShortcut", package);
        Assert.Contains("Condition=\"CREATE_DESKTOP_SHORTCUT = 1\"", package);
        Assert.Contains("ControlExistingCerberusAgentService", package);
        Assert.Contains("Name=\"CerberusAgent\"", package);
        Assert.Contains("Stop=\"both\"", package);
        Assert.Contains("Wait=\"yes\"", package);
        Assert.Contains("TerminateProcess=\"1\"", package);
        Assert.Contains("Schedule=\"afterInstallExecute\"", package);
        Assert.Contains("<?if $(var.ReleaseChannel) = dev ?>", package);
        Assert.Contains("AllowDowngrades=\"yes\"", package);
        Assert.Contains("<?else ?>", package);
        Assert.Contains("DowngradeErrorMessage=\"A newer version of Cerberus Windows Agent is already installed.\"", package);
        Assert.Contains("override Wix4CloseApplications_X64", package);
        Assert.Contains("After=\"InstallInitialize\"", package);
        Assert.Contains("After=\"RemoveExistingProducts\"", package);
        Assert.Contains("RepairExistingCerberusServicePath", package);
        Assert.Contains("StartExistingCerberusServiceAfterRepair", package);
        Assert.Contains("Cerberus.Agent.Service.exe", package);
        Assert.Contains("[APPFOLDER]Cerberus.Agent.Service.exe", package);
        Assert.Contains("Condition=\"NOT REMOVE AND WIX_UPGRADE_DETECTED\"", package);
        Assert.Contains("sc.exe&quot; config CerberusAgent", package);
        Assert.Contains("sc.exe&quot; start CerberusAgent", package);
        Assert.Contains("RemoveLegacyUserStartupShortcut", package);
        Assert.Contains("Cerberus Agent Tray.lnk", package);
        Assert.Contains("WIXUI_EXITDIALOGOPTIONALCHECKBOX", package);
        Assert.Contains("Dialog=\"ExitDialog\"", package);
        Assert.Contains("Value=\"LaunchAgentUi\"", package);
        Assert.Contains("Condition=\"WIXUI_EXITDIALOGOPTIONALCHECKBOX = 1 AND NOT Installed AND NOT REMOVE\"", package);
        Assert.Contains("StartupShortcutComponent", package);
        Assert.Contains("StartupFolder", package);
        Assert.Contains("trayAutostart", package);
        Assert.Contains("Condition=\"START_TRAY_ON_LOGIN = 1\"", package);
        Assert.Contains("ProductCode", package);
        Assert.DoesNotContain("--accept-eula", package, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("powershell.exe", package, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ExecutionPolicy", package, StringComparison.OrdinalIgnoreCase);

        var releaseScript = File.ReadAllText(Path.Combine(repoRoot, "scripts", "build-agent-public-release.ps1"));
        Assert.Contains("$runtimePublishDir = Join-Path $publishDir \"runtime\"", releaseScript);
        Assert.Contains("-p:PublishSingleFile=false", releaseScript);
        Assert.Contains("-p:DebugSymbols=false", releaseScript);
        Assert.Contains("Cerberus.Agent.exe", releaseScript);
        Assert.Contains("Cerberus.Agent.Service.exe", releaseScript);
        Assert.Contains("Cerberus.Agent.Updater.exe", releaseScript);
        Assert.Contains("Cerberus.Agent.Uninstall.exe", releaseScript);
        Assert.Contains("ui_binary = \"app/Cerberus.Agent.exe\"", releaseScript);
        Assert.Contains("service_binary = \"app/Cerberus.Agent.Service.exe\"", releaseScript);
        Assert.Contains("updater_binary = \"app/Cerberus.Agent.Updater.exe\"", releaseScript);
        Assert.Contains("uninstall_binary = \"app/Cerberus.Agent.Uninstall.exe\"", releaseScript);
        Assert.Contains("Compress-Archive -Path (Join-Path $runtimePublishDir \"*\")", releaseScript);
        Assert.Contains("Copy-ChannelLatestAliases", releaseScript);
        Assert.Contains("Cerberus.Agent.Bundle-$Channel-latest", releaseScript);
        Assert.Contains("Cerberus.Agent-$Channel-latest", releaseScript);
        Assert.DoesNotContain("Cerberus.Agent.Setup.exe", releaseScript);
        Assert.DoesNotContain("Cerberus.Agent.Tray.exe", releaseScript);
        Assert.Contains("-p:UpdateManifestUrl=$UpdateManifestUrl", releaseScript);
        Assert.Contains("-p:AgentUpdateManifestPublicKeysB64=$AgentUpdateManifestPublicKeysB64", releaseScript);
        Assert.Contains("-p:UpdateManifestPublicKeyB64=$UpdateManifestPublicKeyB64", releaseScript);
        Assert.Contains("-p:UpdateAllowedArtifactPrefixes=$UpdateAllowedArtifactPrefixes", releaseScript);
        Assert.Contains("CERBERUS_AGENT_UPDATE_MANIFEST_PUBLIC_KEYS_B64", releaseScript);
        Assert.Contains("GitHub dev releases require stable AGENT_UPDATE_MANIFEST_PRIVATE_KEY_PEM", releaseScript);
        Assert.Single(Regex.Matches(releaseScript, @"IsNullOrWhiteSpace\(\$UpdateAllowedArtifactPrefixes\)").Cast<Match>());

        var updater = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.Updater", "Program.cs"));
        Assert.Contains("CERBERUS_EULA_ACCEPTED=1", updater);
        Assert.Contains("/l*v", updater);
        Assert.Contains("msiexec exit code", updater);
        Assert.Contains("AgentUpdateInstallerResult.FromMsiExitCode", updater);
        Assert.Contains("WriteInstallerResult", updater);
        Assert.Contains("AgentUpdateStateStore.CreateDefault()", updater);

        Assert.True(File.Exists(Path.Combine(repoRoot, "src", "Cerberus.Agent.Installer", "Package.en-us.wxl")));
        Assert.True(File.Exists(Path.Combine(repoRoot, "src", "Cerberus.Agent.Installer", "Package.tr-tr.wxl")));

        var workflow = File.ReadAllText(Path.Combine(repoRoot, ".github", "workflows", "auto-publish-exe.yml"));
        Assert.Contains("./scripts/build-agent-public-release.ps1", workflow);
        Assert.Contains("GITHUB_REPOSITORY", releaseScript);
        Assert.Contains("CERBERUS_AGENT_UPDATE_MANIFEST_URL", releaseScript);
        Assert.Contains("CERBERUS_AGENT_UPDATE_MANIFEST_PUBLIC_KEYS_B64", workflow);
        Assert.Contains("CERBERUS_AGENT_UPDATE_MANIFEST_PUBLIC_KEY_B64", workflow);
        Assert.Contains("CERBERUS_AGENT_UPDATE_ALLOWED_ARTIFACT_PREFIXES", workflow);
        Assert.Contains("$latestAssetBase", workflow);
        Assert.Contains("$latestInstallerBase", workflow);
        Assert.Contains("$latestAssetBase.update-manifest.json", workflow);
        Assert.Contains("$latestInstallerBase.msi", workflow);

        var eulaRtf = File.ReadAllText(Path.Combine(
            repoRoot,
            "src",
            "Cerberus.Agent.Installer",
            "Assets",
            "EULA.rtf"));
        Assert.Contains($"Document version: {AgentLegalConsent.EulaVersion}", eulaRtf);
        Assert.Contains($"Privacy Notice version: {AgentLegalConsent.PrivacyNoticeVersion}", eulaRtf);
        Assert.Contains("secure network connector", eulaRtf);
        Assert.Contains("Cerberus-operated tailnet control plane", eulaRtf);
        Assert.DoesNotContain("Headscale", eulaRtf, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("DERP", eulaRtf, StringComparison.OrdinalIgnoreCase);

        var privacyNotice = File.ReadAllText(Path.Combine(
            repoRoot,
            "docs",
            "legal",
            "PRIVACY-NOTICE.md"));
        Assert.Contains($"Document version: `{AgentLegalConsent.PrivacyNoticeVersion}`", privacyNotice);
        Assert.Contains("optional secure network connector status", privacyNotice);
        Assert.Contains("device identity, connection state, private network addressing", privacyNotice);
        Assert.Contains("connector auth keys", privacyNotice);
        Assert.Contains("THIRD-PARTY-NOTICES.md", privacyNotice);
        Assert.Contains("official Tailscale services", privacyNotice);
        Assert.Contains("organization-managed Tailscale account", privacyNotice);
        Assert.DoesNotContain("Headscale", privacyNotice, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("DERP", privacyNotice, StringComparison.OrdinalIgnoreCase);
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
            "NOT Installed AND NOT WIX_UPGRADE_DETECTED AND NOT REMOVE AND UILevel &lt; 5 AND NOT CERBERUS_EULA_ACCEPTED = 1",
            condition);

        Assert.Contains("WIX_UPGRADE_DETECTED", condition);
        Assert.DoesNotContain("WIXUI_ACCEPT_LICENSE_AGREEMENT", condition);
        Assert.DoesNotContain("LicenseAccepted", condition);
    }

    [Fact]
    public void ThirdPartyNotice_DocumentsSecureNetworkConnectorBoundary()
    {
        var repoRoot = FindRepoRoot();
        var notice = File.ReadAllText(Path.Combine(
            repoRoot,
            "docs",
            "legal",
            "THIRD-PARTY-NOTICES.md"));

        Assert.Contains("does not bundle or redistribute", notice, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("https://pkgs.tailscale.com/stable/tailscale-setup-latest-amd64.msi", notice);
        Assert.Contains("CERBERUS_TAILSCALE_ALLOW_CUSTOM_DOWNLOAD_URL", notice);
        Assert.Contains("valid Authenticode signature", notice);
        Assert.Contains("vendor-neutral labels", notice);
        Assert.Contains("not legal advice", notice, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not installer execution or service acceptance evidence", notice, StringComparison.OrdinalIgnoreCase);
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
