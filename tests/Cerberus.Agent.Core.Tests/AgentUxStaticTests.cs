namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUxStaticTests
{
    [Fact]
    public void TrayMenu_KeepsServiceControlsUnderRepairTools()
    {
        var repoRoot = FindRepoRoot();
        var source = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.Tray", "Program.cs"));

        Assert.Contains("ExportDiagnostics", source);
        Assert.Contains("RepairTools", source);
        Assert.Contains("repair.DropDownItems.Add(startService)", source);
        Assert.Contains("repair.DropDownItems.Add(stopService)", source);
        Assert.DoesNotContain("menu.Items.Add(startService)", source);
        Assert.DoesNotContain("menu.Items.Add(stopService)", source);
    }

    [Fact]
    public void Installer_ExposesSingleCustomerFacingAgentShortcut()
    {
        var repoRoot = FindRepoRoot();
        var wxs = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.Installer", "Package.wxs"));

        Assert.Contains("Id=\"StartMenuAgentShortcut\"", wxs);
        Assert.Contains("Name=\"Cerberus Agent\"", wxs);
        Assert.Contains("Target=\"[INSTALLFOLDER]Cerberus.Agent.Tray.exe\"", wxs);
        Assert.Contains("Arguments=\"--open\"", wxs);
        Assert.Contains("Id=\"StartMenuUninstallShortcut\"", wxs);
        Assert.DoesNotContain("StartMenuSetupShortcut", wxs);
        Assert.DoesNotContain("StartMenuTrayShortcut", wxs);
        Assert.DoesNotContain("Name=\"Cerberus Agent Setup\"", wxs);
        Assert.DoesNotContain("Name=\"Cerberus Agent Tray\"", wxs);
    }

    [Fact]
    public void Installer_DesktopAndStartupShortcutsUseTrayEntryPoint()
    {
        var repoRoot = FindRepoRoot();
        var wxs = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.Installer", "Package.wxs"));

        Assert.Contains("Id=\"DesktopAgentShortcut\"", wxs);
        Assert.Contains("Name=\"desktopAgentShortcut\"", wxs);
        Assert.Contains("Id=\"StartupShortcut\"", wxs);
        Assert.Contains("Description=\"Start Cerberus Agent at sign-in\"", wxs);
        Assert.DoesNotContain("DesktopSetupShortcut", wxs);
        Assert.DoesNotContain("Target=\"[INSTALLFOLDER]Cerberus.Agent.Setup.exe\"", wxs);
    }

    [Fact]
    public void Tray_SupportsCustomerOpenSignalsWithoutOpeningSetupWhenReady()
    {
        var repoRoot = FindRepoRoot();
        var source = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.Tray", "Program.cs"));
        var normalized = source.Replace("\r\n", "\n");

        Assert.Contains("private const string OpenSignal = \"open\"", source);
        Assert.Contains("private const string ConnectSignal = \"connect\"", source);
        Assert.Contains("Has(\"--open\")", source);
        Assert.Contains("Has(\"--connect\")", source);
        Assert.Contains("case \"open\":", source);
        Assert.Contains("case \"connect\":", source);
        Assert.Contains("OpenAgentAsync", source);
        Assert.Contains("AgentStatus.IsSetupComplete", source);
        Assert.Contains("ShowBalloonTip", source);
        Assert.Contains("LaunchSibling(\"Cerberus.Agent.Setup.exe\")", source);
        Assert.DoesNotContain("MouseButtons.Left)\n                LaunchSibling(\"Cerberus.Agent.Setup.exe\")", normalized);
    }

    [Fact]
    public void Tray_UpdateCheckUsesPublicManifestWithoutAgentRegistration()
    {
        var repoRoot = FindRepoRoot();
        var source = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.Tray", "Program.cs"));
        var english = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "Localization", "AgentStrings.resx"));
        var turkish = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "Localization", "AgentStrings.tr-TR.resx"));

        Assert.Contains("GetUpdateCheckFailureDetail()", source);
        Assert.Contains("BuildConfiguredManualSignal()", source);
        Assert.Contains("CreateUpdateHttpClient()", source);
        Assert.Contains("AgentUpdateSignal?", source);
        Assert.Contains("UpdateNotConfiguredDetail", english);
        Assert.Contains("UpdateNotConfiguredDetail", turkish);
        Assert.DoesNotContain("SendUpdateCheckHeartbeatAsync", source);
        Assert.DoesNotContain("LoadUpdateSecretsAsync", source);
        Assert.DoesNotContain("Agent registration is not available for update checks", source);
        Assert.DoesNotContain("UpdateCheckFailedDetail\", AgentDiagnosticsBundle.Redact(ex.Message)", source);
    }

    [Fact]
    public void UpdateRuntime_EmbedsPublicManifestTrustDefaults()
    {
        var repoRoot = FindRepoRoot();
        var appProject = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "Cerberus.Agent.App.csproj"));
        var runtimeProject = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.Runtime", "Cerberus.Agent.Runtime.csproj"));
        var trustFactory = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "Updates", "AgentUpdateTrustFactory.cs"));

        Assert.Contains("AgentUpdateManifestPublicKeysB64", appProject);
        Assert.Contains("AgentUpdateManifestUrl", appProject);
        Assert.Contains("AgentUpdateAllowedArtifactPrefixes", appProject);
        Assert.Contains("AgentUpdateManifestPublicKeysB64", runtimeProject);
        Assert.Contains("AgentUpdateManifestUrl", runtimeProject);
        Assert.Contains("AgentUpdateAllowedArtifactPrefixes", runtimeProject);
        Assert.Contains(@"Updates\AgentUpdateDefaults.cs", runtimeProject);
        Assert.Contains("AgentUpdateDefaults.ManifestPublicKeysB64", trustFactory);
        Assert.Contains("AgentUpdateDefaults.ManifestUrl", trustFactory);
        Assert.Contains("AgentUpdateDefaults.AllowedArtifactPrefixes", trustFactory);
    }

    [Fact]
    public void SetupHelper_UsesUnifiedAgentTitleAndFinishReadyState()
    {
        var repoRoot = FindRepoRoot();
        var xaml = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "MainWindow.xaml"));
        var code = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "MainWindow.xaml.cs"));
        var strings = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "Localization", "AgentStrings.resx"));

        Assert.Contains("Title=\"Cerberus Agent\"", xaml);
        Assert.Contains("<value>Cerberus Agent</value>", strings);
        Assert.Contains("AgentLocalizer.Get(\"Finish\")", code);
        Assert.Contains("Close();", code);
        Assert.DoesNotContain("CERBERUS Agent Setup", xaml);
        Assert.DoesNotContain("CERBERUS Agent Setup", strings);
    }

    [Fact]
    public void SetupHelper_AnchorsWindowNearNotificationArea()
    {
        var repoRoot = FindRepoRoot();
        var window = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "MainWindow.xaml.cs"));
        var program = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "Program.cs"));

        Assert.Contains("PositionNearNotificationArea", window);
        Assert.Contains("Screen.PrimaryScreen", window);
        Assert.Contains("Screen.FromPoint", window);
        Assert.Contains("Cursor.Position", window);
        Assert.Contains("WorkingArea", window);
        Assert.Contains("TransformToDevice", window);
        Assert.Contains("TransformFromDevice", window);
        Assert.Contains("Left = originDip.X", window);
        Assert.Contains("Top = originDip.Y", window);
        Assert.Contains("window.PositionNearNotificationArea()", program);
    }

    [Fact]
    public void AppProject_DoesNotKeepLegacyInProcessTrayRuntime()
    {
        var repoRoot = FindRepoRoot();
        var program = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "Program.cs"));
        var args = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "Args.cs"));
        var project = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "Cerberus.Agent.App.csproj"));

        Assert.DoesNotContain("using var tray = new TrayHost()", program);
        Assert.DoesNotContain("SingleInstanceGuard", program);
        Assert.DoesNotContain("args.Tray", program);
        Assert.DoesNotContain("bool Tray", args);
        Assert.DoesNotContain("--tray", args);
        Assert.Contains("<Compile Remove=\"TrayHost.cs\" />", project);
        Assert.Contains("<Compile Remove=\"SingleInstanceGuard.cs\" />", project);
    }

    [Fact]
    public void AcceptanceScriptsUseSetupExecutableInsteadOfLegacyAppExecutable()
    {
        var repoRoot = FindRepoRoot();
        var scriptsRoot = Path.Combine(repoRoot, "scripts");
        foreach (var script in Directory.EnumerateFiles(scriptsRoot, "*.ps1"))
        {
            var text = File.ReadAllText(script);
            Assert.DoesNotContain("Cerberus.Agent.App.exe", text);
        }
    }

    [Fact]
    public void Readme_DocumentsSplitRuntimeInsteadOfLegacySingleExeFlow()
    {
        var repoRoot = FindRepoRoot();
        var readme = File.ReadAllText(Path.Combine(repoRoot, "README.md"));

        Assert.Contains("Cerberus.Agent.Setup.exe", readme);
        Assert.Contains("Cerberus.Agent.Tray.exe", readme);
        Assert.Contains("Cerberus.Agent.Service.exe", readme);
        Assert.Contains("Program Files\\Cerberus\\Windows Agent", readme);
        Assert.Contains("CREATE_DESKTOP_SHORTCUT", readme);
        Assert.DoesNotContain("Single Windows executable", readme);
        Assert.DoesNotContain("per-user install", readme);
        Assert.DoesNotContain("Cerberus.Agent.App.exe --tray", readme);
        Assert.DoesNotContain("bootstrap/descriptor", readme);
        Assert.DoesNotContain("bootstrap/enroll", readme);
    }

    [Fact]
    public void UpdateRuntime_DoesNotRegisterOrGenerateAgentCredentials()
    {
        var repoRoot = FindRepoRoot();
        var coordinator = File.ReadAllText(Path.Combine(
            repoRoot,
            "src",
            "Cerberus.Agent.App",
            "Updates",
            "AgentUpdateCoordinator.cs"));
        var updater = File.ReadAllText(Path.Combine(
            repoRoot,
            "src",
            "Cerberus.Agent.Updater",
            "Program.cs"));
        var updateRuntime = coordinator + Environment.NewLine + updater;

        Assert.DoesNotContain("AgentRegistrar", updateRuntime);
        Assert.DoesNotContain("RegisterAsync", updateRuntime);
        Assert.DoesNotContain("DpapiSecretStore", updateRuntime);
        Assert.DoesNotContain("ISecretStore", updateRuntime);
        Assert.DoesNotContain("GenerateKeyPair", updateRuntime);
        Assert.DoesNotContain("oauth", updateRuntime, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("agent_refresh_token", updateRuntime, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Updater_RestartsTrayInOriginalUserSessionAfterMsiUpdate()
    {
        var repoRoot = FindRepoRoot();
        var updater = File.ReadAllText(Path.Combine(
            repoRoot,
            "src",
            "Cerberus.Agent.Updater",
            "Program.cs"));

        Assert.Contains("closedApplications = CloseTrayAndSetup()", updater);
        Assert.Contains("TryRestartTray(closedApplications, log)", updater);
        Assert.Contains("WTSQueryUserToken", updater);
        Assert.Contains("CreateProcessAsUser", updater);
        Assert.Contains(@"winsta0\default", updater);
        Assert.Contains("CloseHandle(processInfo.hProcess)", updater);
        Assert.Contains("Cerberus.Agent.Tray.exe", updater);
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "src", "Cerberus.Agent.App")) &&
                Directory.Exists(Path.Combine(dir.FullName, "tests", "Cerberus.Agent.Core.Tests")))
            {
                return dir.FullName;
            }

            dir = dir.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate cerberus-windows-agent repository root.");
    }
}
