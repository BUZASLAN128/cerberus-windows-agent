using System.Xml.Linq;
using Cerberus.Agent.Observability;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUxStaticTests
{
    [Fact]
    public void MachineBootstrapPrecedesServiceLoggingConsentWritesAndInstallerServiceAccess()
    {
        var repoRoot = FindRepoRoot();
        var service = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "ServiceMode.cs"));
        var consent = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "Legal", "AgentLegalConsent.cs"));
        var helper = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.Installer", "Helper", "Program.cs"));
        const string gate = "AgentUpdateSecurity.EnsureProtectedRoot(AgentUpdateSecurity.DefaultPrivilegedRoot)";
        Assert.True(service.IndexOf(gate, StringComparison.Ordinal) >= 0);
        Assert.True(service.IndexOf(gate, StringComparison.Ordinal) < service.IndexOf("AgentFileLogger.CreateService", StringComparison.Ordinal));
        Assert.True(consent.IndexOf(gate, StringComparison.Ordinal) >= 0);
        Assert.True(consent.IndexOf(gate, StringComparison.Ordinal) < consent.IndexOf("Directory.CreateDirectory", StringComparison.Ordinal));
        var bootstrapStart = helper.IndexOf("if (operation == \"bootstrap\")", StringComparison.Ordinal);
        var serviceOpen = helper.IndexOf("using var manager = OpenSCManager", StringComparison.Ordinal);
        Assert.True(bootstrapStart >= 0 && serviceOpen > bootstrapStart);
        var bootstrap = helper[bootstrapStart..serviceOpen];
        Assert.Contains(gate, bootstrap);
        Assert.Contains("return 0;", bootstrap);
    }

    [Fact]
    public void TrayMenu_KeepsServiceControlsUnderRepairTools()
    {
        var repoRoot = FindRepoRoot();
        var source = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "TrayHost.cs"));

        Assert.Contains("ExportDiagnostics", source);
        Assert.Contains("RepairTools", source);
        Assert.Contains("repair.DropDownItems.Add(startService)", source);
        Assert.Contains("repair.DropDownItems.Add(stopService)", source);
        Assert.DoesNotContain("menu.Items.Add(startService)", source);
        Assert.DoesNotContain("menu.Items.Add(stopService)", source);
    }

    [Fact]
    public void TrayMenu_UsesPersistedUiContextForWorkspaceAndAccount()
    {
        var repoRoot = FindRepoRoot();
        var source = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "TrayHost.cs"));
        var contextStore = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.Core", "AgentUiContextStore.cs"));

        Assert.Contains("AgentUiContextStore.ReadBestEffort()", source);
        Assert.Contains("AgentUiContextStore.DisplayTenant(uiContext)", source);
        Assert.Contains("AgentUiContextStore.DisplayAccount(uiContext)", source);
        Assert.DoesNotContain("_workspaceStatus.Text = $\"{AgentLocalizer.Get(\"Workspace\")}: -\";", source);
        Assert.DoesNotContain("_accountStatus.Text = $\"{AgentLocalizer.Get(\"Account\")}: -\";", source);
        Assert.Contains("ui-context.json", contextStore);
        Assert.Contains("TenantName", contextStore);
    }

    [Fact]
    public void Installer_ExposesSingleCustomerFacingAgentShortcut()
    {
        var repoRoot = FindRepoRoot();
        var wxs = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.Installer", "Package.wxs"));

        Assert.Contains("Id=\"StartMenuAgentShortcut\"", wxs);
        Assert.Contains("Name=\"Cerberus Agent\"", wxs);
        Assert.Contains("Target=\"[APPFOLDER]Cerberus.Agent.exe\"", wxs);
        Assert.Contains("Arguments=\"--open\"", wxs);
        Assert.Contains("WorkingDirectory=\"APPFOLDER\"", wxs);
        Assert.Contains("Id=\"StartMenuUninstallShortcut\"", wxs);
        Assert.Contains("Target=\"[APPFOLDER]Cerberus.Agent.Uninstall.exe\"", wxs);
        Assert.DoesNotContain("StartMenuSetupShortcut", wxs);
        Assert.DoesNotContain("StartMenuTrayShortcut", wxs);
        Assert.DoesNotContain("Name=\"Cerberus Agent Setup\"", wxs);
        Assert.DoesNotContain("Name=\"Cerberus Agent Tray\"", wxs);
    }

    [Fact]
    public void Installer_DesktopAndStartupShortcutsUseUnifiedAgentEntryPoint()
    {
        var repoRoot = FindRepoRoot();
        var wxs = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.Installer", "Package.wxs"));

        Assert.Contains("Id=\"DesktopAgentShortcut\"", wxs);
        Assert.Contains("Name=\"desktopAgentShortcut\"", wxs);
        Assert.Contains("Id=\"StartupShortcut\"", wxs);
        Assert.Contains("Description=\"Start Cerberus Agent at sign-in\"", wxs);
        Assert.Contains("Target=\"[APPFOLDER]Cerberus.Agent.exe\"", wxs);
        Assert.Contains("Arguments=\"--background\"", wxs);
        Assert.Contains("WorkingDirectory=\"APPFOLDER\"", wxs);
        Assert.DoesNotContain("DesktopSetupShortcut", wxs);
        Assert.DoesNotContain("Target=\"[INSTALLFOLDER]Cerberus.Agent.Setup.exe\"", wxs);
        Assert.DoesNotContain("Target=\"[INSTALLFOLDER]Cerberus.Agent.Tray.exe\"", wxs);
        Assert.DoesNotContain("Target=\"[INSTALLFOLDER]Cerberus.Agent.exe\"", wxs);
    }

    [Fact]
    public void Installer_RemovesLegacyStartupShortcutUnconditionally()
    {
        var repoRoot = FindRepoRoot();
        var wxs = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.Installer", "Package.wxs"));
        var document = XDocument.Parse(wxs, LoadOptions.PreserveWhitespace);
        var ns = XNamespace.Get("http://wixtoolset.org/schemas/v4/wxs");
        var installComponent = document.Descendants(ns + "Component")
            .Single(component => (string?)component.Attribute("Id") == "AgentInstallRegistryComponent");
        var legacyCleanup = installComponent.Elements(ns + "RemoveFile")
            .Single(removeFile => (string?)removeFile.Attribute("Id") == "RemoveLegacyStartupShortcut");
        var startupComponent = document.Descendants(ns + "Component")
            .Single(component => (string?)component.Attribute("Id") == "StartupShortcutComponent");

        Assert.Equal("Cerberus Agent Tray.lnk", (string?)legacyCleanup.Attribute("Name"));
        Assert.Equal("StartupFolder", (string?)legacyCleanup.Attribute("Directory"));
        Assert.Equal("install", (string?)legacyCleanup.Attribute("On"));
        Assert.Null(installComponent.Attribute("Condition"));
        Assert.NotSame(installComponent, startupComponent);
        Assert.Equal("START_TRAY_ON_LOGIN = 1", (string?)startupComponent.Attribute("Condition"));
        Assert.Equal("--background", (string?)startupComponent.Element(ns + "Shortcut")?.Attribute("Arguments"));
    }

    [Fact]
    public void LoggerFactories_KeepUserAndServiceOwnershipDistinct()
    {
        var repoRoot = FindRepoRoot();
        var logger = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.Observability", "AgentFileLogger.cs"));

        Assert.Contains("Environment.SpecialFolder.LocalApplicationData", logger);
        Assert.Contains("Environment.SpecialFolder.CommonApplicationData", logger);
        Assert.Contains("Path.Combine(UserLogDirectory, \"agent-ui.log\")", logger);
        Assert.Contains("Path.Combine(ServiceLogDirectory, \"agent.log\")", logger);
        Assert.NotEqual(AgentFileLogger.UserLogDirectory, AgentFileLogger.ServiceLogDirectory);
    }

    [Fact]
    public void AppEntrypoints_MapInteractiveLoggingToUserAndServiceModeToService()
    {
        var repoRoot = FindRepoRoot();
        var appRoot = Path.Combine(repoRoot, "src", "Cerberus.Agent.App");
        var userEntrypoints = new[]
        {
            "ExportTailscaleUpMode.cs",
            "HeartbeatOnceMode.cs",
            "MainWindow.xaml.cs",
            "RegisterMode.cs",
            "SelfTestMode.cs",
            "SetupMode.cs",
        };

        foreach (var file in userEntrypoints)
        {
            var source = File.ReadAllText(Path.Combine(appRoot, file));
            Assert.Contains("AgentFileLogger.CreateUser", source);
            Assert.DoesNotContain("AgentFileLogger.CreateDefault", source);
        }

        var serviceMode = File.ReadAllText(Path.Combine(appRoot, "ServiceMode.cs"));
        Assert.Contains("AgentFileLogger.CreateService", serviceMode);
        Assert.DoesNotContain("AgentFileLogger.CreateDefault", serviceMode);
    }

    [Fact]
    public void UnifiedAgent_SupportsCustomerOpenSignalsWithoutLaunchingSiblingSetup()
    {
        var repoRoot = FindRepoRoot();
        var program = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "Program.cs"));
        var args = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "Args.cs"));
        var source = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "TrayHost.cs"));
        var normalized = source.Replace("\r\n", "\n");

        Assert.Contains("AgentUiSignals.Open", program);
        Assert.Contains("AgentUiSignals.Connect", program);
        Assert.Contains("Has(\"--open\")", args);
        Assert.Contains("Has(\"--connect\")", args);
        Assert.Contains("case AgentUiSignals.Open:", source);
        Assert.Contains("case AgentUiSignals.Connect:", source);
        Assert.Contains("case AgentUiSignals.Open:\n                    RequestHeartbeatBackoffReset(\"tray_open_signal\");\n                    ShowWindow(centerOnScreen: true);", normalized);
        Assert.Contains("case AgentUiSignals.Connect:\n                    RequestHeartbeatBackoffReset(\"tray_connect_signal\");\n                    ShowWindow(centerOnScreen: true);", normalized);
        Assert.Contains("ShowWindow(centerOnScreen: false)", source);
        Assert.Contains("ShowWindow(centerOnScreen: true)", source);
        Assert.Contains("using var tray = new TrayHost()", program);
        Assert.Contains("ShutdownMode.OnExplicitShutdown", program);
        Assert.DoesNotContain("LaunchSibling", source);
        Assert.DoesNotContain("MouseButtons.Left)\n                LaunchSibling(\"Cerberus.Agent.Setup.exe\")", normalized);
    }

    [Fact]
    public void UiSignals_AllowlistRejectsPrivilegedOrArbitraryPipePayloads()
    {
        Assert.True(Cerberus.Agent.App.AgentUiSignals.TryNormalize(" OPEN ", out var open));
        Assert.Equal(Cerberus.Agent.App.AgentUiSignals.Open, open);
        Assert.True(Cerberus.Agent.App.AgentUiSignals.TryNormalize("connect", out var connect));
        Assert.Equal(Cerberus.Agent.App.AgentUiSignals.Connect, connect);
        Assert.True(Cerberus.Agent.App.AgentUiSignals.TryNormalize("check-updates", out var checkUpdates));
        Assert.Equal(Cerberus.Agent.App.AgentUiSignals.CheckUpdates, checkUpdates);
        Assert.True(Cerberus.Agent.App.AgentUiSignals.TryNormalize("update-now", out var updateNow));
        Assert.Equal(Cerberus.Agent.App.AgentUiSignals.UpdateNow, updateNow);

        var denied = new[]
        {
            "",
            "start-service",
            "stop-service",
            "install-service",
            "uninstall-service",
            "enable-local-user-create",
            "disable-local-user-create",
            "--apply-update-plan=C:\\temp\\plan.json",
            "powershell -enc test",
            "ad.user.create",
        };

        foreach (var signal in denied)
        {
            Assert.False(Cerberus.Agent.App.AgentUiSignals.TryNormalize(signal, out _));
        }
    }

    [Fact]
    public void ServiceMutationEntrypointsRemainAdminGated()
    {
        var repoRoot = FindRepoRoot();
        var source = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "ServiceInstaller.cs"));
        var normalized = source.Replace("\r\n", "\n");

        Assert.Contains("public static void InstallOrThrow()\n    {\n        RequireAdminOrThrow();", normalized);
        Assert.Contains("public static void UninstallOrThrow()\n    {\n        RequireAdminOrThrow();", normalized);
        Assert.Contains("public static void StartOrThrow()\n    {\n        RequireAdminOrThrow();", normalized);
        Assert.Contains("public static void StopOrThrow()\n    {\n        RequireAdminOrThrow();", normalized);
    }

    [Fact]
    public void ServiceMode_RegistersScopedAdWithProtectedPolicyAndFreshAuthority()
    {
        var repoRoot = FindRepoRoot();
        var serviceMode = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "ServiceMode.cs"));

        Assert.DoesNotContain("AdUserCommandHandlers.CreateDefaultHandlers", serviceMode);
        Assert.Contains("LocalUserCommandHandlers.CreateDefaultHandlers(manifest: managedAccounts)", serviceMode);
        Assert.Contains("new ProtectedAdScopePolicy()", serviceMode);
        Assert.Contains("new WindowsAdDirectoryBoundary(), new ProtectedAdOwnershipStore()", serviceMode);
        Assert.Contains("ScopedAdCommandHandlers.CreateDefaultHandlers(loadedSecrets.Identity, lifecycleState,", serviceMode);
        Assert.Contains("api.GetAdCommandAuthorityAsync, adUsers", serviceMode);
    }

    [Fact]
    public void Tray_UpdateRequestsUseServiceIpcWithoutNetworkOrProtectedStateWrites()
    {
        var repoRoot = FindRepoRoot();
        var source = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "TrayHost.cs"));
        var english = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "Localization", "AgentStrings.resx"));
        var turkish = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "Localization", "AgentStrings.tr-TR.resx"));

        Assert.Contains("UpdateCheckFailedDetail", source);
        Assert.Contains("AgentLocalControlClient.SendAsync", source);
        Assert.DoesNotContain("CreateUpdateHttpClient", source);
        Assert.DoesNotContain("BuildConfiguredManualSignal", source);
        Assert.DoesNotContain("AgentUpdateStateStore", source);
        Assert.Contains("ConfirmApplyCheckedUpdate()", source);
        Assert.Contains("MessageBoxButtons.YesNo", source);
        Assert.Contains("UpdateNotConfiguredDetail", english);
        Assert.Contains("UpdateNotConfiguredDetail", turkish);
        Assert.Contains("UpdateNotFoundDetail", english);
        Assert.Contains("UpdateNotFoundDetail", turkish);
        Assert.Contains("UpdateFoundPrompt", english);
        Assert.Contains("UpdateFoundPrompt", turkish);
        Assert.DoesNotContain("SendUpdateCheckHeartbeatAsync", source);
        Assert.DoesNotContain("LoadUpdateSecretsAsync", source);
        Assert.DoesNotContain("Agent registration is not available for update checks", source);
        Assert.DoesNotContain("UpdateCheckFailedDetail\", AgentDiagnosticsBundle.Redact(ex.Message)", source);
    }

    [Fact]
    public void TrayIcon_AnimatesDuringVisibleWorkAndReturnsToIdle()
    {
        var repoRoot = FindRepoRoot();
        var trayHost = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "TrayHost.cs"));
        var animator = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "TrayIconAnimator.cs"));

        Assert.Contains("private readonly TrayIconAnimator _trayIconAnimator", trayHost);
        Assert.Contains("_trayIconAnimator = new TrayIconAnimator(_icon)", trayHost);
        Assert.Contains("BeginTrayActivity();", trayHost);
        Assert.Contains("EndTrayActivity();", trayHost);
        Assert.Contains("_trayIconAnimator.Start();", trayHost);
        Assert.Contains("_trayIconAnimator.Stop();", trayHost);
        Assert.Contains("_trayIconAnimator.Dispose();", trayHost);
        Assert.Contains("private async Task ExportDiagnosticsAsync()", trayHost);
        Assert.DoesNotContain("private static async Task ExportDiagnosticsAsync()", trayHost);

        Assert.Contains("DispatcherTimer", animator);
        Assert.Contains("FrameCount = 24", animator);
        Assert.Contains("Interval = TimeSpan.FromMilliseconds(80)", animator);
        Assert.Contains("MinimumVisibleDuration = TimeSpan.FromMilliseconds(4000)", animator);
        Assert.Contains("ScheduleStop(remaining)", animator);
        Assert.Contains("CancelPendingStop();", animator);
        Assert.Contains("DrawRotatedLogo(graphics, sourceBitmap, i)", animator);
        Assert.Contains("graphics.RotateTransform(angle)", animator);
        Assert.Contains("graphics.DrawImage(sourceBitmap, target)", animator);
        Assert.Contains("SmoothingMode.AntiAlias", animator);
        Assert.Contains("HighQualityBicubic", animator);
        Assert.Contains("DestroyIcon(handle)", animator);
        Assert.Contains("_notifyIcon.Icon = _idleIcon", animator);
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
        Assert.Contains(@"Updates\**\*.cs", runtimeProject);
        Assert.Contains("AgentUpdateDefaults.ManifestPublicKeysB64", trustFactory);
        Assert.Contains("AgentUpdateDefaults.ManifestUrl", trustFactory);
        Assert.Contains("AgentUpdateDefaults.AllowedArtifactPrefixes", trustFactory);
        Assert.Contains("AllowChannelDowngrade: false", trustFactory);
        Assert.Contains("RequireManifestV2: true", trustFactory);
    }

    [Fact]
    public void ReleaseBuild_IncludesManifestSigningPublicKeyInRuntimeAndInstallerTrust()
    {
        var repoRoot = FindRepoRoot();
        var releaseScript = File.ReadAllText(Path.Combine(repoRoot, "scripts", "build-agent-public-release.ps1"));

        Assert.Contains("Get-ManifestPublicKeyPem $manifestPrivateKey", releaseScript);
        Assert.Contains("$UpdateManifestPublicKeyB64 = $manifestPublicKeyB64", releaseScript);
        Assert.Contains("$AgentUpdateManifestPublicKeysB64 = $manifestPublicKeyB64", releaseScript);
        Assert.Contains("-p:AgentUpdateManifestPublicKeysB64=$AgentUpdateManifestPublicKeysB64", releaseScript);
        Assert.Contains("-p:UpdateManifestPublicKeyB64=$UpdateManifestPublicKeyB64", releaseScript);
    }

    [Fact]
    public void HeadlessUpdateCommand_UsesServiceAuthorityAndConcreteConsentOnly()
    {
        var repoRoot = FindRepoRoot();
        var updateCommand = File.ReadAllText(Path.Combine(
            repoRoot,
            "src",
            "Cerberus.Agent.App",
            "Updates",
            "UpdateCommandMode.cs"));

        Assert.Contains("AgentLocalControlClient.SendAsync", updateCommand);
        Assert.Contains("status.AttemptId", updateCommand);
        Assert.DoesNotContain("ReconcileInstallerResultAsync", updateCommand);
        Assert.DoesNotContain("BuildConfiguredManualSignal", updateCommand);
    }

    [Fact]
    public void WindowsDeviceInfo_ReportsSemverInformationalVersionInsteadOfFourPartAssemblyVersion()
    {
        var repoRoot = FindRepoRoot();
        var deviceInfo = File.ReadAllText(Path.Combine(
            repoRoot,
            "src",
            "Cerberus.Agent.App",
            "WindowsDeviceInfo.cs"));

        Assert.Contains("AssemblyInformationalVersionAttribute", deviceInfo);
        Assert.Contains("info.Split('+', 2, StringSplitOptions.TrimEntries)[0].Trim()", deviceInfo);
        Assert.True(
            deviceInfo.IndexOf("GetInformationalVersion()", StringComparison.Ordinal) <
            deviceInfo.IndexOf("GetName().Version", StringComparison.Ordinal));
    }

    [Fact]
    public void SetupHelper_UsesUnifiedAgentTitleAndFinishReadyState()
    {
        var repoRoot = FindRepoRoot();
        var xaml = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "MainWindow.xaml"));
        var code = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "MainWindow.xaml.cs"));
        var project = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "Cerberus.Agent.App.csproj"));
        var installer = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.Installer", "Package.wxs"));
        var strings = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "Localization", "AgentStrings.resx"));

        Assert.Contains("Title=\"Cerberus Agent\"", xaml);
        Assert.Contains("<value>Cerberus Agent</value>", strings);
        Assert.Contains("cerberus-logo.png", project);
        Assert.Contains("cerberus-favicon.ico", project);
        Assert.Contains("cerberus-favicon.ico", installer);
        Assert.Contains("pack://application:,,,/Assets/cerberus-logo.png", xaml);
        Assert.DoesNotContain("cerberus-app-mark", project);
        Assert.DoesNotContain("cerberus-app-mark", installer);
        Assert.DoesNotContain("cerberus-app-mark", xaml);
        Assert.Contains("SystemInfoLabel", xaml);
        Assert.Contains("DeviceSetupCard.Visibility = setupComplete ? Visibility.Collapsed : Visibility.Visible", code);
        Assert.Contains("BuildStatusReport(registered, svc, ts)", code);
        Assert.Contains("ReadinessValue.Text = AgentLocalizer.Get(\"StatusReport\")", code);
        Assert.Contains("AgentLocalizer.Get(\"StatusReportDetail\")", code);
        Assert.Contains("ReportServiceStoppedTitle", strings);
        Assert.Contains("ReportNetworkIssueTitle", strings);
        Assert.Contains("FormatServiceStatus(svc.Text)", code);
        Assert.Contains("FormatConnectorStatus(ts.Text)", code);
        Assert.Contains("Hide();", code);
        Assert.DoesNotContain("UniformGrid Columns=\"4\"", xaml);
        Assert.DoesNotContain("CERBERUS Agent Setup", xaml);
        Assert.DoesNotContain("CERBERUS Agent Setup", strings);
    }

    [Fact]
    public void SetupHelper_AnchorsWindowNearNotificationArea()
    {
        var repoRoot = FindRepoRoot();
        var window = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "MainWindow.xaml.cs"));
        var program = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "Program.cs"));
        var trayHost = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "TrayHost.cs"));

        Assert.Contains("PositionNearNotificationArea", window);
        Assert.Contains("Screen.PrimaryScreen", window);
        Assert.Contains("Screen.FromPoint", window);
        Assert.Contains("Cursor.Position", window);
        Assert.Contains("WorkingArea", window);
        Assert.Contains("TransformToDevice", window);
        Assert.Contains("TransformFromDevice", window);
        Assert.Contains("Left = originDip.X", window);
        Assert.Contains("Top = originDip.Y", window);
        Assert.Contains("using var tray = new TrayHost()", program);
        Assert.Contains("PositionFlyout", trayHost);
    }

    [Fact]
    public void AppProject_IsUnifiedTrayAndControlCenterRuntime()
    {
        var repoRoot = FindRepoRoot();
        var program = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "Program.cs"));
        var args = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "Args.cs"));
        var project = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.App", "Cerberus.Agent.App.csproj"));

        Assert.Contains("using var tray = new TrayHost()", program);
        Assert.DoesNotContain("SingleInstanceGuard", program);
        Assert.DoesNotContain("args.Tray", program);
        Assert.DoesNotContain("bool Tray", args);
        Assert.DoesNotContain("--tray", args);
        Assert.DoesNotContain("<Compile Remove=\"TrayHost.cs\" />", project);
        Assert.Contains("<Compile Remove=\"SingleInstanceGuard.cs\" />", project);
        Assert.Contains("<AssemblyName>Cerberus.Agent</AssemblyName>", project);
    }

    [Fact]
    public void UnifiedAgent_IsOnlyCustomerUiProjectInBuildAndReleaseSurfaces()
    {
        var repoRoot = FindRepoRoot();
        var solution = File.ReadAllText(Path.Combine(repoRoot, "Cerberus.WindowsAgent.slnx"));
        var releaseScript = File.ReadAllText(Path.Combine(repoRoot, "scripts", "build-agent-public-release.ps1"));
        var workflow = File.ReadAllText(Path.Combine(repoRoot, ".github", "workflows", "auto-publish-exe.yml"));

        Assert.Contains("src/Cerberus.Agent.App/Cerberus.Agent.App.csproj", solution);
        Assert.DoesNotContain("src/Cerberus.Agent.Tray/Cerberus.Agent.Tray.csproj", solution);
        Assert.Contains("Publish-AgentProject \"src/Cerberus.Agent.App/Cerberus.Agent.App.csproj\" $true", releaseScript);
        Assert.DoesNotContain("Publish-AgentProject \"src/Cerberus.Agent.Tray/Cerberus.Agent.Tray.csproj\"", releaseScript);
        Assert.Contains("Cerberus.Agent.exe", releaseScript);
        Assert.Contains("ui_binary = \"app/Cerberus.Agent.exe\"", releaseScript);
        Assert.DoesNotContain("Cerberus.Agent.Tray.exe", releaseScript);
        Assert.DoesNotContain("Cerberus.Agent.Setup.exe", releaseScript);
        Assert.Contains("$allowedRuntimeExeNames", releaseScript);
        Assert.Contains("createdump.exe", releaseScript);
        Assert.Contains("Unexpected runtime executable(s) produced", releaseScript);
        Assert.Contains("Cerberus.Agent-$channel-$cleanVersion", workflow);
        Assert.DoesNotContain("Cerberus.Agent.Setup-$channel-$cleanVersion", workflow);
    }

    [Fact]
    public void Installer_CloseApplicationsTerminatesUiWithoutPromptToContinueDialog()
    {
        var repoRoot = FindRepoRoot();
        var wxs = File.ReadAllText(Path.Combine(repoRoot, "src", "Cerberus.Agent.Installer", "Package.wxs"));

        Assert.Contains("CloseRunningAgentUi", wxs);
        Assert.Contains("Target=\"Cerberus.Agent.exe\"", wxs);
        Assert.Contains("TerminateProcess=\"1\"", wxs);
        Assert.Contains("RebootPrompt=\"no\"", wxs);
        Assert.DoesNotContain("PromptToContinue", wxs);
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

        Assert.Contains("Cerberus.Agent.exe", readme);
        Assert.Contains("app/Cerberus.Agent.exe", readme);
        Assert.Contains("app\\Cerberus.Agent.exe --open", readme);
        Assert.Contains("Cerberus.Agent.Service.exe", readme);
        Assert.Contains("Program Files\\Cerberus\\Windows Agent", readme);
        Assert.Contains("CREATE_DESKTOP_SHORTCUT", readme);
        Assert.Contains("Cerberus.Agent-<channel>-<version>.msi", readme);
        Assert.DoesNotContain("Cerberus.Agent.Setup.exe", readme);
        Assert.DoesNotContain("Cerberus.Agent.Tray.exe", readme);
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
    public void Updater_DoesNotKillUserProcessesOrCreateUserSessions()
    {
        var repoRoot = FindRepoRoot();
        var updater = File.ReadAllText(Path.Combine(
            repoRoot,
            "src",
            "Cerberus.Agent.Updater",
            "Program.cs"));

        Assert.DoesNotContain("CloseAgentUiApplications", updater);
        Assert.DoesNotContain("process.Kill", updater);
        Assert.DoesNotContain("WTSQueryUserToken", updater);
        Assert.Contains("AgentUpdateRunnerFiles.Validate", updater);
    }

    [Fact]
    public void Updater_RecordsEvidenceButServiceOwnsInstalledHealthProjection()
    {
        var repoRoot = FindRepoRoot();
        var updater = File.ReadAllText(Path.Combine(
            repoRoot,
            "src",
            "Cerberus.Agent.Updater",
            "Program.cs"));

        Assert.DoesNotContain("WriteCurrentStateFromPlan", updater);
        Assert.DoesNotContain("WriteTransitionAsync", updater);
        Assert.Contains("InstallerResult = installerResult", updater);
        Assert.Contains("Phase = installerResult.State", updater);
    }

    [Fact]
    public void UpdaterAndUninstaller_RequestAdministratorBeforeRunningMsiOperations()
    {
        var repoRoot = FindRepoRoot();
        var updaterProject = File.ReadAllText(Path.Combine(
            repoRoot,
            "src",
            "Cerberus.Agent.Updater",
            "Cerberus.Agent.Updater.csproj"));
        var updaterManifest = File.ReadAllText(Path.Combine(
            repoRoot,
            "src",
            "Cerberus.Agent.Updater",
            "app.manifest"));
        var uninstallProject = File.ReadAllText(Path.Combine(
            repoRoot,
            "src",
            "Cerberus.Agent.Uninstall",
            "Cerberus.Agent.Uninstall.csproj"));
        var uninstallManifest = File.ReadAllText(Path.Combine(
            repoRoot,
            "src",
            "Cerberus.Agent.Uninstall",
            "app.manifest"));

        Assert.Contains("<ApplicationManifest>app.manifest</ApplicationManifest>", updaterProject);
        Assert.Contains("<ApplicationManifest>app.manifest</ApplicationManifest>", uninstallProject);
        Assert.Contains("requestedExecutionLevel level=\"requireAdministrator\"", updaterManifest);
        Assert.Contains("requestedExecutionLevel level=\"requireAdministrator\"", uninstallManifest);
    }

    [Fact]
    public void Updater_IsWindowsExecutableAndTrayDelegatesApplyToServiceFirst()
    {
        var repoRoot = FindRepoRoot();
        var updaterProject = File.ReadAllText(Path.Combine(
            repoRoot,
            "src",
            "Cerberus.Agent.Updater",
            "Cerberus.Agent.Updater.csproj"));
        var serviceHost = File.ReadAllText(Path.Combine(
            repoRoot,
            "src",
            "Cerberus.Agent.App",
            "WindowsServiceHost.cs"));
        var trayHost = File.ReadAllText(Path.Combine(
            repoRoot,
            "src",
            "Cerberus.Agent.App",
            "TrayHost.cs"));
        var coordinator = File.ReadAllText(Path.Combine(
            repoRoot,
            "src",
            "Cerberus.Agent.App",
            "Updates",
            "AgentUpdateCoordinator.cs"));

        Assert.Contains("<OutputType>WinExe</OutputType>", updaterProject);
        Assert.Contains("AgentLocalControlClient.SendAsync", trayHost);
        Assert.Contains("new AgentLocalControlRequest(\"apply\", displayed.AttemptId)", trayHost);
        Assert.DoesNotContain("controller.ExecuteCommand", trayHost);
        Assert.DoesNotContain("Verb = \"runas\"", trayHost);
        Assert.Contains("AgentUpdateLocalService", coordinator);
        Assert.DoesNotContain("await StageUpdateAsync(response, campaignId: null, commandId: null, ct)", coordinator);
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
