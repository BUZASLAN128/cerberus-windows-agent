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
