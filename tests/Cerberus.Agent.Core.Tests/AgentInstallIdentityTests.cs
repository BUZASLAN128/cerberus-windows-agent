using System.Text.RegularExpressions;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentInstallIdentityTests
{
    private static readonly (string Name, string Desktop, string Actual)[] Values =
    [
        ("ServiceName", "CerberusAgent", AgentInstallIdentity.ServiceName),
        ("ServiceDisplayName", "CERBERUS Windows Agent", AgentInstallIdentity.ServiceDisplayName),
        ("DataDirName", "CerberusAgent", AgentInstallIdentity.DataDirName),
        ("RegistryPath", @"Software\Cerberus\WindowsAgent", AgentInstallIdentity.RegistryPath),
        ("LegalConsentRegistryPath", @"Software\Cerberus\WindowsAgent\LegalConsent", AgentInstallIdentity.LegalConsentRegistryPath),
        ("ControlPipeName", "CerberusAgent.Control.v1", AgentInstallIdentity.ControlPipeName),
        ("UiMutexName", @"Global\CerberusAgent.Ui.SingleInstance", AgentInstallIdentity.UiMutexName),
        ("UiPipeName", "CerberusAgent.Ui.SingleInstancePipe", AgentInstallIdentity.UiPipeName),
        ("TrayMutexName", @"Global\CerberusAgent.Tray.SingleInstance", AgentInstallIdentity.TrayMutexName),
        ("TrayPipeName", "CerberusAgent.Tray.SingleInstancePipe", AgentInstallIdentity.TrayPipeName),
    ];

#if !CERBERUS_SERVER_PROFILE
    [Fact]
    public void DesktopValuesEqualHistoricalLiterals()
    {
        foreach (var (name, desktop, actual) in Values)
            Assert.True(desktop == actual, $"{name}: expected '{desktop}' but was '{actual}'");
    }
#else
    [Fact]
    public void ServerValuesDifferFromDesktop()
    {
        foreach (var (name, desktop, actual) in Values)
            Assert.False(string.Equals(desktop, actual, StringComparison.OrdinalIgnoreCase), $"{name} equals the desktop value '{desktop}'");
    }

    [Fact]
    public void ServerValuesMatchContractTable()
    {
        Assert.Equal("CerberusServerAgent", AgentInstallIdentity.ServiceName);
        Assert.Equal("Cerberus Server Agent", AgentInstallIdentity.ServiceDisplayName);
        Assert.Equal("CerberusServerAgent", AgentInstallIdentity.DataDirName);
        Assert.Equal(@"Software\Cerberus\ServerAgent", AgentInstallIdentity.RegistryPath);
        Assert.Equal("CerberusServerAgent.Control.v1", AgentInstallIdentity.ControlPipeName);
    }
#endif

    [Fact]
    public void NoDesktopIdentityLiteralOutsideIdentityFileAndDesktopOnlyExemptions()
    {
        var root = FindRepoRoot();
        var pattern = new Regex(@"CerberusAgent|Cerberus\\{1,2}WindowsAgent", RegexOptions.IgnoreCase);
        var exempt = new[]
        {
            "AgentInstallIdentity.cs", "MainWindow.xaml.cs", "TailscaleUpExporter.cs",
        };
        var exemptDirs = new[] { "Cerberus.Agent.Integrations.", "Cerberus.Agent.Tray", "Cerberus.Agent.Uninstall" };
        var projects = new[]
        {
            "Cerberus.Agent.Core", "Cerberus.Agent.Security", "Cerberus.Agent.Observability",
            "Cerberus.Agent.App", "Cerberus.Agent.Updater", "Cerberus.Agent.Installer",
        };

        var offenders = new List<string>();
        foreach (var project in projects)
        {
            foreach (var file in Directory.EnumerateFiles(Path.Combine(root, "src", project), "*.cs", SearchOption.AllDirectories))
            {
                var rel = Path.GetRelativePath(root, file);
                var parts = rel.Split(Path.DirectorySeparatorChar);
                if (parts.Contains("bin") || parts.Contains("obj")) continue;
                if (exempt.Contains(Path.GetFileName(file))) continue;
                if (exemptDirs.Any(d => parts.Any(p => p.StartsWith(d, StringComparison.Ordinal)))) continue;

                var lines = File.ReadAllLines(file);
                for (var i = 0; i < lines.Length; i++)
                    if (pattern.IsMatch(lines[i]))
                        offenders.Add($"{rel}:{i + 1}: {lines[i].Trim()}");
            }
        }

        Assert.True(offenders.Count == 0, "Desktop identity literals remain:\n" + string.Join("\n", offenders));
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (Directory.Exists(Path.Combine(dir.FullName, "src", "Cerberus.Agent.App")) &&
                Directory.Exists(Path.Combine(dir.FullName, "tests", "Cerberus.Agent.Core.Tests")))
                return dir.FullName;
            dir = dir.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate cerberus-windows-agent repository root.");
    }
}
