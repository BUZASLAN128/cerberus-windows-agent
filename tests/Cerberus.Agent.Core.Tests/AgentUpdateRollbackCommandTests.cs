using System.Text.RegularExpressions;
using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentUpdateRollbackCommandTests
{
    [Fact]
    public void RollbackCommandUsesOnlyTheFixedInstallArguments()
    {
        var root = Path.Combine(Path.GetTempPath(), "root with spaces");
        var now = DateTimeOffset.Parse("2026-11-18T15:30:00Z");
        var args = AgentUpdateRollbackCommand.Arguments(root, "attempt123", now);
        Assert.Equal(new[] { "/i", Path.Combine(root, "lkg", "agent.msi"), "/qn", "/norestart", "CERBERUS_EULA_ACCEPTED=1",
            "CERBERUS_UPDATE_REQUIRE_BACKEND=0", "CERBERUS_ROLLBACK_ATTEMPT=attempt123", "REINSTALLMODE=amus", "/l*v",
            Path.Combine(root, "logs", "msiexec-rollback-20261118T1530000000000Z.log") }, args);
        Assert.Throws<ArgumentException>(() => AgentUpdateRollbackCommand.Arguments(root, "attempt with spaces", now));
    }

    [Fact]
    public void AutomatedUpdateSourceHasNoUninstallCommand()
    {
        var src = Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "src");
        var directories = new[] { "Cerberus.Agent.Updater", Path.Combine("Cerberus.Agent.App", "Updates"),
            Path.Combine("Cerberus.Agent.Installer", "Helper"), "Cerberus.Agent.Core" };
        var forbidden = new Regex(@"(?<![\w/])/(?:x|uninstall)(?![\w])|\bREMOVE=ALL\b|\bMsiConfigureProduct(?:Ex)?\b", RegexOptions.IgnoreCase);
        var matches = directories.Select(dir => Path.Combine(src, dir)).Where(Directory.Exists)
            .SelectMany(dir => Directory.EnumerateFiles(dir, "*.cs", SearchOption.AllDirectories))
            .Where(path => !IsGeneratedOrUnrelated(path))
            .Where(path => File.ReadLines(path).Any(line =>
                !line.TrimStart().StartsWith("//", StringComparison.Ordinal) && forbidden.IsMatch(line)));
        Assert.Empty(matches);
    }

    private static bool IsGeneratedOrUnrelated(string path)
    {
        var components = path.Split(Path.DirectorySeparatorChar);
        return components.Any(part => part is "obj" or "bin");
    }
}
