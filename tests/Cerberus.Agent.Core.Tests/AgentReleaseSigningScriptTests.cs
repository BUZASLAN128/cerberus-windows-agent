using System.Diagnostics;

namespace Cerberus.Agent.Core.Tests;

// Runs scripts/test-release-signing.ps1 (support tier: in-memory keys, fixture publish directory, no signtool,
// no certificate store). The script's exit code is the number of failed checks.
public sealed class AgentReleaseSigningScriptTests
{
    [Fact]
    public void ReleaseSigningScript_ReportsNoFailedChecks()
    {
        var repoRoot = FindRepoRoot();
        var script = Path.Combine(repoRoot, "scripts", "test-release-signing.ps1");
        var coreDll = typeof(AgentUpdateAuthenticode).Assembly.Location;

        var startInfo = new ProcessStartInfo
        {
            FileName = "pwsh",
            WorkingDirectory = repoRoot,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-File", script, "-CoreDll", coreDll })
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start pwsh for the release signing script test.");
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(300_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("Release signing script test did not finish within 5 minutes.");
        }

        Task.WaitAll(standardOutput, standardError);
        var failed = standardOutput.Result
            .Split('\n')
            .Where(line => line.StartsWith("FAIL", StringComparison.Ordinal))
            .ToArray();
        Assert.True(
            process.ExitCode == 0,
            $"exit {process.ExitCode}; failed checks:{Environment.NewLine}{string.Join(Environment.NewLine, failed)}{Environment.NewLine}{standardError.Result}");
        Assert.Contains("failures=0", standardOutput.Result);
    }

    private static string FindRepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "scripts", "test-release-signing.ps1")))
            {
                return directory.FullName;
            }

            directory = directory.Parent;
        }

        throw new DirectoryNotFoundException("scripts/test-release-signing.ps1 was not found above the test output directory.");
    }
}
