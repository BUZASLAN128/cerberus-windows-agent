using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Cerberus.Agent.Core.Tests;

// Release/preflight script gates. Support tier: the secret-scan script runs in pwsh on throwaway files;
// the build and test steps are checked as script text (they need signing inputs and a full build to run).
public sealed class ReleaseScriptGateTests
{
    [Fact]
    public void SecretScanScript_PassesAllCases_AndLeavesNoFixtures()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-secret-scan-gate-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var script = Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "scripts", "test-release-secret-scan.ps1");
            var startInfo = new ProcessStartInfo { FileName = "pwsh", UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
            foreach (var a in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-File", script, "-WorkRoot", root }) startInfo.ArgumentList.Add(a);

            using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start pwsh.");
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            Assert.True(process.WaitForExit(120_000), "secret scan script timed out");
            Task.WaitAll(stdout, stderr);
            var output = stdout.Result + stderr.Result;

            Assert.True(process.ExitCode == 0, output);
            Assert.Contains("mismatched-yes", output);
            Assert.Contains("json-password", output);
            Assert.Empty(Directory.GetFileSystemEntries(root));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void ReleaseScript_RunsServerTestsWithTheServerProfile_AndChecksTheExitCode()
    {
        var script = ReadScript("build-agent-public-release.ps1");

        Assert.Matches(
            new Regex(@"if \(\$BuildProfile -eq ""server""\) \{[^}]*?dotnet test[^}]*?Cerberus\.Agent\.Core\.Tests\.csproj[^}]*?-p:AgentBuildProfile=server[^}]*?AgentCommandTrustAnchorsB64[^}]*?\$LASTEXITCODE -ne 0\) \{ throw", RegexOptions.Singleline),
            script);
    }

    [Fact]
    public void Preflight_ChecksTheExitCodeAfterEveryDotnetStep()
    {
        var lines = ReadScript("preflight.ps1").Split('\n');
        var steps = lines.Select((l, i) => (l, i)).Where(x => Regex.IsMatch(x.l, @"^\s*dotnet (build|test|publish)\b")).ToList();

        Assert.True(steps.Count >= 4, "expected build, test, server test and publish steps");
        foreach (var (line, index) in steps)
        {
            var next = lines.Skip(index + 1).FirstOrDefault(l => !l.TrimEnd().EndsWith("`", StringComparison.Ordinal) && !l.TrimStart().StartsWith("-", StringComparison.Ordinal) && l.Trim().Length > 0 && !l.TrimStart().StartsWith("\"-", StringComparison.Ordinal));
            Assert.True(next is not null && next.Contains("$LASTEXITCODE", StringComparison.Ordinal), "no exit-code check after: " + line.Trim());
        }
    }

    private static string ReadScript(string name)
        => File.ReadAllText(Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "scripts", name));
}
