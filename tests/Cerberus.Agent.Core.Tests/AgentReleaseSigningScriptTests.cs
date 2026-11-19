using System.Diagnostics;

namespace Cerberus.Agent.Core.Tests;

// Support-tier signing and resigning checks use in-memory certificates and disposable fixtures.
// The release signing suite also uses Windows SDK signtool.exe to verify that unsigned files are refused.
public sealed class AgentReleaseSigningScriptTests
{
    [Fact]
    public Task ReleaseSigningScript_ReportsNoFailedChecks() =>
        RunScript(FindRepoRoot(), "test-release-signing.ps1", typeof(AgentUpdateAuthenticode).Assembly.Location);

    [Fact]
    public async Task ResignScript_UsesDefaultVerifierPath()
    {
        const string testScript = "test-resign-agent-update-manifest.ps1";
        var sourceScripts = Path.Combine(FindRepoRoot(), "scripts");
        var fixture = Directory.CreateTempSubdirectory("cerberus-resign-repo-");
        try
        {
            var scripts = fixture.CreateSubdirectory("scripts");
            foreach (var name in new[] { testScript, "resign-agent-update-manifest.ps1", "release-signing-lib.ps1", "release-trust-lib.ps1" })
            {
                File.Copy(Path.Combine(sourceScripts, name), Path.Combine(scripts.FullName, name));
            }

            // Stage the verifier where the operator script looks for it when no override is supplied.
            var verifier = fixture.CreateSubdirectory("src/Cerberus.Agent.Core/bin/Release/net10.0");
            File.Copy(typeof(AgentUpdateAuthenticode).Assembly.Location, Path.Combine(verifier.FullName, "Cerberus.Agent.Core.dll"));
            await RunScript(fixture.FullName, testScript);
        }
        finally
        {
            fixture.Delete(recursive: true);
        }
    }

    private static async Task RunScript(string repoRoot, string scriptName, string? coreDll = null)
    {
        var script = Path.Combine(repoRoot, "scripts", scriptName);
        var startInfo = new ProcessStartInfo
        {
            FileName = "pwsh",
            WorkingDirectory = repoRoot,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-File", script })
        {
            startInfo.ArgumentList.Add(argument);
        }
        if (coreDll is not null)
        {
            startInfo.ArgumentList.Add("-CoreDll");
            startInfo.ArgumentList.Add(coreDll);
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException($"Could not start pwsh for {scriptName}.");
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            throw new TimeoutException($"{scriptName} did not finish within 5 minutes.");
        }

        var output = await standardOutput;
        var errors = await standardError;
        var failed = output
            .Split('\n')
            .Where(line => line.StartsWith("FAIL", StringComparison.Ordinal))
            .ToArray();
        Assert.True(
            process.ExitCode == 0,
            $"{scriptName} exit {process.ExitCode}; failed checks:{Environment.NewLine}{string.Join(Environment.NewLine, failed)}{Environment.NewLine}{errors}");
        Assert.Contains("failures=0", output);
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
