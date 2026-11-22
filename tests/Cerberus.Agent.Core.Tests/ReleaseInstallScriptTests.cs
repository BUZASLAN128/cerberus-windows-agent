using System.Diagnostics;
using System.Text;
using Xunit;

namespace Cerberus.Agent.Core.Tests;

// Support tier: the one-line installer generated with every release ("irm <url> | iex").
public sealed class ReleaseInstallScriptTests
{
    private const string Sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string Url = "https://feed.example.test/updates/preview/Cerberus.Agent-preview-1.2.3-server.msi";

    [Fact]
    public void InstallScript_EmbedsTheReleaseArtifactAndRunsUnderIex()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"install-script-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        try
        {
            var path = Path.Combine(dir, "Agent.install.ps1");
            var run = Generate("1.2.3", Url, Sha, "151588864", path);
            Assert.True(run.ExitCode == 0, run.Output);

            var bytes = File.ReadAllBytes(path);
            Assert.All(bytes, b => Assert.True(b is 9 or 10 or 13 or (>= 32 and <= 126), $"non-ASCII byte {b}"));
            var text = Encoding.ASCII.GetString(bytes);
            Assert.Contains($"$url = '{Url}'", text);
            Assert.Contains($"$sha256 = '{Sha}'", text);
            Assert.Contains("$length = [long]'151588864'", text);
            Assert.DoesNotMatch("__[A-Z0-9_]+__", text);
            Assert.Contains("[IO.FileShare]::Read", text);

            // "irm | iex" runs in the caller's session on Windows PowerShell 5.1: it must parse there and never exit.
            var legacy = RunWindowsPowerShell(
                $"$e = $null; $ast = [Management.Automation.Language.Parser]::ParseFile('{path}', [ref]$null, [ref]$e); " +
                "if ($e) { $e[0].Message; exit 1 }; " +
                "if ($ast.FindAll({ param($n) $n -is [Management.Automation.Language.ExitStatementAst] }, $true).Count) { 'exit statement'; exit 1 }");
            Assert.True(legacy.ExitCode == 0, legacy.Output);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Theory]
    [InlineData("1.2.3", "http://feed.example.test/a.msi", Sha, "9")]
    [InlineData("1.2.3", "https://feed.example.test/a'.msi", Sha, "9")]
    [InlineData("1.2.3", "https://feed.example.test/a.exe", Sha, "9")]
    [InlineData("1.2.3", "https://feed.example.test/a.msi", "ABC", "9")]
    [InlineData("1.2.3", "https://feed.example.test/a.msi", Sha, "0")]
    [InlineData("1.2.3'; calc; '", "https://feed.example.test/a.msi", Sha, "9")]
    public void InstallScript_RefusesValuesItCannotEmbedSafely(string version, string url, string sha, string length)
    {
        var path = Path.Combine(Path.GetTempPath(), $"install-script-{Guid.NewGuid():N}.ps1");
        var run = Generate(version, url, sha, length, path);
        Assert.NotEqual(0, run.ExitCode);
        Assert.Contains("Install script", run.Output);
        Assert.False(File.Exists(path));
    }

    private static (int ExitCode, string Output) Generate(string version, string url, string sha, string length, string path)
    {
        var lib = Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "scripts", "release-install-script-lib.ps1");
        return ServerPackageStaticTests.RunPwsh(
            $". '{lib}'; $m = [ordered]@{{ version = '{Q(version)}'; artifact_url = '{Q(url)}'; sha256 = '{Q(sha)}'; artifact_length = '{Q(length)}' }}; " +
            $"$t = New-AgentInstallScriptText $m; $null = Write-AgentInstallScript -Path '{path}' -Text $t");
    }

    private static string Q(string value) => value.Replace("'", "''");

    private static (int ExitCode, string Output) RunWindowsPowerShell(string command)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command })
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start powershell.exe.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(60_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("powershell.exe check did not finish within 1 minute.");
        }

        Task.WaitAll(stdout, stderr);
        return (process.ExitCode, stdout.Result + stderr.Result);
    }
}
