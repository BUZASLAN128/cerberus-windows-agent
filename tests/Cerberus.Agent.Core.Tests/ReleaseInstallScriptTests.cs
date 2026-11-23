using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Xunit;

namespace Cerberus.Agent.Core.Tests;

// Support tier: the one-line installer generated with every release ("irm <url> | iex").
public sealed class ReleaseInstallScriptTests
{
    private const string Sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string Url = "https://feed.example.test/updates/preview/Cerberus.Agent-preview-1.2.3-server.msi";

    [Theory]
    [InlineData("server")]
    [InlineData("desktop")]
    public void InstallScript_EmbedsTheReleaseArtifactAndRunsUnderIex(string profile)
    {
        var dir = NewTempDir();
        try
        {
            var path = Path.Combine(dir, "Agent.install.ps1");
            var run = Generate("1.2.3", Url, Sha, "151588864", path, profile);
            Assert.True(run.ExitCode == 0, run.Output);

            var bytes = File.ReadAllBytes(path);
            Assert.All(bytes, b => Assert.True(b is 9 or 10 or 13 or (>= 32 and <= 126), $"non-ASCII byte {b}"));
            var text = Encoding.ASCII.GetString(bytes);
            Assert.Contains($"$url = '{Url}'", text);
            Assert.Contains($"$sha256 = '{Sha}'", text);
            Assert.Contains("$length = [long]'151588864'", text);
            Assert.Contains($"$buildProfile = '{profile}'", text);
            Assert.DoesNotMatch("__[A-Z0-9_]+__", text);
            Assert.Contains("[IO.FileShare]::Read", text);
            // Elevated downloads go to a new folder under Program Files, resolved by the system rather than the environment.
            Assert.Contains("[Environment]::GetFolderPath('ProgramFiles')", text);
            Assert.DoesNotContain("$env:", text);
            Assert.DoesNotContain("ProgramData", text);
            // msiexec alone is awaited: the Desktop finish page can start the agent window, which keeps running.
            Assert.DoesNotMatch(@"Start-Process[^\r\n]*-Wait\b", text);
            Assert.Contains(".WaitForExit()", text);

            // "irm | iex" runs in the caller's session on Windows PowerShell 5.1: it must parse there, define nothing
            // in that session and never exit.
            var legacy = RunWindowsPowerShell(
                $"$e = $null; $ast = [Management.Automation.Language.Parser]::ParseFile('{path}', [ref]$null, [ref]$e); " +
                "if ($e) { $e[0].Message; exit 1 }; " +
                "if ($ast.FindAll({ param($n) $n -is [Management.Automation.Language.ExitStatementAst] }, $true).Count) { 'exit statement'; exit 1 }; " +
                "if ($ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] }, $true).Count) { 'function'; exit 1 }; " +
                "if ($ast.ParamBlock) { 'top-level param'; exit 1 }");
            Assert.True(legacy.ExitCode == 0, legacy.Output);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Theory]
    [InlineData("v1.2.3")]
    [InlineData("1.2.3+build.7")]
    [InlineData("1.2.3-preview.1")]
    public void InstallScript_AcceptsTheVersionsTheReleaseBuildAccepts(string version)
    {
        var dir = NewTempDir();
        try
        {
            var run = Generate(version, Url, Sha, "9", Path.Combine(dir, "Agent.install.ps1"), "server");
            Assert.True(run.ExitCode == 0, run.Output);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Theory]
    [InlineData("1.2.3", "http://feed.example.test/a.msi", Sha, "9", "server")]
    [InlineData("1.2.3", "https://feed.example.test/a'.msi", Sha, "9", "server")]
    [InlineData("1.2.3", "https://feed.example.test/a.exe", Sha, "9", "server")]
    [InlineData("1.2.3", "https://feed.example.test/a.msi", "ABC", "9", "server")]
    [InlineData("1.2.3", "https://feed.example.test/a.msi", Sha, "0", "server")]
    [InlineData("1.2.3'; calc; '", "https://feed.example.test/a.msi", Sha, "9", "server")]
    [InlineData("1.2.3", "https://feed.example.test/a.msi", Sha, "9", "Server")]
    [InlineData("1.2.3", "https://feed.example.test/a.msi", Sha, "9", "server'; calc; '")]
    public void InstallScript_RefusesValuesItCannotEmbedSafely(string version, string url, string sha, string length, string profile)
    {
        var path = Path.Combine(Path.GetTempPath(), $"install-script-{Guid.NewGuid():N}.ps1");
        var run = Generate(version, url, sha, length, path, profile);
        Assert.NotEqual(0, run.ExitCode);
        Assert.Contains("Install script", run.Output);
        Assert.False(File.Exists(path));
    }

    [Fact]
    public void InstallScript_DownloadOnlyVerifiesTheFileAndLeavesNothingBehindOnMismatch()
    {
        // Elevated runs (CI runners) would download under Program Files; the elevated path is checked on a real machine.
        using (var identity = WindowsIdentity.GetCurrent())
        {
            if (new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                return;
        }

        var dir = NewTempDir();
        try
        {
            var good = Path.Combine(dir, "good.bin");
            File.WriteAllBytes(good, Encoding.ASCII.GetBytes("cerberus agent test package"));
            var bad = Path.Combine(dir, "bad.bin");
            File.WriteAllBytes(bad, Encoding.ASCII.GetBytes("cerberus agent test packagX"));
            var shortFile = Path.Combine(dir, "short.bin");
            File.WriteAllBytes(shortFile, Encoding.ASCII.GetBytes("cer"));
            var hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(good))).ToLowerInvariant();
            var script = Path.Combine(dir, "Agent.install.ps1");
            var generated = Generate("1.2.3", "https://feed.example.test/u/Agent.msi", hash, new FileInfo(good).Length.ToString(), script, "server");
            Assert.True(generated.ExitCode == 0, generated.Output);

            // Invoke-WebRequest is shadowed by a copy of a local file: no network, no installer.
            var run = RunWindowsPowerShell(
                $"$text = [IO.File]::ReadAllText('{script}'); " +
                "function global:Invoke-WebRequest { param($Uri, $OutFile, [switch]$UseBasicParsing) Copy-Item -LiteralPath $global:Source -Destination $OutFile }; " +
                "$DownloadOnly = 'caller'; $ErrorActionPreference = 'Continue'; " +
                $"$global:Source = '{good}'; try {{ Invoke-Expression $text; 'install:ran' }} catch {{ 'install:' + $_.Exception.Message }}; " +
                "\"after:DownloadOnly=$DownloadOnly eap=$ErrorActionPreference\"; " +
                $"$global:Source = '{good}'; & ([scriptblock]::Create($text)) -DownloadOnly *>&1 | ForEach-Object {{ \"good:$_\" }}; " +
                $"$global:Source = '{bad}'; try {{ & ([scriptblock]::Create($text)) -DownloadOnly *>&1 | Out-Null; 'bad:ran' }} catch {{ 'bad:' + $_.Exception.Message }}; " +
                $"$global:Source = '{shortFile}'; try {{ & ([scriptblock]::Create($text)) -DownloadOnly *>&1 | Out-Null; 'short:ran' }} catch {{ 'short:' + $_.Exception.Message }}",
                tempDirectory: dir);
            Assert.True(run.ExitCode == 0, run.Output);
            Assert.Contains("install:Run PowerShell as Administrator", run.Output);
            Assert.Contains("after:DownloadOnly=caller eap=Continue", run.Output);
            Assert.Contains("bad:Downloaded installer does not match the published SHA-256.", run.Output);
            Assert.Contains("short:Downloaded installer has 3 bytes, expected", run.Output);

            var verified = Regex.Match(run.Output, @"good:Verified: (?<path>\S+)");
            Assert.True(verified.Success, run.Output);
            var downloaded = verified.Groups["path"].Value;
            Assert.StartsWith(Path.Combine(dir, "Cerberus.Install."), downloaded, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(File.ReadAllBytes(good), File.ReadAllBytes(downloaded));
            // The refused downloads removed their files and folders; only the verified download remains.
            Assert.Equal(new[] { Path.GetDirectoryName(downloaded) }, Directory.GetDirectories(dir, "Cerberus.Install.*"));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static string NewTempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"install-script-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static (int ExitCode, string Output) Generate(string version, string url, string sha, string length, string path, string profile)
    {
        var lib = Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "scripts", "release-install-script-lib.ps1");
        return ServerPackageStaticTests.RunPwsh(
            $". '{lib}'; $m = [ordered]@{{ version = '{Q(version)}'; artifact_url = '{Q(url)}'; sha256 = '{Q(sha)}'; artifact_length = '{Q(length)}' }}; " +
            $"$t = New-AgentInstallScriptText $m '{Q(profile)}'; $null = Write-AgentInstallScript -Path '{path}' -Text $t");
    }

    private static string Q(string value) => value.Replace("'", "''");

    private static (int ExitCode, string Output) RunWindowsPowerShell(string command, string? tempDirectory = null)
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

        if (tempDirectory is not null)
        {
            startInfo.Environment["TEMP"] = tempDirectory;
            startInfo.Environment["TMP"] = tempDirectory;
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
