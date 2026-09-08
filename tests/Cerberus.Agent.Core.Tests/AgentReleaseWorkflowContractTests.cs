using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace Cerberus.Agent.Core.Tests;

public sealed class AgentReleaseWorkflowContractTests
{
    [Theory]
    [InlineData("workflow_dispatch", "refs/heads/dev", "preview", "v1.2.3-preview.1", true)]
    [InlineData("workflow_dispatch", "refs/heads/dev", "preview", "1.2.3+build.7", true)]
    [InlineData("push", "refs/heads/dev", "dev", "ignored", true)]
    [InlineData("push", "refs/heads/develop", "dev", "ignored", true)]
    [InlineData("workflow_dispatch", "refs/heads/main", "stable", "1.2.3", true)]
    [InlineData("workflow_dispatch", "refs/heads/main", "preview", "1.2.3", false)]
    [InlineData("workflow_dispatch", "refs/heads/main", "dev", "1.2.3", false)]
    [InlineData("workflow_dispatch", "refs/heads/dev", "stable", "1.2.3", false)]
    [InlineData("workflow_dispatch", "refs/heads/Main", "stable", "1.2.3", false)]
    [InlineData("workflow_dispatch", "refs/heads/Dev", "preview", "1.2.3", false)]
    [InlineData("workflow_dispatch", "refs/heads/feature/release", "stable", "1.2.3", false)]
    [InlineData("workflow_dispatch", "refs/tags/v1.2.3", "stable", "1.2.3", false)]
    [InlineData("workflow_dispatch", "refs/heads/x\";$ref=\"refs/heads/main\";Write-Output MARKER;#", "stable", "1.2.3", false)]
    [InlineData("push", "refs/heads/main", "dev", "ignored", false)]
    [InlineData("workflow_dispatch", "refs/heads/dev", "preview", "1.2.3\n", false)]
    [InlineData("workflow_dispatch", "refs/heads/dev", "preview", "1.2.3/evil", false)]
    [InlineData("workflow_dispatch", "refs/heads/dev", "preview", "1.2.3\\evil", false)]
    [InlineData("workflow_dispatch", "refs/heads/dev", "preview", "1.2.3$evil", false)]
    [InlineData("workflow_dispatch", "refs/heads/dev", "preview", "1.2.3;evil", false)]
    [InlineData("workflow_dispatch", "refs/heads/dev", "preview", "1.2.3\nMARKER", false)]
    [InlineData("workflow_dispatch", "refs/heads/dev", "preview", "1.2.3\";Write-Output MARKER", false)]
    [InlineData("workflow_dispatch", "refs/heads/dev", "preview", "1.2.3-preview.bad!", false)]
    [InlineData("workflow_dispatch", "refs/heads/dev", "preview", "1.2.3-01", false)]
    public void ResolveReleaseInputs_EnforcesRefEventChannelMatrix(
        string eventName,
        string gitRef,
        string channel,
        string version,
        bool expectedSuccess)
    {
        var result = RunResolveReleaseInputs(eventName, gitRef, channel, version);

        Assert.Equal(
            expectedSuccess,
            result.ExitCode == 0);
        if (eventName == "push" && expectedSuccess)
        {
            Assert.Contains("channel=dev", result.GitHubOutput, StringComparison.Ordinal);
            Assert.Contains("version=0.2.7-dev.7", result.GitHubOutput, StringComparison.Ordinal);
            Assert.Contains("tag=v0.2.7-dev.7", result.GitHubOutput, StringComparison.Ordinal);
            Assert.Contains("asset_base=Cerberus.Agent.Bundle-dev-0.2.7-dev.7", result.GitHubOutput, StringComparison.Ordinal);
            Assert.Contains("setup_base=Cerberus.Agent-dev-0.2.7-dev.7", result.GitHubOutput, StringComparison.Ordinal);
        }
        else if (expectedSuccess)
        {
            Assert.Contains($"channel={channel}", result.GitHubOutput, StringComparison.Ordinal);
            var normalizedVersion = version.TrimStart('v');
            Assert.Contains($"version={normalizedVersion}", result.GitHubOutput, StringComparison.Ordinal);
            Assert.Contains($"tag=v{normalizedVersion}", result.GitHubOutput, StringComparison.Ordinal);
            Assert.Contains($"asset_base=Cerberus.Agent.Bundle-{channel}-{normalizedVersion}", result.GitHubOutput, StringComparison.Ordinal);
            Assert.Contains($"setup_base=Cerberus.Agent-{channel}-{normalizedVersion}", result.GitHubOutput, StringComparison.Ordinal);
        }
        if (!expectedSuccess)
        {
            Assert.Contains("release", result.StandardError + result.StandardOutput, StringComparison.OrdinalIgnoreCase);
            Assert.Empty(result.GitHubOutput);
            Assert.DoesNotContain("MARKER", result.StandardError + result.StandardOutput, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ReleaseWorkflow_ExecutesEveryChannelAliasWithoutStealingLatest()
    {
        var repoRoot = FindRepoRoot();
        var workflow = File.ReadAllText(Path.Combine(repoRoot, ".github", "workflows", "auto-publish-exe.yml"));
        foreach (var stepName in new[] { "Resolve release inputs", "Build gated release bundle", "Update channel latest release" })
        {
            Assert.DoesNotContain("${{", ExtractRunBlock(workflow, stepName), StringComparison.Ordinal);
        }
        var resolverStep = ExtractRunBlock(workflow, "Resolve release inputs");
        Assert.Contains("\\z", resolverStep, StringComparison.Ordinal);
        Assert.True(
            resolverStep.IndexOf("$versionMatch", StringComparison.Ordinal) <
            resolverStep.IndexOf("$env:GITHUB_OUTPUT", StringComparison.Ordinal),
            "release_version validation must precede every GITHUB_OUTPUT write.");
        var latestStep = ExtractRunBlock(workflow, "Update channel latest release");

        var latestStepStart = workflow.IndexOf(
            "      - name: Update channel latest release",
            StringComparison.Ordinal);
        var stableStepGuard = workflow.IndexOf(
            "        if: ${{ steps.release.outputs.channel != 'stable' }}",
            latestStepStart,
            StringComparison.Ordinal);
        Assert.True(latestStepStart >= 0 && stableStepGuard > latestStepStart);
        Assert.Contains("$channel = $env:CERBERUS_RELEASE_CHANNEL", latestStep);
        Assert.Contains("$setupBase = $env:CERBERUS_RELEASE_SETUP_BASE", latestStep);
        Assert.Contains("$assetBase = $env:CERBERUS_RELEASE_ASSET_BASE", latestStep);
        Assert.Contains("$workflowSha = $env:CERBERUS_WORKFLOW_SHA", latestStep);
        Assert.Contains("$latestReleaseOptions", latestStep);
        Assert.Contains("\"--latest=false\"", latestStep);
        Assert.Contains("if ($channel -cne \"stable\")", latestStep);
        Assert.Contains("$latestAssetBase.update-manifest.json", latestStep);
        Assert.Contains("$latestAssetBase.update-manifest.v2.json", latestStep);

        var versionedAssets = ExtractArtifactBlock(workflow, "Create GitHub release");
        Assert.Contains("${{ steps.release.outputs.asset_base }}.update-manifest.json", versionedAssets);
        Assert.Contains("${{ steps.release.outputs.asset_base }}.update-manifest.v2.json", versionedAssets);
        Assert.Contains("Cerberus.Agent.Bundle-${{ steps.release.outputs.channel }}-latest.update-manifest.v2.json", versionedAssets);
        var releaseInputs = workflow[workflow.IndexOf("      - name: Create GitHub release", StringComparison.Ordinal)..];
        Assert.Contains("artifactErrorsFailBuild: true", releaseInputs, StringComparison.Ordinal);
        Assert.Contains("immutableCreate: ${{ steps.release.outputs.channel == 'stable' }}", releaseInputs, StringComparison.Ordinal);

        // The mutable alias step is executed only for dev/preview. Stable is
        // guarded by the workflow condition above and is intentionally not
        // simulated with a fabricated successful process result.
        foreach (var channel in new[] { "dev", "preview" })
        {
            var result = RunLatestReleaseBlock(channel);
            Assert.True(
                result.ExitCode == 0,
                result.StandardError + result.StandardOutput);

            Assert.Equal(2, result.Commands.Count);
            Assert.Equal(
                new[] { "release", "delete", $"{channel}-latest", "--yes", "--cleanup-tag" },
                result.Commands[0]);

            var create = result.Commands[1];
            var versionedAssetBase = $"Cerberus.Agent.Bundle-{channel}-1.2.3";
            var versionedInstallerBase = $"Cerberus.Agent-{channel}-1.2.3";
            var latestAssetBase = $"Cerberus.Agent.Bundle-{channel}-latest";
            var latestInstallerBase = $"Cerberus.Agent-{channel}-latest";
            Assert.Equal("release", create[0]);
            Assert.Equal("create", create[1]);
            Assert.Equal($"{channel}-latest", create[2]);
            Assert.Contains($"out/public-release/publish/{versionedInstallerBase}.msi", create);
            Assert.Contains($"out/public-release/publish/{versionedAssetBase}.update-manifest.json", create);
            Assert.Contains($"out/public-release/publish/{versionedAssetBase}.update-manifest.v2.json", create);
            Assert.Contains($"out/public-release/publish/{latestInstallerBase}.msi", create);
            Assert.Contains($"out/public-release/publish/{latestAssetBase}.update-manifest.json", create);
            Assert.Contains($"out/public-release/publish/{latestAssetBase}.update-manifest.v2.json", create);
            Assert.Contains("--latest=false", create);
            var targetIndex = Array.IndexOf(create, "--target");
            Assert.True(targetIndex >= 0 && targetIndex + 1 < create.Length);
            Assert.Equal(new string('a', 40), create[targetIndex + 1]);
            if (channel == "stable")
            {
                Assert.DoesNotContain("--prerelease", create);
            }
            else
            {
                Assert.Contains("--prerelease", create);
            }
        }

        var releaseScript = File.ReadAllText(Path.Combine(repoRoot, "scripts", "build-agent-public-release.ps1"));
        Assert.Contains("releases/latest/download/Cerberus.Agent.Bundle-stable-latest.update-manifest.v2.json", releaseScript);
        Assert.Contains("releases/download/$Channel-latest/Cerberus.Agent.Bundle-$Channel-latest.update-manifest.v2.json", releaseScript);
        Assert.Contains("Cerberus.Agent.Bundle-$Channel-latest.update-manifest.v2.json", releaseScript);
    }

    private static ProcessResult RunResolveReleaseInputs(
        string eventName,
        string gitRef,
        string channel,
        string version)
    {
        var repoRoot = FindRepoRoot();
        var workflow = File.ReadAllText(Path.Combine(repoRoot, ".github", "workflows", "auto-publish-exe.yml"));
        var script = ExtractRunBlock(workflow, "Resolve release inputs");

        var tempRoot = Path.Combine(
            Path.GetTempPath(),
            "cerberus-agent-release-routing-tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);
        var outputPath = Path.Combine(tempRoot, "github-output.txt");

        try
        {
            // The real step reads remote tags only to choose the next generated dev
            // version. Shadow git locally so the actual resolver never reaches a
            // remote repository during this contract test.
            var localGitStub = """
                function git {
                  param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Arguments)
                  @()
                }
                """;
            var encodedScript = Convert.ToBase64String(
                Encoding.Unicode.GetBytes(localGitStub + Environment.NewLine + script));
            var startInfo = new ProcessStartInfo
            {
                FileName = "pwsh",
                Arguments = $"-NoLogo -NoProfile -NonInteractive -EncodedCommand {encodedScript}",
                WorkingDirectory = tempRoot,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            startInfo.Environment["DISPATCH_RELEASE_VERSION"] = version;
            startInfo.Environment["DISPATCH_CHANNEL"] = channel;
            startInfo.Environment["DISPATCH_RELEASE_NOTES"] = "contract test";
            startInfo.Environment["CERBERUS_EVENT_NAME"] = eventName;
            startInfo.Environment["CERBERUS_REF"] = gitRef;
            startInfo.Environment["CERBERUS_REF_NAME"] = gitRef[(gitRef.LastIndexOf('/') + 1)..];
            startInfo.Environment["CERBERUS_WORKFLOW_SHA"] = new string('a', 40);
            startInfo.Environment["CERBERUS_RUN_NUMBER"] = "7";
            startInfo.Environment["GITHUB_OUTPUT"] = outputPath;

            using var process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("Could not start pwsh for release workflow contract test.");
            var standardOutput = process.StandardOutput.ReadToEndAsync();
            var standardError = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(30_000))
            {
                process.Kill(entireProcessTree: true);
                throw new TimeoutException("Release workflow input contract did not finish within 30 seconds.");
            }

            Task.WaitAll(standardOutput, standardError);
            var githubOutput = File.Exists(outputPath)
                ? File.ReadAllText(outputPath)
                : string.Empty;
            return new ProcessResult(process.ExitCode, standardOutput.Result, standardError.Result, githubOutput);
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                Directory.Delete(tempRoot, recursive: true);
            }
        }
    }

    private static ProcessResult RunLatestReleaseBlock(string channel)
    {
        var repoRoot = FindRepoRoot();
        var workflow = File.ReadAllText(Path.Combine(repoRoot, ".github", "workflows", "auto-publish-exe.yml"));
        var script = ExtractRunBlock(workflow, "Update channel latest release");

        var tempRoot = Path.Combine(
            Path.GetTempPath(),
            "cerberus-agent-release-alias-tests",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);
        var capturePath = Path.Combine(tempRoot, "gh-arguments.jsonl");

        // Execute the workflow's actual argument construction. The local gh function
        // records arguments and never reaches the external GitHub CLI.
        var captureFunction = """
            function gh {
              param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Arguments)
              Add-Content -LiteralPath $env:CAPTURE_PATH -Value (ConvertTo-Json -InputObject @($Arguments) -Compress)
              $global:LASTEXITCODE = 0
            }
            """;
        var encodedScript = Convert.ToBase64String(
            Encoding.Unicode.GetBytes(captureFunction + Environment.NewLine + script));

        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "pwsh",
                Arguments = $"-NoLogo -NoProfile -NonInteractive -EncodedCommand {encodedScript}",
                WorkingDirectory = tempRoot,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            startInfo.Environment["CAPTURE_PATH"] = capturePath;
            startInfo.Environment["CERBERUS_RELEASE_CHANNEL"] = channel;
            startInfo.Environment["CERBERUS_RELEASE_SETUP_BASE"] = $"Cerberus.Agent-{channel}-1.2.3";
            startInfo.Environment["CERBERUS_RELEASE_ASSET_BASE"] = $"Cerberus.Agent.Bundle-{channel}-1.2.3";
            startInfo.Environment["CERBERUS_WORKFLOW_SHA"] = new string('a', 40);
            using var process = Process.Start(startInfo)
                ?? throw new InvalidOperationException("Could not start pwsh for release alias contract test.");
            var standardOutput = process.StandardOutput.ReadToEndAsync();
            var standardError = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(30_000))
            {
                process.Kill(entireProcessTree: true);
                throw new TimeoutException("Release workflow alias contract did not finish within 30 seconds.");
            }

            Task.WaitAll(standardOutput, standardError);
            var commands = File.Exists(capturePath)
                ? File.ReadAllLines(capturePath)
                    .Where(line => !string.IsNullOrWhiteSpace(line))
                    .Select(line => System.Text.Json.JsonSerializer.Deserialize<string[]>(line)
                        ?? throw new InvalidOperationException("gh argument capture was not a JSON array."))
                    .ToArray()
                : Array.Empty<string[]>();
            return new ProcessResult(process.ExitCode, standardOutput.Result, standardError.Result, string.Empty, commands);
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                Directory.Delete(tempRoot, recursive: true);
            }
        }
    }

    private static string ExtractRunBlock(string workflow, string stepName)
    {
        var stepMarker = $"      - name: {stepName}";
        var stepStart = workflow.IndexOf(stepMarker, StringComparison.Ordinal);
        Assert.True(stepStart >= 0, $"Workflow step '{stepName}' was not found.");

        var runMarker = "        run: |";
        var runStart = workflow.IndexOf(runMarker, stepStart, StringComparison.Ordinal);
        Assert.True(runStart >= 0, $"Workflow step '{stepName}' has no literal PowerShell run block.");

        var bodyStart = workflow.IndexOf('\n', runStart + runMarker.Length);
        Assert.True(bodyStart >= 0, $"Workflow step '{stepName}' run block is empty.");
        bodyStart++;

        var nextStep = workflow.IndexOf("\n      - name:", bodyStart, StringComparison.Ordinal);
        if (nextStep < 0)
        {
            nextStep = workflow.Length;
        }

        var body = workflow[bodyStart..nextStep];
        return Regex.Replace(body, @"(?m)^ {10}", string.Empty).Trim();
    }

    private static string ExtractArtifactBlock(string workflow, string stepName)
    {
        var stepMarker = $"      - name: {stepName}";
        var stepStart = workflow.IndexOf(stepMarker, StringComparison.Ordinal);
        Assert.True(stepStart >= 0, $"Workflow step '{stepName}' was not found.");

        var artifactsMarker = "          artifacts: |";
        var artifactsStart = workflow.IndexOf(artifactsMarker, stepStart, StringComparison.Ordinal);
        Assert.True(artifactsStart >= 0, $"Workflow step '{stepName}' has no artifacts block.");

        var bodyStart = workflow.IndexOf('\n', artifactsStart + artifactsMarker.Length);
        Assert.True(bodyStart >= 0, $"Workflow step '{stepName}' artifacts block is empty.");
        bodyStart++;

        var tokenMarker = workflow.IndexOf("\n          token:", bodyStart, StringComparison.Ordinal);
        Assert.True(tokenMarker >= 0, $"Workflow step '{stepName}' artifacts block has no token boundary.");

        return Regex.Replace(workflow[bodyStart..tokenMarker], @"(?m)^ {12}", string.Empty).Trim();
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Cerberus.WindowsAgent.slnx")))
                return dir.FullName;
            dir = dir.Parent;
        }

        throw new DirectoryNotFoundException("Could not locate cerberus-windows-agent repository root.");
    }

    private sealed record ProcessResult(
        int ExitCode,
        string StandardOutput,
        string StandardError,
        string GitHubOutput = "",
        IReadOnlyList<string[]>? CapturedCommands = null)
    {
        public IReadOnlyList<string[]> Commands { get; } = CapturedCommands ?? Array.Empty<string[]>();
    }
}
