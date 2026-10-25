using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Cerberus.Agent.Core.Tests;

// Build-time command anchor check (CERBAGENT006 in AgentCommandAnchors.targets): a direct MSBuild run of the
// server profile must reject a well-formed but unusable anchor, or one equal to a given manifest key, without
// the release script. Support tier: only the validation target runs (no compile, no MSI).
public sealed class ServerAnchorBuildCheckTests
{
    [Fact]
    public void Build_AcceptsTheFixtureAnchor_BesideADifferentManifestKey()
    {
        using var manifest = RSA.Create(2048);

        var result = Validate(FixtureLines(), manifest);

        Assert.True(result.ExitCode == 0, result.Output);
    }

    [Fact]
    public void Build_RejectsAWeakKeyBesideAGoodOne_NamingOnlyTheLine()
    {
        using var weak = RSA.Create(1024);
        var weakB64 = Convert.ToBase64String(weak.ExportSubjectPublicKeyInfo());

        var result = Validate(FixtureLines().Append(weakB64));

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("CERBAGENT006", result.Output);
        Assert.Contains("line 2", result.Output);
        Assert.DoesNotContain(weakB64, result.Output);
    }

    [Fact]
    public void Build_RejectsATruncatedKeyBesideAGoodOne()
    {
        var good = FixtureLines().Single();

        var result = Validate(new[] { good, good[..(good.Length - 12)] });

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("CERBAGENT006", result.Output);
        Assert.Contains("line 2", result.Output);
    }

    [Fact]
    public void Build_RejectsAnAnchorEqualToAManifestKey_NamingOnlyTheKeyId()
    {
        using var manifest = RSA.Create(2048);
        var spki = manifest.ExportSubjectPublicKeyInfo();
        var spkiB64 = Convert.ToBase64String(spki);

        var result = Validate(FixtureLines().Append(spkiB64), manifest);

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("CERBAGENT006", result.Output);
        Assert.Contains(AgentProfileMetadata.ComputeKeyId(spki), result.Output);
        Assert.DoesNotContain(spkiB64, result.Output);
    }

    private static IReadOnlyList<string> FixtureLines()
    {
        var value = File.ReadAllText(Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "tests", "fixtures", "agent-command-test-anchors.b64")).Trim();
        return Encoding.UTF8.GetString(Convert.FromBase64String(value))
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static (int ExitCode, string Output) Validate(IEnumerable<string> lines, RSA? manifestKey = null)
    {
        var root = ServerPackageStaticTests.FindRepoRoot();
        var anchors = Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Join("\n", lines)));
        var temp = Path.Combine(Path.GetTempPath(), "cerberus-anchor-build-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            };
            var args = new List<string>
            {
                "msbuild", Path.Combine(root, "src", "Cerberus.Agent.Core", "Cerberus.Agent.Core.csproj"),
                "-nologo", "-t:ValidateAgentCommandAnchors", "-p:AgentBuildProfile=server",
                "-p:AgentCommandTrustAnchorsB64=" + anchors,
                "-p:BaseIntermediateOutputPath=" + Path.Combine(temp, "obj") + Path.DirectorySeparatorChar,
                "-p:IntermediateOutputPath=" + Path.Combine(temp, "obj", "x") + Path.DirectorySeparatorChar,
                "-p:BaseOutputPath=" + Path.Combine(temp, "bin") + Path.DirectorySeparatorChar,
            };
            if (manifestKey is not null)
            {
                args.Add("-p:AgentUpdateManifestPublicKeysB64=" + Convert.ToBase64String(Encoding.UTF8.GetBytes(manifestKey.ExportSubjectPublicKeyInfoPem())));
            }

            foreach (var a in args) startInfo.ArgumentList.Add(a);

            using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start dotnet.");
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            if (!process.WaitForExit(240_000))
            {
                process.Kill(entireProcessTree: true);
                throw new TimeoutException("anchor build check did not finish within 4 minutes.");
            }

            Task.WaitAll(stdout, stderr);
            return (process.ExitCode, stdout.Result + stderr.Result);
        }
        finally
        {
            try { Directory.Delete(temp, recursive: true); } catch (IOException) { }
        }
    }
}
