using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Cerberus.Agent.Core.Tests;

// A command anchor equal to an update manifest key is dropped by AgentProfileMetadata.ParseAnchors, so the
// release script must reject it (support tier: pwsh runs only Assert-CommandAnchorsNotManifestKeys).
public sealed class ServerAnchorManifestOverlapTests
{
    [Fact]
    public void ReleaseValidation_RejectsAnAnchorThatIsTheManifestKey_NamingOnlyTheKeyId()
    {
        using var manifest = RSA.Create(2048);

        var result = Run(Anchors(manifest), ManifestPem(manifest));

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("equal an update manifest public key", result.Output);
        Assert.Contains(AgentProfileMetadata.ComputeKeyId(manifest.ExportSubjectPublicKeyInfo()), result.Output);
        Assert.DoesNotContain(Convert.ToBase64String(manifest.ExportSubjectPublicKeyInfo()), result.Output);
    }

    [Fact]
    public void ReleaseValidation_RejectsOverlapBesideADistinctAnchor_AndMatchesAnyManifestKeyInTheList()
    {
        using var manifestA = RSA.Create(2048);
        using var manifestB = RSA.Create(2048);
        using var distinct = RSA.Create(2048);

        var result = Run(Anchors(distinct, manifestB), ManifestPem(manifestA), ManifestPem(manifestB));

        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains(AgentProfileMetadata.ComputeKeyId(manifestB.ExportSubjectPublicKeyInfo()), result.Output);
        Assert.DoesNotContain(AgentProfileMetadata.ComputeKeyId(distinct.ExportSubjectPublicKeyInfo()), result.Output);
    }

    [Fact]
    public void ReleaseValidation_AcceptsAnchorsThatDifferFromEveryManifestKey()
    {
        using var manifestA = RSA.Create(2048);
        using var manifestB = RSA.Create(2048);
        using var distinct = RSA.Create(2048);

        var result = Run(Anchors(distinct), ManifestPem(manifestA), ManifestPem(manifestB));

        Assert.Equal(0, result.ExitCode);
    }

    [Fact]
    public void ReleaseScript_ChecksTheOverlapForServerBuilds()
    {
        var script = File.ReadAllText(Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "scripts", "build-agent-public-release.ps1"));

        Assert.Matches(@"if \(\$BuildProfile -eq ""server""\) \{\s*Assert-CommandAnchorsNotManifestKeys \$releaseProfile\.AnchorsB64", script);
    }

    private static string Anchors(params RSA[] keys)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Join("\n", keys.Select(k => Convert.ToBase64String(k.ExportSubjectPublicKeyInfo())))));

    // The script takes each manifest key as base64 of the PEM text.
    private static string ManifestPem(RSA key)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(key.ExportSubjectPublicKeyInfoPem()));

    private static (int ExitCode, string Output) Run(string anchorsB64, params string[] manifestKeysB64)
    {
        var lib = Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "scripts", "release-profile-lib.ps1");
        var list = string.Join(",", manifestKeysB64.Select(k => $"'{k}'"));
        var command = $"$ErrorActionPreference='Stop'; . '{lib}'; Assert-CommandAnchorsNotManifestKeys '{anchorsB64}' @({list})";
        var startInfo = new ProcessStartInfo
        {
            FileName = "pwsh",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var argument in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command })
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start pwsh.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(120_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("anchor overlap check did not finish within 2 minutes.");
        }

        Task.WaitAll(stdout, stderr);
        return (process.ExitCode, stdout.Result + stderr.Result);
    }
}
