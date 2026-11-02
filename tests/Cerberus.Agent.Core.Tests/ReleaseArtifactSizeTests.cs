using Cerberus.Agent.Core;

namespace Cerberus.Agent.Core.Tests;

public sealed class ReleaseArtifactSizeTests
{
    [Fact]
    public void GuardUsesCompiledDefaultAndRejectsEmptyAndOversizedMsi()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-size-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            File.Copy(typeof(AgentUpdateTrust).Assembly.Location, Path.Combine(root, "Cerberus.Agent.Core.dll"));
            var expected = (long)typeof(AgentUpdateTrust).GetConstructors()
                .SelectMany(c => c.GetParameters()).Single(p => p.Name == "MaxArtifactBytes").DefaultValue!;
            var repo = ServerPackageStaticTests.FindRepoRoot();
            var lib = Path.Combine(repo, "scripts", "release-size-lib.ps1");
            var command = $$"""
                $ErrorActionPreference='Stop'; . '{{lib}}'; $r='{{root}}';
                $limit=Get-ReleaseArtifactByteLimit $r;
                if($limit -ne {{expected}}){throw 'compiled limit mismatch'};
                $f=[IO.File]::Create((Join-Path $r 'sample.msi'));
                try {
                  $f.SetLength($limit); $f.Dispose();
                  Assert-ReleaseArtifactSize (Join-Path $r 'sample.msi') $r;
                  foreach($length in @(0,($limit+1))) {
                    $f=[IO.File]::OpenWrite((Join-Path $r 'sample.msi')); $f.SetLength($length); $f.Dispose();
                    $denied=$false; try { Assert-ReleaseArtifactSize (Join-Path $r 'sample.msi') $r } catch {$denied=$true};
                    if(-not $denied){throw 'invalid artifact accepted'};
                  }
                } finally {$f.Dispose()}; 'passed'
                """;
            var run = ServerPackageStaticTests.RunPwsh(command);
            Assert.True(run.ExitCode == 0, run.Output);
            Assert.Contains("passed", run.Output);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public void GuardRejectsMissingOrCorruptRuntimeLimit()
    {
        var root = Path.Combine(Path.GetTempPath(), "cerberus-size-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            File.WriteAllText(Path.Combine(root, "Cerberus.Agent.Core.dll"), "invalid PE");
            var lib = Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "scripts", "release-size-lib.ps1");
            var run = ServerPackageStaticTests.RunPwsh($"$ErrorActionPreference='Stop'; . '{lib}'; Get-ReleaseArtifactByteLimit '{root}'");
            Assert.NotEqual(0, run.ExitCode);
        }
        finally { Directory.Delete(root, recursive: true); }
    }

    [Fact]
    public void MsiGuardPrecedesSigningAndChecksSignedLength()
    {
        var source = File.ReadAllText(Path.Combine(ServerPackageStaticTests.FindRepoRoot(), "scripts", "build-agent-public-release.ps1"));
        var guard = source.IndexOf("Assert-ReleaseArtifactSize $msi $runtimePublishDir", StringComparison.Ordinal);
        Assert.True(guard > source.IndexOf("MSI installer was not produced:", StringComparison.Ordinal));
        Assert.True(guard < source.IndexOf("Write-Step \"Signing MSI installer\"", StringComparison.Ordinal));
        var final = source.LastIndexOf("Assert-ReleaseArtifactSize $msi $runtimePublishDir", StringComparison.Ordinal);
        Assert.True(final > source.IndexOf("-Stage PostSign", StringComparison.Ordinal));
        Assert.True(final < source.IndexOf("$msiHash =", StringComparison.Ordinal));
    }
}
