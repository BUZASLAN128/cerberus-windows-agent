using System.Diagnostics;

namespace Cerberus.Agent.Core.Tests;

public sealed partial class AgentUpdaterContractTests
{
    [Fact]
    public async Task SourceLockGate_OnFixtureFiles()
    {
        var work = Path.Combine(Path.GetTempPath(), "cerberus-updater-gate-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(work);
        try
        {
            SyntheticSingleFileBundle.Write(Path.Combine(work, "managed.exe"),
                ("managed.dll", 1), ("app.deps.json", 3), ("app.runtimeconfig.json", 4), ("managed.pdb", 5));
            (string Name, byte Kind)[] frameworkNatives =
            [
                ("D3DCompiler_47_cor3.dll", 2), ("PenImc_cor3.dll", 2), ("PresentationNative_cor3.dll", 2),
                ("vcruntime140_cor3.dll", 2), ("wpfgfx_cor3.dll", 2),
            ];
            SyntheticSingleFileBundle.Write(Path.Combine(work, "app.exe"), frameworkNatives);
            SyntheticSingleFileBundle.Write(Path.Combine(work, "app-extra.exe"), [.. frameworkNatives, ("other.dll", 2)]);
            SyntheticSingleFileBundle.Write(Path.Combine(work, "app-unknown.exe"), ("D3DCompiler_47_cor3.dll", 0));
            SyntheticSingleFileBundle.Write(Path.Combine(work, "service-native.exe"), ("PenImc_cor3.dll", 2));
            SyntheticSingleFileBundle.Write(Path.Combine(work, "updater-native.exe"), ("wpfgfx_cor3.dll", 2));
            SyntheticSingleFileBundle.Write(Path.Combine(work, "updater-unknown.exe"), ("unknown.dll", 0));

            var script = Path.Combine(work, "gate.ps1");
            await File.WriteAllTextAsync(script, GateChecks);
            var startInfo = new ProcessStartInfo("pwsh")
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            foreach (var arg in new[]
                     {
                         "-NoLogo", "-NoProfile", "-NonInteractive", "-File", script,
                         "-Repo", ServerPackageStaticTests.FindRepoRoot(), "-Work", work,
                     })
                startInfo.ArgumentList.Add(arg);

            using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start pwsh.");
            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            try { await process.WaitForExitAsync(timeout.Token); }
            catch (OperationCanceledException) { process.Kill(entireProcessTree: true); throw; }
            var output = await stdout;
            Assert.True(process.ExitCode == 0, $"exit {process.ExitCode}\n{output}\n{await stderr}");
            Assert.Contains("C1 gate fixtures passed", output);
        }
        finally
        {
            Directory.Delete(work, recursive: true);
        }
    }

    private const string GateChecks = """
        param([string]$Repo, [string]$Work)
        $ErrorActionPreference = 'Stop'
        . (Join-Path $Repo 'scripts/release-trust-lib.ps1')
        . (Join-Path $Repo 'scripts/test-release-signing-fixture.ps1')

        function Refuses([scriptblock]$Check, [string]$ErrorPattern) {
          try { & $Check | Out-Null } catch { if ($_.Exception.Message -match $ErrorPattern) { return }; throw }
          throw "Expected refusal matching: $ErrorPattern"
        }

        $root = Join-Path $Work 'source'
        $core = Join-Path $root 'src/Cerberus.Agent.Update.Core'
        $updater = Join-Path $root 'src/Cerberus.Agent.Updater'
        $null = New-Item -ItemType Directory -Path $core, $updater -Force
        Set-Content -LiteralPath (Join-Path $root 'Directory.Build.props') -Value '<Project />' -Encoding utf8
        Set-Content -LiteralPath (Join-Path $core 'AgentUpdaterContract.cs') -Value '    public const string Version = "1";' -Encoding utf8
        $tracked = Join-Path $updater 'UpdaterLab.Release.cs'
        $lf = [char]10
        $crlf = [string][char]13 + $lf
        [IO.File]::WriteAllText($tracked, "trusted$($lf)source$lf")
        $fingerprint = Get-UpdaterSourceFingerprint $root
        [IO.File]::WriteAllText($tracked, "trusted$($crlf)source$crlf", [Text.UTF8Encoding]::new($true))
        Set-Content -LiteralPath (Join-Path $updater 'UpdaterLab.Runtime.cs') -Value 'excluded runtime source'
        $obj = Join-Path $updater 'obj-fixture'
        $null = New-Item -ItemType Directory -Path $obj
        Set-Content -LiteralPath (Join-Path $obj 'generated.cs') -Value 'excluded generated source'
        if ((Get-UpdaterSourceFingerprint $root) -cne $fingerprint) { throw 'Fingerprint changed on normalization or exclusions.' }
        $lock = Join-Path $core 'updater-contract.lock'
        $older = 'a' * 64
        Set-Content -LiteralPath $lock -Value @("1 $older", "1 $fingerprint")
        if ((Assert-UpdaterSourceLock $root) -ne 1) { throw 'Expected lock version 1.' }
        Add-Content -LiteralPath $tracked -Value 'different'
        Refuses { Assert-UpdaterSourceLock $root } 'fingerprint does not match'
        [IO.File]::WriteAllText($tracked, "trusted$($lf)source$lf")
        Set-Content -LiteralPath $lock -Value @("2 $older", "1 $fingerprint")
        Refuses { Assert-UpdaterSourceLock $root } 'versions decrease'
        Set-Content -LiteralPath $lock -Value @("1 $fingerprint", "1 $fingerprint")
        Refuses { Assert-UpdaterSourceLock $root } 'duplicate fingerprint'
        Set-Content -LiteralPath $lock -Value "2 $fingerprint"
        Refuses { Assert-UpdaterSourceLock $root } 'differs from source'
        Set-Content -LiteralPath $lock -Value "1 $fingerprint"

        Assert-UpdaterBundleHasNoNativeEntries (Join-Path $Work 'managed.exe')
        Assert-ServerAgentBundleEntryKinds (Join-Path $Work 'app.exe')
        Refuses { Assert-ServerAgentBundleEntryKinds (Join-Path $Work 'app-extra.exe') } 'disallowed entry kind 2: other.dll'
        Refuses { Assert-ServerAgentBundleEntryKinds (Join-Path $Work 'app-unknown.exe') } 'disallowed entry kind 0'
        Refuses { Assert-UpdaterBundleHasNoNativeEntries (Join-Path $Work 'service-native.exe') } 'disallowed entry kind 2'
        Refuses { Assert-UpdaterBundleHasNoNativeEntries (Join-Path $Work 'updater-native.exe') } 'disallowed entry kind 2'
        Refuses { Assert-UpdaterBundleHasNoNativeEntries (Join-Path $Work 'updater-unknown.exe') } 'disallowed entry kind 0'

        $runtime = Join-Path $Work 'runtime'
        $null = New-Item -ItemType Directory -Path $runtime
        $agent = Join-Path $runtime 'Cerberus.Agent.dll'
        $updaterAssembly = Join-Path $runtime 'Cerberus.Agent.Updater.dll'
        $updateCore = Join-Path $runtime 'Cerberus.Agent.Update.Core.dll'
        $deps = Join-Path $runtime 'Cerberus.Agent.Updater.deps.json'
        Set-Content -LiteralPath $deps -Value '{"libraries":{"Cerberus.Agent.Updater/1.0":{},"Cerberus.Agent.Update.Core/1.0":{}}}'
        $rsa = [Security.Cryptography.RSA]::Create(2048)
        $otherRsa = [Security.Cryptography.RSA]::Create(2048)
        try {
          $key = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($rsa.ExportSubjectPublicKeyInfoPem()))
          $otherKey = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($otherRsa.ExportSubjectPublicKeyInfoPem()))
        } finally { $rsa.Dispose(); $otherRsa.Dispose() }
        $trust = @(Get-TrustPairs -Keys @($key) -Pins @('unsigned-dev') -Prefix 'https://example.test/' -Channel dev) +
          ,@('AgentUpdateManifestUrl', 'https://example.test/manifest.json') + ,@('AllowUnsignedDevBuild', 'true')
        function Make-Updater($Pairs) {
          New-MetadataAssembly -Path $updaterAssembly -AssemblyName 'Cerberus.Agent.Updater' -Pairs $Pairs
        }
        function Make-Core([string]$Version) {
          $pairs = @(@('AgentUpdaterContractVersion', $Version), @('BackendTrustAnchors', 'AA==,AQ=='))
          New-MetadataAssembly -Path $updateCore -AssemblyName 'Cerberus.Agent.Update.Core' -Pairs $pairs
        }
        New-MetadataAssembly -Path $agent -AssemblyName 'Cerberus.Agent' -Pairs $trust
        Make-Updater $trust
        Make-Core '1'
        Assert-UpdaterBuildContract $runtime desktop $root $false 'AA==%2CAQ=='
        Assert-FinalUpdaterContract $runtime $root
        Refuses { Assert-UpdaterBuildContract $runtime desktop $root $false '' } 'BackendTrustAnchors differ'
        Make-Core '2'
        Refuses { Assert-UpdaterBuildContract $runtime desktop $root $false 'AA==%2CAQ==' } 'differs from expected version'
        Refuses { Assert-FinalUpdaterContract $runtime $root } 'differs from expected version'
        Make-Core 'non-integer'
        Refuses { Assert-FinalUpdaterContract $runtime $root } 'positive updater contract version'

        Set-Content -LiteralPath $deps -Value '{"libraries":{"Cerberus.Agent.Updater/1.0":{},"Cerberus.Agent.Update.Core/1.0":{},"Cerberus.Agent.Runtime/1.0":{}}}'
        Make-Core '1'
        Refuses { Assert-UpdaterBuildContract $runtime desktop $root $false 'AA==%2CAQ==' } 'forbidden dependency'
        Make-Core '2'
        Assert-UpdaterBuildContract $runtime desktop $root $true 'AA==%2CAQ=='

        $changes = [ordered]@{
          AgentUpdateManifestPublicKeysB64 = @($otherKey, 'PublicKeyPems')
          AgentUpdateAllowedArtifactPrefixes = @('https://other.example/', 'ArtifactPrefixes')
          AgentReleaseChannel = @('stable', 'release channels')
          AgentUpdateManifestUrl = @('https://example.test/other.json', 'update manifest URLs')
        }
        foreach ($change in $changes.GetEnumerator()) {
          $changed = @($trust | ForEach-Object {
            if ($_[0] -ceq $change.Key) { ,@($_[0], $change.Value[0]) } else { ,$_ }
          })
          Make-Updater $changed
          Refuses { Assert-UpdaterBuildContract $runtime desktop $root $true 'AA==%2CAQ==' } "different $($change.Value[1])"
        }

        Write-Output 'C1 gate fixtures passed'
        """;
}
