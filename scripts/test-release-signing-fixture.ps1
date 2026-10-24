# Fixture helpers for scripts/test-release-signing.ps1 (dot-source only; no side effects on load).
# Builds a publish directory that finalize can measure: an assembly carrying only AssemblyMetadata,
# placeholder runtime executables, a Core assembly copy, a fixture MSI and a matching pending payload.

function New-MetadataAssembly([string]$Path, [string]$KeysB64List, [string]$SignerPins) {
  $builder = [System.Reflection.Emit.PersistedAssemblyBuilder]::new([Reflection.AssemblyName]::new("Cerberus.Agent"), [object].Assembly)
  $ctor = [Reflection.AssemblyMetadataAttribute].GetConstructor([type[]]@([string], [string]))
  foreach ($pair in @(@("AgentUpdateManifestPublicKeysB64", $KeysB64List), @("AgentUpdateAllowedSignerKeyIdentity", $SignerPins), @("AgentReleaseChannel", "stable"))) {
    $builder.SetCustomAttribute([Reflection.Emit.CustomAttributeBuilder]::new($ctor, [object[]]@($pair[0], $pair[1])))
  }
  $null = $builder.DefineDynamicModule("Cerberus.Agent")
  $builder.Save($Path)
}

function New-FinalizeFixture {
  param(
    [Parameter(Mandatory = $true)][string]$PublishDir,
    [Parameter(Mandatory = $true)][string]$CoreDll,
    [Parameter(Mandatory = $true)][string[]]$KeyListB64,
    [Parameter(Mandatory = $true)][string]$SignerPin,
    [Parameter(Mandatory = $true)][string]$Prefix,
    [string]$PayloadVersion = "9.9.9",
    [long]$LengthDelta = 0
  )
  $runtime = Join-Path $PublishDir "runtime"
  New-Item -ItemType Directory -Path $runtime -Force | Out-Null
  Copy-Item -LiteralPath $CoreDll -Destination (Join-Path $runtime "Cerberus.Agent.Core.dll")
  New-MetadataAssembly (Join-Path $runtime "Cerberus.Agent.dll") ($KeyListB64 -join ",") $SignerPin
  foreach ($exe in $script:ReleaseRuntimeExecutableNames) { Set-Content -LiteralPath (Join-Path $runtime $exe) -Value "fixture $exe" }
  $msi = Join-Path $PublishDir "Cerberus.Agent-stable-9.9.9.msi"
  Set-Content -LiteralPath $msi -Value "fixture msi bytes"
  foreach ($file in @("Cerberus.Agent.Bundle-stable-9.9.9.zip", "Cerberus.Agent.Bundle-stable-9.9.9.sbom.json", "Cerberus.Agent.Bundle-stable-9.9.9.provenance.json")) {
    Set-Content -LiteralPath (Join-Path $PublishDir $file) -Value "fixture $file"
  }
  $now = [DateTimeOffset]::UtcNow
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $msi).Hash.ToLowerInvariant()
  $length = (Get-Item -LiteralPath $msi).Length + $LengthDelta
  $canonical = @("msi", $PayloadVersion, "stable", "${Prefix}a.msi", $hash, "Cerberus Agent Release", $now.AddMinutes(-1).ToString("O"),
    "agent.heartbeat.v1", "false", "agent.update.manifest.v2", $now.ToUnixTimeMilliseconds().ToString(), $now.AddDays(30).ToString("O"),
    $length.ToString(), $SignerPin) -join "`n"
  Write-PendingExternalManifest -PublishDir $PublishDir -AssetBase "Cerberus.Agent.Bundle-stable-9.9.9" -Canonical $canonical `
    -KeyListB64 $KeyListB64 -ArtifactPrefixes @($Prefix) -SignerPins @($SignerPin) 6>$null
  return [pscustomobject]@{ Publish = $PublishDir; Msi = $msi; Canonical = $canonical }
}
