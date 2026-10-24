# Publish and finalize helpers for scripts/build-agent-public-release.ps1.
# Dot-source only, after release-signing-lib.ps1. Loading this file has no side effects.
# No function here prompts for, accepts or logs a PIN or password.

$script:ReleaseRuntimeExecutableNames = @(
  "Cerberus.Agent.exe",
  "Cerberus.Agent.Service.exe",
  "Cerberus.Agent.Updater.exe",
  "Cerberus.Agent.Uninstall.exe"
)

function Invoke-SecretScan([string]$Path) {
  $patterns = @(
    "tskey-[A-Za-z0-9_-]{20,}",
    "headscale[_-]?(api[_-]?)?key\s*[:=]\s*['""][^'""]+['""]",
    "-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----",
    "Bearer\s+[A-Za-z0-9._~+/=-]{20,}",
    "(password|refresh_token|signing_key|private_key)\s*[:=]\s*['""][^'""]+['""]"
  )
  $hits = New-Object System.Collections.Generic.List[string]
  $files = Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch "\\(bin|obj|out|\.git|tests)\\" }
  foreach ($file in $files) {
    $text = Get-Content -Raw -LiteralPath $file.FullName -ErrorAction SilentlyContinue
    if ($null -eq $text) { continue }
    foreach ($pattern in $patterns) {
      if ($text -match $pattern) {
        $hits.Add($file.FullName)
        break
      }
    }
  }
  return $hits
}

function New-MinimalSbom([string]$RepoRoot, [string]$OutputFile) {
  $projects = Get-ChildItem -Path (Join-Path $RepoRoot "src"), (Join-Path $RepoRoot "tests") -Recurse -Filter *.csproj |
    Where-Object { $_.FullName -notmatch "\\(bin|obj)\\" }
  $packages = @()
  foreach ($project in $projects) {
    [xml]$xml = Get-Content -Raw -LiteralPath $project.FullName
    foreach ($item in $xml.Project.ItemGroup.PackageReference) {
      if ($item.Include) {
        $packages += [ordered]@{
          project = $project.FullName.Substring($RepoRoot.Length + 1)
          name = [string]$item.Include
          version = [string]$item.Version
        }
      }
    }
  }
  $sbom = [ordered]@{
    schema = "cerberus.agent.sbom.v1"
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("O")
    packages = $packages
  }
  $sbom | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputFile -Encoding utf8
}

function New-Provenance([string]$RepoRoot, [string]$OutputFile, [string]$ArtifactName, [string]$ArtifactSha) {
  $commit = (git -C $RepoRoot rev-parse HEAD 2>$null)
  $status = (git -C $RepoRoot status --short 2>$null)
  $provenance = [ordered]@{
    schema = "cerberus.agent.provenance.v1"
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("O")
    artifact = $ArtifactName
    artifact_sha256 = $ArtifactSha
    git_commit = $commit
    github_run_id = $env:GITHUB_RUN_ID
    github_run_number = $env:GITHUB_RUN_NUMBER
    github_repository = $env:GITHUB_REPOSITORY
    dirty_worktree = -not [string]::IsNullOrWhiteSpace(($status -join "`n"))
  }
  $provenance | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputFile -Encoding utf8
}

function Copy-ChannelLatestAliases(
  [string]$PublishDir,
  [string]$Channel,
  [string]$Msi,
  [string]$Zip,
  [string]$Sbom,
  [string]$Provenance,
  [string]$Manifest,
  [string]$Gate,
  [string]$MsiHash,
  [string]$ZipHash
) {
  $aliasAssetBase = "Cerberus.Agent.Bundle-$Channel-latest"
  $aliasInstallerBase = "Cerberus.Agent-$Channel-latest"
  Copy-Item -LiteralPath $Msi -Destination (Join-Path $PublishDir "$aliasInstallerBase.msi") -Force
  Copy-Item -LiteralPath $Zip -Destination (Join-Path $PublishDir "$aliasAssetBase.zip") -Force
  Copy-Item -LiteralPath $Sbom -Destination (Join-Path $PublishDir "$aliasAssetBase.sbom.json") -Force
  Copy-Item -LiteralPath $Provenance -Destination (Join-Path $PublishDir "$aliasAssetBase.provenance.json") -Force
  if (-not [string]::IsNullOrWhiteSpace($Manifest)) {
    Copy-Item -LiteralPath $Manifest -Destination (Join-Path $PublishDir "$aliasAssetBase.update-manifest.json") -Force
  }
  Copy-Item -LiteralPath $Gate -Destination (Join-Path $PublishDir "$aliasAssetBase.release-gate.json") -Force
  @(
    "$ZipHash  $aliasAssetBase.zip",
    "$MsiHash  $aliasInstallerBase.msi"
  ) | Set-Content -LiteralPath (Join-Path $PublishDir "$aliasAssetBase.sha256") -Encoding utf8
}

function Publish-ReleaseOutputs(
  [string]$PublishDir,
  [string]$Channel,
  [string]$AssetBase,
  [string]$InstallerBase,
  [System.Collections.IDictionary]$Manifest,
  [System.Collections.IDictionary]$LegacyManifest,
  [bool]$AllowUnsignedBuildMetadata,
  [bool]$Signed
) {
  $msi = Join-Path $PublishDir "$InstallerBase.msi"
  $zip = Join-Path $PublishDir "$AssetBase.zip"
  $sbom = Join-Path $PublishDir "$AssetBase.sbom.json"
  $provenance = Join-Path $PublishDir "$AssetBase.provenance.json"
  $msiHash = [string]$Manifest["sha256"]
  $zipHash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()

  $manifestPath = Join-Path $PublishDir "$AssetBase.update-manifest.v2.json"
  $Manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8
  $legacyManifestPath = ""
  if ($null -ne $LegacyManifest) {
    $legacyManifestPath = Join-Path $PublishDir "$AssetBase.update-manifest.json"
    $LegacyManifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $legacyManifestPath -Encoding utf8
  }
  Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $PublishDir "Cerberus.Agent.Bundle-$Channel-latest.update-manifest.v2.json") -Force

  $gate = [ordered]@{
    schema = "cerberus.agent.release_gate.v1"
    channel = $Channel
    manifest_schema = "agent.update.manifest.v2"
    manifest_sequence = $Manifest["sequence"]
    manifest_expires_at_utc = $Manifest["expires_at_utc"]
    signer_key_identity = $Manifest["signer_key_identity"]
    unsigned_dev_build_allowed = $AllowUnsignedBuildMetadata
    authenticode_signature_present = $Signed
    checksum_sha256 = $msiHash
    installer = [ordered]@{
      name = "$InstallerBase.msi"
      checksum_sha256 = $msiHash
      authenticode_signature_present = $Signed
      eula_consent_source = "msi_eula_dialog"
      eula_required_for_execute_sequence = $true
      headless_eula_property = "CERBERUS_EULA_ACCEPTED=1"
      consent_storage = "hklm_registry_imported_by_agent"
      launches_agent_arguments = ""
      ui_binary = "app/Cerberus.Agent.exe"
      service_binary = "app/Cerberus.Agent.Service.exe"
      updater_binary = "app/Cerberus.Agent.Updater.exe"
      uninstall_binary = "app/Cerberus.Agent.Uninstall.exe"
      powershell_custom_action_present = $false
    }
    sbom_present = (Test-Path -LiteralPath $sbom)
    provenance_present = (Test-Path -LiteralPath $provenance)
    secret_scan_hits = @()
    tenant_update_url_present = $false
    tenant_signing_key_present = $false
  }
  $gatePath = Join-Path $PublishDir "$AssetBase.release-gate.json"
  $gate | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $gatePath -Encoding utf8

  Copy-ChannelLatestAliases `
    -PublishDir $PublishDir `
    -Channel $Channel `
    -Msi $msi `
    -Zip $zip `
    -Sbom $sbom `
    -Provenance $provenance `
    -Manifest $legacyManifestPath `
    -Gate $gatePath `
    -MsiHash $msiHash `
    -ZipHash $zipHash
}

function Complete-ExternalManifestSigning(
  [string]$PublishDir,
  [string]$Channel,
  [string]$Version,
  [string]$AssetBase,
  [string]$InstallerBase,
  [string]$SignaturePath,
  [string]$PublicKeyPath,
  # Test seam only: build-agent-public-release.ps1 never passes it, so the real path always uses Assert-ReleaseFileSigned.
  [scriptblock]$FileSignatureCheck = $null
) {
  Write-Step "Verifying detached manifest signature"
  if (-not (Test-Path -LiteralPath $PublicKeyPath -PathType Leaf)) {
    throw "Manifest public key file was not found: $PublicKeyPath"
  }
  $payloadPath = Join-Path $PublishDir "$AssetBase.update-manifest.v2.payload.bin"
  $pendingPath = Join-Path $PublishDir "$AssetBase.update-manifest.v2.pending.json"
  if (-not (Test-Path -LiteralPath $pendingPath) -or -not (Test-Path -LiteralPath $payloadPath)) {
    throw "No pending manifest for $AssetBase. Run the build in token mode with -ManifestSigningPublicKeyFile first."
  }
  $pending = Get-Content -Raw -LiteralPath $pendingPath | ConvertFrom-Json
  $signature = Confirm-DetachedManifestSignature -PayloadFile $payloadPath -ExpectedPayloadSha256 $pending.payload_sha256 -SignatureFile $SignaturePath
  $canonical = [Text.UTF8Encoding]::new($false, $true).GetString([IO.File]::ReadAllBytes($payloadPath))

  # Everything below is measured from the publish directory; nothing is written until every check has passed.
  $runtimeDir = Join-Path $PublishDir "runtime"
  $trust = Get-EmbeddedReleaseTrust (Join-Path $runtimeDir "Cerberus.Agent.dll")
  $sameSet = { param($a, $b) ((@($a | Sort-Object -Unique -CaseSensitive) -join "`n") -ceq (@($b | Sort-Object -Unique -CaseSensitive) -join "`n")) }
  $pendingKeys = @($pending.public_keys_b64 | ForEach-Object { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_)).Trim() })
  if (-not (& $sameSet $pendingKeys $trust.PublicKeyPems)) {
    throw "Pending manifest keys do not match the keys embedded in the built runtime."
  }
  if (-not (& $sameSet (ConvertTo-NormalizedSignerPins @($pending.signer_pins)) $trust.SignerPins)) {
    throw "Pending signer pins do not match the signer pins embedded in the built runtime."
  }

  $expectedKey = Read-ManifestPublicKeyFile $PublicKeyPath
  $manifest = Assert-ManifestAgainstBuild `
    -Canonical $canonical -Signature $signature -ExpectedKeyPem $expectedKey -Trust $trust `
    -CoreAssembly (Join-Path $runtimeDir "Cerberus.Agent.Core.dll") -Channel $Channel -ArtifactPrefixes @($pending.allowed_artifact_prefixes)
  if ($manifest["version"] -cne $Version) { throw "Pending manifest version does not match -Version." }

  $msi = Join-Path $PublishDir "$InstallerBase.msi"
  if (-not (Test-Path -LiteralPath $msi -PathType Leaf)) { throw "MSI installer was not found: $msi" }
  if ((Get-FileHash -Algorithm SHA256 -LiteralPath $msi).Hash.ToLowerInvariant() -cne ([string]$manifest["sha256"]).ToLowerInvariant()) {
    throw "MSI hash does not match the signed payload."
  }
  if ((Get-Item -LiteralPath $msi).Length -ne [long]$manifest["artifact_length"]) {
    throw "MSI length does not match the signed payload."
  }

  $check = if ($null -ne $FileSignatureCheck) { $FileSignatureCheck } else { { param($Path, $AllowedPins) Assert-ReleaseFileSigned -Path $Path -AllowedPins $AllowedPins } }
  $signedFiles = @($script:ReleaseRuntimeExecutableNames | ForEach-Object { Join-Path $runtimeDir $_ }) + @($msi)
  $verified = 0
  foreach ($file in $signedFiles) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Expected signed file was not found: $file" }
    & $check $file @($trust.SignerPins)
    $verified++
  }
  $signed = ($verified -eq $signedFiles.Count)

  Publish-ReleaseOutputs `
    -PublishDir $PublishDir -Channel $Channel -AssetBase $AssetBase -InstallerBase $InstallerBase `
    -Manifest $manifest -LegacyManifest $null -AllowUnsignedBuildMetadata $false -Signed $signed
  Remove-Item -LiteralPath $payloadPath, $pendingPath -Force
  Write-Step "Release bundle ready: $PublishDir"
}
