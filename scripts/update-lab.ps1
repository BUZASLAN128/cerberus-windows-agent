param(
  [Parameter(Mandatory = $true)]
  [string]$OldVersion,

  [Parameter(Mandatory = $true)]
  [string]$TargetVersion,

  [ValidateSet("dev", "preview", "stable")]
  [string]$Channel = "dev",

  [string]$Owner = "BUZASLAN128",
  [string]$Repo = "cerberus-windows-agent",
  [string]$BindAddress = "127.0.0.1",
  [int]$Port = 8899,
  [string]$OutputRoot = "out/update-lab",
  [string]$PythonCommand = "py",
  [switch]$NoBuild,
  [switch]$NoServe
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
  Write-Host "==> $Message"
}

function Get-AssetBase([string]$Version) {
  return "Cerberus.Agent.Bundle-$Channel-$Version"
}

function Get-InstallerBase([string]$Version) {
  return "Cerberus.Agent-$Channel-$Version"
}

function ConvertTo-Base64Utf8([string]$Value) {
  return [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Value.Trim()))
}

function Copy-ReleaseAssets([string]$Version, [string]$BuildPublishDir, [string]$ReleaseDir) {
  New-Item -ItemType Directory -Force -Path $ReleaseDir | Out-Null
  Copy-Item -Path (Join-Path $BuildPublishDir "*") -Destination $ReleaseDir -Force
  $assetBase = Get-AssetBase $Version
  $installerBase = Get-InstallerBase $Version
  foreach ($required in @(
      "$installerBase.msi",
      "$assetBase.update-manifest.json",
      "$assetBase.sha256"
    )) {
    $path = Join-Path $ReleaseDir $required
    if (-not (Test-Path -LiteralPath $path)) {
      throw "Update lab release asset is missing: $path"
    }
  }
}

function Get-CanonicalManifestPayload([pscustomobject]$Manifest) {
  return @(
    ([string]$Manifest.artifact_kind).ToLowerInvariant(),
    [string]$Manifest.version,
    [string]$Manifest.channel,
    [string]$Manifest.artifact_url,
    ([string]$Manifest.sha256).ToLowerInvariant(),
    [string]$Manifest.signing_identity,
    [string]$Manifest.released_at_utc,
    [string]$Manifest.minimum_protocol_version,
    $(if ([bool]$Manifest.rollback_allowed) { "true" } else { "false" })
  ) -join "`n"
}

function Test-ManifestSignature([string]$ManifestPath, [string]$PublicKeyPem) {
  $manifest = Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json
  $rsa = [Security.Cryptography.RSA]::Create()
  $rsa.ImportFromPem($PublicKeyPem)
  $payload = [Text.Encoding]::UTF8.GetBytes((Get-CanonicalManifestPayload $manifest))
  $signature = [Convert]::FromBase64String([string]$manifest.signature)
  return $rsa.VerifyData(
    $payload,
    $signature,
    [Security.Cryptography.HashAlgorithmName]::SHA256,
    [Security.Cryptography.RSASignaturePadding]::Pkcs1)
}

function Set-ManifestSignature([string]$ManifestPath, [string]$PrivateKeyPem) {
  $manifest = Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json
  $rsa = [Security.Cryptography.RSA]::Create()
  $rsa.ImportFromPem($PrivateKeyPem)
  $signature = $rsa.SignData(
    [Text.Encoding]::UTF8.GetBytes((Get-CanonicalManifestPayload $manifest)),
    [Security.Cryptography.HashAlgorithmName]::SHA256,
    [Security.Cryptography.RSASignaturePadding]::Pkcs1)
  $manifest.signature = [Convert]::ToBase64String($signature)
  $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $ManifestPath -Encoding utf8
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$labRoot = Join-Path $repoRoot $OutputRoot
$buildRoot = Join-Path $labRoot "builds"
$webRoot = Join-Path $labRoot "www"
$stateDir = Join-Path $labRoot "state"
$downloadPath = "$Owner/$Repo/releases/download"
$baseDownloadUrl = "http://$BindAddress`:$Port/$downloadPath"
$latestTag = "$Channel-latest"
$oldTag = "v$OldVersion"
$targetTag = "v$TargetVersion"
$oldReleaseDir = Join-Path $webRoot "$downloadPath/$oldTag"
$targetReleaseDir = Join-Path $webRoot "$downloadPath/$targetTag"
$latestReleaseDir = Join-Path $webRoot "$downloadPath/$latestTag"

New-Item -ItemType Directory -Force -Path $labRoot, $buildRoot, $webRoot, $stateDir | Out-Null

$privateKeyPath = Join-Path $stateDir "manifest-signing-private.pem"
$publicKeyPath = Join-Path $stateDir "manifest-signing-public.pem"
if (-not (Test-Path -LiteralPath $privateKeyPath)) {
  Write-Step "Generating update-lab manifest signing key"
  $rsa = [Security.Cryptography.RSA]::Create(3072)
  $rsa.ExportPkcs8PrivateKeyPem() | Set-Content -LiteralPath $privateKeyPath -Encoding ascii
  $rsa.ExportSubjectPublicKeyInfoPem() | Set-Content -LiteralPath $publicKeyPath -Encoding ascii
} elseif (-not (Test-Path -LiteralPath $publicKeyPath)) {
  $rsa = [Security.Cryptography.RSA]::Create()
  $rsa.ImportFromPem((Get-Content -Raw -LiteralPath $privateKeyPath))
  $rsa.ExportSubjectPublicKeyInfoPem() | Set-Content -LiteralPath $publicKeyPath -Encoding ascii
}

$privateKeyPem = Get-Content -Raw -LiteralPath $privateKeyPath
$publicKeyPem = Get-Content -Raw -LiteralPath $publicKeyPath
$publicKeyB64 = ConvertTo-Base64Utf8 $publicKeyPem

if (-not $NoBuild) {
  foreach ($version in @($OldVersion, $TargetVersion)) {
    Write-Step "Building local GitHub-compatible release $version"
    $versionBuildRoot = Join-Path $buildRoot $version
    $versionBuildOutputRoot = Join-Path $OutputRoot "builds/$version"
    Remove-Item -LiteralPath $versionBuildRoot -Recurse -Force -ErrorAction SilentlyContinue

    $oldPrivateKey = $env:AGENT_UPDATE_MANIFEST_PRIVATE_KEY_PEM
    $oldPublicKey = $env:CERBERUS_AGENT_UPDATE_MANIFEST_PUBLIC_KEY_B64
    $oldAllowedPrefixes = $env:CERBERUS_AGENT_UPDATE_ALLOWED_ARTIFACT_PREFIXES
    $oldArtifactBase = $env:AGENT_RELEASE_ARTIFACT_BASE_URL
    $oldGithubRepository = $env:GITHUB_REPOSITORY
    try {
      $env:AGENT_UPDATE_MANIFEST_PRIVATE_KEY_PEM = $privateKeyPem
      $env:CERBERUS_AGENT_UPDATE_MANIFEST_PUBLIC_KEY_B64 = $publicKeyB64
      $env:CERBERUS_AGENT_UPDATE_ALLOWED_ARTIFACT_PREFIXES = "$baseDownloadUrl/"
      $env:AGENT_RELEASE_ARTIFACT_BASE_URL = "$baseDownloadUrl/v$version"
      $env:GITHUB_REPOSITORY = "$Owner/$Repo"

      & (Join-Path $repoRoot "scripts/build-agent-public-release.ps1") `
        -Version $version `
        -Channel $Channel `
        -OutputRoot $versionBuildOutputRoot `
        -AllowUnsignedDevBuild `
        -AllowEphemeralManifestKey `
        -SkipTests
    } finally {
      $env:AGENT_UPDATE_MANIFEST_PRIVATE_KEY_PEM = $oldPrivateKey
      $env:CERBERUS_AGENT_UPDATE_MANIFEST_PUBLIC_KEY_B64 = $oldPublicKey
      $env:CERBERUS_AGENT_UPDATE_ALLOWED_ARTIFACT_PREFIXES = $oldAllowedPrefixes
      $env:AGENT_RELEASE_ARTIFACT_BASE_URL = $oldArtifactBase
      $env:GITHUB_REPOSITORY = $oldGithubRepository
    }
  }
}

Write-Step "Publishing local GitHub-compatible release tree"
Remove-Item -LiteralPath $oldReleaseDir, $targetReleaseDir, $latestReleaseDir -Recurse -Force -ErrorAction SilentlyContinue
$oldPublishDir = Join-Path $buildRoot "$OldVersion/publish"
$targetPublishDir = Join-Path $buildRoot "$TargetVersion/publish"
$oldAssetBase = Get-AssetBase $OldVersion
$targetAssetBase = Get-AssetBase $TargetVersion
Set-ManifestSignature -ManifestPath (Join-Path $oldPublishDir "$oldAssetBase.update-manifest.json") -PrivateKeyPem $privateKeyPem
Set-ManifestSignature -ManifestPath (Join-Path $oldPublishDir "Cerberus.Agent.Bundle-$Channel-latest.update-manifest.json") -PrivateKeyPem $privateKeyPem
Set-ManifestSignature -ManifestPath (Join-Path $targetPublishDir "$targetAssetBase.update-manifest.json") -PrivateKeyPem $privateKeyPem
Set-ManifestSignature -ManifestPath (Join-Path $targetPublishDir "Cerberus.Agent.Bundle-$Channel-latest.update-manifest.json") -PrivateKeyPem $privateKeyPem
Copy-ReleaseAssets -Version $OldVersion -BuildPublishDir $oldPublishDir -ReleaseDir $oldReleaseDir
Copy-ReleaseAssets -Version $TargetVersion -BuildPublishDir $targetPublishDir -ReleaseDir $targetReleaseDir
Copy-ReleaseAssets -Version $TargetVersion -BuildPublishDir $targetPublishDir -ReleaseDir $latestReleaseDir

$oldManifestPath = Join-Path $oldReleaseDir "$oldAssetBase.update-manifest.json"
$targetManifestPath = Join-Path $targetReleaseDir "$targetAssetBase.update-manifest.json"
$latestManifestPath = Join-Path $latestReleaseDir "Cerberus.Agent.Bundle-$Channel-latest.update-manifest.json"
if (-not (Test-ManifestSignature -ManifestPath $oldManifestPath -PublicKeyPem $publicKeyPem)) {
  throw "Old manifest signature does not verify with update-lab public key."
}
if (-not (Test-ManifestSignature -ManifestPath $targetManifestPath -PublicKeyPem $publicKeyPem)) {
  throw "Target manifest signature does not verify with update-lab public key."
}
if (-not (Test-ManifestSignature -ManifestPath $latestManifestPath -PublicKeyPem $publicKeyPem)) {
  throw "Latest manifest signature does not verify with update-lab public key."
}

$serverPidPath = Join-Path $stateDir "server.pid"
if (-not $NoServe) {
  $existing = $null
  if (Test-Path -LiteralPath $serverPidPath) {
    $existingPid = (Get-Content -Raw -LiteralPath $serverPidPath).Trim()
    if ($existingPid) {
      $existing = Get-Process -Id ([int]$existingPid) -ErrorAction SilentlyContinue
    }
  }

  if ($existing) {
    Write-Step "Update lab server already running: pid $($existing.Id)"
  } else {
    Write-Step "Starting update lab server on http://$BindAddress`:$Port"
    $server = Start-Process `
      -FilePath $PythonCommand `
      -ArgumentList @("-m", "http.server", "$Port", "--bind", $BindAddress, "--directory", $webRoot) `
      -WindowStyle Hidden `
      -PassThru
    $server.Id | Set-Content -LiteralPath $serverPidPath -Encoding ascii
    Start-Sleep -Seconds 1
  }
}

$backendEnvPath = Join-Path $stateDir "backend-update-env.ps1"
@"
`$env:AGENT_UPDATE_CHANNEL = "$Channel"
`$env:AGENT_LATEST_RECOMMENDED_VERSION = "$TargetVersion"
`$env:AGENT_UPDATE_MANIFEST_URL = "$baseDownloadUrl/$latestTag/Cerberus.Agent.Bundle-$Channel-latest.update-manifest.json"
`$env:AGENT_UPDATE_ALLOWED_ARTIFACT_URL_PREFIXES = "$baseDownloadUrl/"
`$env:AGENT_UPDATE_MANIFEST_PUBLIC_KEY_PEM = @'
$($publicKeyPem.Trim())
'@
"@ | Set-Content -LiteralPath $backendEnvPath -Encoding utf8

$agentEnvPath = Join-Path $stateDir "agent-update-env.ps1"
@"
`$env:CERBERUS_AGENT_UPDATE_MANIFEST_URL = "$baseDownloadUrl/$latestTag/Cerberus.Agent.Bundle-$Channel-latest.update-manifest.json"
`$env:AGENT_UPDATE_MANIFEST_URL = "$baseDownloadUrl/$latestTag/Cerberus.Agent.Bundle-$Channel-latest.update-manifest.json"
`$env:CERBERUS_AGENT_UPDATE_ALLOWED_ARTIFACT_PREFIXES = "$baseDownloadUrl/"
`$env:CERBERUS_AGENT_UPDATE_MANIFEST_PUBLIC_KEY_B64 = "$publicKeyB64"
"@ | Set-Content -LiteralPath $agentEnvPath -Encoding utf8

$commandPayloadPath = Join-Path $stateDir "agent-update-request-command.json"
$commandPayload = [ordered]@{
  schema_version = "agent.update.request.v1"
  campaign_id = "update-lab-$Channel-$TargetVersion"
  mode = "stage_and_prompt"
  target_version = $TargetVersion
  channel = $Channel
  manifest_url = "$baseDownloadUrl/$latestTag/Cerberus.Agent.Bundle-$Channel-latest.update-manifest.json"
  reason = "update_lab_acceptance"
  jitter_seconds = 600
}
$commandPayload | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $commandPayloadPath -Encoding utf8

$acceptanceNotesPath = Join-Path $stateDir "acceptance-notes.md"
@"
# Cerberus Agent Update Lab

This lab prepares signed local update artifacts and support files only. It does not install, uninstall, publish, or force an update.

Generated files:

- Backend env: $backendEnvPath
- Agent env: $agentEnvPath
- Command payload: $commandPayloadPath
- Expected agent state file: %ProgramData%\CerberusAgent\updates\update-state.json
- Expected updater result file: %ProgramData%\CerberusAgent\updates\update-result.json

Suggested support flow:

1. Source the backend env file before starting the backend used for update request testing.
2. Source the agent env file in the agent process environment for local signed manifest checks.
3. Enqueue agent.update.request with the generated command payload through the existing portal/API command path.
4. Verify heartbeat update_status stores agent:update_status:{agent_id} and the portal/API projection shows the same state.
5. Treat unit/API checks as support evidence. Do not claim public-agent acceptance without a real installed-agent path.
"@ | Set-Content -LiteralPath $acceptanceNotesPath -Encoding utf8

$summary = [ordered]@{
  schema = "cerberus.agent.update_lab.v1"
  web_root = $webRoot
  base_download_url = $baseDownloadUrl
  old_version = $OldVersion
  target_version = $TargetVersion
  old_msi_url = "$baseDownloadUrl/$oldTag/$(Get-InstallerBase $OldVersion).msi"
  target_msi_url = "$baseDownloadUrl/$targetTag/$(Get-InstallerBase $TargetVersion).msi"
  manifest_url = "$baseDownloadUrl/$latestTag/Cerberus.Agent.Bundle-$Channel-latest.update-manifest.json"
  backend_env = $backendEnvPath
  agent_env = $agentEnvPath
  command_payload = $commandPayloadPath
  update_state_path = "%ProgramData%\CerberusAgent\updates\update-state.json"
  update_result_path = "%ProgramData%\CerberusAgent\updates\update-result.json"
  acceptance_notes = $acceptanceNotesPath
  server_pid_file = if ($NoServe) { $null } else { $serverPidPath }
}

$summaryPath = Join-Path $stateDir "summary.json"
$summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $summaryPath -Encoding utf8
$summary | ConvertTo-Json -Depth 4
