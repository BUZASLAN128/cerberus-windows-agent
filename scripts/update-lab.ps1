param(
  [Parameter(Mandatory = $true)]
  [string]$OldVersion,

  [Parameter(Mandatory = $true)]
  [string]$TargetVersion,

  [ValidateSet("dev", "preview", "stable")]
  [string]$Channel = "dev",

  [Parameter(Mandatory = $true)]
  [string]$HttpsBaseUrl,

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
if (-not [Uri]::IsWellFormedUriString($HttpsBaseUrl, [UriKind]::Absolute) -or ([Uri]$HttpsBaseUrl).Scheme -ne "https") { throw "An externally provisioned trusted HTTPS lab endpoint is required." }
if ($Channel -ne "dev") { throw "Unsigned lab builds are restricted to dev." }

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
      "$assetBase.update-manifest.v2.json",
      "$assetBase.sha256"
    )) {
    $path = Join-Path $ReleaseDir $required
    if (-not (Test-Path -LiteralPath $path)) {
      throw "Update lab release asset is missing: $path"
    }
  }
}

function Get-ManifestJsonNode([string]$ManifestPath) {
  $json = Get-Content -Raw -LiteralPath $ManifestPath
  $node = [System.Text.Json.Nodes.JsonNode]::Parse($json)
  Write-Output -NoEnumerate $node
}

function Get-ManifestString([System.Text.Json.Nodes.JsonNode]$Manifest, [string]$Name) {
  $value = $Manifest[$Name]
  if ($null -eq $value) {
    throw "Update manifest field is missing: $Name"
  }
  return $value.GetValue[string]()
}

function Get-ManifestBool([System.Text.Json.Nodes.JsonNode]$Manifest, [string]$Name) {
  $value = $Manifest[$Name]
  if ($null -eq $value) {
    throw "Update manifest field is missing: $Name"
  }
  return $value.GetValue[bool]()
}

function Get-CanonicalManifestPayload([System.Text.Json.Nodes.JsonNode]$Manifest) {
  return @(
    (Get-ManifestString $Manifest "artifact_kind").ToLowerInvariant(),
    (Get-ManifestString $Manifest "version"),
    (Get-ManifestString $Manifest "channel"),
    (Get-ManifestString $Manifest "artifact_url"),
    (Get-ManifestString $Manifest "sha256").ToLowerInvariant(),
    (Get-ManifestString $Manifest "signing_identity"),
    (Get-ManifestString $Manifest "released_at_utc"),
    (Get-ManifestString $Manifest "minimum_protocol_version"),
    $(if (Get-ManifestBool $Manifest "rollback_allowed") { "true" } else { "false" }),
    (Get-ManifestString $Manifest "schema_version"),
    $Manifest["sequence"].ToJsonString(),
    (Get-ManifestString $Manifest "expires_at_utc"),
    $Manifest["artifact_length"].ToJsonString(),
    (Get-ManifestString $Manifest "signer_key_identity")
  ) -join "`n"
}

function Test-ManifestSignature([string]$ManifestPath, [string]$PublicKeyPem) {
  $manifest = Get-ManifestJsonNode $ManifestPath
  $rsa = [Security.Cryptography.RSA]::Create()
  $rsa.ImportFromPem($PublicKeyPem)
  $payload = [Text.Encoding]::UTF8.GetBytes((Get-CanonicalManifestPayload $manifest))
  $signature = [Convert]::FromBase64String((Get-ManifestString $manifest "signature"))
  return $rsa.VerifyData(
    $payload,
    $signature,
    [Security.Cryptography.HashAlgorithmName]::SHA256,
    [Security.Cryptography.RSASignaturePadding]::Pkcs1)
}

function Set-ManifestSignature([string]$ManifestPath, [string]$PrivateKeyPem) {
  $manifest = Get-ManifestJsonNode $ManifestPath
  $rsa = [Security.Cryptography.RSA]::Create()
  $rsa.ImportFromPem($PrivateKeyPem)
  $signature = $rsa.SignData(
    [Text.Encoding]::UTF8.GetBytes((Get-CanonicalManifestPayload $manifest)),
    [Security.Cryptography.HashAlgorithmName]::SHA256,
    [Security.Cryptography.RSASignaturePadding]::Pkcs1)
  $manifest["signature"] = [Convert]::ToBase64String($signature)
  $jsonOptions = [System.Text.Json.JsonSerializerOptions]::new()
  $jsonOptions.WriteIndented = $true
  $manifest.ToJsonString($jsonOptions) | Set-Content -LiteralPath $ManifestPath -Encoding utf8
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$labRoot = Join-Path $repoRoot $OutputRoot
$buildRoot = Join-Path $labRoot "builds"
$webRoot = Join-Path $labRoot "www"
$stateDir = Join-Path $labRoot "state"
$downloadPath = "$Owner/$Repo/releases/download"
$baseDownloadUrl = "$($HttpsBaseUrl.TrimEnd('/'))/$downloadPath"
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
    if (Test-Path -LiteralPath $versionBuildRoot) { throw "Use a fresh OutputRoot; existing lab builds are preserved." }

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
        -UpdateManifestUrl "$baseDownloadUrl/$latestTag/Cerberus.Agent.Bundle-$Channel-latest.update-manifest.v2.json" `
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
foreach ($releasePath in @($oldReleaseDir, $targetReleaseDir, $latestReleaseDir)) { if (Test-Path -LiteralPath $releasePath) { throw "Use a fresh OutputRoot; existing release trees are preserved." } }
$oldPublishDir = Join-Path $buildRoot "$OldVersion/publish"
$targetPublishDir = Join-Path $buildRoot "$TargetVersion/publish"
$oldAssetBase = Get-AssetBase $OldVersion
$targetAssetBase = Get-AssetBase $TargetVersion
Set-ManifestSignature -ManifestPath (Join-Path $oldPublishDir "$oldAssetBase.update-manifest.v2.json") -PrivateKeyPem $privateKeyPem
Set-ManifestSignature -ManifestPath (Join-Path $oldPublishDir "Cerberus.Agent.Bundle-$Channel-latest.update-manifest.v2.json") -PrivateKeyPem $privateKeyPem
Set-ManifestSignature -ManifestPath (Join-Path $targetPublishDir "$targetAssetBase.update-manifest.v2.json") -PrivateKeyPem $privateKeyPem
Set-ManifestSignature -ManifestPath (Join-Path $targetPublishDir "Cerberus.Agent.Bundle-$Channel-latest.update-manifest.v2.json") -PrivateKeyPem $privateKeyPem
Copy-ReleaseAssets -Version $OldVersion -BuildPublishDir $oldPublishDir -ReleaseDir $oldReleaseDir
Copy-ReleaseAssets -Version $TargetVersion -BuildPublishDir $targetPublishDir -ReleaseDir $targetReleaseDir
Copy-ReleaseAssets -Version $TargetVersion -BuildPublishDir $targetPublishDir -ReleaseDir $latestReleaseDir

$oldManifestPath = Join-Path $oldReleaseDir "$oldAssetBase.update-manifest.v2.json"
$targetManifestPath = Join-Path $targetReleaseDir "$targetAssetBase.update-manifest.v2.json"
$latestManifestPath = Join-Path $latestReleaseDir "Cerberus.Agent.Bundle-$Channel-latest.update-manifest.v2.json"
if (-not (Test-ManifestSignature -ManifestPath $oldManifestPath -PublicKeyPem $publicKeyPem)) {
  throw "Old manifest signature does not verify with update-lab public key."
}
if (-not (Test-ManifestSignature -ManifestPath $targetManifestPath -PublicKeyPem $publicKeyPem)) {
  throw "Target manifest signature does not verify with update-lab public key."
}
if (-not (Test-ManifestSignature -ManifestPath $latestManifestPath -PublicKeyPem $publicKeyPem)) {
  throw "Latest manifest signature does not verify with update-lab public key."
}

Write-Step "Serve the prepared web root through the separately provisioned trusted HTTPS endpoint: $HttpsBaseUrl"

$backendEnvPath = Join-Path $stateDir "backend-update-env.ps1"
@"
`$env:AGENT_UPDATE_CHANNEL = "$Channel"
`$env:AGENT_LATEST_RECOMMENDED_VERSION = "$TargetVersion"
`$env:AGENT_UPDATE_MANIFEST_URL = "$baseDownloadUrl/$latestTag/Cerberus.Agent.Bundle-$Channel-latest.update-manifest.v2.json"
`$env:AGENT_UPDATE_ALLOWED_ARTIFACT_URL_PREFIXES = "$baseDownloadUrl/"
`$env:AGENT_UPDATE_MANIFEST_PUBLIC_KEY_PEM = @'
$($publicKeyPem.Trim())
'@
"@ | Set-Content -LiteralPath $backendEnvPath -Encoding utf8

$agentEnvPath = Join-Path $stateDir "agent-update-env.ps1"
@"
`$env:CERBERUS_AGENT_UPDATE_MANIFEST_URL = "$baseDownloadUrl/$latestTag/Cerberus.Agent.Bundle-$Channel-latest.update-manifest.v2.json"
`$env:AGENT_UPDATE_MANIFEST_URL = "$baseDownloadUrl/$latestTag/Cerberus.Agent.Bundle-$Channel-latest.update-manifest.v2.json"
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
  manifest_url = "$baseDownloadUrl/$latestTag/Cerberus.Agent.Bundle-$Channel-latest.update-manifest.v2.json"
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
- Expected agent state file: %ProgramData%\CerberusAgent\Privileged\Updates\update-state.json
- Expected updater result file: %ProgramData%\CerberusAgent\Privileged\Updates\update-result.json

Suggested support flow:

1. Source the backend env file before starting the backend used for update request testing.
2. Use the lab MSI whose build embeds this HTTPS endpoint and manifest key; runtime environment overrides do not grant update trust.
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
  manifest_url = "$baseDownloadUrl/$latestTag/Cerberus.Agent.Bundle-$Channel-latest.update-manifest.v2.json"
  backend_env = $backendEnvPath
  agent_env = $agentEnvPath
  command_payload = $commandPayloadPath
  update_state_path = "%ProgramData%\CerberusAgent\Privileged\Updates\update-state.json"
  update_result_path = "%ProgramData%\CerberusAgent\Privileged\Updates\update-result.json"
  acceptance_notes = $acceptanceNotesPath
  server_pid_file = $null
  channel = $Channel
  old_msi_path = Join-Path $oldReleaseDir "$(Get-InstallerBase $OldVersion).msi"
}

$summaryPath = Join-Path $stateDir "summary.json"
$summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $summaryPath -Encoding utf8
$summary | ConvertTo-Json -Depth 4
