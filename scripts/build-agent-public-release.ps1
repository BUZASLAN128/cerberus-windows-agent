param(
  [Parameter(Mandatory = $true)]
  [string]$Version,

  [ValidateSet("dev", "preview", "stable")]
  [string]$Channel = "dev",

  [string]$Configuration = "Release",
  [string]$Runtime = "win-x64",
  [string]$OutputRoot = "out/public-release",
  [string]$TimestampUrl = "http://timestamp.digicert.com",
  [string]$DefaultBackendUrl = $env:CERBERUS_BACKEND_URL,
  [string]$DefaultSsoBaseUrl = $env:CERBERUS_SSO_BASE_URL,
  [string]$DefaultSsoClientId = $env:CERBERUS_SSO_CLIENT_ID,
  [string]$DefaultSsoScope = $env:CERBERUS_SSO_SCOPE,
  [string]$UpdateManifestUrl = $env:CERBERUS_AGENT_UPDATE_MANIFEST_URL,
  [string]$AgentUpdateManifestPublicKeysB64 = $env:CERBERUS_AGENT_UPDATE_MANIFEST_PUBLIC_KEYS_B64,
  [string]$UpdateManifestPublicKeyB64 = $env:CERBERUS_AGENT_UPDATE_MANIFEST_PUBLIC_KEY_B64,
  [string]$UpdateAllowedArtifactPrefixes = $env:CERBERUS_AGENT_UPDATE_ALLOWED_ARTIFACT_PREFIXES,
  [int]$DefaultOAuthRedirectPort = 0,
  [switch]$SkipTests,
  [switch]$AllowUnsignedDevBuild,
  [switch]$AllowEphemeralManifestKey
)

$ErrorActionPreference = "Stop"

if ($PSVersionTable.PSEdition -ne "Core") {
  throw "PowerShell 7+ (pwsh) is required for public release signing and manifest generation."
}

function Write-Step([string]$Message) {
  Write-Host "==> $Message"
}

function ConvertTo-Base64Utf8([string]$Value) {
  if ([string]::IsNullOrWhiteSpace($Value)) {
    return ""
  }
  return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Value.Trim()))
}

function Find-SignTool {
  $candidates = @(
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe",
    "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\signtool.exe"
  )
  foreach ($pattern in $candidates) {
    $tool = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue |
      Sort-Object FullName -Descending |
      Select-Object -First 1
    if ($tool) {
      return $tool.FullName
    }
  }
  throw "signtool.exe was not found. Install Windows SDK or use windows-latest GitHub runner."
}

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

function Sign-ManifestPayload([string]$CanonicalPayload, [string]$PrivateKeyPem) {
  $rsa = [System.Security.Cryptography.RSA]::Create()
  $rsa.ImportFromPem($PrivateKeyPem)
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($CanonicalPayload)
  $sig = $rsa.SignData(
    $bytes,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
  return [Convert]::ToBase64String($sig)
}

function Get-ManifestPublicKeyPem([string]$PrivateKeyPem) {
  $rsa = [System.Security.Cryptography.RSA]::Create()
  $rsa.ImportFromPem($PrivateKeyPem)
  return $rsa.ExportSubjectPublicKeyInfoPem()
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
  Copy-Item -LiteralPath $Manifest -Destination (Join-Path $PublishDir "$aliasAssetBase.update-manifest.json") -Force
  Copy-Item -LiteralPath $Gate -Destination (Join-Path $PublishDir "$aliasAssetBase.release-gate.json") -Force
  @(
    "$ZipHash  $aliasAssetBase.zip",
    "$MsiHash  $aliasInstallerBase.msi"
  ) | Set-Content -LiteralPath (Join-Path $PublishDir "$aliasAssetBase.sha256") -Encoding utf8
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$outputRootPath = Join-Path $repoRoot $OutputRoot
$publishDir = Join-Path $outputRootPath "publish"
Remove-Item -LiteralPath $publishDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $publishDir | Out-Null
$runtimePublishDir = Join-Path $publishDir "runtime"
New-Item -ItemType Directory -Force -Path $runtimePublishDir | Out-Null

if ($DefaultOAuthRedirectPort -le 0) {
  $redirectPortFromEnv = $env:CERBERUS_OAUTH_REDIRECT_PORT
  if ($null -eq $redirectPortFromEnv) {
    $redirectPortFromEnv = ""
  }
  $redirectPortFromEnv = $redirectPortFromEnv.Trim()
  if ([int]::TryParse($redirectPortFromEnv, [ref]$DefaultOAuthRedirectPort) -and
      ($DefaultOAuthRedirectPort -le 0 -or $DefaultOAuthRedirectPort -gt 65535)) {
    $DefaultOAuthRedirectPort = 0
  }
}
if ($Channel -eq "dev") {
  if ([string]::IsNullOrWhiteSpace($DefaultBackendUrl)) { $DefaultBackendUrl = "http://127.0.0.1:8000" }
  if ([string]::IsNullOrWhiteSpace($DefaultSsoBaseUrl)) { $DefaultSsoBaseUrl = "http://localhost:18000" }
  if ([string]::IsNullOrWhiteSpace($DefaultSsoClientId)) { $DefaultSsoClientId = "1ad45750a9cc2eaed763" }
  if ([string]::IsNullOrWhiteSpace($DefaultSsoScope)) { $DefaultSsoScope = "openid profile email groups" }
  if ($DefaultOAuthRedirectPort -le 0) { $DefaultOAuthRedirectPort = 19823 }
}

$manifestPrivateKey = [Environment]::GetEnvironmentVariable("AGENT_UPDATE_MANIFEST_PRIVATE_KEY_PEM")
if ([string]::IsNullOrWhiteSpace($manifestPrivateKey) -and
    $Channel -eq "dev" -and
    $AllowUnsignedDevBuild -and
    $AllowEphemeralManifestKey) {
  if ([string]::Equals($env:GITHUB_ACTIONS, "true", [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "GitHub dev releases require stable AGENT_UPDATE_MANIFEST_PRIVATE_KEY_PEM; ephemeral manifest keys are local/lab only."
  }
  $ephemeralManifestKey = [System.Security.Cryptography.RSA]::Create(3072)
  $manifestPrivateKey = $ephemeralManifestKey.ExportPkcs8PrivateKeyPem()
}
if ([string]::IsNullOrWhiteSpace($manifestPrivateKey)) {
  throw "Required environment variable 'AGENT_UPDATE_MANIFEST_PRIVATE_KEY_PEM' is missing. Use -AllowEphemeralManifestKey only for local update-lab artifacts that will not be published as latest."
}
$manifestPublicKeyB64 = ConvertTo-Base64Utf8 (Get-ManifestPublicKeyPem $manifestPrivateKey)
$UpdateManifestPublicKeyB64 = $manifestPublicKeyB64
$AgentUpdateManifestPublicKeysB64 = $manifestPublicKeyB64
if ([string]::IsNullOrWhiteSpace($UpdateManifestUrl)) {
  $manifestRepo = if ([string]::IsNullOrWhiteSpace($env:GITHUB_REPOSITORY)) { "BUZASLAN128/cerberus-windows-agent" } else { $env:GITHUB_REPOSITORY }
  $UpdateManifestUrl = "https://github.com/$manifestRepo/releases/download/$Channel-latest/Cerberus.Agent.Bundle-$Channel-latest.update-manifest.json"
}
if ([string]::IsNullOrWhiteSpace($UpdateAllowedArtifactPrefixes)) {
  $artifactRepo = if ([string]::IsNullOrWhiteSpace($env:GITHUB_REPOSITORY)) { "BUZASLAN128/cerberus-windows-agent" } else { $env:GITHUB_REPOSITORY }
  $UpdateAllowedArtifactPrefixes = "https://github.com/$artifactRepo/releases/download/"
}

$artifactUrlBase = [Environment]::GetEnvironmentVariable("AGENT_RELEASE_ARTIFACT_BASE_URL")
if ([string]::IsNullOrWhiteSpace($artifactUrlBase) -and $Channel -eq "dev" -and -not [string]::IsNullOrWhiteSpace($env:GITHUB_REPOSITORY)) {
  $releaseTag = if ($Version.StartsWith("v")) { $Version } else { "v$Version" }
  $artifactUrlBase = "https://github.com/$env:GITHUB_REPOSITORY/releases/download/$releaseTag"
}
if ([string]::IsNullOrWhiteSpace($artifactUrlBase)) {
  throw "Required environment variable 'AGENT_RELEASE_ARTIFACT_BASE_URL' is missing."
}

if (-not $SkipTests) {
  Write-Step "Running dotnet tests"
  dotnet test (Join-Path $repoRoot "Cerberus.WindowsAgent.slnx") -c $Configuration
}

function Publish-AgentProject([string]$Project, [bool]$WithSetupConfig) {
  $args = @(
    "publish",
    (Join-Path $repoRoot $Project),
    "-c", $Configuration,
    "-r", $Runtime,
    "--self-contained", "true",
    "-p:PublishSingleFile=false",
    "-p:DebugType=None",
    "-p:DebugSymbols=false",
    "-p:Version=$Version",
    "-p:AgentUpdateManifestPublicKeysB64=$AgentUpdateManifestPublicKeysB64",
    "-p:AgentUpdateManifestUrl=$UpdateManifestUrl",
    "-p:AgentUpdateAllowedArtifactPrefixes=$UpdateAllowedArtifactPrefixes",
    "-o", $runtimePublishDir
  )
  if ($WithSetupConfig) {
    $args += @(
      "-p:AgentDefaultBackendUrlBase64=$(ConvertTo-Base64Utf8 $DefaultBackendUrl)",
      "-p:AgentDefaultSsoBaseUrlBase64=$(ConvertTo-Base64Utf8 $DefaultSsoBaseUrl)",
      "-p:AgentDefaultSsoClientIdBase64=$(ConvertTo-Base64Utf8 $DefaultSsoClientId)",
      "-p:AgentDefaultSsoScopeBase64=$(ConvertTo-Base64Utf8 $DefaultSsoScope)",
      "-p:AgentDefaultOAuthRedirectPort=$DefaultOAuthRedirectPort"
    )
  }
  dotnet @args
}

Write-Step "Publishing split agent runtime"
Publish-AgentProject "src/Cerberus.Agent.App/Cerberus.Agent.App.csproj" $true
Publish-AgentProject "src/Cerberus.Agent.Service/Cerberus.Agent.Service.csproj" $false
Publish-AgentProject "src/Cerberus.Agent.Updater/Cerberus.Agent.Updater.csproj" $false
Publish-AgentProject "src/Cerberus.Agent.Uninstall/Cerberus.Agent.Uninstall.csproj" $false

$assetBase = "Cerberus.Agent.Bundle-$Channel-$Version"
$installerBase = "Cerberus.Agent-$Channel-$Version"
$versionWithoutPrefix = if ($Version.StartsWith("v")) { $Version.Substring(1) } else { $Version }
if ($versionWithoutPrefix -notmatch "^(\d+\.\d+\.\d+)") {
  throw "Release version '$Version' must start with a numeric major.minor.patch version for MSI ProductVersion."
}
$msiProductVersion = $Matches[1]
$runtimeExecutables = @(
  (Join-Path $runtimePublishDir "Cerberus.Agent.exe"),
  (Join-Path $runtimePublishDir "Cerberus.Agent.Service.exe"),
  (Join-Path $runtimePublishDir "Cerberus.Agent.Updater.exe"),
  (Join-Path $runtimePublishDir "Cerberus.Agent.Uninstall.exe")
)
$allowedRuntimeExeNames = @(
  "Cerberus.Agent.exe",
  "Cerberus.Agent.Service.exe",
  "Cerberus.Agent.Updater.exe",
  "Cerberus.Agent.Uninstall.exe"
)
Remove-Item -LiteralPath (Join-Path $runtimePublishDir "createdump.exe") -Force -ErrorAction SilentlyContinue
foreach ($runtimeExe in $runtimeExecutables) {
  if (-not (Test-Path -LiteralPath $runtimeExe)) {
    throw "Expected runtime executable was not produced: $runtimeExe"
  }
}
$unexpectedRuntimeExecutables = Get-ChildItem -LiteralPath $runtimePublishDir -Filter "*.exe" |
  Where-Object { $allowedRuntimeExeNames -notcontains $_.Name } |
  Select-Object -ExpandProperty Name
if ($unexpectedRuntimeExecutables.Count -gt 0) {
  throw "Unexpected runtime executable(s) produced: $($unexpectedRuntimeExecutables -join ', ')"
}

$certBase64 = [Environment]::GetEnvironmentVariable("WINDOWS_SIGNING_CERT_BASE64")
$certPassword = [Environment]::GetEnvironmentVariable("WINDOWS_SIGNING_CERT_PASSWORD")
$signed = $false
if (-not [string]::IsNullOrWhiteSpace($certBase64)) {
  Write-Step "Signing runtime executables"
  $certPath = Join-Path $env:RUNNER_TEMP "cerberus-agent-signing.pfx"
  if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    $certPath = Join-Path $outputRootPath "cerberus-agent-signing.pfx"
  }
  [IO.File]::WriteAllBytes($certPath, [Convert]::FromBase64String($certBase64))
  $signtool = Find-SignTool
  foreach ($runtimeExe in $runtimeExecutables) {
    & $signtool sign /fd SHA256 /td SHA256 /tr $TimestampUrl /f $certPath /p $certPassword $runtimeExe
    & $signtool verify /pa /v $runtimeExe
  }
  Remove-Item -LiteralPath $certPath -Force -ErrorAction SilentlyContinue
  $signed = $true
}

if (-not $signed -and -not ($Channel -eq "dev" -and $AllowUnsignedDevBuild)) {
  throw "Unsigned public agent release denied. Configure WINDOWS_SIGNING_CERT_BASE64 and WINDOWS_SIGNING_CERT_PASSWORD."
}

Write-Step "Building MSI installer"
$installerProject = Join-Path $repoRoot "src/Cerberus.Agent.Installer/Cerberus.Agent.Installer.wixproj"
$installerProjectDir = Split-Path -Parent $installerProject
Remove-Item -LiteralPath (Join-Path $installerProjectDir "obj") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $installerProjectDir "bin") -Recurse -Force -ErrorAction SilentlyContinue
$installerBuildBase = "Cerberus.Agent"
dotnet build $installerProject `
  -c $Configuration `
  -p:Version=$Version `
  -p:MsiProductVersion=$msiProductVersion `
  -p:Channel=$Channel `
  -p:AgentPublishDir=$runtimePublishDir `
  -p:InstallerAssetBase=$installerBuildBase `
  -p:UpdateManifestUrl=$UpdateManifestUrl `
  -p:UpdateManifestPublicKeyB64=$UpdateManifestPublicKeyB64 `
  -p:UpdateAllowedArtifactPrefixes=$UpdateAllowedArtifactPrefixes `
  -p:OutputPath="$publishDir\"

$msi = Join-Path $publishDir "$installerBase.msi"
$builtMsi = Join-Path $publishDir "$installerBuildBase.msi"
if ((Test-Path -LiteralPath $builtMsi) -and ($builtMsi -ne $msi)) {
  Move-Item -LiteralPath $builtMsi -Destination $msi -Force
}
if (-not (Test-Path -LiteralPath $msi)) {
  $localizedMsi = Get-ChildItem -LiteralPath $publishDir -Recurse -Filter "$installerBuildBase.msi" |
    Where-Object { $_.FullName -notmatch "\\(bin|obj|runtime)\\" } |
    Sort-Object FullName |
    Select-Object -First 1
  if ($localizedMsi) {
    Copy-Item -LiteralPath $localizedMsi.FullName -Destination $msi -Force
  }
}
if (-not (Test-Path -LiteralPath $msi)) {
  throw "MSI installer was not produced: $msi"
}

if ($signed) {
  Write-Step "Signing MSI installer"
  $certPath = Join-Path $env:RUNNER_TEMP "cerberus-agent-signing.pfx"
  if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    $certPath = Join-Path $outputRootPath "cerberus-agent-signing.pfx"
  }
  [IO.File]::WriteAllBytes($certPath, [Convert]::FromBase64String($certBase64))
  $signtool = Find-SignTool
  & $signtool sign /fd SHA256 /td SHA256 /tr $TimestampUrl /f $certPath /p $certPassword $msi
  & $signtool verify /pa /v $msi
  Remove-Item -LiteralPath $certPath -Force -ErrorAction SilentlyContinue
}

Write-Step "Creating checksums, SBOM, provenance, manifest"
$zip = Join-Path $publishDir "$assetBase.zip"
Compress-Archive -Path (Join-Path $runtimePublishDir "*") -DestinationPath $zip -Force
$zipHash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
$msiHash = (Get-FileHash -Algorithm SHA256 $msi).Hash.ToLowerInvariant()
$checksums = Join-Path $publishDir "$assetBase.sha256"
@(
  "$zipHash  $assetBase.zip",
  "$msiHash  $installerBase.msi"
) | Set-Content -LiteralPath $checksums -Encoding utf8

$sbom = Join-Path $publishDir "$assetBase.sbom.json"
$provenance = Join-Path $publishDir "$assetBase.provenance.json"
New-MinimalSbom -RepoRoot $repoRoot -OutputFile $sbom
New-Provenance -RepoRoot $repoRoot -OutputFile $provenance -ArtifactName "$installerBase.msi" -ArtifactSha $msiHash

$secretHits = Invoke-SecretScan -Path $repoRoot
if ($secretHits.Count -gt 0) {
  $preview = ($secretHits | Select-Object -First 10) -join "`n"
  throw "Release secret scan failed:`n$preview"
}

$artifactUrl = ($artifactUrlBase.TrimEnd("/") + "/$installerBase.msi")
$releasedAt = (Get-Date).ToUniversalTime().ToString("O")
$canonical = @(
  "msi",
  $Version,
  $Channel,
  $artifactUrl,
  $msiHash,
  "Cerberus Agent Release",
  $releasedAt,
  "agent.heartbeat.v1",
  "false"
) -join "`n"
$manifestSignature = Sign-ManifestPayload -CanonicalPayload $canonical -PrivateKeyPem $manifestPrivateKey
$manifest = [ordered]@{
  artifact_kind = "msi"
  version = $Version
  channel = $Channel
  artifact_url = $artifactUrl
  sha256 = $msiHash
  signing_identity = "Cerberus Agent Release"
  released_at_utc = $releasedAt
  minimum_protocol_version = "agent.heartbeat.v1"
  rollback_allowed = $false
  signature = $manifestSignature
}
$manifestPath = Join-Path $publishDir "$assetBase.update-manifest.json"
$manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding utf8

$gate = [ordered]@{
  schema = "cerberus.agent.release_gate.v1"
  channel = $Channel
  authenticode_signature_present = $signed
  checksum_sha256 = $msiHash
  installer = [ordered]@{
    name = "$installerBase.msi"
    checksum_sha256 = $msiHash
    authenticode_signature_present = $signed
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
$gatePath = Join-Path $publishDir "$assetBase.release-gate.json"
$gate | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $gatePath -Encoding utf8

Copy-ChannelLatestAliases `
  -PublishDir $publishDir `
  -Channel $Channel `
  -Msi $msi `
  -Zip $zip `
  -Sbom $sbom `
  -Provenance $provenance `
  -Manifest $manifestPath `
  -Gate $gatePath `
  -MsiHash $msiHash `
  -ZipHash $zipHash

Write-Step "Release bundle ready: $publishDir"
