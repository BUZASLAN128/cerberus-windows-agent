param(
  [Parameter(Mandatory = $true)]
  [string]$Version,

  [ValidateSet("dev", "preview", "stable")]
  [string]$Channel = "dev",

  [string]$Configuration = "Release",
  [string]$Runtime = "win-x64",
  [string]$OutputRoot = "out/public-release",
  [string]$TimestampUrl = "http://timestamp.digicert.com",
  [switch]$SkipTests,
  [switch]$AllowUnsignedDevBuild
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
  Write-Host "==> $Message"
}

function Require-Env([string]$Name) {
  $value = [Environment]::GetEnvironmentVariable($Name)
  if ([string]::IsNullOrWhiteSpace($value)) {
    throw "Required environment variable '$Name' is missing."
  }
  return $value
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
    Where-Object { $_.FullName -notmatch "\\(bin|obj|out|\.git)\\" }
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

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$outputRootPath = Join-Path $repoRoot $OutputRoot
$publishDir = Join-Path $outputRootPath "publish"
New-Item -ItemType Directory -Force -Path $publishDir | Out-Null

if (-not $SkipTests) {
  Write-Step "Running dotnet tests"
  dotnet test (Join-Path $repoRoot "Cerberus.WindowsAgent.slnx") -c $Configuration
}

Write-Step "Publishing single-file agent"
dotnet publish (Join-Path $repoRoot "src/Cerberus.Agent.App/Cerberus.Agent.App.csproj") `
  -c $Configuration `
  -r $Runtime `
  --self-contained true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:EnableCompressionInSingleFile=true `
  -p:Version=$Version `
  -o $publishDir

$assetBase = "Cerberus.Agent.App-$Channel-$Version"
$exe = Join-Path $publishDir "$assetBase.exe"
Copy-Item (Join-Path $publishDir "Cerberus.Agent.App.exe") $exe -Force

$certBase64 = [Environment]::GetEnvironmentVariable("WINDOWS_SIGNING_CERT_BASE64")
$certPassword = [Environment]::GetEnvironmentVariable("WINDOWS_SIGNING_CERT_PASSWORD")
$signed = $false
if (-not [string]::IsNullOrWhiteSpace($certBase64)) {
  Write-Step "Signing executable"
  $certPath = Join-Path $env:RUNNER_TEMP "cerberus-agent-signing.pfx"
  if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    $certPath = Join-Path $outputRootPath "cerberus-agent-signing.pfx"
  }
  [IO.File]::WriteAllBytes($certPath, [Convert]::FromBase64String($certBase64))
  $signtool = Find-SignTool
  & $signtool sign /fd SHA256 /td SHA256 /tr $TimestampUrl /f $certPath /p $certPassword $exe
  & $signtool verify /pa /v $exe
  Remove-Item -LiteralPath $certPath -Force -ErrorAction SilentlyContinue
  $signed = $true
}

if (-not $signed -and -not ($Channel -eq "dev" -and $AllowUnsignedDevBuild)) {
  throw "Unsigned public agent release denied. Configure WINDOWS_SIGNING_CERT_BASE64 and WINDOWS_SIGNING_CERT_PASSWORD."
}

Write-Step "Creating checksums, SBOM, provenance, manifest"
$zip = Join-Path $publishDir "$assetBase.zip"
Compress-Archive -Path $exe -DestinationPath $zip -Force
$exeHash = (Get-FileHash -Algorithm SHA256 $exe).Hash.ToLowerInvariant()
$zipHash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
$checksums = Join-Path $publishDir "$assetBase.sha256"
@(
  "$exeHash  $assetBase.exe",
  "$zipHash  $assetBase.zip"
) | Set-Content -LiteralPath $checksums -Encoding utf8

$sbom = Join-Path $publishDir "$assetBase.sbom.json"
$provenance = Join-Path $publishDir "$assetBase.provenance.json"
New-MinimalSbom -RepoRoot $repoRoot -OutputFile $sbom
New-Provenance -RepoRoot $repoRoot -OutputFile $provenance -ArtifactName "$assetBase.exe" -ArtifactSha $exeHash

$secretHits = Invoke-SecretScan -Path $repoRoot
if ($secretHits.Count -gt 0) {
  $preview = ($secretHits | Select-Object -First 10) -join "`n"
  throw "Release secret scan failed:`n$preview"
}

$artifactUrlBase = Require-Env "AGENT_RELEASE_ARTIFACT_BASE_URL"
$manifestPrivateKey = Require-Env "AGENT_UPDATE_MANIFEST_PRIVATE_KEY_PEM"
$artifactUrl = ($artifactUrlBase.TrimEnd("/") + "/$assetBase.exe")
$releasedAt = (Get-Date).ToUniversalTime().ToString("O")
$canonical = @(
  $Version,
  $Channel,
  $artifactUrl,
  $exeHash,
  "Cerberus Agent Release",
  $releasedAt,
  "agent.heartbeat.v1",
  "false"
) -join "`n"
$manifestSignature = Sign-ManifestPayload -CanonicalPayload $canonical -PrivateKeyPem $manifestPrivateKey
$manifest = [ordered]@{
  version = $Version
  channel = $Channel
  artifact_url = $artifactUrl
  sha256 = $exeHash
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
  checksum_sha256 = $exeHash
  sbom_present = (Test-Path -LiteralPath $sbom)
  provenance_present = (Test-Path -LiteralPath $provenance)
  secret_scan_hits = @()
  tenant_update_url_present = $false
  tenant_signing_key_present = $false
}
$gate | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $publishDir "$assetBase.release-gate.json") -Encoding utf8

Write-Step "Release bundle ready: $publishDir"
