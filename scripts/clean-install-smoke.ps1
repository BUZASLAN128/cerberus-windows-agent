param(
  [string]$ExePath = "",
  [string]$SsoBaseUrl = "http://100.101.130.51:31080",
  [string]$BootstrapDescriptorUrl = "",
  [switch]$RunEnrollment,
  [switch]$InstallService,
  [switch]$StartService
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
  Write-Host "==> $Message"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($ExePath)) {
  $publishDir = Join-Path $repoRoot "out/clean-install-smoke/publish"
  Write-Step "Publishing local smoke executable"
  dotnet publish (Join-Path $repoRoot "src/Cerberus.Agent.App/Cerberus.Agent.App.csproj") `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:EnableCompressionInSingleFile=true `
    -o $publishDir
  $ExePath = Join-Path $publishDir "Cerberus.Agent.App.exe"
}

if (-not (Test-Path -LiteralPath $ExePath)) {
  throw "Agent exe not found: $ExePath"
}

$env:CERBERUS_SSO_BASE_URL = $SsoBaseUrl
if (-not [string]::IsNullOrWhiteSpace($BootstrapDescriptorUrl)) {
  $env:CERBERUS_AGENT_BOOTSTRAP_DESCRIPTOR_URL = $BootstrapDescriptorUrl
}

Write-Step "Running read-only self-test"
& $ExePath --self-test --self-test-json
if ($LASTEXITCODE -ne 0) {
  throw "Self-test failed with exit code $LASTEXITCODE"
}

if ($RunEnrollment) {
  Write-Step "Starting interactive PKCE enrollment"
  & $ExePath --register
  if ($LASTEXITCODE -ne 0) {
    throw "Enrollment failed with exit code $LASTEXITCODE"
  }
}

if ($InstallService) {
  Write-Step "Installing Windows service"
  & $ExePath --install-service
  if ($LASTEXITCODE -ne 0) {
    throw "Service install failed with exit code $LASTEXITCODE"
  }
}

if ($StartService) {
  Write-Step "Starting Windows service"
  & $ExePath --start-service
  if ($LASTEXITCODE -ne 0) {
    throw "Service start failed with exit code $LASTEXITCODE"
  }
}

Write-Step "Clean install smoke completed"
