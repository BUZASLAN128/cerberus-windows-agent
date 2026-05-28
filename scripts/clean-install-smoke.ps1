param(
  [string]$ExePath = "",
  [string]$SsoBaseUrl = "http://100.101.130.51:31080",
  [string]$BootstrapDescriptorUrl = "",
  [switch]$RunEnrollment,
  [switch]$HeartbeatOnce,
  [ValidateRange(1, 100)]
  [int]$HeartbeatRepeat = 1,
  [switch]$InstallService,
  [switch]$StartService,
  [switch]$StopService,
  [switch]$UninstallService
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
  Write-Host "==> $Message"
}

function Invoke-AgentExe {
  param(
    [Parameter(Mandatory=$true)]
    [string[]]$Arguments,
    [Parameter(Mandatory=$true)]
    [string]$FailureMessage,
    [switch]$Interactive
  )

  if ($Interactive) {
    & $ExePath @Arguments
    $rc = if ($null -eq $LASTEXITCODE) { 0 } else { $LASTEXITCODE }
    if ($rc -ne 0) {
      throw "$FailureMessage with exit code $rc"
    }
    return
  }

  $safeName = (($Arguments -join "_") -replace '[^A-Za-z0-9_.-]', '_').Trim('_')
  if ([string]::IsNullOrWhiteSpace($safeName)) {
    $safeName = "agent-command"
  }
  $logDir = Join-Path $repoRoot "out/clean-install-smoke"
  New-Item -ItemType Directory -Force -Path $logDir | Out-Null
  $stdoutPath = Join-Path $logDir "$safeName.out.txt"
  $stderrPath = Join-Path $logDir "$safeName.err.txt"
  Remove-Item -LiteralPath $stdoutPath, $stderrPath -ErrorAction SilentlyContinue

  $process = Start-Process `
    -FilePath $ExePath `
    -ArgumentList $Arguments `
    -Wait `
    -PassThru `
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdoutPath `
    -RedirectStandardError $stderrPath

  if (Test-Path -LiteralPath $stdoutPath) {
    Get-Content -LiteralPath $stdoutPath
  }
  if (Test-Path -LiteralPath $stderrPath) {
    Get-Content -LiteralPath $stderrPath
  }
  if ($process.ExitCode -ne 0) {
    throw "$FailureMessage with exit code $($process.ExitCode). See $stdoutPath and $stderrPath"
  }
}

function Test-IsAdmin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-ServiceState {
  param(
    [Parameter(Mandatory=$true)]
    [string]$Phase
  )

  $serviceName = "CerberusAgent"
  $logDir = Join-Path $repoRoot "out/clean-install-smoke"
  New-Item -ItemType Directory -Force -Path $logDir | Out-Null
  $safePhase = ($Phase -replace '[^A-Za-z0-9_.-]', '_')
  $outPath = Join-Path $logDir "service-state-$safePhase.txt"

  $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
  if ($null -eq $service) {
    "phase=$Phase`nservice=$serviceName`ninstalled=false" | Set-Content -LiteralPath $outPath -Encoding UTF8
    Write-Host "service-state[$Phase]: installed=false"
    return
  }

  $row = [PSCustomObject]@{
    phase = $Phase
    service = $serviceName
    installed = $true
    status = $service.Status.ToString()
    can_stop = $service.CanStop
    start_type = $service.StartType.ToString()
  }
  $row | Format-List * | Out-String | Set-Content -LiteralPath $outPath -Encoding UTF8
  Write-Host "service-state[$Phase]: installed=true status=$($service.Status)"
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
  $ExePath = Join-Path $publishDir "Cerberus.Agent.exe"
}

if (-not (Test-Path -LiteralPath $ExePath)) {
  throw "Agent exe not found: $ExePath"
}

$env:CERBERUS_SSO_BASE_URL = $SsoBaseUrl
if (-not [string]::IsNullOrWhiteSpace($BootstrapDescriptorUrl)) {
  $env:CERBERUS_AGENT_BOOTSTRAP_DESCRIPTOR_URL = $BootstrapDescriptorUrl
}

$needsAdmin = $InstallService -or $StartService -or $StopService -or $UninstallService
if ($needsAdmin -and -not (Test-IsAdmin)) {
  Write-ServiceState -Phase "blocked-non-admin"
  throw "Administrator privileges are required for service install/start/stop/uninstall acceptance."
}

Write-Step "Running read-only self-test"
Invoke-AgentExe -Arguments @("--self-test", "--self-test-json") -FailureMessage "Self-test failed"

if ($RunEnrollment) {
  Write-Step "Starting interactive PKCE enrollment"
  Invoke-AgentExe -Arguments @("--register") -FailureMessage "Enrollment failed" -Interactive
}

if ($HeartbeatOnce) {
  for ($i = 1; $i -le $HeartbeatRepeat; $i++) {
    Write-Step "Running heartbeat-once ($i/$HeartbeatRepeat)"
    Invoke-AgentExe -Arguments @("--heartbeat-once") -FailureMessage "Heartbeat-once failed"
  }
}

if ($InstallService) {
  Write-Step "Installing Windows service"
  Write-ServiceState -Phase "before-install"
  Invoke-AgentExe -Arguments @("--install-service") -FailureMessage "Service install failed"
  Write-ServiceState -Phase "after-install"
}

if ($StartService) {
  Write-Step "Starting Windows service"
  Write-ServiceState -Phase "before-start"
  Invoke-AgentExe -Arguments @("--start-service") -FailureMessage "Service start failed"
  Write-ServiceState -Phase "after-start"
}

if ($StopService) {
  Write-Step "Stopping Windows service"
  Write-ServiceState -Phase "before-stop"
  Invoke-AgentExe -Arguments @("--stop-service") -FailureMessage "Service stop failed"
  Write-ServiceState -Phase "after-stop"
}

if ($UninstallService) {
  Write-Step "Uninstalling Windows service"
  Write-ServiceState -Phase "before-uninstall"
  Invoke-AgentExe -Arguments @("--uninstall-service") -FailureMessage "Service uninstall failed"
  Write-ServiceState -Phase "after-uninstall"
}

Write-Step "Clean install smoke completed"
