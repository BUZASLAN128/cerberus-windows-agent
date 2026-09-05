param(
  [string]$SummaryPath = "out\update-lab\state\summary.json",
  [string]$ArtifactRoot = "out\update-lab\acceptance",
  [switch]$UsePreparedBaseline,
  [Parameter(Mandatory = $true)]
  [switch]$DisposableMachineConfirmed
)

$ErrorActionPreference = "Stop"

function Test-IsAdmin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-RepoPath([string]$Path) {
  if ([IO.Path]::IsPathRooted($Path)) {
    return $Path
  }
  return Join-Path $repoRoot $Path
}

function Write-Step([string]$Message) {
  $line = "==> $Message"
  Write-Host $line
  Add-Content -LiteralPath $mainLog -Value $line
}

function Invoke-ProcessChecked {
  param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,
    [Parameter(Mandatory = $true)]
    [string]$Arguments,
    [Parameter(Mandatory = $true)]
    [string]$Name,
    [int[]]$AllowedExitCodes = @(0)
  )

  $stdout = Join-Path $artifactRoot "$Name.out.txt"
  $stderr = Join-Path $artifactRoot "$Name.err.txt"
  Remove-Item -LiteralPath $stdout, $stderr -ErrorAction SilentlyContinue
  $process = Start-Process `
    -FilePath $FilePath `
    -ArgumentList $Arguments `
    -Wait `
    -PassThru `
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr

  Add-Content -LiteralPath $mainLog -Value "$Name exit_code=$($process.ExitCode)"
  if ($AllowedExitCodes -notcontains $process.ExitCode) {
    throw "$Name failed with exit code $($process.ExitCode). stdout=$stdout stderr=$stderr"
  }
  return $process.ExitCode
}

function Get-InstalledBinaryVersions {
  $installRoot = "C:\Program Files\Cerberus\Windows Agent"
  if (-not (Test-Path -LiteralPath $installRoot)) {
    return @()
  }

  $runtimeRoot = Join-Path $installRoot "app"
  if (-not (Test-Path -LiteralPath $runtimeRoot)) {
    $runtimeRoot = $installRoot
  }

  return @(Get-ChildItem -LiteralPath $runtimeRoot -Filter "Cerberus.Agent*.exe" |
    ForEach-Object {
      [PSCustomObject]@{
        name = $_.Name
        file_version = $_.VersionInfo.FileVersion
        product_version = $_.VersionInfo.ProductVersion
        path = $_.FullName
      }
    })
}

function Get-InstalledAgentExe {
  $installRoot = "C:\Program Files\Cerberus\Windows Agent"
  $appAgentExe = Join-Path (Join-Path $installRoot "app") "Cerberus.Agent.exe"
  if (Test-Path -LiteralPath $appAgentExe) {
    return $appAgentExe
  }

  return (Join-Path $installRoot "Cerberus.Agent.exe")
}

function Get-ServiceSnapshot([string]$Phase) {
  $svc = Get-Service -Name CerberusAgent -ErrorAction SilentlyContinue
  if ($null -eq $svc) {
    return [PSCustomObject]@{
      phase = $Phase
      installed = $false
    }
  }
  return [PSCustomObject]@{
    phase = $Phase
    installed = $true
    status = $svc.Status.ToString()
    start_type = $svc.StartType.ToString()
  }
}

function Write-JsonArtifact([string]$Name, [object]$Value) {
  $path = Join-Path $artifactRoot $Name
  $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding utf8
  return $path
}

function Wait-ForTargetVersion([string]$TargetVersion, [int]$TimeoutSeconds = 180) {
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    $versions = Get-InstalledBinaryVersions
    if ($versions.Count -gt 0 -and ($versions | Where-Object { $_.product_version -like "$TargetVersion*" }).Count -eq $versions.Count) {
      return $versions
    }
    Start-Sleep -Seconds 3
  } while ((Get-Date) -lt $deadline)

  return Get-InstalledBinaryVersions
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Resolve-RepoPath $ArtifactRoot
New-Item -ItemType Directory -Force -Path $artifactRoot | Out-Null
$mainLog = Join-Path $artifactRoot "update-lab-acceptance.log"
Set-Content -LiteralPath $mainLog -Value "update-lab acceptance started $(Get-Date -Format O)"

if (-not $DisposableMachineConfirmed -or -not (Test-IsAdmin)) { throw "Explicit disposable-machine confirmation and an already approved elevated test shell are required. This harness never self-elevates." }

$summaryPath = Resolve-RepoPath $SummaryPath
$summary = Get-Content -Raw -LiteralPath $summaryPath | ConvertFrom-Json
$oldMsi = [string]$summary.old_msi_path
$targetVersion = [string]$summary.target_version
$manifestUri = [Uri]$summary.manifest_url
if ($manifestUri.Scheme -ne "https") { throw "Trusted HTTPS lab endpoint is required." }

Write-JsonArtifact "before-service.json" (Get-ServiceSnapshot "before")
Write-JsonArtifact "before-binaries.json" (Get-InstalledBinaryVersions)

$registryPath = "HKLM:\Software\Cerberus\WindowsAgent"
$updateRoot = Join-Path ([Environment]::GetFolderPath("CommonApplicationData")) "CerberusAgent\Privileged\Updates"
if (-not $UsePreparedBaseline -and ((Test-Path -LiteralPath $registryPath) -or (Get-Service CerberusAgent -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $updateRoot))) {
  throw "Use a clean disposable VM snapshot. Existing installation, lifecycle and accepted update records are preserved; this harness never uninstalls or clears them."
}

if (-not $UsePreparedBaseline) {
Write-Step "Installing old MSI $($summary.old_version); this is bootstrap, not an update smoke"
$props = "CERBERUS_EULA_ACCEPTED=1"
Invoke-ProcessChecked `
  -FilePath "msiexec.exe" `
  -Arguments "/i `"$oldMsi`" /qn /norestart $props /l*v `"$artifactRoot\install-old-msi.log`"" `
  -Name "install-old" `
  -AllowedExitCodes @(0) | Out-Null
}

if (-not (Get-Service CerberusAgent -ErrorAction SilentlyContinue)) {
  throw "Initial bootstrap MSI is installed. Complete the documented approved enrollment/claim and --install-service step separately, then rerun with -UsePreparedBaseline. This is not update acceptance."
}
$baseline = Get-ItemProperty -LiteralPath $registryPath
if ([int]$baseline.updateProtocolBaseline -lt 2) { throw "First v2 baseline requires manual/MDM deployment." }
$baselineVersions = Get-InstalledBinaryVersions
if ($baselineVersions.Count -eq 0 -or @($baselineVersions | Where-Object { $_.product_version -notlike "$($summary.old_version)*" }).Count -gt 0) { throw "Prepared baseline does not match the declared old version." }

$agentExe = Get-InstalledAgentExe
Write-JsonArtifact "after-old-install-service.json" (Get-ServiceSnapshot "after-old-install")
Write-JsonArtifact "after-old-install-binaries.json" (Get-InstalledBinaryVersions)

Write-Step "Running headless update check"
Invoke-ProcessChecked `
  -FilePath $agentExe `
  -Arguments "--update-check-once" `
  -Name "update-check-once" | Out-Null

$statePath = Join-Path $updateRoot "update-state.json"
$deadline = [DateTimeOffset]::UtcNow.AddMinutes(5)
do {
  $state = if (Test-Path -LiteralPath $statePath) { Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json } else { $null }
  if ($state.state -in @("failed", "blocked", "quarantined", "recovery_required")) { throw "Staging failed: $($state.state)." }
  if ($state.state -eq "awaiting_consent") { break }
  Start-Sleep -Milliseconds 500
} while ([DateTimeOffset]::UtcNow -lt $deadline)
if ($state.state -ne "awaiting_consent" -or $state.target_version -ne $targetVersion -or [string]::IsNullOrWhiteSpace($state.attempt_id)) { throw "Expected concrete attempt is not ready for manual consent." }
$consentedAttempt = $state.attempt_id
Write-Step "Running headless update apply for consented attempt"
Invoke-ProcessChecked `
  -FilePath $agentExe `
  -Arguments "--update-apply-once" `
  -Name "update-apply-once" | Out-Null

Write-Step "Waiting for target version $targetVersion"
$finalVersions = Wait-ForTargetVersion -TargetVersion $targetVersion -TimeoutSeconds 240

$deadline = [DateTimeOffset]::UtcNow.AddMinutes(5)
do {
  $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
  if ($state.attempt_id -ne $consentedAttempt) { throw "Attempt changed after consent." }
  if ($state.state -in @("installed", "pending_reboot", "failed", "blocked", "quarantined", "recovery_required")) { break }
  Start-Sleep -Seconds 1
} while ([DateTimeOffset]::UtcNow -lt $deadline)
# Service reconciliation, not a second check or executable version alone, proves healthy installation.
Write-JsonArtifact "after-update-service.json" (Get-ServiceSnapshot "after-update")
Write-JsonArtifact "after-update-binaries.json" $finalVersions

$statePath = Join-Path $updateRoot "update-state.json"
$resultPath = Join-Path $updateRoot "update-result.json"
if (Test-Path -LiteralPath $statePath) {
  Copy-Item -LiteralPath $statePath -Destination (Join-Path $artifactRoot "update-state.json") -Force
}
if (Test-Path -LiteralPath $resultPath) {
  Copy-Item -LiteralPath $resultPath -Destination (Join-Path $artifactRoot "update-result.json") -Force
}

$success = $state.state -eq "installed" -and $state.health_state -eq "healthy" -and $finalVersions.Count -gt 0 -and
  (($finalVersions | Where-Object { $_.product_version -like "$targetVersion*" }).Count -eq $finalVersions.Count)
$summaryOut = [PSCustomObject]@{
  success = $success
  update_state = $state.state
  attempt_id = $consentedAttempt
  missing = if ($state.state -eq "pending_reboot") { "Real reboot plus exact-build service health; no reboot or downgrade performed." } else { $null }
  old_version = [string]$summary.old_version
  target_version = $targetVersion
  manifest_url = [string]$summary.manifest_url
  artifact_root = $artifactRoot
  service = Get-ServiceSnapshot "summary"
  final_versions = $finalVersions
}
Write-JsonArtifact "summary.json" $summaryOut
if (-not $success) {
  throw "Installed-service acceptance incomplete: $($state.state). See $artifactRoot; protected transaction state is preserved."
}

Write-Step "Update lab acceptance completed"
