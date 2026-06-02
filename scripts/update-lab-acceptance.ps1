param(
  [string]$SummaryPath = "out\update-lab\state\summary.json",
  [string]$ArtifactRoot = "out\update-lab\acceptance",
  [switch]$NoElevate
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

if (-not (Test-IsAdmin)) {
  if ($NoElevate) {
    throw "Administrator privileges are required for MSI install/update acceptance."
  }

  Write-Step "Relaunching elevated"
  $scriptPath = $PSCommandPath
  $fullSummary = Resolve-RepoPath $SummaryPath
  $fullArtifactRoot = Resolve-RepoPath $ArtifactRoot
  $argList = @(
    "-NoProfile",
    "-ExecutionPolicy", "Bypass",
    "-File", "`"$scriptPath`"",
    "-SummaryPath", "`"$fullSummary`"",
    "-ArtifactRoot", "`"$fullArtifactRoot`"",
    "-NoElevate"
  )
  $child = Start-Process -FilePath "pwsh" -ArgumentList $argList -Verb RunAs -Wait -PassThru
  Add-Content -LiteralPath $mainLog -Value "elevated_exit_code=$($child.ExitCode)"
  exit $child.ExitCode
}

$summaryPath = Resolve-RepoPath $SummaryPath
$summary = Get-Content -Raw -LiteralPath $summaryPath | ConvertFrom-Json
$oldMsi = Join-Path $repoRoot "out\update-lab\www\BUZASLAN128\cerberus-windows-agent\releases\download\v$($summary.old_version)\Cerberus.Agent-dev-$($summary.old_version).msi"
$targetVersion = [string]$summary.target_version
$agentEnv = Get-Content -Raw -LiteralPath $summary.agent_env
. $summary.agent_env

Write-JsonArtifact "before-service.json" (Get-ServiceSnapshot "before")
Write-JsonArtifact "before-binaries.json" (Get-InstalledBinaryVersions)

$registryPath = "HKLM:\Software\Cerberus\WindowsAgent"
$existingProductCode = $null
if (Test-Path -LiteralPath $registryPath) {
  $existingProductCode = (Get-ItemProperty -LiteralPath $registryPath).ProductCode
}
if (-not [string]::IsNullOrWhiteSpace($existingProductCode)) {
  Write-Step "Uninstalling existing Cerberus Agent product $existingProductCode"
  Invoke-ProcessChecked `
    -FilePath "msiexec.exe" `
    -Arguments "/x $existingProductCode /qn /norestart /l*v `"$artifactRoot\uninstall-existing-msi.log`"" `
    -Name "uninstall-existing" `
    -AllowedExitCodes @(0, 1605, 1614, 3010) | Out-Null
}

Write-Step "Clearing generated update state artifacts"
$updateRoot = "C:\ProgramData\CerberusAgent\updates"
if (Test-Path -LiteralPath $updateRoot) {
  Remove-Item -LiteralPath (Join-Path $updateRoot "update-state.json") -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath (Join-Path $updateRoot "update-result.json") -Force -ErrorAction SilentlyContinue
}

Write-Step "Installing old MSI $($summary.old_version)"
$props = @(
  "CERBERUS_EULA_ACCEPTED=1",
  "CERBERUS_AGENT_UPDATE_MANIFEST_URL=`"$env:CERBERUS_AGENT_UPDATE_MANIFEST_URL`"",
  "CERBERUS_AGENT_UPDATE_MANIFEST_PUBLIC_KEY_B64=`"$env:CERBERUS_AGENT_UPDATE_MANIFEST_PUBLIC_KEY_B64`"",
  "CERBERUS_AGENT_UPDATE_ALLOWED_ARTIFACT_PREFIXES=`"$env:CERBERUS_AGENT_UPDATE_ALLOWED_ARTIFACT_PREFIXES`""
) -join " "
Invoke-ProcessChecked `
  -FilePath "msiexec.exe" `
  -Arguments "/i `"$oldMsi`" /qn /norestart $props /l*v `"$artifactRoot\install-old-msi.log`"" `
  -Name "install-old" `
  -AllowedExitCodes @(0, 3010) | Out-Null

$agentExe = Get-InstalledAgentExe
Write-JsonArtifact "after-old-install-service.json" (Get-ServiceSnapshot "after-old-install")
Write-JsonArtifact "after-old-install-binaries.json" (Get-InstalledBinaryVersions)

Write-Step "Running headless update check"
Invoke-ProcessChecked `
  -FilePath $agentExe `
  -Arguments "--update-check-once" `
  -Name "update-check-once" | Out-Null

Write-Step "Running headless update apply"
Invoke-ProcessChecked `
  -FilePath $agentExe `
  -Arguments "--update-apply-once" `
  -Name "update-apply-once" | Out-Null

Write-Step "Waiting for target version $targetVersion"
$finalVersions = Wait-ForTargetVersion -TargetVersion $targetVersion -TimeoutSeconds 240

Write-Step "Reconciling installer result with updated agent"
Invoke-ProcessChecked `
  -FilePath $agentExe `
  -Arguments "--update-check-once" `
  -Name "post-current-check" | Out-Null

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

$success = $finalVersions.Count -gt 0 -and
  (($finalVersions | Where-Object { $_.product_version -like "$targetVersion*" }).Count -eq $finalVersions.Count)
$summaryOut = [PSCustomObject]@{
  success = $success
  old_version = [string]$summary.old_version
  target_version = $targetVersion
  manifest_url = [string]$summary.manifest_url
  artifact_root = $artifactRoot
  service = Get-ServiceSnapshot "summary"
  final_versions = $finalVersions
}
Write-JsonArtifact "summary.json" $summaryOut
if (-not $success) {
  throw "Target version was not installed on all agent binaries. See $artifactRoot"
}

Write-Step "Update lab acceptance completed"
