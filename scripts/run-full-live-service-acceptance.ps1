param(
  [Parameter(Mandatory=$true)]
  [string]$AgentId,
  [string]$BackendUrl = "http://127.0.0.1:8000",
  [string]$AppRoot = "",
  [string]$ExePath = "",
  [string]$Username = "cerbtest_codex1",
  [string]$PortalEmail = "",
  [string]$PortalPasswordEnvVar = "CERBERUS_ACCEPTANCE_LOGIN_PASSWORD",
  [string]$PortalBearerTokenFile = "",
  [switch]$PromptForPortalPassword,
  [switch]$PreflightOnly,
  [switch]$SkipLocalUserLifecycle,
  [switch]$SkipManagedAssignmentLifecycle,
  [ValidateRange(1, 10)]
  [int]$AcceptanceRepeat = 10,
  [ValidateRange(10, 300)]
  [int]$BearerMintTimeoutSeconds = 60
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
  Write-Host "==> $Message"
}

function Resolve-RepoPaths {
  $windowsRepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
  if ([string]::IsNullOrWhiteSpace($script:AppRoot)) {
    $script:AppRoot = (Resolve-Path (Join-Path $windowsRepoRoot "..\cerberus-app")).Path
  }
  if ([string]::IsNullOrWhiteSpace($script:ExePath)) {
    $script:ExePath = Join-Path $windowsRepoRoot "out\clean-install-smoke\publish\Cerberus.Agent.App.exe"
  }
  $script:LiveAcceptanceScript = Join-Path $windowsRepoRoot "scripts\live-service-acceptance.ps1"

  if (-not (Test-Path -LiteralPath $script:AppRoot)) {
    throw "Cerberus app root not found."
  }
  if (-not (Test-Path -LiteralPath $script:ExePath)) {
    throw "Agent executable not found. Run scripts\preflight.ps1 or scripts\clean-install-smoke.ps1 first."
  }
  if (-not (Test-Path -LiteralPath $script:LiveAcceptanceScript)) {
    throw "Live acceptance script not found."
  }
}

function Convert-SecureStringToPlainText {
  param([Parameter(Mandatory=$true)][securestring]$Secret)

  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
  try {
    return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
  }
  finally {
    if ($bstr -ne [IntPtr]::Zero) {
      [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
  }
}

function Get-PortalPassword {
  $fromEnv = [Environment]::GetEnvironmentVariable($PortalPasswordEnvVar)
  if (-not [string]::IsNullOrWhiteSpace($fromEnv)) {
    return $fromEnv
  }

  if (-not $PromptForPortalPassword) {
    throw "Portal password missing. Set env $PortalPasswordEnvVar or pass -PromptForPortalPassword."
  }

  $secure = Read-Host -Prompt "Portal password for $PortalEmail" -AsSecureString
  return Convert-SecureStringToPlainText -Secret $secure
}

function New-PortalBearerToken {
  if ([string]::IsNullOrWhiteSpace($PortalEmail)) {
    $envEmail = [Environment]::GetEnvironmentVariable("CERBERUS_ACCEPTANCE_LOGIN_EMAIL")
    if ([string]::IsNullOrWhiteSpace($envEmail)) {
      throw "Portal email missing. Pass -PortalEmail or set CERBERUS_ACCEPTANCE_LOGIN_EMAIL."
    }
    $script:PortalEmail = $envEmail.Trim()
  }

  $password = Get-PortalPassword
  $tempScript = New-TemporaryFile
  $pythonSource = @'
import asyncio
import os
import sys

app_root = os.environ.get("CERBERUS_APP_ROOT", "").strip()
if app_root and app_root not in sys.path:
    sys.path.insert(0, app_root)

from app.core.config import get_settings
from scripts.security_suite.native_identity import _casdoor_login_native


async def main() -> int:
    settings = get_settings()
    email = os.environ.get("CERBERUS_ACCEPTANCE_LOGIN_EMAIL", "").strip()
    password = os.environ.get("CERBERUS_ACCEPTANCE_LOGIN_PASSWORD", "")
    if not email or not password:
        raise RuntimeError("acceptance login email/password missing")
    token = await _casdoor_login_native(
        casdoor_base_url=str(settings.CASDOOR_ENDPOINT),
        organization=str(settings.CASDOOR_ORGANIZATION_NAME),
        application=str(settings.CASDOOR_APPLICATION_NAME),
        client_id=str(settings.CASDOOR_CLIENT_ID),
        client_secret=str(settings.CASDOOR_CLIENT_SECRET),
        username=email,
        email=email,
        password=password,
    )
    if not token or token.count(".") != 2:
        raise RuntimeError("portal bearer token is not JWT-like")
    sys.stdout.write(token)
    return 0


raise SystemExit(asyncio.run(main()))
'@
  Set-Content -LiteralPath $tempScript -Value $pythonSource -Encoding UTF8

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = "py"
  $psi.Arguments = "`"$tempScript`""
  $psi.WorkingDirectory = $AppRoot
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.EnvironmentVariables["CERBERUS_ACCEPTANCE_LOGIN_EMAIL"] = $PortalEmail
  $psi.EnvironmentVariables["CERBERUS_ACCEPTANCE_LOGIN_PASSWORD"] = $password
  $psi.EnvironmentVariables["CERBERUS_APP_ROOT"] = $AppRoot

  try {
    $process = [System.Diagnostics.Process]::Start($psi)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($BearerMintTimeoutSeconds * 1000)) {
      try {
        $process.Kill()
      }
      catch {
      }
      throw "Portal bearer mint timed out after $BearerMintTimeoutSeconds seconds. Check Casdoor reachability and transient credentials."
    }
    $process.WaitForExit()
    $stdout = $stdoutTask.Result
    $stderr = $stderrTask.Result
    if ($process.ExitCode -ne 0) {
      throw "Portal bearer mint failed. Check app/Casdoor settings and transient credentials. stderr_len=$($stderr.Length)"
    }
    $token = $stdout.Trim()
    if ([string]::IsNullOrWhiteSpace($token) -or ($token.Split(".").Count -ne 3)) {
      throw "Portal bearer mint returned an invalid token shape."
    }
    return $token
  }
  finally {
    Remove-Item -LiteralPath $tempScript -ErrorAction SilentlyContinue
  }
}

Resolve-RepoPaths

$liveArgs = @(
  "-NoProfile",
  "-ExecutionPolicy",
  "Bypass",
  "-File",
  $LiveAcceptanceScript,
  "-ExePath",
  $ExePath,
  "-BackendUrl",
  $BackendUrl,
  "-AgentId",
  $AgentId,
  "-Username",
  $Username,
  "-InstallService",
  "-StopService",
  "-UninstallService",
  "-AcceptanceRepeat",
  [string]$AcceptanceRepeat,
  "-ReinstallBetweenRepeats"
)

if (-not $SkipLocalUserLifecycle) {
  $liveArgs += "-RunLocalUserLifecycle"
}
if (-not $SkipManagedAssignmentLifecycle) {
  $liveArgs += @(
    "-RunManagedAssignmentLifecycle",
    "-RotateManagedPassword",
    "-DeleteAssignmentAfterManagedLifecycle"
  )
}
if ($PreflightOnly) {
  $liveArgs += "-PreflightOnly"
}
if (-not [string]::IsNullOrWhiteSpace($PortalBearerTokenFile)) {
  $liveArgs += @("-PortalBearerTokenFile", $PortalBearerTokenFile)
}

$previousBearer = [Environment]::GetEnvironmentVariable("CERBERUS_PORTAL_BEARER")
try {
  if ([string]::IsNullOrWhiteSpace($PortalBearerTokenFile) -and [string]::IsNullOrWhiteSpace($previousBearer)) {
    Write-Step "Minting transient portal bearer for acceptance process"
    $transientBearer = New-PortalBearerToken
    [Environment]::SetEnvironmentVariable("CERBERUS_PORTAL_BEARER", $transientBearer, "Process")
  }
  Write-Step "Running live service acceptance wrapper"
  & powershell @liveArgs
  $childExitCode = $LASTEXITCODE
  if ($childExitCode -ne 0) {
    throw "Live service acceptance failed with exit code $childExitCode."
  }
}
finally {
  if ([string]::IsNullOrWhiteSpace($previousBearer)) {
    [Environment]::SetEnvironmentVariable("CERBERUS_PORTAL_BEARER", $null, "Process")
  }
  else {
    [Environment]::SetEnvironmentVariable("CERBERUS_PORTAL_BEARER", $previousBearer, "Process")
  }
}
