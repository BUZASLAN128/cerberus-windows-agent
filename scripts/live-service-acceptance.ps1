param(
  [string]$ExePath = "",
  [string]$BackendUrl = "http://127.0.0.1:8000",
  [string]$AgentId = "",
  [string]$PortalBearerTokenFile = "",
  [string]$PortalBearerEnvVar = "CERBERUS_PORTAL_BEARER",
  [string]$Username = "",
  [switch]$RunLocalUserLifecycle,
  [switch]$RunManagedAssignmentLifecycle,
  [switch]$RunDoubleLockAcceptance,
  [switch]$DoubleLockExclusiveDisposableTarget,
  [string]$ManagedUserId = "",
  [string]$ManagedUserEmail = "",
  [string]$ManagedDisplayName = "",
  [switch]$RotateManagedPassword,
  [switch]$DeleteAssignmentAfterManagedLifecycle,
  [switch]$InstallService,
  [switch]$StartService,
  [switch]$StopService,
  [switch]$UninstallService,
  [ValidateRange(1, 10)]
  [int]$AcceptanceRepeat = 1,
  [switch]$ReinstallBetweenRepeats,
  [switch]$RestartServiceForEachCommand,
  [ValidateRange(0, 120)]
  [int]$RestartServiceCooldownSeconds = 0,
  [ValidateRange(30, 900)]
  [int]$CommandTimeoutSeconds = 240,
  [ValidateRange(1, 60)]
  [int]$PollSeconds = 5,
  [ValidateRange(15, 600)]
  [int]$ServiceProjectionTimeoutSeconds = 180,
  [switch]$SkipServiceProjectionCheck,
  [switch]$PreflightOnly
)

$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
  Write-Host "==> $Message"
}

function Test-IsAdmin {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-ArtifactRoot {
  $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
  $path = Join-Path $repoRoot "out/live-service-acceptance/$stamp"
  New-Item -ItemType Directory -Force -Path $path | Out-Null
  return $path
}

function Write-ArtifactJson {
  param(
    [Parameter(Mandatory=$true)]
    [string]$Name,
    [Parameter(Mandatory=$true)]
    [object]$Value
  )
  $safeName = $Name
  if (-not [string]::IsNullOrWhiteSpace($script:ArtifactScopePrefix)) {
    $safeName = "$script:ArtifactScopePrefix$Name"
  }
  $path = Join-Path $artifactRoot $safeName
  $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $path -Encoding UTF8
  return $path
}

function Set-ArtifactScope {
  param([string]$Prefix)

  $script:ArtifactScopePrefix = $Prefix
}

function Invoke-AgentExe {
  param(
    [Parameter(Mandatory=$true)]
    [string[]]$Arguments,
    [Parameter(Mandatory=$true)]
    [string]$FailureMessage
  )

  $safeName = (($Arguments -join "_") -replace '[^A-Za-z0-9_.-]', '_').Trim('_')
  if ([string]::IsNullOrWhiteSpace($safeName)) {
    $safeName = "agent-command"
  }
  if (-not [string]::IsNullOrWhiteSpace($script:ArtifactScopePrefix)) {
    $safeName = "$script:ArtifactScopePrefix$safeName"
  }
  $stdoutPath = Join-Path $artifactRoot "$safeName.out.txt"
  $stderrPath = Join-Path $artifactRoot "$safeName.err.txt"
  Remove-Item -LiteralPath $stdoutPath, $stderrPath -ErrorAction SilentlyContinue

  $process = Start-Process `
    -FilePath $ExePath `
    -ArgumentList $Arguments `
    -Wait `
    -PassThru `
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdoutPath `
    -RedirectStandardError $stderrPath

  if ($process.ExitCode -ne 0) {
    throw "$FailureMessage with exit code $($process.ExitCode). See $stdoutPath and $stderrPath"
  }
}

function Get-ServiceState {
  param([string]$Phase)

  $serviceName = "CerberusAgent"
  $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
  if ($null -eq $service) {
    return [PSCustomObject]@{
      phase = $Phase
      service = $serviceName
      installed = $false
    }
  }

  return [PSCustomObject]@{
    phase = $Phase
    service = $serviceName
    installed = $true
    status = $service.Status.ToString()
    can_stop = $service.CanStop
    start_type = $service.StartType.ToString()
  }
}

function Write-ServiceState {
  param([string]$Phase)

  $state = Get-ServiceState -Phase $Phase
  $path = Write-ArtifactJson -Name "service-state-$Phase.json" -Value $state
  Write-Host "service-state[$Phase] -> $path"
  return $state
}

function Get-AgentSecretState {
  param([string]$Phase)

  $userPath = Join-Path (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) "CerberusAgent") "secrets.json"
  $machinePath = Join-Path (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) "CerberusAgent") "secrets.json"
  return [PSCustomObject]@{
    phase = $Phase
    user_scope_present = Test-Path -LiteralPath $userPath
    machine_scope_present = Test-Path -LiteralPath $machinePath
    content_redacted = $true
  }
}

function Write-AgentSecretState {
  param([string]$Phase)

  $state = Get-AgentSecretState -Phase $Phase
  $path = Write-ArtifactJson -Name "agent-secret-state-$Phase.json" -Value $state
  Write-Host "agent-secret-state[$Phase] -> $path"
  return $state
}

function Wait-ServiceStatus {
  param(
    [Parameter(Mandatory=$true)]
    [string]$Expected,
    [int]$TimeoutSeconds = 60
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    $state = Get-ServiceState -Phase "wait-$Expected"
    if ($state.installed -and $state.status -eq $Expected) {
      return
    }
    Start-Sleep -Seconds 2
  } while ((Get-Date) -lt $deadline)

  $final = Write-ServiceState -Phase "wait-$Expected-timeout"
  throw "CerberusAgent did not reach status=$Expected. Final status=$($final.status)"
}

function Wait-ServiceAbsent {
  param([int]$TimeoutSeconds = 60)

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    $state = Get-ServiceState -Phase "wait-absent"
    if (-not $state.installed) {
      return
    }
    Start-Sleep -Seconds 2
  } while ((Get-Date) -lt $deadline)

  $final = Write-ServiceState -Phase "wait-absent-timeout"
  throw "CerberusAgent was still installed after uninstall. Final status=$($final.status)"
}

function Assert-ServiceRunningForCommandLoop {
  $state = Write-ServiceState -Phase "before-command-loop"
  if (-not $state.installed -or $state.status -ne "Running") {
    throw "CerberusAgent service must be installed and Running before command lifecycle acceptance."
  }
}

function Test-BackendHealth {
  try {
    $response = Invoke-RestMethod -Method Get -Uri "$BackendUrl/health" -TimeoutSec 5
    return [PSCustomObject]@{
      ok = $true
      status = [string]$response.status
    }
  }
  catch {
    return [PSCustomObject]@{
      ok = $false
      error = $_.Exception.GetType().Name
      message = $_.Exception.Message
    }
  }
}

function Read-PortalBearerToken {
  if (-not [string]::IsNullOrWhiteSpace($PortalBearerTokenFile)) {
    if (-not (Test-Path -LiteralPath $PortalBearerTokenFile)) {
      throw "Portal bearer token file not found."
    }
    $tokenFromFile = (Get-Content -LiteralPath $PortalBearerTokenFile -Raw).Trim()
    if (-not [string]::IsNullOrWhiteSpace($tokenFromFile)) {
      return $tokenFromFile
    }
  }

  $tokenFromEnv = [Environment]::GetEnvironmentVariable($PortalBearerEnvVar)
  if ([string]::IsNullOrWhiteSpace($tokenFromEnv)) {
    throw "Portal bearer token missing. Provide -PortalBearerTokenFile or env $PortalBearerEnvVar."
  }
  return $tokenFromEnv.Trim()
}

function New-PortalContext {
  $token = Read-PortalBearerToken
  $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
  $headers = @{
    Authorization = "Bearer $token"
  }
  $csrfUri = "$BackendUrl/api/v1/csrf/csrf-token"
  $csrf = Invoke-RestMethod -Method Get -Uri $csrfUri -Headers $headers -WebSession $session
  if ([string]::IsNullOrWhiteSpace($csrf.csrf_token)) {
    throw "CSRF token response missing csrf_token."
  }
  $headers["X-CSRFToken"] = [string]$csrf.csrf_token
  return [PSCustomObject]@{
    Headers = $headers
    Session = $session
  }
}

function Ensure-PortalContext {
  if ($null -eq $script:portal) {
    $script:portal = New-PortalContext
  }
}

function Test-PortalReadiness {
  param([bool]$RequireAgentReadable)

  $result = [ordered]@{
    token_file_present = -not [string]::IsNullOrWhiteSpace($PortalBearerTokenFile)
    token_env_name = $PortalBearerEnvVar
    token_env_present = -not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($PortalBearerEnvVar))
    csrf_ok = $false
    agent_read_ok = $false
  }

  try {
    Ensure-PortalContext
    $result["csrf_ok"] = $true
    if ($RequireAgentReadable) {
      $agent = Invoke-PortalJson -Method GET -Path "/api/v1/portal/agents/$AgentId"
      $result["agent_read_ok"] = -not [string]::IsNullOrWhiteSpace([string]$agent.agent_id)
      $result["agent_status"] = [string]$agent.status
      $result["agent_lifecycle_state"] = [string]$agent.lifecycle_state
      $result["agent_registration_state"] = [string]$agent.registration_state
      $result["agent_command_ready"] = [bool]$agent.command_ready
    }
  }
  catch {
    $result["error"] = $_.Exception.GetType().Name
    $result["message"] = $_.Exception.Message
  }

  return [PSCustomObject]$result
}

function Test-LiveAcceptancePreflight {
  param(
    [bool]$RequirePortal,
    [bool]$NeedsAdmin
  )

  if ($RunLocalUserLifecycle -or $RunManagedAssignmentLifecycle) {
    Assert-LabUsername -Value $Username
  }

  $isAdmin = Test-IsAdmin
  $serviceState = Get-ServiceState -Phase "preflight"
  $backendHealth = Test-BackendHealth
  $portalReadiness = $null
  if ($RequirePortal) {
    $portalReadiness = Test-PortalReadiness -RequireAgentReadable (-not [string]::IsNullOrWhiteSpace($AgentId))
  }

  $checks = [ordered]@{
    exe_present = Test-Path -LiteralPath $ExePath
    backend_health_ok = [bool]$backendHealth.ok
    admin_required = [bool]$NeedsAdmin
    is_admin = [bool]$isAdmin
    agent_id_required = [bool]$RequirePortal
    agent_id_present = -not [string]::IsNullOrWhiteSpace($AgentId)
    portal_required = [bool]$RequirePortal
    portal_csrf_ok = if ($null -eq $portalReadiness) { $null } else { [bool]$portalReadiness.csrf_ok }
    portal_agent_read_ok = if ($null -eq $portalReadiness) { $null } else { [bool]$portalReadiness.agent_read_ok }
  }

  $failures = @()
  if (-not $checks.exe_present) {
    $failures += "exe_missing"
  }
  if (-not $checks.backend_health_ok) {
    $failures += "backend_health_failed"
  }
  if ($NeedsAdmin -and -not $isAdmin) {
    $failures += "admin_required"
  }
  if ($RunManagedAssignmentLifecycle -and -not $InstallService -and -not $StartService) {
    if (-not $serviceState.installed -or $serviceState.status -ne "Running") {
      $failures += "service_running_required"
    }
  }
  if ($RequirePortal -and [string]::IsNullOrWhiteSpace($AgentId)) {
    $failures += "agent_id_required"
  }
  if ($RequirePortal -and $null -ne $portalReadiness -and -not [bool]$portalReadiness.csrf_ok) {
    $failures += "portal_auth_failed"
  }
  if (
    $RequirePortal `
      -and -not [string]::IsNullOrWhiteSpace($AgentId) `
      -and $null -ne $portalReadiness `
      -and [bool]$portalReadiness.csrf_ok `
      -and -not [bool]$portalReadiness.agent_read_ok
  ) {
    $failures += "portal_agent_read_failed"
  }

  $result = [ordered]@{
    checked_at = (Get-Date).ToUniversalTime().ToString("O")
    artifact_root = $artifactRoot
    backend_url_present = -not [string]::IsNullOrWhiteSpace($BackendUrl)
    checks = $checks
    failures = $failures
    service_state = $serviceState
    backend_health = $backendHealth
    portal_readiness = $portalReadiness
  }

  $path = Write-ArtifactJson -Name "preflight.json" -Value $result
  Write-Host "preflight -> $path"

  if ($failures.Count -gt 0) {
    throw "Live service acceptance preflight failed: $($failures -join ', ')"
  }
}

function Invoke-PortalJson {
  param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("GET", "POST", "PATCH", "DELETE")]
    [string]$Method,
    [Parameter(Mandatory=$true)]
    [string]$Path,
    [object]$Body = $null
  )

  $uri = "$BackendUrl$Path"
  $script:LastPortalFailure = $null
  try {
    if ($null -eq $Body) {
      $response = Invoke-RestMethod -Method $Method -Uri $uri -Headers $portal.Headers -WebSession $portal.Session
      return $response
    }

    $json = $Body | ConvertTo-Json -Depth 8
    $response = Invoke-RestMethod `
      -Method $Method `
      -Uri $uri `
      -Headers $portal.Headers `
      -WebSession $portal.Session `
      -ContentType "application/json" `
      -Body $json
    return $response
  } catch {
    $errorRecord = $_
    $responseBody = $null
    $statusCode = $null
    $response = $null
    try {
      if ($null -ne $errorRecord.Exception) {
        $response = $errorRecord.Exception.Response
      }
    } catch {
      $response = $null
    }
    if ($null -ne $response) {
      try {
        $statusCode = [int]$response.StatusCode
      } catch {
        $statusCode = $null
      }
    }

    # Windows PowerShell 5.1 consumes the WebException response stream before
    # this catch block and exposes the JSON through ErrorDetails.Message.
    try {
      if ($null -ne $errorRecord.ErrorDetails) {
        $errorDetailsBody = [string]$errorRecord.ErrorDetails.Message
        if (-not [string]::IsNullOrWhiteSpace($errorDetailsBody)) {
          $responseBody = $errorDetailsBody
        }
      }
    } catch {
      $responseBody = $null
    }

    # PowerShell 7 exposes an HttpResponseMessage. Prefer its content when
    # PS5.1 did not provide ErrorDetails.Message, then retain the legacy stream
    # fallback for WebException implementations that still expose a body.
    if ([string]::IsNullOrWhiteSpace($responseBody) -and $null -ne $response) {
      try {
        $content = $response.Content
        if ($null -ne $content) {
          if ($content -is [string]) {
            $responseBody = [string]$content
          } else {
            $readAsStringMethod = $content.PSObject.Methods["ReadAsStringAsync"]
            if ($null -ne $readAsStringMethod) {
              $contentTask = $content.ReadAsStringAsync()
              if ($null -ne $contentTask) {
                $responseBody = [string]$contentTask.GetAwaiter().GetResult()
              }
            }
          }
        }
      } catch {
        $responseBody = $null
      }
    }
    if ([string]::IsNullOrWhiteSpace($responseBody) -and $null -ne $response) {
      try {
        $stream = $response.GetResponseStream()
        if ($stream) {
          $reader = [System.IO.StreamReader]::new($stream)
          $responseBody = $reader.ReadToEnd()
          $reader.Dispose()
        }
      } catch {
        $responseBody = "<failed to read response body>"
      }
    }
    $detailCode = $null
    $blockerCodes = @()
    if (-not [string]::IsNullOrWhiteSpace($responseBody) -and $responseBody -ne "<failed to read response body>") {
      try {
        $parsedFailure = $responseBody | ConvertFrom-Json -ErrorAction Stop
        $detailProperty = if ($null -eq $parsedFailure) { $null } else { $parsedFailure.PSObject.Properties["detail"] }
        if ($null -ne $detailProperty) {
          $detail = $detailProperty.Value
          if ($detail -is [string]) {
            if (-not [string]::IsNullOrWhiteSpace($detail)) {
              $detailCode = [string]$detail
            }
          } elseif ($null -ne $detail) {
            $codeProperty = $detail.PSObject.Properties["code"]
            if ($null -ne $codeProperty -and $codeProperty.Value -is [string] -and
                -not [string]::IsNullOrWhiteSpace([string]$codeProperty.Value)) {
              $detailCode = [string]$codeProperty.Value
            }
            $paramsProperty = $detail.PSObject.Properties["params"]
            if ($null -ne $paramsProperty -and $null -ne $paramsProperty.Value) {
              $blockerProperty = $paramsProperty.Value.PSObject.Properties["blocker_codes"]
              if ($null -ne $blockerProperty -and $blockerProperty.Value -is [string]) {
                $blockerCodes = @(
                  [string]$blockerProperty.Value -split ',' |
                    ForEach-Object { $_.Trim() } |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                )
              }
            }
          }
        }
      } catch {
        $detailCode = $null
        $blockerCodes = @()
      }
    }
    $script:LastPortalFailure = [ordered]@{
      status_code = $statusCode
      detail_code = $detailCode
      blocker_codes = $blockerCodes
    }
    $safeFailure = [ordered]@{
      method = $Method
      path = $Path
      status_code = $statusCode
      request_body = $Body
      response_body = $responseBody
      error = $errorRecord.Exception.Message
    }
    $failurePath = Write-ArtifactJson -Name "portal-request-failed-$($Method.ToLowerInvariant())-$((New-ClientRequestId -Prefix 'http') -replace '[^a-zA-Z0-9-]', '-').json" -Value $safeFailure
    Write-Host "portal-request-failed -> $failurePath"
    throw
  }
}

function Get-ObjectPropertyValue {
  param(
    [Parameter(Mandatory=$true)]
    [object]$InputObject,
    [Parameter(Mandatory=$true)]
    [string]$Name
  )

  $property = $InputObject.PSObject.Properties[$Name]
  if ($null -eq $property) {
    return $null
  }
  return $property.Value
}

function Write-PortalAgentSnapshot {
  param([string]$Phase)

  if ([string]::IsNullOrWhiteSpace($AgentId)) {
    throw "AgentId is required for portal agent projection evidence."
  }

  Ensure-PortalContext
  $agent = Invoke-PortalJson -Method GET -Path "/api/v1/portal/agents/$AgentId"
  $safePhase = ($Phase -replace '[^A-Za-z0-9_.-]', '_')
  $path = Write-ArtifactJson -Name "portal-agent-$safePhase.json" -Value $agent
  Write-Host "portal-agent[$Phase] -> $path"
  return $agent
}

function Wait-PortalServiceProjection {
  param(
    [Parameter(Mandatory=$true)]
    [string]$Phase,
    [Parameter(Mandatory=$true)]
    [bool]$ExpectedInstalled,
    [Parameter(Mandatory=$true)]
    [bool]$ExpectedRunning
  )

  if ($SkipServiceProjectionCheck) {
    return
  }

  $deadline = (Get-Date).AddSeconds($ServiceProjectionTimeoutSeconds)
  $lastProjection = $null
  do {
    $agent = Write-PortalAgentSnapshot -Phase "$Phase-latest"
    $installed = Get-ObjectPropertyValue -InputObject $agent -Name "service_installed"
    $running = Get-ObjectPropertyValue -InputObject $agent -Name "service_running"
    $lastProjection = [ordered]@{
      phase = $Phase
      expected_installed = $ExpectedInstalled
      expected_running = $ExpectedRunning
      actual_installed = $installed
      actual_running = $running
      registration_state = [string](Get-ObjectPropertyValue -InputObject $agent -Name "registration_state")
      lifecycle_state = [string](Get-ObjectPropertyValue -InputObject $agent -Name "lifecycle_state")
      status = [string](Get-ObjectPropertyValue -InputObject $agent -Name "status")
      command_ready = Get-ObjectPropertyValue -InputObject $agent -Name "command_ready"
      last_heartbeat_at = [string](Get-ObjectPropertyValue -InputObject $agent -Name "last_heartbeat_at")
      captured_at = (Get-Date).ToUniversalTime().ToString("O")
    }

    if ($installed -eq $ExpectedInstalled -and $running -eq $ExpectedRunning) {
      $path = Write-ArtifactJson -Name "portal-service-projection-$Phase.json" -Value $lastProjection
      Write-Host "portal-service-projection[$Phase] -> $path"
      return
    }

    Start-Sleep -Seconds $PollSeconds
  } while ((Get-Date) -lt $deadline)

  $path = Write-ArtifactJson -Name "portal-service-projection-$Phase-timeout.json" -Value $lastProjection
  throw "Portal service projection did not reach installed=$ExpectedInstalled running=$ExpectedRunning for phase=$Phase. See $path"
}

function Assert-LabUsername {
  param([string]$Value)

  if ($Value -notmatch '^cerb_[a-z][a-z0-9]{4}_[a-z2-7]{8}$') {
    throw "Username must match cerb_<base5>_<hash8>; refusing to mutate arbitrary local users."
  }
}

function Get-RemoteDesktopUsersGroupName {
  try {
    $sid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-555")
    $account = $sid.Translate([System.Security.Principal.NTAccount]).Value
    return ($account -split "\\")[-1]
  }
  catch {
    return "Remote Desktop Users"
  }
}

function Test-RemoteDesktopUsersMember {
  param([string]$Name)

  try {
    $groupName = Get-RemoteDesktopUsersGroupName
    $members = Get-LocalGroupMember -Group $groupName -ErrorAction Stop
    foreach ($member in $members) {
      $memberName = [string]$member.Name
      if ($memberName.Equals($Name, [System.StringComparison]::OrdinalIgnoreCase) -or
          $memberName.EndsWith("\$Name", [System.StringComparison]::OrdinalIgnoreCase)) {
        return $true
      }
    }
    return $false
  }
  catch {
    return $null
  }
}

function Get-LocalUserState {
  param([string]$Name)

  $user = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
  if ($null -eq $user) {
    return [PSCustomObject]@{
      username = $Name
      exists = $false
    }
  }
  return [PSCustomObject]@{
    username = $Name
    exists = $true
    sid = [string]$user.SID.Value
    enabled = [bool]$user.Enabled
    description = [string]$user.Description
    password_cannot_change = -not [bool]$user.UserMayChangePassword
    password_never_expires = $null -eq $user.PasswordExpires
    password_required = [bool]$user.PasswordRequired
    remote_desktop_users_member = Test-RemoteDesktopUsersMember -Name $Name
  }
}

function Write-LocalUserState {
  param(
    [string]$Phase,
    [string]$Name
  )

  $state = Get-LocalUserState -Name $Name
  $path = Write-ArtifactJson -Name "local-user-$Phase.json" -Value $state
  Write-Host "local-user[$Phase] -> $path"
  return $state
}

function Cleanup-LabLocalUserOnFailure {
  param(
    [string]$Phase,
    [string]$Name
  )

  if ([string]::IsNullOrWhiteSpace($Name)) {
    return
  }
  Assert-LabUsername -Value $Name
  $before = Write-LocalUserState -Phase "$Phase-cleanup-before" -Name $Name
  $result = [ordered]@{
    phase = $Phase
    username = $Name
    attempted = $false
    removed = $false
    error = $null
  }
  if (-not $before.exists) {
    $result["removed"] = $true
    Write-ArtifactJson -Name "local-user-$Phase-cleanup-result.json" -Value $result | Out-Null
    return
  }

  try {
    $result["attempted"] = $true
    Remove-LocalUser -Name $Name -ErrorAction Stop
    $after = Write-LocalUserState -Phase "$Phase-cleanup-after" -Name $Name
    $result["removed"] = -not [bool]$after.exists
  }
  catch {
    $result["error"] = $_.Exception.Message
  }
  Write-ArtifactJson -Name "local-user-$Phase-cleanup-result.json" -Value $result | Out-Null
}

function Enqueue-LocalUserCommand {
  param(
    [ValidateSet("create", "disable", "delete")]
    [string]$Action,
    [string]$Name
  )

  throw "Direct local-user lab command lifecycle is retired. Use -RunManagedAssignmentLifecycle for production managed-user acceptance."
}

function New-ClientRequestId {
  param([string]$Prefix)

  return "live-$Prefix-$([Guid]::NewGuid().ToString('N'))"
}

function Resolve-ManagedAssignmentUser {
  if (-not [string]::IsNullOrWhiteSpace($ManagedUserId) -and -not $ManagedUserId.StartsWith("LIVE/")) {
    return
  }

  $usersResponse = Invoke-PortalJson -Method GET -Path "/api/v1/portal/users/?limit=100"
  $users = @()
  if ($usersResponse.PSObject.Properties["users"]) {
    $users = @($usersResponse.users)
  }

  $activeUsers = @(
    $users | Where-Object {
      -not [string]::IsNullOrWhiteSpace([string]$_.user_id) -and
      ([string]$_.state).Trim().ToLowerInvariant() -eq "active"
    }
  )
  if ($activeUsers.Count -lt 1) {
    throw "No active tenant users are available for managed assignment acceptance."
  }

  $assignmentRows = @()
  if (-not [string]::IsNullOrWhiteSpace($AgentId)) {
    try {
      $assignmentsResponse = Invoke-PortalJson -Method GET -Path "/api/v1/portal/agents/$AgentId/assignments"
      $assignmentRows = @($assignmentsResponse)
    } catch {
      Write-Host "managed assignment candidate scan skipped: $($_.Exception.Message)"
    }
  }
  $occupiedUserIds = @()
  $candidateEvidence = @()
  foreach ($assignmentRow in $assignmentRows) {
    $assignedUserId = [string]$assignmentRow.user_id
    $assignedUsername = [string]$assignmentRow.managed_username
    if ([string]::IsNullOrWhiteSpace($assignedUserId) -or [string]::IsNullOrWhiteSpace($assignedUsername)) {
      continue
    }
    $localState = Get-LocalUserState -Name $assignedUsername
    $candidateEvidence += [ordered]@{
      user_id = $assignedUserId
      managed_username = $assignedUsername
      local_user_exists = [bool]$localState.exists
      account_status = [string]$assignmentRow.managed_account_status
      assignment_status = [string]$assignmentRow.status
    }
    if ($localState.exists) {
      $occupiedUserIds += $assignedUserId
    }
  }
  if ($candidateEvidence.Count -gt 0) {
    $path = Write-ArtifactJson -Name "portal-managed-assignment-candidates.json" -Value $candidateEvidence
    Write-Host "portal-managed-assignment-candidates -> $path"
  }

  $availableUsers = @(
    $activeUsers | Where-Object {
      $occupiedUserIds -notcontains [string]$_.user_id
    }
  )
  if ($availableUsers.Count -lt 1) {
    $availableUsers = $activeUsers
  }

  $selected = $null
  if (-not [string]::IsNullOrWhiteSpace($ManagedUserEmail)) {
    $wantedEmail = $ManagedUserEmail.Trim().ToLowerInvariant()
    $selected = $availableUsers | Where-Object {
      ([string]$_.email).Trim().ToLowerInvariant() -eq $wantedEmail -or
      ([string]$_.user_email).Trim().ToLowerInvariant() -eq $wantedEmail
    } | Select-Object -First 1
  }
  if ($null -eq $selected) {
    $selected = $availableUsers | Where-Object {
      ([string]$_.email).Trim().ToLowerInvariant().EndsWith("@acceptance.local") -or
      ([string]$_.user_email).Trim().ToLowerInvariant().EndsWith("@acceptance.local")
    } | Select-Object -First 1
  }
  if ($null -eq $selected) {
    $selected = $availableUsers | Where-Object {
      $role = ([string]$_.role).Trim().ToLowerInvariant()
      $role -notin @("tenant_owner", "owner", "workspace_owner")
    } | Select-Object -First 1
  }
  if ($null -eq $selected) {
    $selected = $availableUsers | Select-Object -First 1
  }

  $script:ManagedUserId = [string]$selected.user_id
  $email = [string]$selected.email
  if ([string]::IsNullOrWhiteSpace($email)) {
    $email = [string]$selected.user_email
  }
  if (-not [string]::IsNullOrWhiteSpace($email)) {
    $script:ManagedUserEmail = $email
  }
  if ([string]::IsNullOrWhiteSpace($ManagedDisplayName)) {
    $script:ManagedDisplayName = if (-not [string]::IsNullOrWhiteSpace($email)) { $email } else { $script:ManagedUserId }
  }

  $path = Write-ArtifactJson -Name "portal-managed-assignment-user.json" -Value ([ordered]@{
    user_id = $script:ManagedUserId
    email = $script:ManagedUserEmail
    role = [string]$selected.role
    state = [string]$selected.state
  })
  Write-Host "portal-managed-assignment-user -> $path"
}

function New-ManagedAssignment {
  Resolve-ManagedAssignmentUser

  $body = @{
    user_id = $ManagedUserId
    access_profile = "managed_local_user"
  }
  if (-not [string]::IsNullOrWhiteSpace($ManagedUserEmail)) {
    $body["user_email"] = $ManagedUserEmail
  }
  if (-not [string]::IsNullOrWhiteSpace($ManagedDisplayName)) {
    $body["display_name"] = $ManagedDisplayName
  }

  $response = Invoke-PortalJson `
    -Method POST `
    -Path "/api/v1/portal/agents/$AgentId/assignments" `
    -Body $body
  $path = Write-ArtifactJson -Name "portal-managed-assignment.json" -Value $response
  Write-Host "portal-managed-assignment -> $path"
  return $response
}

function Enqueue-ManagedUserCommand {
  param(
    [ValidateSet("create", "rotate-password", "disable", "delete")]
    [string]$Action,
    [string]$AssignmentId
  )

  $body = @{
    reason = "Phase 7 live managed assignment acceptance"
    client_request_id = New-ClientRequestId -Prefix $Action
  }
  if ($Action -eq "delete") {
    $body["confirm_delete"] = $true
  }
  $response = Invoke-PortalJson `
    -Method POST `
    -Path "/api/v1/portal/agents/$AgentId/managed-users/$AssignmentId/$Action" `
    -Body $body
  $safeAction = ($Action -replace '[^A-Za-z0-9_.-]', '_')
  $path = Write-ArtifactJson -Name "portal-managed-command-$safeAction.json" -Value $response
  Write-Host "portal-managed-command[$Action] -> $path"
  return $response
}

function Remove-ManagedAssignment {
  param([string]$AssignmentId)

  $response = Invoke-PortalJson `
    -Method DELETE `
    -Path "/api/v1/portal/agents/$AgentId/assignments/$AssignmentId"
  $path = Write-ArtifactJson -Name "portal-managed-assignment-delete.json" -Value $response
  Write-Host "portal-managed-assignment-delete -> $path"
  return $response
}

function Assert-DoubleLockDisabledAccountState {
  param(
    [Parameter(Mandatory=$true)][ValidateSet("disable", "rotate")][string]$Action,
    [Parameter(Mandatory=$true)][object]$State,
    [Parameter(Mandatory=$true)][string]$ExpectedSid
  )

  if (-not $State.exists -or [bool]$State.enabled -or
      $State.remote_desktop_users_member -ne $false -or
      [string]$State.sid -ne $ExpectedSid) {
    $description = if ($Action -eq "disable") {
      "preserve the account/SID while removing RDP membership"
    } else {
      "preserve the disabled state/SID without restoring RDP membership"
    }
    throw "Double-lock disabled-account $Action did not $description."
  }
}

function Assert-DoubleLockAgentDetail {
  param([Parameter(Mandatory=$true)][string]$Phase)

  $detail = Invoke-PortalJson -Method GET -Path "/api/v1/portal/agents/$AgentId"
  if ($null -eq $detail -or [string]$detail.agent_id -ne [string]$AgentId) {
    throw "Double-lock agent detail identity changed before $Phase."
  }
  return $detail
}

function Cleanup-DoubleLockManagedAssignment {
  param(
    [Parameter(Mandatory=$true)][string]$AssignmentId,
    [Parameter(Mandatory=$true)][string]$ManagedUsername,
    [AllowEmptyCollection()][string[]]$OwnedCommandIds = @()
  )

  Assert-LabUsername -Value $ManagedUsername
  $ownedIds = @($OwnedCommandIds + @($script:DoubleLockOwnedCommandIds) | Select-Object -Unique)
  $before = Write-LocalUserState -Phase "double-lock-product-cleanup-before" -Name $ManagedUsername
  $ownershipBefore = Get-ManagedOwnershipState -Name $ManagedUsername

  $assignmentRows = @(Invoke-PortalJson -Method GET -Path "/api/v1/portal/agents/$AgentId/assignments")
  $assignmentMatches = @($assignmentRows | Where-Object { [string]$_.id -eq $AssignmentId })
  if ($assignmentMatches.Count -ne 1) {
    throw "Double-lock cleanup requires exactly one live target assignment."
  }
  $assignment = $assignmentMatches[0]
  if ([string]$assignment.user_id -ne [string]$ManagedUserId -or
      [string]$assignment.managed_username -ne $ManagedUsername) {
    throw "Double-lock cleanup target assignment identity changed."
  }

  if (-not $before.exists -and -not $ownershipBefore.exists) {
    Assert-DoubleLockPreflight -Phase "failure-before-SAM-cleanup" -BaselineCommands $script:DoubleLockBaselineCommands `
      -AssignmentId $AssignmentId -ManagedUsername $ManagedUsername -OwnedCommandIds $ownedIds -Stage "failure-before-SAM"
    Remove-ManagedAssignment -AssignmentId $AssignmentId | Out-Null
    $remaining = @(Invoke-PortalJson -Method GET -Path "/api/v1/portal/agents/$AgentId/assignments" | Where-Object { [string]$_.id -eq $AssignmentId })
    if ($remaining.Count -ne 0) { throw "Double-lock failure cleanup did not remove the created assignment." }
    return
  }

  Assert-DoubleLockPreflight -Phase "product-cleanup" -BaselineCommands $script:DoubleLockBaselineCommands `
    -AssignmentId $AssignmentId -ManagedUsername $ManagedUsername -OwnedCommandIds $ownedIds -Stage "owned"
  Run-ManagedUserAction -Action "disable" -AssignmentId $AssignmentId | Out-Null
  $afterDisable = Write-LocalUserState -Phase "double-lock-product-cleanup-after-disable" -Name $ManagedUsername
  if ($afterDisable.exists -and [bool]$afterDisable.enabled) {
    throw "Product managed disable did not disable $ManagedUsername."
  }
  Run-ManagedUserAction -Action "delete" -AssignmentId $AssignmentId | Out-Null
  $afterDelete = Write-LocalUserState -Phase "double-lock-product-cleanup-after-delete" -Name $ManagedUsername
  $ownershipAfterDelete = Get-ManagedOwnershipState -Name $ManagedUsername
  if ($afterDelete.exists -or $ownershipAfterDelete.exists -or $afterDelete.remote_desktop_users_member) {
    throw "Product managed delete did not remove the exact local user, RDP membership, and ownership marker."
  }
  Assert-DoubleLockPreflight -Phase "product-cleanup-before-assignment-removal" -BaselineCommands $script:DoubleLockBaselineCommands `
    -AssignmentId $AssignmentId -ManagedUsername $ManagedUsername -OwnedCommandIds $script:DoubleLockOwnedCommandIds -Stage "failure-before-SAM"
  Remove-ManagedAssignment -AssignmentId $AssignmentId | Out-Null
  $remainingAssignments = @(Invoke-PortalJson -Method GET -Path "/api/v1/portal/agents/$AgentId/assignments") |
    Where-Object { [string]$_.id -eq $AssignmentId }
  if ($remainingAssignments.Count -ne 0) {
    throw "Managed assignment $AssignmentId remains visible after product cleanup."
  }
  Assert-DoubleLockPreflight -Phase "product-cleanup-complete" -BaselineCommands $script:DoubleLockBaselineCommands `
    -ManagedUsername $ManagedUsername -OwnedCommandIds $script:DoubleLockOwnedCommandIds -Stage "post-cleanup"
}

function Get-ManagedUserPolicy {
  Ensure-PortalContext
  $agent = Invoke-PortalJson -Method GET -Path "/api/v1/portal/agents/$AgentId"
  $policy = Get-ObjectPropertyValue -InputObject $agent -Name "managed_user_policy"
  if ($null -eq $policy) {
    throw "Portal agent projection did not include managed_user_policy."
  }
  return $policy
}

function Set-WebManagedUserPolicy {
  param(
    [Parameter(Mandatory=$true)]
    [bool]$Enabled,
    [Parameter(Mandatory=$true)]
    [string]$Reason
  )

  $current = Get-ManagedUserPolicy
  $revision = [int](Get-ObjectPropertyValue -InputObject $current -Name "revision")
  $response = Invoke-PortalJson `
    -Method PATCH `
    -Path "/api/v1/portal/agents/$AgentId/account-policy" `
    -Body @{
      web_enabled = $Enabled
      expected_revision = $revision
      reason = $Reason.Substring(0, [Math]::Min($Reason.Length, 160))
    }
  $path = Write-ArtifactJson -Name "double-lock-web-policy-$($Enabled.ToString().ToLowerInvariant()).json" -Value $response
  Write-Host "double-lock web policy enabled=$Enabled -> $path"
  return $response
}

function Wait-ManagedUserPolicy {
  param(
    [Parameter(Mandatory=$true)]
    [bool]$ExpectedWebEnabled,
    [Parameter(Mandatory=$true)]
    [string]$ExpectedLocalState,
    [Parameter(Mandatory=$true)]
    [string]$Phase
  )

  $deadline = (Get-Date).AddSeconds($ServiceProjectionTimeoutSeconds)
  $last = $null
  do {
    $last = Get-ManagedUserPolicy
    $web = [bool](Get-ObjectPropertyValue -InputObject $last -Name "web_enabled")
    $local = [string](Get-ObjectPropertyValue -InputObject $last -Name "local_state")
    if ($web -eq $ExpectedWebEnabled -and $local -eq $ExpectedLocalState) {
      $path = Write-ArtifactJson -Name "double-lock-policy-$Phase.json" -Value $last
      Write-Host "double-lock policy[$Phase] -> $path"
      return $last
    }
    Start-Sleep -Seconds $PollSeconds
  } while ((Get-Date) -lt $deadline)

  $path = Write-ArtifactJson -Name "double-lock-policy-$Phase-timeout.json" -Value $last
  throw "Managed account policy did not reach web_enabled=$ExpectedWebEnabled local_state=$ExpectedLocalState. See $path"
}

function Set-LocalManagedUserPolicy {
  param([Parameter(Mandatory=$true)][bool]$Enabled)

  # This is the same installed-agent CLI path used by the GUI control. It
  # writes the canonical machine policy and deliberately does not restart the
  # service; the running service must observe the change on its next heartbeat.
  $argument = if ($Enabled) { "--enable-local-user-create" } else { "--disable-local-user-create" }
  Invoke-AgentExe -Arguments @($argument) -FailureMessage "Local managed-user policy toggle failed"
  Write-ArtifactJson -Name "double-lock-local-policy-$($Enabled.ToString().ToLowerInvariant()).json" -Value ([ordered]@{
    enabled = $Enabled
    service_restart_requested = $false
    cli_argument = $argument
  }) | Out-Null
}

function Invoke-ManagedActionExpectedDenied {
  param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("create", "rotate-password")]
    [string]$Action,
    [Parameter(Mandatory=$true)]
    [string]$AssignmentId,
    [Parameter(Mandatory=$true)]
    [string]$Phase,
    [Parameter(Mandatory=$true)]
    [string[]]$ExpectedBlockerCodes
  )

  $script:LastPortalFailure = $null
  try {
    $null = Enqueue-ManagedUserCommand -Action $Action -AssignmentId $AssignmentId
    throw "Expected managed-user $Action denial was not observed while double lock was closed."
  }
  catch {
    $failure = $script:LastPortalFailure
    $statusCode = if ($null -eq $failure) { $null } else { $failure.status_code }
    $detailCode = if ($null -eq $failure) { $null } else { [string]$failure.detail_code }
    $actualBlockerCodes = if ($null -eq $failure) { @() } else { @($failure.blocker_codes) }
    $missingBlockers = @($ExpectedBlockerCodes | Where-Object { $actualBlockerCodes -notcontains $_ })
    if ($statusCode -ne 409 -or $detailCode -ne "managed_user_create_policy_blocked" -or $missingBlockers.Count -gt 0) {
      throw "Managed-user $Action denial was not the expected policy rejection (status=$statusCode code=$detailCode blockers=$($actualBlockerCodes -join ','))."
    }
    $path = Write-ArtifactJson -Name "double-lock-denied-$Phase.json" -Value ([ordered]@{
      action = $Action
      phase = $Phase
      status_code = $statusCode
      detail_code = $detailCode
      blocker_codes = $actualBlockerCodes
      denied = $true
    })
    Write-Host "double-lock denied[$Action/$Phase] -> $path"
  }
}

function Get-ManagedOwnershipState {
  param([Parameter(Mandatory=$true)][string]$Name)

  Assert-LabUsername -Value $Name
  $path = "HKLM:\SOFTWARE\Cerberus\ManagedLocalUsers\$Name"
  $key = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue
  if ($null -eq $key) {
    return [PSCustomObject]@{ username = $Name; registry_path = $path; exists = $false }
  }
  return [PSCustomObject]@{
    username = $Name
    registry_path = $path
    exists = $true
    marker_id = [string]$key.marker_id
    assignment_id = [string]$key.assignment_id
    managed_account_id = [string]$key.managed_account_id
    membership_user_id = [string]$key.membership_user_id
    agent_id = [string]$key.agent_id
    tenant_id = [string]$key.tenant_id
    local_sid = [string]$key.local_sid
  }
}

function Get-AllAgentCommands {
  $pageSize = 100
  $offset = 0
  $all = @()
  $seen = @{}
  $previousCreatedAt = $null
  while ($true) {
    $page = @(Invoke-PortalJson -Method GET -Path "/api/v1/portal/agents/$AgentId/commands?offset=$offset&limit=$pageSize")
    foreach ($command in $page) {
      $id = [string]$command.id
      if ([string]::IsNullOrWhiteSpace($id) -or $seen.ContainsKey($id)) {
        throw "Agent command pagination was inconsistent; refusing double-lock mutation."
      }
      $createdAt = [string]$command.created_at
      if ($null -ne $previousCreatedAt -and $createdAt -gt $previousCreatedAt) {
        throw "Agent command pagination order changed; refusing double-lock mutation."
      }
      $seen[$id] = $true
      $all += $command
      $previousCreatedAt = $createdAt
    }
    if ($page.Count -lt $pageSize) { return $all }
    $offset += $page.Count
  }
}

function Assert-DoubleLockPreflight {
  param(
    [Parameter(Mandatory=$true)][string]$Phase,
    [Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$BaselineCommands,
    [ValidateSet("pre-create", "owned", "post-create", "failure-before-SAM", "post-cleanup")][string]$Stage = "pre-create",
    [AllowEmptyCollection()][string[]]$OwnedCommandIds = @(),
    [string]$AssignmentId = "",
    [string]$ManagedUsername = ""
  )

  $assignments = @(Invoke-PortalJson -Method GET -Path "/api/v1/portal/agents/$AgentId/assignments")
  if ([string]::IsNullOrWhiteSpace($AssignmentId)) {
    if ($assignments.Count -ne 0) { throw "Double-lock disposable target has active assignments before $Phase." }
  }
  else {
    $targetAssignments = @($assignments | Where-Object { [string]$_.id -eq $AssignmentId })
    if ($targetAssignments.Count -ne 1 -or
        @($assignments | Where-Object { [string]$_.id -ne $AssignmentId }).Count -ne 0 -or
        [string]$targetAssignments[0].user_id -ne [string]$ManagedUserId) {
      throw "Double-lock target assignment changed before $Phase."
    }
    if (-not [string]::IsNullOrWhiteSpace($ManagedUsername) -and
        [string]$targetAssignments[0].managed_username -ne $ManagedUsername) {
      throw "Double-lock target managed username changed before $Phase."
    }
  }

  $commands = @(Get-AllAgentCommands)
  $baselineById = @{}
  foreach ($command in $BaselineCommands) {
    $baselineById[[string]$command.id] = [string]$command.status
  }
  foreach ($id in $baselineById.Keys) {
    $current = @($commands | Where-Object { [string]$_.id -eq $id })
    if ($current.Count -ne 1 -or [string]$current[0].status -ne $baselineById[$id]) {
      throw "Double-lock command baseline changed before $Phase (command=$id)."
    }
  }
  $ownedById = @{}
  foreach ($id in $OwnedCommandIds) { if (-not [string]::IsNullOrWhiteSpace($id)) { $ownedById[$id] = $true } }
  foreach ($command in $commands) {
    $id = [string]$command.id
    if (-not $baselineById.ContainsKey($id) -and -not $ownedById.ContainsKey($id)) {
      throw "Double-lock command baseline has an unknown new command before $Phase (command=$id)."
    }
  }
  foreach ($id in $ownedById.Keys) {
    $owned = @($commands | Where-Object { [string]$_.id -eq $id })
    if ($owned.Count -ne 1 -or [string]$owned[0].status -notin @("DONE", "FAILED")) {
      throw "Double-lock owned command $id is not terminal before $Phase."
    }
  }
  $inFlight = @($commands | Where-Object {
    $status = [string]$_.status
    $managedPrefix = ([string]$_.idempotency_key).StartsWith("managed-user:", [System.StringComparison]::Ordinal)
    ($status -in @("QUEUED", "PROCESSING")) -and
      ($managedPrefix -or [string]$_.type -eq "windows.local_user.create")
  })
  if ($inFlight.Count -gt 0) {
    throw "Double-lock target has queued/processing managed-user work before $Phase."
  }

  if ($Stage -in @("pre-create", "failure-before-SAM", "post-cleanup") -and -not [string]::IsNullOrWhiteSpace($ManagedUsername)) {
    $local = Get-LocalUserState -Name $ManagedUsername
    $ownership = Get-ManagedOwnershipState -Name $ManagedUsername
    if ($local.exists -or $ownership.exists) {
      throw "Double-lock target local user or ownership marker already exists before $Phase."
    }
  }
  if ($Stage -in @("owned", "post-create") -and -not [string]::IsNullOrWhiteSpace($ManagedUsername)) {
    $target = $targetAssignments[0]
    $local = Get-LocalUserState -Name $ManagedUsername
    $ownership = Get-ManagedOwnershipState -Name $ManagedUsername
    if (-not $local.exists -or -not $ownership.exists -or
        [string]$ownership.assignment_id -ne $AssignmentId -or
        [string]$ownership.membership_user_id -ne [string]$ManagedUserId -or
        [string]$ownership.agent_id -ne [string]$AgentId -or
        [string]$ownership.marker_id -eq "" -or
        ([string]$target.managed_account_id -ne "" -and [string]$ownership.managed_account_id -ne [string]$target.managed_account_id) -or
        ([string]$target.tenant_id -ne "" -and [string]$ownership.tenant_id -ne [string]$target.tenant_id)) {
      throw "Double-lock owned account/marker identity is not exact before $Phase."
    }
    if ([string]$ownership.local_sid -ne "" -and [string]$local.sid -ne [string]$ownership.local_sid) {
      throw "Double-lock ownership marker SID does not match the local account before $Phase."
    }
  }
}

function Run-DoubleLockAcceptance {
  if (-not $DoubleLockExclusiveDisposableTarget) {
    throw "Double-lock acceptance requires -DoubleLockExclusiveDisposableTarget; refusing a non-exclusive live target."
  }
  if ([string]::IsNullOrWhiteSpace($AgentId) -or [string]::IsNullOrWhiteSpace($ManagedUserId) -or $ManagedUserId.StartsWith("LIVE/")) {
    throw "Double-lock acceptance requires exact -AgentId and durable -ManagedUserId values."
  }
  Assert-ServiceRunningForCommandLoop
  Ensure-PortalContext
  Assert-DoubleLockAgentDetail -Phase "initial target" | Out-Null

  $baselineCommands = @(Get-AllAgentCommands)
  $script:DoubleLockBaselineCommands = $baselineCommands
  $script:DoubleLockOwnedCommandIds = @()
  Assert-DoubleLockPreflight -Phase "initial target" -BaselineCommands $baselineCommands

  $original = Get-ManagedUserPolicy
  $originalWeb = [bool](Get-ObjectPropertyValue -InputObject $original -Name "web_enabled")
  $originalLocal = [string](Get-ObjectPropertyValue -InputObject $original -Name "local_state")
  if ($originalLocal -notin @("enabled", "disabled")) {
    throw "Double-lock acceptance requires a restorable local policy observation; current state=$originalLocal."
  }
  Write-ArtifactJson -Name "double-lock-original-policy.json" -Value $original | Out-Null

  $assignmentId = ""
  $managedUsername = ""
  try {
    $assignment = New-ManagedAssignment
    $assignmentId = [string]$assignment.id
    $managedUsername = [string]$assignment.managed_username
    if ([string]::IsNullOrWhiteSpace($assignmentId) -or [string]::IsNullOrWhiteSpace($managedUsername)) {
      throw "Double-lock assignment response did not include id and managed_username."
    }
    Assert-LabUsername -Value $managedUsername
    Assert-DoubleLockPreflight -Phase "assignment creation" -BaselineCommands $baselineCommands `
      -AssignmentId $assignmentId -ManagedUsername $managedUsername

    # Open both locks through their real control surfaces, then create and
    # rotate through the real API -> command -> installed service chain.
    Assert-DoubleLockPreflight -Phase "web policy open" -BaselineCommands $baselineCommands `
      -AssignmentId $assignmentId -ManagedUsername $managedUsername
    Set-WebManagedUserPolicy -Enabled $true -Reason "double-lock acceptance open web policy" | Out-Null
    Assert-DoubleLockPreflight -Phase "local policy open" -BaselineCommands $baselineCommands `
      -AssignmentId $assignmentId -ManagedUsername $managedUsername
    Set-LocalManagedUserPolicy -Enabled $true
    Wait-ManagedUserPolicy -ExpectedWebEnabled $true -ExpectedLocalState "enabled" -Phase "both-open" | Out-Null
    $openDecision = Get-ManagedUserPolicy
    if (-not [bool](Get-ObjectPropertyValue -InputObject $openDecision -Name "effective_enabled")) {
      throw "Double-lock both-open policy did not become effective."
    }

    $before = Write-LocalUserState -Phase "double-lock-before-create" -Name $managedUsername
    $ownershipBefore = Get-ManagedOwnershipState -Name $managedUsername
    if ($before.exists -or $ownershipBefore.exists) { throw "Double-lock managed account or ownership marker already exists before create." }

    Run-ManagedUserAction -Action "create" -AssignmentId $assignmentId | Out-Null
    $created = Write-LocalUserState -Phase "double-lock-after-create" -Name $managedUsername
    if (-not $created.exists -or -not $created.enabled) { throw "Double-lock create did not create an enabled local account." }

    Run-ManagedUserAction -Action "rotate-password" -AssignmentId $assignmentId | Out-Null
    $rotated = Write-LocalUserState -Phase "double-lock-after-open-rotate" -Name $managedUsername
    if (-not $rotated.exists -or -not $rotated.enabled) { throw "Double-lock open rotate did not preserve the local account." }
    $createdSid = [string]$created.sid
    if ([string]::IsNullOrWhiteSpace($createdSid) -or [string]$rotated.sid -ne $createdSid) {
      throw "Double-lock open rotate changed or omitted the managed account SID."
    }

    # Exercise the disabled-account sibling while both locks are still open:
    # disable, rotate without re-enabling, then use the canonical create action
    # for explicit re-enable. The acceptance path deliberately does not add an
    # agent payload field; the real create endpoint must carry the explicit
    # enable intent understood by the installed agent.
    Assert-DoubleLockPreflight -Phase "disabled-account-before-disable" -BaselineCommands $baselineCommands `
      -AssignmentId $assignmentId -ManagedUsername $managedUsername -OwnedCommandIds $script:DoubleLockOwnedCommandIds -Stage "owned"
    Run-ManagedUserAction -Action "disable" -AssignmentId $assignmentId | Out-Null
    $disabled = Write-LocalUserState -Phase "double-lock-after-disabled-account-disable" -Name $managedUsername
    Assert-DoubleLockDisabledAccountState -Action "disable" -State $disabled -ExpectedSid $createdSid

    Run-ManagedUserAction -Action "rotate-password" -AssignmentId $assignmentId | Out-Null
    $rotatedDisabled = Write-LocalUserState -Phase "double-lock-after-disabled-account-rotate" -Name $managedUsername
    Assert-DoubleLockDisabledAccountState -Action "rotate" -State $rotatedDisabled -ExpectedSid $createdSid

    Run-ManagedUserAction -Action "create" -AssignmentId $assignmentId | Out-Null
    $reenabled = Write-LocalUserState -Phase "double-lock-after-disabled-account-reenable" -Name $managedUsername
    if (-not $reenabled.exists -or -not $reenabled.enabled -or
        $reenabled.remote_desktop_users_member -ne $true -or
        [string]$reenabled.sid -ne $createdSid) {
      throw "Double-lock explicit re-enable did not restore the account/RDP membership or preserve its SID."
    }

    Assert-DoubleLockPreflight -Phase "local policy close" -BaselineCommands $baselineCommands `
      -AssignmentId $assignmentId -ManagedUsername $managedUsername -OwnedCommandIds $script:DoubleLockOwnedCommandIds -Stage "owned"
    Set-LocalManagedUserPolicy -Enabled $false
    Wait-ManagedUserPolicy -ExpectedWebEnabled $true -ExpectedLocalState "disabled" -Phase "local-closed" | Out-Null
    Invoke-ManagedActionExpectedDenied -Action "create" -AssignmentId $assignmentId -Phase "local-closed" -ExpectedBlockerCodes @("local_policy_disabled")
    Invoke-ManagedActionExpectedDenied -Action "rotate-password" -AssignmentId $assignmentId -Phase "local-closed" -ExpectedBlockerCodes @("local_policy_disabled")
    $afterLocalClose = Write-LocalUserState -Phase "double-lock-after-local-close" -Name $managedUsername
    if (-not $afterLocalClose.exists -or [bool]$afterLocalClose.enabled -ne [bool]$created.enabled) { throw "Local policy closure did not preserve existing local account state." }

    Assert-DoubleLockPreflight -Phase "local policy reopen" -BaselineCommands $baselineCommands `
      -AssignmentId $assignmentId -ManagedUsername $managedUsername -OwnedCommandIds $script:DoubleLockOwnedCommandIds -Stage "owned"
    Set-LocalManagedUserPolicy -Enabled $true
    Wait-ManagedUserPolicy -ExpectedWebEnabled $true -ExpectedLocalState "enabled" -Phase "local-reopened" | Out-Null

    # Exercise the two single-lock closures and the both-closed state. A
    # denied create/rotate must be rejected at the API boundary; no command is
    # allowed to be delivered while either lock is closed.
    Assert-DoubleLockPreflight -Phase "web policy close" -BaselineCommands $baselineCommands `
      -AssignmentId $assignmentId -ManagedUsername $managedUsername -OwnedCommandIds $script:DoubleLockOwnedCommandIds -Stage "owned"
    Set-WebManagedUserPolicy -Enabled $false -Reason "double-lock acceptance close web policy" | Out-Null
    Wait-ManagedUserPolicy -ExpectedWebEnabled $false -ExpectedLocalState "enabled" -Phase "web-closed" | Out-Null
    Invoke-ManagedActionExpectedDenied -Action "create" -AssignmentId $assignmentId -Phase "web-closed" -ExpectedBlockerCodes @("web_disabled")
    Invoke-ManagedActionExpectedDenied -Action "rotate-password" -AssignmentId $assignmentId -Phase "web-closed" -ExpectedBlockerCodes @("web_disabled")
    $afterWebClose = Write-LocalUserState -Phase "double-lock-after-web-close" -Name $managedUsername
    if (-not $afterWebClose.exists -or [bool]$afterWebClose.enabled -ne [bool]$created.enabled) { throw "Web policy closure did not preserve existing local account state." }

    Assert-DoubleLockPreflight -Phase "both policy close" -BaselineCommands $baselineCommands `
      -AssignmentId $assignmentId -ManagedUsername $managedUsername -OwnedCommandIds $script:DoubleLockOwnedCommandIds -Stage "owned"
    Set-LocalManagedUserPolicy -Enabled $false
    Wait-ManagedUserPolicy -ExpectedWebEnabled $false -ExpectedLocalState "disabled" -Phase "both-closed" | Out-Null
    Invoke-ManagedActionExpectedDenied -Action "create" -AssignmentId $assignmentId -Phase "both-closed" -ExpectedBlockerCodes @("web_disabled", "local_policy_disabled")
    Invoke-ManagedActionExpectedDenied -Action "rotate-password" -AssignmentId $assignmentId -Phase "both-closed" -ExpectedBlockerCodes @("web_disabled", "local_policy_disabled")
    $afterBothClose = Write-LocalUserState -Phase "double-lock-after-both-close" -Name $managedUsername
    if (-not $afterBothClose.exists -or [bool]$afterBothClose.enabled -ne [bool]$created.enabled) { throw "Both-lock closure did not preserve existing local account state." }

    # Existing-account lifecycle remains available under closed create locks.
    Run-ManagedUserAction -Action "disable" -AssignmentId $assignmentId | Out-Null
    $disabled = Write-LocalUserState -Phase "double-lock-after-closed-disable" -Name $managedUsername
    if (-not $disabled.exists -or $disabled.enabled) { throw "Disable under closed locks did not disable the existing account." }
    Run-ManagedUserAction -Action "delete" -AssignmentId $assignmentId | Out-Null
    $deleted = Write-LocalUserState -Phase "double-lock-after-closed-delete" -Name $managedUsername
    if ($deleted.exists) { throw "Delete under closed locks did not remove the managed account." }
    Remove-ManagedAssignment -AssignmentId $assignmentId | Out-Null
    Assert-DoubleLockPreflight -Phase "normal-cleanup-complete" -BaselineCommands $baselineCommands `
      -ManagedUsername $managedUsername -OwnedCommandIds $script:DoubleLockOwnedCommandIds -Stage "post-cleanup"
    $assignmentId = ""

    Write-ArtifactJson -Name "double-lock-native-hook-gaps.json" -Value ([ordered]@{
      evidence_tier = "live"
      covered = @("web_api_policy", "installed_agent_cli_policy", "both_open_create_rotate", "disabled_account_rotate_preserves_state", "explicit_reenable_preserves_sid", "single_lock_create_rotate_denial", "both_lock_create_rotate_denial", "closed_lock_disable_delete", "existing_account_preserved")
      missing = @("web_ui_playwright_assertion_app_owned", "queued_vs_delivered_assertion_native_hook_unavailable")
      proposal = "Complete the UI assertion in the App-owned native Playwright phase; keep queued-vs-delivered unclaimed until an existing deterministic native hook is available."
    }) | Out-Null
  }
  finally {
    $cleanupErrors = @()
    if (-not [string]::IsNullOrWhiteSpace($managedUsername)) {
      try {
        if (-not [string]::IsNullOrWhiteSpace($assignmentId)) {
          Cleanup-DoubleLockManagedAssignment -AssignmentId $assignmentId -ManagedUsername $managedUsername `
            -OwnedCommandIds $script:DoubleLockOwnedCommandIds
          $assignmentId = ""
        }
        else {
          $remaining = Get-LocalUserState -Name $managedUsername
          $ownership = Get-ManagedOwnershipState -Name $managedUsername
          if ($remaining.exists -or $ownership.exists) {
            throw "Double-lock cleanup has no live assignment handle; refusing direct local-user removal."
          }
        }
      }
      catch {
        $cleanupErrors += "local account cleanup: $($_.Exception.Message)"
      }
    }
    $restoreErrors = @()
    try {
      Assert-DoubleLockPreflight -Phase "web policy restoration" -BaselineCommands $baselineCommands `
        -AssignmentId $assignmentId -ManagedUsername $managedUsername -OwnedCommandIds $script:DoubleLockOwnedCommandIds -Stage "post-cleanup"
      Set-WebManagedUserPolicy -Enabled $originalWeb -Reason "double-lock acceptance restore web policy" | Out-Null
    }
    catch {
      $restoreErrors += "web policy restoration: $($_.Exception.Message)"
    }
    try {
      Assert-DoubleLockPreflight -Phase "local policy restoration" -BaselineCommands $baselineCommands `
        -AssignmentId $assignmentId -ManagedUsername $managedUsername -OwnedCommandIds $script:DoubleLockOwnedCommandIds -Stage "post-cleanup"
      Set-LocalManagedUserPolicy -Enabled ($originalLocal -eq "enabled")
    }
    catch {
      $restoreErrors += "local policy restoration: $($_.Exception.Message)"
    }
    try {
      Wait-ManagedUserPolicy -ExpectedWebEnabled $originalWeb -ExpectedLocalState $originalLocal -Phase "restored" | Out-Null
    }
    catch {
      $restoreErrors += "policy restoration verification: $($_.Exception.Message)"
    }
    if ($cleanupErrors.Count -gt 0 -or $restoreErrors.Count -gt 0) {
      $cleanupFailure = [ordered]@{
        cleanup_errors = $cleanupErrors
        restore_errors = $restoreErrors
        original_web_enabled = $originalWeb
        original_local_state = $originalLocal
      }
      Write-ArtifactJson -Name "double-lock-cleanup-or-restore-failed.json" -Value $cleanupFailure | Out-Null
      throw "Double-lock cleanup/restoration failed: $((($cleanupErrors + $restoreErrors) -join '; '))"
    }
  }
}

function Wait-CommandDone {
  param(
    [string]$CommandId,
    [string]$Action
  )

  $deadline = (Get-Date).AddSeconds($CommandTimeoutSeconds)
  do {
    $items = Invoke-PortalJson `
      -Method GET `
      -Path "/api/v1/portal/agents/$AgentId/commands?offset=0&limit=50"
    $match = @($items | Where-Object { $_.id -eq $CommandId }) | Select-Object -First 1
    if ($null -ne $match) {
      $path = Write-ArtifactJson -Name "portal-command-$Action-latest.json" -Value $match
      $status = [string]$match.status
      $resultStatus = [string]$match.result_status
      if ($status -in @("DONE", "FAILED") -or $resultStatus -in @("DONE", "FAILED")) {
        if ($status -eq "FAILED" -or $resultStatus -eq "FAILED") {
          throw "Command $CommandId failed. See $path"
        }
        return $match
      }
    }
    Start-Sleep -Seconds $PollSeconds
  } while ((Get-Date) -lt $deadline)

  throw "Command $CommandId did not finish within $CommandTimeoutSeconds seconds."
}

function Restart-ServiceForCommandPickup {
  if (-not $RestartServiceForEachCommand) {
    return
  }
  if ($RestartServiceCooldownSeconds -gt 0 -and $null -ne $script:LastCommandRestartAt) {
    $elapsed = ((Get-Date) - $script:LastCommandRestartAt).TotalSeconds
    $remaining = $RestartServiceCooldownSeconds - [int][Math]::Floor($elapsed)
    if ($remaining -gt 0) {
      Start-Sleep -Seconds $remaining
    }
  }
  Invoke-AgentExe -Arguments @("--stop-service") -FailureMessage "Service stop failed"
  Wait-ServiceStatus -Expected "Stopped" -TimeoutSeconds 60
  Invoke-AgentExe -Arguments @("--start-service") -FailureMessage "Service start failed"
  Wait-ServiceStatus -Expected "Running" -TimeoutSeconds 60
  $script:LastCommandRestartAt = Get-Date
  Wait-PortalServiceProjection -Phase "after-command-restart" -ExpectedInstalled $true -ExpectedRunning $true
}

function Install-AgentService {
  Write-Step "Install service"
  Write-ServiceState -Phase "before-install" | Out-Null
  Write-AgentSecretState -Phase "before-install" | Out-Null
  Invoke-AgentExe -Arguments @("--install-service") -FailureMessage "Service install failed"
  Wait-ServiceStatus -Expected "Running" -TimeoutSeconds 60
  Write-ServiceState -Phase "after-install" | Out-Null
  $secretState = Write-AgentSecretState -Phase "after-install"
  if ($secretState.user_scope_present -or -not $secretState.machine_scope_present) {
    throw "Service install did not promote registration to machine scope as expected."
  }
  Wait-PortalServiceProjection -Phase "after-install" -ExpectedInstalled $true -ExpectedRunning $true
}

function Start-AgentService {
  Write-Step "Start service"
  Write-ServiceState -Phase "before-start" | Out-Null
  Invoke-AgentExe -Arguments @("--start-service") -FailureMessage "Service start failed"
  Wait-ServiceStatus -Expected "Running" -TimeoutSeconds 60
  Write-ServiceState -Phase "after-start" | Out-Null
  Wait-PortalServiceProjection -Phase "after-start" -ExpectedInstalled $true -ExpectedRunning $true
}

function Stop-AgentService {
  Write-Step "Stop service"
  Write-ServiceState -Phase "before-stop" | Out-Null
  Invoke-AgentExe -Arguments @("--stop-service") -FailureMessage "Service stop failed"
  Wait-ServiceStatus -Expected "Stopped" -TimeoutSeconds 60
  Write-ServiceState -Phase "after-stop" | Out-Null
  if (-not $SkipServiceProjectionCheck -and -not [string]::IsNullOrWhiteSpace($AgentId)) {
    Write-PortalAgentSnapshot -Phase "after-stop" | Out-Null
  }
}

function Uninstall-AgentService {
  Write-Step "Uninstall service"
  Write-ServiceState -Phase "before-uninstall" | Out-Null
  Write-AgentSecretState -Phase "before-uninstall" | Out-Null
  Invoke-AgentExe -Arguments @("--uninstall-service") -FailureMessage "Service uninstall failed"
  Wait-ServiceAbsent -TimeoutSeconds 60
  Write-ServiceState -Phase "after-uninstall" | Out-Null
  $secretState = Write-AgentSecretState -Phase "after-uninstall"
  if (-not $secretState.user_scope_present -or $secretState.machine_scope_present) {
    throw "Service uninstall did not preserve user-scope registration and clear machine-scope state."
  }
  if (-not $SkipServiceProjectionCheck -and -not [string]::IsNullOrWhiteSpace($AgentId)) {
    Write-PortalAgentSnapshot -Phase "after-uninstall" | Out-Null
  }
}

function Run-LocalUserAction {
  param(
    [ValidateSet("create", "disable", "delete")]
    [string]$Action,
    [string]$Name
  )

  Write-Step "Enqueue local user $Action"
  $command = Enqueue-LocalUserCommand -Action $Action -Name $Name
  Restart-ServiceForCommandPickup
  Wait-CommandDone -CommandId ([string]$command.command_id) -Action $Action
}

function Run-ManagedUserAction {
  param(
    [ValidateSet("create", "rotate-password", "disable", "delete")]
    [string]$Action,
    [string]$AssignmentId
  )

  Write-Step "Enqueue managed user $Action"
  $command = Enqueue-ManagedUserCommand -Action $Action -AssignmentId $AssignmentId
  if ($null -ne $script:DoubleLockOwnedCommandIds) {
    $commandId = [string]$command.command_id
    if ([string]::IsNullOrWhiteSpace($commandId)) {
      throw "Managed command enqueue did not return a command_id before pickup."
    }
    if ($script:DoubleLockOwnedCommandIds -notcontains $commandId) {
      $script:DoubleLockOwnedCommandIds += $commandId
    }
  }
  Restart-ServiceForCommandPickup
  $safeAction = ($Action -replace '[^A-Za-z0-9_.-]', '_')
  Wait-CommandDone -CommandId ([string]$command.command_id) -Action "managed-$safeAction" | Out-Null
  return $command
}

function Run-LocalUserLifecycle {
  throw "Direct local-user lab lifecycle is retired. Use managed assignment lifecycle."
  Assert-LabUsername -Value $Username
  if ([string]::IsNullOrWhiteSpace($AgentId)) {
    throw "AgentId is required for local-user lifecycle acceptance."
  }
  try {
    Ensure-PortalContext
    Assert-ServiceRunningForCommandLoop
    Write-LocalUserState -Phase "before" -Name $Username | Out-Null

    Run-LocalUserAction -Action "create" -Name $Username
    $created = Write-LocalUserState -Phase "after-create" -Name $Username
    if (-not $created.exists -or -not $created.enabled) {
      throw "Local user was not created/enabled as expected."
    }

    Run-LocalUserAction -Action "disable" -Name $Username
    $disabled = Write-LocalUserState -Phase "after-disable" -Name $Username
    if (-not $disabled.exists -or $disabled.enabled) {
      throw "Local user was not disabled as expected."
    }

    Run-LocalUserAction -Action "delete" -Name $Username
    $deleted = Write-LocalUserState -Phase "after-delete" -Name $Username
    if ($deleted.exists) {
      throw "Local user still exists after delete command."
    }
  }
  catch {
    Cleanup-LabLocalUserOnFailure -Phase "direct" -Name $Username
    throw
  }
}

function Run-ManagedAssignmentLifecycle {
  if ([string]::IsNullOrWhiteSpace($AgentId)) {
    throw "AgentId is required for managed assignment lifecycle acceptance."
  }
  if ([string]::IsNullOrWhiteSpace($ManagedDisplayName)) {
    $script:ManagedDisplayName = "Cerberus Live Acceptance"
  }

  $assignmentId = ""
  $managedUsername = ""
  try {
    Ensure-PortalContext
    Assert-ServiceRunningForCommandLoop
    $assignment = New-ManagedAssignment
    $assignmentId = [string]$assignment.id
    $managedUsername = [string]$assignment.managed_username
    if ([string]::IsNullOrWhiteSpace($assignmentId) -or [string]::IsNullOrWhiteSpace($managedUsername)) {
      throw "Managed assignment response did not include id and managed_username."
    }
    Assert-LabUsername -Value $managedUsername

    $beforeManaged = Write-LocalUserState -Phase "managed-before" -Name $managedUsername
    if ($beforeManaged.exists) {
      throw "Managed local user already exists before acceptance; cleanup first."
    }

    Run-ManagedUserAction -Action "create" -AssignmentId $assignmentId | Out-Null
    $createdManaged = Write-LocalUserState -Phase "managed-after-create" -Name $managedUsername
    if (-not $createdManaged.exists -or -not $createdManaged.enabled) {
      throw "Managed local user was not created/enabled as expected."
    }
    if ($createdManaged.remote_desktop_users_member -ne $true) {
      throw "Managed local user was not added to Remote Desktop Users."
    }
    if ($createdManaged.password_cannot_change -ne $true) {
      throw "Managed local user may still change the managed password."
    }
    if ($createdManaged.password_never_expires -ne $true) {
      throw "Managed local user password is not marked as never expiring."
    }

    if ($RotateManagedPassword) {
      Run-ManagedUserAction -Action "rotate-password" -AssignmentId $assignmentId | Out-Null
      $rotatedManaged = Write-LocalUserState -Phase "managed-after-rotate" -Name $managedUsername
      if (-not $rotatedManaged.exists -or -not $rotatedManaged.enabled) {
        throw "Managed local user was not present/enabled after password rotation."
      }
      if ($rotatedManaged.remote_desktop_users_member -ne $true) {
        throw "Managed local user lost Remote Desktop Users membership after password rotation."
      }
      if ($rotatedManaged.password_cannot_change -ne $true) {
        throw "Managed local user may still change the managed password after rotation."
      }
      if ($rotatedManaged.password_never_expires -ne $true) {
        throw "Managed local user password is not marked as never expiring after rotation."
      }
    }

    Run-ManagedUserAction -Action "disable" -AssignmentId $assignmentId | Out-Null
    $disabledManaged = Write-LocalUserState -Phase "managed-after-disable" -Name $managedUsername
    if (-not $disabledManaged.exists -or $disabledManaged.enabled) {
      throw "Managed local user was not disabled as expected."
    }
    if ($disabledManaged.remote_desktop_users_member -eq $true) {
      throw "Managed local user remained in Remote Desktop Users after disable."
    }

    Run-ManagedUserAction -Action "delete" -AssignmentId $assignmentId | Out-Null
    $deletedManaged = Write-LocalUserState -Phase "managed-after-delete" -Name $managedUsername
    if ($deletedManaged.exists) {
      throw "Managed local user still exists after managed delete command."
    }

    if ($DeleteAssignmentAfterManagedLifecycle) {
      Remove-ManagedAssignment -AssignmentId $assignmentId | Out-Null
    }
  }
  catch {
    if (-not [string]::IsNullOrWhiteSpace($managedUsername)) {
      Cleanup-LabLocalUserOnFailure -Phase "managed" -Name $managedUsername
    }
    if ($DeleteAssignmentAfterManagedLifecycle -and -not [string]::IsNullOrWhiteSpace($assignmentId)) {
      try {
        Remove-ManagedAssignment -AssignmentId $assignmentId | Out-Null
      }
      catch {
        Write-ArtifactJson -Name "portal-managed-assignment-delete-failed.json" -Value ([ordered]@{
          assignment_id_present = $true
          error = $_.Exception.Message
        }) | Out-Null
      }
    }
    throw
  }
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = New-ArtifactRoot

try {
  if ([string]::IsNullOrWhiteSpace($ExePath)) {
    $ExePath = Join-Path $repoRoot "out/clean-install-smoke/publish/Cerberus.Agent.exe"
  }
  if (-not (Test-Path -LiteralPath $ExePath)) {
    throw "Agent exe not found: $ExePath"
  }
  if ([string]::IsNullOrWhiteSpace($Username)) {
    $alphabet = "234567abcdefghijklmnopqrstuvwxyz".ToCharArray()
    $suffix = -join (1..8 | ForEach-Object { $alphabet[(Get-Random -Minimum 0 -Maximum $alphabet.Length)] })
    $Username = "cerb_livea_$suffix"
  }
  $Username = $Username.Trim().ToLowerInvariant()

  $summary = [ordered]@{
    started_at = (Get-Date).ToUniversalTime().ToString("O")
    artifact_root = $artifactRoot
    backend_url_present = -not [string]::IsNullOrWhiteSpace($BackendUrl)
    agent_id_present = -not [string]::IsNullOrWhiteSpace($AgentId)
    username = $Username
    run_local_user_lifecycle = [bool]$RunLocalUserLifecycle
    run_managed_assignment_lifecycle = [bool]$RunManagedAssignmentLifecycle
    run_double_lock_acceptance = [bool]$RunDoubleLockAcceptance
    managed_user_id_present = -not [string]::IsNullOrWhiteSpace($ManagedUserId)
    managed_user_email_present = -not [string]::IsNullOrWhiteSpace($ManagedUserEmail)
    rotate_managed_password = [bool]$RotateManagedPassword
    delete_assignment_after_managed_lifecycle = [bool]$DeleteAssignmentAfterManagedLifecycle
    install_service = [bool]$InstallService
    start_service = [bool]$StartService
    stop_service = [bool]$StopService
    uninstall_service = [bool]$UninstallService
    acceptance_repeat = $AcceptanceRepeat
    reinstall_between_repeats = [bool]$ReinstallBetweenRepeats
    restart_service_for_each_command = [bool]$RestartServiceForEachCommand
    restart_service_cooldown_seconds = $RestartServiceCooldownSeconds
    service_projection_check = -not [bool]$SkipServiceProjectionCheck
    service_projection_timeout_seconds = $ServiceProjectionTimeoutSeconds
    preflight_only = [bool]$PreflightOnly
  }
  Write-ArtifactJson -Name "summary-start.json" -Value $summary | Out-Null

  if ($ReinstallBetweenRepeats -and (-not $InstallService -or -not $UninstallService)) {
    throw "ReinstallBetweenRepeats requires both -InstallService and -UninstallService."
  }
  if ($AcceptanceRepeat -gt 1 -and $RunManagedAssignmentLifecycle -and -not $DeleteAssignmentAfterManagedLifecycle) {
    throw "Repeated managed assignment acceptance requires -DeleteAssignmentAfterManagedLifecycle to avoid leftover assignments."
  }

  $needsAdmin = $InstallService -or $StartService -or $StopService -or $UninstallService -or $RunLocalUserLifecycle -or $RunDoubleLockAcceptance
  $serviceProjectionNeedsPortal = (-not $SkipServiceProjectionCheck) -and ($InstallService -or $StartService -or $StopService -or $UninstallService)
  $needsPortal = $RunLocalUserLifecycle -or $RunManagedAssignmentLifecycle -or $RunDoubleLockAcceptance -or $serviceProjectionNeedsPortal
  Test-LiveAcceptancePreflight -RequirePortal $needsPortal -NeedsAdmin $needsAdmin

  if ($PreflightOnly) {
    $summary["finished_at"] = (Get-Date).ToUniversalTime().ToString("O")
    $summary["result"] = "preflight_pass"
    Write-ArtifactJson -Name "summary-final.json" -Value $summary | Out-Null
    Write-Step "Live service acceptance preflight completed. Artifacts: $artifactRoot"
    return
  }

  if ($needsAdmin -and -not (Test-IsAdmin)) {
    Write-ServiceState -Phase "blocked-non-admin" | Out-Null
    throw "Administrator privileges are required for service/local-user live acceptance."
  }

  $iterationResults = @()
  $serviceLifecycleInsideRepeat = [bool]$ReinstallBetweenRepeats

  if (-not $serviceLifecycleInsideRepeat) {
    if ($InstallService) {
      Install-AgentService
    }
    if ($StartService) {
      Start-AgentService
    }
  }

  for ($iteration = 1; $iteration -le $AcceptanceRepeat; $iteration++) {
    $iterationPrefix = "iteration-$iteration-"
    Set-ArtifactScope -Prefix $iterationPrefix
    $iterationStarted = Get-Date
    $iterationSummary = [ordered]@{
      iteration = $iteration
      started_at = $iterationStarted.ToUniversalTime().ToString("O")
      service_lifecycle_inside_repeat = $serviceLifecycleInsideRepeat
      run_local_user_lifecycle = [bool]$RunLocalUserLifecycle
      run_managed_assignment_lifecycle = [bool]$RunManagedAssignmentLifecycle
      run_double_lock_acceptance = [bool]$RunDoubleLockAcceptance
      result = "running"
    }
    Write-ArtifactJson -Name "summary-start.json" -Value $iterationSummary | Out-Null
    try {
      Write-Step "Acceptance iteration $iteration/$AcceptanceRepeat"
      if ($serviceLifecycleInsideRepeat) {
        if ($InstallService) {
          Install-AgentService
        }
        if ($StartService) {
          Start-AgentService
        }
      }

      if ($RunLocalUserLifecycle) {
        Run-LocalUserLifecycle
      }

      if ($RunManagedAssignmentLifecycle) {
        Run-ManagedAssignmentLifecycle
      }

      if ($RunDoubleLockAcceptance) {
        Run-DoubleLockAcceptance
      }

      if ($serviceLifecycleInsideRepeat) {
        if ($StopService) {
          Stop-AgentService
        }
        if ($UninstallService) {
          Uninstall-AgentService
        }
      }

      $duration = ((Get-Date) - $iterationStarted).TotalSeconds
      $iterationSummary["finished_at"] = (Get-Date).ToUniversalTime().ToString("O")
      $iterationSummary["duration_seconds"] = [Math]::Round($duration, 3)
      $iterationSummary["result"] = "pass"
      Write-ArtifactJson -Name "summary-final.json" -Value $iterationSummary | Out-Null
      $iterationResults += [PSCustomObject]$iterationSummary
    }
    catch {
      $duration = ((Get-Date) - $iterationStarted).TotalSeconds
      $iterationSummary["finished_at"] = (Get-Date).ToUniversalTime().ToString("O")
      $iterationSummary["duration_seconds"] = [Math]::Round($duration, 3)
      $iterationSummary["result"] = "fail"
      $iterationSummary["message"] = $_.Exception.Message
      Write-ArtifactJson -Name "summary-failed.json" -Value $iterationSummary | Out-Null
      throw
    }
    finally {
      Set-ArtifactScope -Prefix ""
    }
  }

  if (-not $serviceLifecycleInsideRepeat) {
    if ($StopService) {
      Stop-AgentService
    }
    if ($UninstallService) {
      Uninstall-AgentService
    }
  }

  $summary["finished_at"] = (Get-Date).ToUniversalTime().ToString("O")
  $summary["result"] = "pass"
  $summary["iterations"] = $iterationResults
  Write-ArtifactJson -Name "summary-final.json" -Value $summary | Out-Null
  Write-Step "Live service acceptance completed. Artifacts: $artifactRoot"
}
catch {
  $failure = [ordered]@{
    finished_at = (Get-Date).ToUniversalTime().ToString("O")
    result = "fail"
    message = $_.Exception.Message
    artifact_root = $artifactRoot
  }
  Write-ArtifactJson -Name "summary-failed.json" -Value $failure | Out-Null
  Write-Error -ErrorRecord $_
  exit 1
}
