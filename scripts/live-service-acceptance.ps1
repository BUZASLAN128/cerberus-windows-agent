param(
  [string]$ExePath = "",
  [string]$BackendUrl = "http://127.0.0.1:8000",
  [string]$AgentId = "",
  [string]$PortalBearerTokenFile = "",
  [string]$PortalBearerEnvVar = "CERBERUS_PORTAL_BEARER",
  [string]$Username = "",
  [switch]$RunLocalUserLifecycle,
  [switch]$RunManagedAssignmentLifecycle,
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
    [ValidateSet("GET", "POST", "DELETE")]
    [string]$Method,
    [Parameter(Mandatory=$true)]
    [string]$Path,
    [object]$Body = $null
  )

  $uri = "$BackendUrl$Path"
  if ($null -eq $Body) {
    return Invoke-RestMethod -Method $Method -Uri $uri -Headers $portal.Headers -WebSession $portal.Session
  }

  $json = $Body | ConvertTo-Json -Depth 8
  return Invoke-RestMethod `
    -Method $Method `
    -Uri $uri `
    -Headers $portal.Headers `
    -WebSession $portal.Session `
    -ContentType "application/json" `
    -Body $json
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

  if ($Value -notmatch '^cerbtest_[a-z0-9_]{1,11}$') {
    throw "Username must match cerbtest_[a-z0-9_]{1,11}; refusing to mutate arbitrary local users."
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
    enabled = [bool]$user.Enabled
    description = [string]$user.Description
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

  $requestId = "live-$Action-$([Guid]::NewGuid().ToString('N'))"
  $body = @{
    action = $Action
    username = $Name
    reason = "Phase 7 live service acceptance"
    client_request_id = $requestId
  }
  $response = Invoke-PortalJson `
    -Method POST `
    -Path "/api/v1/portal/agents/$AgentId/commands/local-user-test" `
    -Body $body
  $path = Write-ArtifactJson -Name "portal-command-$Action.json" -Value $response
  Write-Host "portal-command[$Action] -> $path"
  return $response
}

function New-ClientRequestId {
  param([string]$Prefix)

  return "live-$Prefix-$([Guid]::NewGuid().ToString('N'))"
}

function New-ManagedAssignment {
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
  Invoke-AgentExe -Arguments @("--stop-service") -FailureMessage "Service stop failed"
  Wait-ServiceStatus -Expected "Stopped" -TimeoutSeconds 60
  Invoke-AgentExe -Arguments @("--start-service") -FailureMessage "Service start failed"
  Wait-ServiceStatus -Expected "Running" -TimeoutSeconds 60
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
  Restart-ServiceForCommandPickup
  $safeAction = ($Action -replace '[^A-Za-z0-9_.-]', '_')
  Wait-CommandDone -CommandId ([string]$command.command_id) -Action "managed-$safeAction" | Out-Null
  return $command
}

function Run-LocalUserLifecycle {
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
  if ([string]::IsNullOrWhiteSpace($ManagedUserId)) {
    $script:ManagedUserId = "LIVE/$Username"
  }
  if ([string]::IsNullOrWhiteSpace($ManagedUserEmail)) {
    $script:ManagedUserEmail = "$($Username -replace '_', '.')@acceptance.local"
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

    if ($RotateManagedPassword) {
      Run-ManagedUserAction -Action "rotate-password" -AssignmentId $assignmentId | Out-Null
      $rotatedManaged = Write-LocalUserState -Phase "managed-after-rotate" -Name $managedUsername
      if (-not $rotatedManaged.exists -or -not $rotatedManaged.enabled) {
        throw "Managed local user was not present/enabled after password rotation."
      }
    }

    Run-ManagedUserAction -Action "disable" -AssignmentId $assignmentId | Out-Null
    $disabledManaged = Write-LocalUserState -Phase "managed-after-disable" -Name $managedUsername
    if (-not $disabledManaged.exists -or $disabledManaged.enabled) {
      throw "Managed local user was not disabled as expected."
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
    $ExePath = Join-Path $repoRoot "out/clean-install-smoke/publish/Cerberus.Agent.App.exe"
  }
  if (-not (Test-Path -LiteralPath $ExePath)) {
    throw "Agent exe not found: $ExePath"
  }
  if ([string]::IsNullOrWhiteSpace($Username)) {
    $Username = "cerbtest_$((Get-Random -Minimum 100000 -Maximum 999999))"
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

  $needsAdmin = $InstallService -or $StartService -or $StopService -or $UninstallService -or $RunLocalUserLifecycle -or $RunManagedAssignmentLifecycle
  $serviceProjectionNeedsPortal = (-not $SkipServiceProjectionCheck) -and ($InstallService -or $StartService -or $StopService -or $UninstallService)
  $needsPortal = $RunLocalUserLifecycle -or $RunManagedAssignmentLifecycle -or $serviceProjectionNeedsPortal
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
