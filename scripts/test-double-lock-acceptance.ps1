#Requires -Version 7.4
<##
.SYNOPSIS
Support-only regression oracle for the double-lock acceptance harness.
.DESCRIPTION
Extracts the real preflight, cleanup, and double-lock entry functions from the
acceptance script. External portal, Windows, service, and artifact operations
are replaced with in-memory stubs; this never claims live or acceptance
evidence and performs no host mutation.
##>
$ErrorActionPreference = "Stop"
$sourcePath = Join-Path $PSScriptRoot "live-service-acceptance.ps1"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($sourcePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw ($parseErrors -join "`n") }

$required = @("Assert-DoubleLockAgentDetail", "Assert-DoubleLockDisabledAccountState", "Assert-DoubleLockPreflight", "Cleanup-DoubleLockManagedAssignment", "Run-DoubleLockAcceptance")
$definitions = @($ast.FindAll({
  param($node)
  $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $required -contains $node.Name
}, $true))
if ($definitions.Count -ne $required.Count) { throw "Expected all named double-lock functions in the source script." }
foreach ($name in $required) {
  if (@($definitions | Where-Object Name -eq $name).Count -ne 1) { throw "Expected exactly one source definition for $name." }
}
$portalDefinitions = @($ast.FindAll({
  param($node)
  $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq "Invoke-PortalJson"
}, $true))
if ($portalDefinitions.Count -ne 1) { throw "Expected exactly one source definition for Invoke-PortalJson." }

$AgentId = "agent-test"
$ManagedUserId = "user-test"
$script:BaselineAssignments = @()
$script:FakeAssignments = @()
$script:FakeCommands = @()
$script:FakeLocal = [pscustomobject]@{ username = ""; exists = $false }
$script:FakeOwnership = [pscustomobject]@{ username = ""; exists = $false }
$script:FakeAgentDetail = [pscustomobject]@{ agent_id = $AgentId; tenant_id = "tenant-test" }
$script:OwnedCommandIds = @()
$script:DoubleLockBaselineCommands = @()
$script:DoubleLockOwnedCommandIds = @()
$script:RemoveAssignmentShouldFail = $false
$script:PolicyWrites = 0

function Assert-LabUsername { param([string]$Value) if ([string]::IsNullOrWhiteSpace($Value)) { throw "username required" } }
function Write-LocalUserState { param([string]$Phase, [string]$Name) return $script:FakeLocal }
function Get-LocalUserState { param([string]$Name) return $script:FakeLocal }
function Get-ManagedOwnershipState { param([string]$Name) return $script:FakeOwnership }
function Get-AllAgentCommands { return @($script:FakeCommands) }
function Invoke-PortalJson {
  param([string]$Method, [string]$Path, [object]$Body)
  if ($Method -eq "GET" -and $Path -eq "/api/v1/portal/agents/$AgentId") { return $script:FakeAgentDetail }
  if ($Method -eq "GET" -and $Path -like "*/assignments") { return @($script:FakeAssignments) }
  if ($Method -eq "DELETE" -and $Path -like "*/assignments/*") {
    if ($script:RemoveAssignmentShouldFail) { throw "forced assignment removal failure" }
    $removed = [string]($Path -split "/")[-1]
    $script:FakeAssignments = @($script:FakeAssignments | Where-Object { [string]$_.id -ne $removed })
    return [pscustomobject]@{ id = $removed; deleted = $true }
  }
  throw "unexpected support request: $Method $Path"
}
function Remove-ManagedAssignment { param([string]$AssignmentId) Invoke-PortalJson -Method DELETE -Path "/api/v1/portal/agents/$AgentId/assignments/$AssignmentId" }
function Write-ArtifactJson { param([string]$Name, [object]$Value) return $Name }
function Run-ManagedUserAction {
  param([string]$Action, [string]$AssignmentId)
  $id = "owned-$Action-$([Guid]::NewGuid().ToString('N'))"
  $script:DoubleLockOwnedCommandIds += $id
  $script:FakeCommands += [pscustomobject]@{ id = $id; status = "DONE"; type = "windows.local_user.$Action"; idempotency_key = "managed-user:${AssignmentId}:$Action" }
  $rdpLogonRight = $null
  if ($Action -eq "create") {
    $sid = if ($script:FakeLocal.exists) { [string]$script:FakeLocal.sid } else { "sid-1" }
    $script:FakeLocal = [pscustomobject]@{ username = $script:FakeLocal.username; exists = $true; sid = $sid; enabled = $true; remote_desktop_users_member = $true }
    $rdpLogonRight = "granted"
  }
  if ($Action -eq "rotate-password") {
    if (-not $script:FakeLocal.exists) { throw "Cannot rotate a missing support account." }
    # A rotation has no enable intent: preserve both account state and access.
    $rdpLogonRight = "preserved"
  }
  if ($Action -eq "disable") {
    $script:FakeLocal = [pscustomobject]@{ username = $script:FakeLocal.username; exists = $true; sid = [string]$script:FakeLocal.sid; enabled = $false; remote_desktop_users_member = $false }
    $rdpLogonRight = "removed"
  }
  if ($Action -eq "delete") {
    $script:FakeLocal = [pscustomobject]@{ username = $script:FakeLocal.username; exists = $false; remote_desktop_users_member = $false }
    $script:FakeOwnership = [pscustomobject]@{ username = $script:FakeOwnership.username; exists = $false }
    $rdpLogonRight = "removed"
  }
  return [pscustomobject]@{ command_id = $id; rdp_logon_right = $rdpLogonRight }
}

$functionText = ($definitions | Sort-Object { $_.Extent.StartOffset } | ForEach-Object { $_.Extent.Text }) -join "`n`n"
. ([scriptblock]::Create($functionText))

function Reset-Case {
  $script:FakeAssignments = @()
  $script:FakeCommands = @()
  $script:FakeLocal = [pscustomobject]@{ username = "managed-test"; exists = $false }
  $script:FakeOwnership = [pscustomobject]@{ username = "managed-test"; exists = $false }
  $script:FakeAgentDetail = [pscustomobject]@{ agent_id = $AgentId; tenant_id = "tenant-test" }
  $script:DoubleLockBaselineCommands = @()
  $script:DoubleLockOwnedCommandIds = @()
  $script:RemoveAssignmentShouldFail = $false
}
function New-TargetAssignment {
  return [pscustomobject]@{ id = "assignment-1"; user_id = $ManagedUserId; managed_username = "managed-test"; tenant_id = "tenant-test" }
}
function Set-OwnedState {
  $script:FakeLocal = [pscustomobject]@{ username = "managed-test"; exists = $true; sid = "sid-1"; enabled = $true; remote_desktop_users_member = $true }
  $script:FakeOwnership = [pscustomobject]@{ username = "managed-test"; exists = $true; assignment_id = "assignment-1"; managed_account_id = "account-1"; membership_user_id = $ManagedUserId; agent_id = $AgentId; tenant_id = "tenant-test"; marker_id = "marker-1"; local_sid = "sid-1" }
}
function Assert-Throws([scriptblock]$Case, [string]$Name) { try { & $Case; throw "Expected support case to fail: $Name" } catch { if ($_.Exception.Message -like "Expected support case*") { throw } } }

# 1. Empty command history is a valid baseline.
Reset-Case
Assert-DoubleLockPreflight -Phase "empty-history" -BaselineCommands @()

# 2. An unrelated queued command is rejected before any policy write.
Reset-Case
$script:FakeCommands = @([pscustomobject]@{ id = "unrelated-queued"; status = "QUEUED"; type = "windows.local_user.create"; idempotency_key = "other-assignment" })
Assert-Throws { Assert-DoubleLockPreflight -Phase "unrelated-queued" -BaselineCommands @() } "unrelated queued command"

# 3. The canonical agent detail binds the exact agent, while the scoped
# assignment-list row is accepted without an agent_id field.
Reset-Case
Assert-DoubleLockAgentDetail -Phase "canonical-agent-detail" | Out-Null
$script:FakeAssignments = @(New-TargetAssignment)
Set-OwnedState
$script:DoubleLockOwnedCommandIds = @("owned-create")
$script:FakeCommands = @([pscustomobject]@{ id = "owned-create"; status = "DONE"; type = "windows.local_user.create"; idempotency_key = "managed-user:assignment-1:create" })
Assert-DoubleLockPreflight -Phase "owned-next-stage" -BaselineCommands @() -AssignmentId "assignment-1" -ManagedUsername "managed-test" -OwnedCommandIds $script:DoubleLockOwnedCommandIds -Stage "owned"

# 4. Missing/wrong agent detail and wrong assignment row/user identities are
# refused without weakening the scoped single-row check.
Reset-Case
$script:FakeAgentDetail = [pscustomobject]@{ tenant_id = "tenant-test" }
Assert-Throws { Assert-DoubleLockAgentDetail -Phase "missing-agent-id" } "missing canonical agent_id"
Reset-Case
$script:FakeAgentDetail = [pscustomobject]@{ agent_id = "wrong-agent"; tenant_id = "tenant-test" }
Assert-Throws { Assert-DoubleLockAgentDetail -Phase "wrong-agent-detail" } "wrong agent detail"
Reset-Case
$script:FakeAssignments = @([pscustomobject]@{ id = "wrong-row"; user_id = $ManagedUserId; managed_username = "managed-test"; tenant_id = "tenant-test" })
Assert-Throws { Assert-DoubleLockPreflight -Phase "wrong-row" -BaselineCommands @() -AssignmentId "assignment-1" -ManagedUsername "managed-test" } "wrong assignment row"
Reset-Case
$script:FakeAssignments = @([pscustomobject]@{ id = "assignment-1"; user_id = "other-user"; managed_username = "managed-test"; tenant_id = "tenant-test" })
Assert-Throws { Assert-DoubleLockPreflight -Phase "wrong-user" -BaselineCommands @() -AssignmentId "assignment-1" -ManagedUsername "managed-test" } "wrong assignment user"
Reset-Case
$target = New-TargetAssignment
$script:FakeAssignments = @($target, [pscustomobject]@{ id = "unrelated-assignment"; user_id = "other-user"; managed_username = "other-user" })
Assert-Throws { Assert-DoubleLockPreflight -Phase "unrelated-assignment" -BaselineCommands @() -AssignmentId "assignment-1" -ManagedUsername "managed-test" } "unrelated assignment"
Reset-Case
$script:FakeCommands = @([pscustomobject]@{ id = "unknown-done"; status = "DONE"; type = "windows.local_user.create"; idempotency_key = "other-assignment" })
Assert-Throws { Assert-DoubleLockPreflight -Phase "unknown-command" -BaselineCommands @() } "unknown new command"

# 5. Failure before SAM creation releases the created assignment.
Reset-Case
$script:FakeAssignments = @(New-TargetAssignment)
$script:DoubleLockOwnedCommandIds = @("owned-create-failed")
$script:FakeCommands = @([pscustomobject]@{ id = "owned-create-failed"; status = "FAILED"; type = "windows.local_user.create"; idempotency_key = "managed-user:assignment-1:create" })
Cleanup-DoubleLockManagedAssignment -AssignmentId "assignment-1" -ManagedUsername "managed-test" -OwnedCommandIds $script:DoubleLockOwnedCommandIds
if ($script:FakeAssignments.Count -ne 0) { throw "Failure-before-SAM cleanup leaked the assignment." }

# 6. Forced failure after SAM uses product disable/delete and clears ownership.
Reset-Case
$script:FakeAssignments = @(New-TargetAssignment)
Set-OwnedState
$script:DoubleLockOwnedCommandIds = @("owned-create")
$script:FakeCommands = @([pscustomobject]@{ id = "owned-create"; status = "FAILED"; type = "windows.local_user.create"; idempotency_key = "managed-user:assignment-1:create" })
Cleanup-DoubleLockManagedAssignment -AssignmentId "assignment-1" -ManagedUsername "managed-test" -OwnedCommandIds $script:DoubleLockOwnedCommandIds
if ($script:FakeAssignments.Count -ne 0 -or $script:FakeLocal.exists -or $script:FakeOwnership.exists) { throw "Forced post-SAM cleanup did not close product ownership." }

# 7. A clean rerun after cleanup remains accepted.
Assert-DoubleLockPreflight -Phase "clean-rerun" -BaselineCommands @() -OwnedCommandIds $script:DoubleLockOwnedCommandIds -Stage "post-cleanup"

# 8. Cleanup errors propagate and cannot be converted into a fake pass.
Reset-Case
$script:FakeAssignments = @(New-TargetAssignment)
Set-OwnedState
$script:DoubleLockOwnedCommandIds = @("owned-create")
$script:FakeCommands = @([pscustomobject]@{ id = "owned-create"; status = "FAILED"; type = "windows.local_user.create"; idempotency_key = "managed-user:assignment-1:create" })
$script:RemoveAssignmentShouldFail = $true
Assert-Throws { Cleanup-DoubleLockManagedAssignment -AssignmentId "assignment-1" -ManagedUsername "managed-test" -OwnedCommandIds $script:DoubleLockOwnedCommandIds } "cleanup failure propagation"

# 9. The extracted disabled-account assertion rejects unknown membership state
# for both the disable and disabled-rotation phases; an error reading the local
# group cannot be treated as evidence that membership is absent.
$unknownState = [pscustomobject]@{ exists = $true; enabled = $false; sid = "sid-1"; remote_desktop_users_member = $null }
Assert-Throws { Assert-DoubleLockDisabledAccountState -Action "disable" -State $unknownState -ExpectedSid "sid-1" } "unknown membership after disable"
Assert-Throws { Assert-DoubleLockDisabledAccountState -Action "rotate" -State $unknownState -ExpectedSid "sid-1" } "unknown membership after disabled rotation"

# 10. A fresh create grants an enabled account and RDP membership.
Reset-Case
$createdResult = Run-ManagedUserAction -Action "create" -AssignmentId "assignment-1"
if (-not $script:FakeLocal.exists -or -not $script:FakeLocal.enabled -or
    $script:FakeLocal.remote_desktop_users_member -ne $true -or
    $createdResult.rdp_logon_right -ne "granted") {
  throw "Support create did not grant the expected enabled-account/RDP state."
}

# 11. Rotation of an enabled account preserves its SID and membership.
Reset-Case
Set-OwnedState
$enabledBeforeRotate = $script:FakeLocal
$rotateResult = Run-ManagedUserAction -Action "rotate-password" -AssignmentId "assignment-1"
if (-not $script:FakeLocal.enabled -or $script:FakeLocal.remote_desktop_users_member -ne $true -or
    [string]$script:FakeLocal.sid -ne [string]$enabledBeforeRotate.sid -or
    $rotateResult.rdp_logon_right -ne "preserved") {
  throw "Support enabled-account rotation did not preserve enabled/SID/RDP state."
}

# 12. Disable removes RDP membership while preserving the account and SID.
Reset-Case
Set-OwnedState
$disabledResult = Run-ManagedUserAction -Action "disable" -AssignmentId "assignment-1"
if (-not $script:FakeLocal.exists -or $script:FakeLocal.enabled -or
    $script:FakeLocal.remote_desktop_users_member -eq $true -or
    [string]$script:FakeLocal.sid -ne "sid-1" -or
    $disabledResult.rdp_logon_right -ne "removed") {
  throw "Support disable did not remove RDP while preserving the account/SID."
}

# 13. Rotation while disabled cannot restore RDP membership or enabled state.
Reset-Case
Set-OwnedState
Run-ManagedUserAction -Action "disable" -AssignmentId "assignment-1" | Out-Null
$disabledBeforeRotate = $script:FakeLocal
$disabledRotateResult = Run-ManagedUserAction -Action "rotate-password" -AssignmentId "assignment-1"
if ($script:FakeLocal.enabled -or $script:FakeLocal.remote_desktop_users_member -eq $true -or
    [string]$script:FakeLocal.sid -ne [string]$disabledBeforeRotate.sid -or
    $disabledRotateResult.rdp_logon_right -ne "preserved") {
  throw "Support disabled-account rotation restored access or changed state/SID."
}

# 14. Explicit create/re-enable restores enabled state and RDP membership.
Reset-Case
Set-OwnedState
Run-ManagedUserAction -Action "disable" -AssignmentId "assignment-1" | Out-Null
$disabledSid = [string]$script:FakeLocal.sid
$reenableResult = Run-ManagedUserAction -Action "create" -AssignmentId "assignment-1"
if (-not $script:FakeLocal.enabled -or $script:FakeLocal.remote_desktop_users_member -ne $true -or
    [string]$script:FakeLocal.sid -ne $disabledSid -or
    $reenableResult.rdp_logon_right -ne "granted") {
  throw "Support explicit re-enable did not restore enabled/RDP state or preserve SID."
}

# 15. Rotation does not grant RDP to an enabled account whose membership was absent.
Reset-Case
Set-OwnedState
$script:FakeLocal = [pscustomobject]@{ username = "managed-test"; exists = $true; sid = "sid-1"; enabled = $true; remote_desktop_users_member = $false }
$missingMembershipResult = Run-ManagedUserAction -Action "rotate-password" -AssignmentId "assignment-1"
if (-not $script:FakeLocal.enabled -or $script:FakeLocal.remote_desktop_users_member -eq $true -or
    $missingMembershipResult.rdp_logon_right -ne "preserved") {
  throw "Support rotation incorrectly granted missing RDP membership."
}

# 16. Re-enable after a disabled rotation grants RDP exactly once and keeps the SID.
Reset-Case
Set-OwnedState
Run-ManagedUserAction -Action "disable" -AssignmentId "assignment-1" | Out-Null
Run-ManagedUserAction -Action "rotate-password" -AssignmentId "assignment-1" | Out-Null
$recoveredSid = [string]$script:FakeLocal.sid
Run-ManagedUserAction -Action "create" -AssignmentId "assignment-1" | Out-Null
if (-not $script:FakeLocal.enabled -or $script:FakeLocal.remote_desktop_users_member -ne $true -or
    [string]$script:FakeLocal.sid -ne $recoveredSid) {
  throw "Support re-enable after disabled rotation did not restore the exact account/access state."
}

# 17. Delete removes the account, ownership marker, and RDP membership.
Reset-Case
Set-OwnedState
$deleteResult = Run-ManagedUserAction -Action "delete" -AssignmentId "assignment-1"
if ($script:FakeLocal.exists -or $script:FakeLocal.remote_desktop_users_member -eq $true -or
    $script:FakeOwnership.exists -or $deleteResult.rdp_logon_right -ne "removed") {
  throw "Support delete did not clear account ownership and RDP membership."
}

# 18. The real portal wrapper must preserve empty, single, and multi-item JSON
# responses while leaving scalar response objects intact. The stub deliberately
# emits each response as one pipeline object, matching Windows PowerShell's
# native Invoke-RestMethod array behavior that exposed the original bug.
$portalFunctionText = $portalDefinitions[0].Extent.Text
. ([scriptblock]::Create($portalFunctionText))
$BackendUrl = "https://support.invalid"
$portal = [pscustomobject]@{ Headers = @{}; Session = $null }
$script:StubPortalResponse = $null
$script:StubPortalError = $null
function Invoke-RestMethod {
  param(
    [string]$Method,
    [string]$Uri,
    [object]$Headers,
    [object]$WebSession,
    [string]$ContentType,
    [string]$Body
  )
  if ($null -ne $script:StubPortalError) {
    $errorRecord = $script:StubPortalError
    $script:StubPortalError = $null
    Write-Error -ErrorRecord $errorRecord -ErrorAction Stop
  }
  Write-Output -NoEnumerate $script:StubPortalResponse
}
function New-ClientRequestId { param([string]$Prefix) return "$Prefix-support" }

$transportCases = @(
  [pscustomobject]@{
    Name = "empty-array"
    Value = [object[]]@()
    ExpectedCount = 0
  }
  [pscustomobject]@{
    Name = "one-item-array"
    Value = [object[]]@([pscustomobject]@{ value = "one" })
    ExpectedCount = 1
  }
  [pscustomobject]@{
    Name = "two-item-array"
    Value = [object[]]@(
      [pscustomobject]@{ value = "one" },
      [pscustomobject]@{ value = "two" }
    )
    ExpectedCount = 2
  }
  [pscustomobject]@{
    Name = "scalar-object"
    Value = [pscustomobject]@{ value = "object" }
    ExpectedCount = 1
  }
)
foreach ($case in $transportCases) {
  foreach ($withBody in @($false, $true)) {
    $script:StubPortalResponse = $case.Value
    $response = if ($withBody) {
      Invoke-PortalJson -Method POST -Path "/transport" -Body @{ probe = $case.Name }
    } else {
      Invoke-PortalJson -Method GET -Path "/transport"
    }
    $items = @($response)
    if ($items.Count -ne $case.ExpectedCount) {
      throw "Portal transport case $($case.Name) body=$withBody returned $($items.Count) item(s), expected $($case.ExpectedCount)."
    }
    if ($case.ExpectedCount -gt 0 -and $items[0].value -ne "one" -and $case.Name -ne "scalar-object") {
      throw "Portal transport case $($case.Name) lost its first response object."
    }
    if ($case.Name -eq "scalar-object" -and $items[0].value -ne "object") {
      throw "Portal transport scalar response object was not preserved."
    }
  }
}

function New-SupportPortalResponse {
  param(
    [Parameter(Mandatory=$true)][int]$StatusCode,
    [string]$StreamBody = "",
    [string]$ContentBody = "",
    [switch]$ExposeContent
  )

  $response = [pscustomobject]@{
    StatusCode = $StatusCode
    StreamBody = $StreamBody
  }
  $response | Add-Member -MemberType ScriptMethod -Name GetResponseStream -Value {
    if ([string]::IsNullOrEmpty([string]$this.StreamBody)) {
      return [System.IO.MemoryStream]::new()
    }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes([string]$this.StreamBody)
    return [System.IO.MemoryStream]::new($bytes)
  }
  if ($ExposeContent) {
    $content = [pscustomobject]@{ Body = $ContentBody }
    $content | Add-Member -MemberType ScriptMethod -Name ReadAsStringAsync -Value {
      return [System.Threading.Tasks.Task[string]]::FromResult([string]$this.Body)
    }
    $response | Add-Member -MemberType NoteProperty -Name Content -Value $content
  }
  return $response
}

function New-SupportPortalErrorRecord {
  param(
    [Parameter(Mandatory=$true)][int]$StatusCode,
    [Parameter(Mandatory=$true)][object]$Response,
    [string]$ErrorDetailsMessage = $null
  )

  $exception = [Exception]::new("support HTTP $StatusCode")
  $exception | Add-Member -MemberType NoteProperty -Name Response -Value $Response -Force
  $record = New-Object System.Management.Automation.ErrorRecord (
    $exception,
    "SupportHttpError",
    [System.Management.Automation.ErrorCategory]::InvalidOperation,
    $null
  )
  if ($null -ne $ErrorDetailsMessage) {
    $record.ErrorDetails = [System.Management.Automation.ErrorDetails]::new($ErrorDetailsMessage)
  }
  return $record
}

function Invoke-SupportPortalFailure {
  $script:LastPortalFailure = $null
  try {
    $null = Invoke-PortalJson -Method POST -Path "/support-error" -Body @{ probe = "error" }
    throw "Expected support portal request to fail."
  } catch {
    if ($null -eq $script:LastPortalFailure) {
      throw "Support portal request did not record a structured failure."
    }
  }
}

function Assert-SupportPortalFailure {
  param(
    [Parameter(Mandatory=$true)][int]$ExpectedStatusCode,
    [object]$ExpectedDetailCode = $null,
    [AllowEmptyCollection()][string[]]$ExpectedBlockerCodes = @()
  )

  $failure = $script:LastPortalFailure
  if ($null -eq $failure -or $failure.status_code -ne $ExpectedStatusCode) {
    throw "Support portal failure status was not $ExpectedStatusCode."
  }
  $actualDetailCode = if ($null -eq $failure.detail_code) { $null } else { [string]$failure.detail_code }
  if (($null -eq $ExpectedDetailCode -and $null -ne $actualDetailCode) -or
      ($null -ne $ExpectedDetailCode -and $actualDetailCode -ne [string]$ExpectedDetailCode)) {
    throw "Support portal failure detail code was '$actualDetailCode', expected '$ExpectedDetailCode'."
  }
  $actualBlockerCodes = @($failure.blocker_codes)
  if ($actualBlockerCodes.Count -ne $ExpectedBlockerCodes.Count) {
    throw "Support portal failure blocker count was $($actualBlockerCodes.Count), expected $($ExpectedBlockerCodes.Count)."
  }
  for ($index = 0; $index -lt $ExpectedBlockerCodes.Count; $index++) {
    if ([string]$actualBlockerCodes[$index] -ne [string]$ExpectedBlockerCodes[$index]) {
      throw "Support portal failure blocker at index $index was '$($actualBlockerCodes[$index])', expected '$($ExpectedBlockerCodes[$index])'."
    }
  }
}

# ErrorRecord.ErrorDetails.Message is the response body on Windows PowerShell
# 5.1 after Invoke-RestMethod has consumed the WebException stream.
$ps51Response = New-SupportPortalResponse -StatusCode 409
$script:StubPortalError = New-SupportPortalErrorRecord -StatusCode 409 -Response $ps51Response `
  -ErrorDetailsMessage '{"detail":{"code":"managed_user_create_policy_blocked","params":{"blocker_codes":"web_policy_disabled, local_user_create_disabled, agent_disabled"}}}'
Invoke-SupportPortalFailure
Assert-SupportPortalFailure -ExpectedStatusCode 409 -ExpectedDetailCode "managed_user_create_policy_blocked" `
  -ExpectedBlockerCodes @("web_policy_disabled", "local_user_create_disabled", "agent_disabled")

# A malformed consumed ErrorDetails body must leave the policy decision
# unknown; HTTP status alone is never accepted as the expected denial.
$script:StubPortalError = New-SupportPortalErrorRecord -StatusCode 409 -Response (New-SupportPortalResponse -StatusCode 409) `
  -ErrorDetailsMessage '{"detail":'
Invoke-SupportPortalFailure
Assert-SupportPortalFailure -ExpectedStatusCode 409

# Plain text from a proxy or server must also remain an unknown denial reason.
$script:StubPortalError = New-SupportPortalErrorRecord -StatusCode 409 -Response (New-SupportPortalResponse -StatusCode 409) `
  -ErrorDetailsMessage 'backend refused the request'
Invoke-SupportPortalFailure
Assert-SupportPortalFailure -ExpectedStatusCode 409

# PowerShell 7 exposes HttpResponseMessage.Content when ErrorDetails.Message
# is absent; exercise the async content fallback and the same canonical shape.
$ps7Response = New-SupportPortalResponse -StatusCode 409 -ExposeContent `
  -ContentBody '{"detail":{"code":"managed_user_create_policy_blocked","params":{"blocker_codes":"web_policy_disabled, local_user_create_disabled"}}}'
$script:StubPortalError = New-SupportPortalErrorRecord -StatusCode 409 -Response $ps7Response
Invoke-SupportPortalFailure
Assert-SupportPortalFailure -ExpectedStatusCode 409 -ExpectedDetailCode "managed_user_create_policy_blocked" `
  -ExpectedBlockerCodes @("web_policy_disabled", "local_user_create_disabled")

# Keep the legacy response-stream fallback for WebException-like providers
# that expose an unread body but no ErrorDetails.Message or HttpContent.
$streamResponse = New-SupportPortalResponse -StatusCode 409 `
  -StreamBody '{"detail":{"code":"managed_user_create_policy_blocked","params":{"blocker_codes":"local_user_create_disabled"}}}'
$script:StubPortalError = New-SupportPortalErrorRecord -StatusCode 409 -Response $streamResponse
Invoke-SupportPortalFailure
Assert-SupportPortalFailure -ExpectedStatusCode 409 -ExpectedDetailCode "managed_user_create_policy_blocked" `
  -ExpectedBlockerCodes @("local_user_create_disabled")

Write-Output "Double-lock support oracle: 18 cases passed; portal transport oracle: 8 cases passed; portal error oracle: 5 cases passed; support-only, no live/host mutation."
