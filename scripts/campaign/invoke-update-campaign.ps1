#requires -Version 7.5
<# Runs one self-update test campaign on this machine; reads only the agent's local records and the test feed.
  -Step Bootstrap installs the first MSI with a lab transaction id; -Step Hops runs the fault table of the mode (trial |
  counted); -Step All does both. Stops at the first failure, never retries; a started step never runs again.
  Only start-update-campaign.ps1 starts it: every input comes from its custody folder and must match launch.json.
  The functions live in campaign-lib.ps1, loaded from custody only after its bytes match launch.json. #>
param(
  [ValidateSet('Bootstrap', 'Hops', 'All')][string]$Step = 'All',
  [switch]$InstallerBusyFallback
)
$ErrorActionPreference = 'Stop'
# ValidateSet accepts any casing; every later comparison is case-sensitive, so use the canonical name.
$Step = @('Bootstrap', 'Hops', 'All') | Where-Object { $_ -ieq $Step } | Select-Object -First 1
$env:PSModulePath = Join-Path $PSHOME 'Modules'
$HopTimeout = [TimeSpan]::FromMinutes(25)
$HoldProductCode = '{6E0B7D4A-3C1F-4B8E-9A52-7F1D2C3B4A50}'   # must match hold-installer.wxs
$HoldCap = [TimeSpan]::FromSeconds(255)                       # hold MSI gives up by itself after 135 rounds (270-300 s)
$StagedSuffix = '.campaign-staged'                            # full MSI waits on the feed under this name during a truncated hop
$Msiexec = Join-Path ([Environment]::GetFolderPath('System')) 'msiexec.exe'
$Pinned = [ordered]@{ serviceName = 'CerberusServerAgent'; controlPipeName = 'CerberusServerAgent.Control.v1'
  privilegedUpdateRoot = 'C:\ProgramData\CerberusServerAgent\Privileged\Updates' }   # server profile only; same values in the launcher
$ReceiptsRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'cerberus-campaign-receipts'   # same in the launcher
# Hops 1-10; the same table is written by build-agent-test-campaign.ps1 into campaign-artifacts.json (faultSchedule).
$Schedule = @('installer-busy-1618', 'feed-truncated-artifact', 'kill-health-pending', 'feed-truncated-artifact', 'service-pre-download-exit',
  'updater-pre-installer-exit', 'installer-busy-1618', 'service-pre-download-exit', 'updater-pre-installer-exit', 'service-pre-download-exit')
# In-product faults: the product hard-codes them on Versions[5], [8], [10] and Versions[6], [9] and records <version>.json.
$InProductFaults = @('service-pre-download-exit', 'updater-pre-installer-exit')
# Failure codes an injected fault may leave on a new failed record (derived from source, not yet observed live): a short
# artifact fails the manifest length check (manifest_invalid) or the BITS length backstop (unknown), other BITS errors are
# download_failed; the restarted service closes the interrupted check as staging_failed. Any other new failure is fatal.
$ExpectedFailures = @{ 'feed-truncated-artifact' = @('manifest_invalid', 'download_failed', 'hash_mismatch', 'unknown'); 'service-pre-download-exit' = @('staging_failed') }
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run elevated.' }
# Custody: only the launcher's protected folder, every file matching launch.json. No fallback to config paths.
$custody = $PSScriptRoot
$custodyRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'cerberus-campaign-custody'
if (-not [string]::Equals((Split-Path -Parent $custody), $custodyRoot, [StringComparison]::OrdinalIgnoreCase) -or
  (Split-Path -Leaf $PSCommandPath) -cne 'invoke-update-campaign.ps1') { throw 'Start the campaign with start-update-campaign.ps1; this runner is not in custody.' }
$launch = Get-Content -LiteralPath (Join-Path $custody 'launch.json') -Raw | ConvertFrom-Json -DateKind String
function Get-CmpgnSha256([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
foreach ($n in 'invoke-update-campaign.ps1', 'campaign-lib.ps1') { if (-not $launch.files.$n -or $launch.files.$n.actual -cne $launch.files.$n.expected) { throw "launch.json does not record $n from the commit." } }
if ((Get-CmpgnSha256 $PSCommandPath) -cne $launch.files.'invoke-update-campaign.ps1'.actual) { throw 'Runner hash differs from launch.json.' }
foreach ($f in $launch.files.PSObject.Properties) { if ((Get-CmpgnSha256 (Join-Path $custody $f.Name)) -cne $f.Value.actual) { throw "Custody file differs from launch.json: $($f.Name)" } }
foreach ($t in $launch.tools.PSObject.Properties) {
  if ($t.Value.actual -cne $t.Value.expected -or (Get-CmpgnSha256 $t.Value.path) -cne $t.Value.actual) { throw "Tool differs from its pinned SHA-256: $($t.Name)" }
}
if ($launch.step -cne $Step -or [bool]$launch.installerBusyFallback -ne [bool]$InstallerBusyFallback -or $launch.custody -ne $custody) { throw 'Arguments differ from launch.json.' }
# Load the functions from the bytes just hashed; the file is not read again.
$libBytes = [IO.File]::ReadAllBytes((Join-Path $custody 'campaign-lib.ps1'))
if ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($libBytes)).ToLowerInvariant() -cne $launch.files.'campaign-lib.ps1'.actual) { throw 'campaign-lib.ps1 differs from launch.json.' }
. ([scriptblock]::Create([Text.UTF8Encoding]::new($false).GetString($libBytes).TrimStart([char]0xFEFF)))
$cfg = Get-Content -LiteralPath (Join-Path $custody 'campaign-config.json') -Raw | ConvertFrom-Json -DateKind String
foreach ($k in $Pinned.Keys) { if (-not [string]::Equals([string]$cfg.$k, $Pinned[$k], [StringComparison]::OrdinalIgnoreCase)) { throw "Config $k must be $($Pinned[$k])." } }
if ($cfg.mode -cnotin 'trial', 'counted') { throw 'Config mode must be trial or counted.' }
if (-not $cfg.feed.publishCommand -or -not $cfg.feed.urlPrefix -or $null -eq $cfg.feed.remotePrefix -or -not $launch.tools.publish) { throw 'Config feed section is incomplete.' }
$camp = Get-Content -LiteralPath (Join-Path $custody 'campaign-artifacts.json') -Raw | ConvertFrom-Json -DateKind String
$cid = [string]$camp.campaignId
if ($cid -notmatch '\A[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\z' -or $camp.source -cne $launch.commit -or $cid -cne $launch.campaignId) { throw 'campaign-artifacts.json does not match the launch record.' }
$arts = @($camp.artifacts)
foreach ($a in $arts) { if ([string]$a.version -cnotmatch '\A[0-9]+\.[0-9]+\.[0-9]+\z') { throw 'campaign-artifacts.json has an invalid version string.' } }
$holdMsi = Join-Path $custody 'hold-installer.msi'
$ti = [int]$cfg.targetIndex
$root = $Pinned.privilegedUpdateRoot
$labRoot = Join-Path $root ('lab-campaign-' + $cid)
$identityFile = Join-Path (Split-Path -Parent $root) 'agent-state.v1.json'
$lifecycleFile = Join-Path (Split-Path -Parent $root) 'lifecycle-state.json'   # DurableAgentLifecycleStateStore default path
$receipts = Join-Path $ReceiptsRoot $cid
if ($launch.receipts -cne $receipts -or -not [IO.Directory]::Exists($receipts)) { throw 'The launcher did not prepare the receipts folder.' }
if ($ti -lt 0 -or $ti -ge @($arts[0].manifests).Count) { throw 'targetIndex is outside the campaign targets.' }
# Same digest as the launcher's fallback gate: first 16 hex digits of SHA-256 over the tagged agent id.
$targetHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes('cerberus-campaign-target:' + $arts[0].manifests[$ti].agentId))).Substring(0, 16).ToLowerInvariant()
$faults = @{}; for ($h = 1; $h -le 10; $h++) { $faults[$h] = $Schedule[$h - 1] }
if ($cfg.mode -ceq 'trial') { $faults[3] = 'kill-during-msi-health'; $faults[4] = 'kill-during-msi-health' }   # D3 rollback proof; hop 4 only after a miss
if ($InstallerBusyFallback) { foreach ($k in @($faults.Keys)) { if ($faults[$k] -ceq 'installer-busy-1618') { $faults[$k] = 'feed-truncated-artifact' } } }
$script:callNo = 0; $script:deadline = [DateTime]::UtcNow.Add($HopTimeout)
$http = Get-CmpgnHttpClient
# Preflight: everything that can be checked before a step claims its one-shot lock.
$hopCount = if ($cfg.mode -ceq 'trial') { 4 } else { 10 }
if (($cfg.mode -ceq 'counted' -and $arts.Count -ne 11) -or ($cfg.mode -ceq 'trial' -and $arts.Count -lt 5)) { throw 'A counted campaign needs all 11 packages, a trial at least 5.' }
if (-not $arts[0].bootstrap) { throw 'artifacts[0] is not the bootstrap package.' }
for ($h = 1; $h -le 10; $h++) { if ([string]$camp.faultSchedule."$h" -cne $Schedule[$h - 1]) { throw "campaign-artifacts.json fault for hop $h differs from the runner table." } }
for ($h = 1; $h -lt $arts.Count; $h++) { if ([string]$arts[$h].fault -cne $Schedule[$h - 1]) { throw "Package $h carries fault '$($arts[$h].fault)', expected $($Schedule[$h - 1])." } }
for ($h = 1; $h -le $hopCount; $h++) {
  if ($faults[$h] -ceq 'feed-truncated-artifact' -and -not $arts[$h].manifests[$ti].truncated) { throw "Hop $h needs a truncated copy." }
  if ($faults[$h] -ceq 'feed-truncated-artifact' -and -not ($cfg.feed.renameCommand -and $launch.tools.rename)) { throw 'Truncated hops need feed.renameCommand.' }
  if ($faults[$h] -ceq 'installer-busy-1618' -and -not $launch.files.'hold-installer.msi') { throw 'Installer-busy hops need the hold MSI in custody.' }
}
if ($cfg.backendQueryCommand -and -not $launch.tools.backendQuery) { throw 'backendQueryCommand is not in launch.json.' }
# Every package, manifest and truncated copy this step publishes or installs must be present and unchanged.
$need = @(if ($Step -cin 'Bootstrap', 'All') { , @($arts[0].msi, $arts[0].sha256) }
  if ($Step -cin 'Hops', 'All') { for ($h = 1; $h -le $hopCount; $h++) { $pm = $arts[$h].manifests[$ti]; , @($arts[$h].msi, $arts[$h].sha256); , @($pm.path, $pm.sha256)
      if ($faults[$h] -ceq 'feed-truncated-artifact') { , @($pm.truncated.path, $pm.truncated.sha256) } } })
foreach ($p in $need) { if (-not [IO.File]::Exists([string]$p[0]) -or (Get-CmpgnSha256 ([string]$p[0])) -cne ([string]$p[1]).ToLowerInvariant()) { throw "Campaign file is missing or changed: $($p[0])" } }
$summaryPath = Join-Path $receipts "summary-$($Step.ToLowerInvariant()).json"
if (Test-Path -LiteralPath $summaryPath) { throw 'This step already ran for this campaign.' }
$preflight = [ordered]@{ lifecycleRecord = (Get-CmpgnLifecycleDigest).status; signedStateRecord = [bool](Get-CmpgnIdentityDigest) }
if ($Step -ceq 'Hops') {
  $boot = Get-Content -LiteralPath (Join-Path $receipts 'bootstrap.jsonl') -ErrorAction SilentlyContinue | Select-Object -Last 1 | ConvertFrom-Json
  if ($boot.result -cne 'pass' -or $boot.campaignId -cne $cid -or $boot.targetIdHash -cne $targetHash -or $boot.candidateHead -cne $camp.source) {
    throw 'No passing bootstrap receipt for this campaign, target and head; run -Step Bootstrap first.' }
  $first = Assert-CmpgnPrecondition $arts[0].version $true
  $preflight.readiness = Read-CmpgnReadiness $first.svcPid
  if (-not $preflight.readiness.success) { throw 'The agent does not answer readiness on its control pipe.' }
}
# Start guard: each step claims its lock exactly once and keeps it open. A lock without a summary is a failed campaign.
$lockSteps = @(if ($Step -cin 'Bootstrap', 'All') { 'bootstrap' }; if ($Step -cin 'Hops', 'All') { 'hops' })
if (-not $lockSteps.Count) { throw "Step '$Step' selects nothing to run." }
$locks = foreach ($n in $lockSteps) {
  try { $l = [IO.File]::Open((Join-Path $receipts "started-$n.lock"), [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read) }
  catch { throw "Step $n of campaign $cid was already started; it cannot be resumed. Start a new campaign." }
  $b = [Text.Encoding]::UTF8.GetBytes((([ordered]@{ step = $n; startedUtc = [DateTime]::UtcNow.ToString('o'); custody = $custody }) | ConvertTo-Json -Compress))
  $l.Write($b, 0, $b.Length); $l.Flush($true); $l
}
$summary = [ordered]@{ campaignId = $cid; candidateHead = $camp.source; mode = $cfg.mode; step = $Step; targetIdHash = $targetHash
  installerBusyVerified = (-not $InstallerBusyFallback); startedUtc = [DateTime]::UtcNow.ToString('o'); preflight = $preflight; launch = $launch; hops = @() }
if ($InstallerBusyFallback) { $summary.openItem = '1618 / installer-busy scenario not verified; truncated-package hops used instead.' }
$ok = $true
if ($Step -cin 'Bootstrap', 'All') { $ok = Invoke-CmpgnBootstrap; $summary.bootstrap = if ($ok) { 'pass' } else { 'fail' } }
if ($ok -and $Step -cin 'Hops', 'All') {
  $summary.backendStart = Invoke-CmpgnBackendQuery 'start' ([DateTime]::UtcNow.AddMinutes(5))
  for ($h = 1; $h -le $hopCount; $h++) {
    $r = Invoke-CmpgnHop $h $faults[$h]
    $summary.hops += [ordered]@{ hop = $h; fault = $faults[$h]; window = $r.fault.window; result = $r.result; durationSec = $r.durationSec; failureReason = $r.failureReason }
    if ($cfg.mode -ceq 'trial' -and $h -eq 3 -and $r.result -ceq 'rolled_back') { break }
    if ($cfg.mode -ceq 'trial' -and $h -eq 3 -and $r.result -ceq 'missed') { continue }
    if ($r.result -cnotin 'pass', 'rolled_back') { $ok = $false; break }
  }
  if ($cfg.mode -ceq 'trial' -and $ok -and -not ($summary.hops | Where-Object { $_.result -ceq 'rolled_back' })) { $ok = $false }
  $summary.backendEnd = Invoke-CmpgnBackendQuery 'end' ([DateTime]::UtcNow.AddMinutes(5))
  $summary.countedPassed = if ($cfg.mode -ceq 'counted') { @($summary.hops | Where-Object { $_.result -ceq 'pass' }).Count } else { 0 }
  $summary.evidenceScope = if ($cfg.backendQueryCommand) { 'agent records + backend query' } else { 'agent-side records only' }
}
# A summary passes only when a step actually ran.
if (-not ($summary.Contains('bootstrap') -or @($summary.hops).Count)) { $ok = $false }
$summary.result = if ($ok) { 'pass' } else { 'fail' }
$summary.endedUtc = [DateTime]::UtcNow.ToString('o')
$summary | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding utf8
Write-Output "Campaign $cid $($cfg.mode) $Step`: $($summary.result). Receipts: $receipts"
if (-not $ok) { exit 1 }
