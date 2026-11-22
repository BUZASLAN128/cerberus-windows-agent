<# Functions for invoke-update-campaign.ps1. Function definitions and one Add-Type only: the runner checks these bytes
  against launch.json and loads them from its custody folder. They read the runner's variables ($custody, $launch, $cfg,
  $camp, $Pinned, $root, $labRoot, $receipts ...) when called. #>
function Read-CmpgnJson([string]$Path) {
  for ($i = 0; $i -lt 3; $i++) {
    try { if (-not [IO.File]::Exists($Path)) { return $null }; $fs = [IO.File]::Open($Path, 'Open', 'Read', [IO.FileShare]'ReadWrite,Delete')
      try { $text = [IO.StreamReader]::new($fs).ReadToEnd() } finally { $fs.Dispose() }; return $text | ConvertFrom-Json -DateKind String
    } catch { Start-Sleep -Milliseconds 100 }
  }
  throw "Record unreadable: $(Split-Path $Path -Leaf)"
}
function Write-CmpgnRecord([string]$Name, $Record) { ($Record | ConvertTo-Json -Depth 8 -Compress) | Add-Content -LiteralPath (Join-Path $receipts $Name) -Encoding utf8 }
function Get-CmpgnTool([string]$Name) {   # re-hashed before every start: system-location tools are not in custody
  $t = $launch.tools.$Name; if (-not $t) { throw "Tool $Name is not in launch.json." }
  if ((Get-CmpgnSha256 ([string]$t.path)) -cne $t.actual) { throw "Tool $Name differs from its pinned SHA-256." }; [string]$t.path
}
function Get-CmpgnToolArgs([string]$Name) { foreach ($x in @($launch.tools.$Name.args)) { [string]$x } }
function Get-CmpgnServiceExe($Svc) { $p = [string]$Svc.PathName; if ($p.StartsWith('"')) { $p.Substring(1, $p.IndexOf('"', 1) - 1) } else { ($p -split ' ')[0] } }
function Get-CmpgnObservation {
  $j = Read-CmpgnJson (Join-Path $root 'transaction.json')
  $s = Get-CimInstance Win32_Service -Filter "Name='$($Pinned.serviceName)'"
  $ver = $null
  try { $pv = (Get-Item -LiteralPath (Get-CmpgnServiceExe $s)).VersionInfo.ProductVersion; if ($pv) { $ver = $pv -replace '[+-].*$', '' } } catch {}
  $ir = $j.installerResult
  # Same rule as the agent's projection: the journal cause counts only while bound to this attempt and installer result.
  $code = if ($j.failureCode -and $j.failureAttemptId -ceq $j.attemptId -and $j.failureInstallerResultId -ceq $ir.result_id) { $j.failureCode } else { $ir.error_code }
  [pscustomobject]@{ utc = [DateTime]::UtcNow.ToString('o'); phase = [string]$j.phase; revision = [long]$j.revision; attemptId = $j.attemptId
    healthy = $j.healthyInstalledVersion; failureCode = $code; resultId = $ir.result_id; msiExit = $ir.msi_exit_code; errorCode = $ir.error_code
    svcState = [string]$s.State; svcPid = [int]$s.ProcessId; binaryVersion = $ver }
}
function Get-CmpgnTextDigest([string]$Text) { [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Text))).ToLowerInvariant() }
# Informational: SHA-256 of the agent id in the signed-state record, which exists only after a signed agent_state command.
function Get-CmpgnIdentityDigest {
  try { $id = [string](Read-CmpgnJson $identityFile).state.agent_id } catch { $id = $null }
  if ($id) { Get-CmpgnTextDigest $id }
}
# Re-enrollment check: SHA-256 of the lifecycle record's last enrollment nonce. No raw value is written; the DPAPI store is
# never read. 'unavailable' when the record cannot be read; the proof then rests on readiness and backend contact.
function Get-CmpgnLifecycleDigest {
  try { $l = Read-CmpgnJson $lifecycleFile } catch { $l = $null }
  if (-not $l -or $l.schema_version -cne 'cerberus-agent-lifecycle.v1') { return [ordered]@{ status = 'unavailable' } }
  $n = [string]$l.last_enrollment_nonce
  [ordered]@{ status = 'available'; generation = $l.generation; enrollmentNonceDigest = $(if ($n) { Get-CmpgnTextDigest $n } else { 'none' }) }
}
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using Microsoft.Win32.SafeHandles;
public static class CmpgnPipeAuthority { [DllImport("kernel32.dll", SetLastError = true)] public static extern bool GetNamedPipeServerProcessId(SafePipeHandle p, out uint id); }
public static class CmpgnBits {   // read-only progress of the agent's BITS job (Bits.h vtable order; S3-S11 are never called)
  [ComImport, Guid("4991D34B-80A1-4291-83B6-3328366B9097")] class Manager { }
  [ComImport, Guid("5CE34C0D-0DC9-4C1F-897C-DAA1B78CEE7C"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IManager { [PreserveSig] int CreateJob(IntPtr name, int type, out Guid id, out IntPtr job); [PreserveSig] int GetJob(ref Guid id, out IJob job); }
  [ComImport, Guid("37668D37-507E-4160-9316-26306D150B12"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  interface IJob { void S3(); void S4(); void S5(); void S6(); void S7(); void S8(); void S9(); void S10(); void S11(); [PreserveSig] int GetProgress(out Progress p); }
  [StructLayout(LayoutKind.Sequential)] struct Progress { public ulong Total, Done; public uint FilesTotal, FilesDone; }
  public static long Transferred(Guid id) {
    var m = (IManager)new Manager();
    try { IJob j; if (m.GetJob(ref id, out j) != 0 || j == null) return -1;
      try { Progress p; return j.GetProgress(out p) == 0 ? (long)p.Done : -1; } finally { Marshal.ReleaseComObject(j); } }
    finally { Marshal.ReleaseComObject(m); }
  }
}
'@
# Bytes the agent's BITS job for this attempt has received; -1 when the job or its receipt cannot be read.
function Get-CmpgnBitsBytes([string]$AttemptId) {
  try { [CmpgnBits]::Transferred([Guid][string](Read-CmpgnJson (Join-Path $root "attempts\attempt-$AttemptId\bits-job.json")).jobId) } catch { -1 }
}
function Get-CmpgnAttemptAgeSec([string]$AttemptId) {   # since the runner first saw this attempt
  $f = @($script:events | Where-Object { $_.attempt -ceq $AttemptId })[0]
  if ($f) { [int]([DateTime]::UtcNow - [DateTimeOffset]::Parse($f.utc).UtcDateTime).TotalSeconds } else { 0 }
}
function Read-CmpgnReadiness([int]$ExpectedPid) {
  # The pipe grants administrators client rights only; InOut would also ask for FILE_CREATE_PIPE_INSTANCE and be denied.
  $rights = [IO.Pipes.PipeAccessRights]'ReadData, WriteData, ReadAttributes, ReadPermissions, Synchronize'
  $pipe = [IO.Pipes.NamedPipeClientStream]::new('.', $Pinned.controlPipeName, $rights, [IO.Pipes.PipeOptions]::Asynchronous,
    [Security.Principal.TokenImpersonationLevel]::Identification, [IO.HandleInheritability]::None)
  try {
    $pipe.Connect(3000); $server = [uint32]0
    if (-not [CmpgnPipeAuthority]::GetNamedPipeServerProcessId($pipe.SafePipeHandle, [ref]$server) -or $server -ne $ExpectedPid) { return $null }
    $body = [Text.Encoding]::UTF8.GetBytes('{"operation":"readiness","attemptId":null,"schemaVersion":"agent.local-control.v1"}')
    $pipe.Write([BitConverter]::GetBytes([int]$body.Length), 0, 4); $pipe.Write($body, 0, $body.Length); $pipe.Flush()
    $read = { param([int]$n) $b = [byte[]]::new($n); $o = 0
      while ($o -lt $n) { $t = $pipe.ReadAsync($b, $o, $n - $o); if (-not $t.Wait(5000) -or $t.Result -le 0) { throw 'readiness read' }; $o += $t.Result }; , $b }
    $len = [BitConverter]::ToInt32((& $read 4), 0)
    if ($len -le 0 -or $len -gt 16384) { return $null }
    $r = [Text.Encoding]::UTF8.GetString((& $read $len)) | ConvertFrom-Json -DateKind String
    [pscustomobject]@{ pid = $ExpectedPid; success = $r.success; currentVersion = $r.currentVersion; lifecycleState = $r.lifecycleState
      lifecycleGeneration = $r.lifecycleGeneration; lastBackendContactUtc = $r.lastBackendContactUtc }
  } catch { return $null } finally { $pipe.Dispose() }
}
function Test-CmpgnInstallerBusy {
  $m = $null; try { if ([Threading.Mutex]::TryOpenExisting('Global\_MSIExecute', [ref]$m)) { $m.Dispose(); return $true }; return $false }
  catch [UnauthorizedAccessException] { return $true }
}
function Test-CmpgnMachineHealth {
  $o = [ordered]@{}; foreach ($n in $(if ($cfg.healthServices) { @($cfg.healthServices) } else { @('TermService', 'Tailscale') })) { $o[$n] = [string](Get-Service -Name $n -ErrorAction SilentlyContinue).Status }; $o
}
# Every external program runs against a deadline and is killed with its children when the deadline passes.
function Invoke-CmpgnBounded([string[]]$Cmd, [string]$Label, [DateTime]$Deadline) {
  $script:callNo++; $Label = "$Label-$($script:callNo)"
  $limit = [int][Math]::Max(0, ($Deadline - [DateTime]::UtcNow).TotalMilliseconds)
  if ($limit -le 0) { throw "$Label was not started: the hop deadline has passed." }
  $psi = [Diagnostics.ProcessStartInfo]::new($Cmd[0])
  foreach ($x in @($Cmd | Select-Object -Skip 1)) { $psi.ArgumentList.Add([string]$x) }
  $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
  $psi.WorkingDirectory = $custody   # bare names resolve only to pinned custody copies
  $p = [Diagnostics.Process]::Start($psi); $out = $p.StandardOutput.ReadToEndAsync(); $err = $p.StandardError.ReadToEndAsync()
  if (-not $p.WaitForExit($limit)) {
    try { $p.Kill($true) } catch {}
    Write-CmpgnRecord 'timeouts.jsonl' ([ordered]@{ label = $Label; utc = [DateTime]::UtcNow.ToString('o'); limitSec = [int]($limit / 1000) })
    throw "$Label timed out after $([int]($limit / 1000)) s and was stopped."
  }
  $log = Join-Path $receipts "$Label.log"
  $text = foreach ($task in $out, $err) { if ($task.Wait(5000)) { $task.Result } else { '[output not closed]' } }
  Set-Content -LiteralPath $log -Value ($text -join "`n") -Encoding utf8
  [ordered]@{ label = $Label; exitCode = $p.ExitCode; log = $log }
}
function Get-CmpgnHttpClient {   # trusts only the custody copy of the feed root when one is configured; the deadline is a token
  $h = [Net.Http.SocketsHttpHandler]::new(); $h.AllowAutoRedirect = $false
  if ($launch.files.'feed-root.cer') {
    $p = [Security.Cryptography.X509Certificates.X509ChainPolicy]::new(); $p.TrustMode = 'CustomRootTrust'; $p.RevocationMode = 'NoCheck'
    $null = $p.CustomTrustStore.Add([Security.Cryptography.X509Certificates.X509Certificate2]::new((Join-Path $custody 'feed-root.cer'))); $h.SslOptions.CertificateChainPolicy = $p
  }
  $c = [Net.Http.HttpClient]::new($h); $c.Timeout = [Threading.Timeout]::InfiniteTimeSpan; $c
}
function Get-CmpgnRemote([string]$Url) {
  if (-not $Url.StartsWith('https://', [StringComparison]::Ordinal) -or -not $Url.StartsWith($cfg.feed.urlPrefix, [StringComparison]::Ordinal)) { throw "URL outside the test feed: $Url" }
  $remote = [string]$cfg.feed.remotePrefix + $Url.Substring($cfg.feed.urlPrefix.Length)
  if ($remote -notmatch '\A[A-Za-z0-9._/-]+\z' -or $remote -match '\.\.') { throw 'Remote feed path is unsafe.' }
  $remote
}
# Arguments come from launch.json, where the launcher rewrote every pinned file argument to its custody copy.
function Invoke-CmpgnFeedTool([string]$Tool, [hashtable]$Values) {
  $cmd = @((Get-CmpgnTool $Tool)) + @(foreach ($s in @(Get-CmpgnToolArgs $Tool)) { foreach ($k in $Values.Keys) { $s = $s.Replace("{$k}", $Values[$k]) }; $s })
  $r = Invoke-CmpgnBounded $cmd "feed-$Tool" $script:deadline
  if ($r.exitCode -ne 0) { throw "Feed $Tool failed ($($r.exitCode)); see $($r.log)." }
}
function Assert-CmpgnServed([string]$Url, [string]$Sha256) {
  $limit = [int][Math]::Max(0, ($script:deadline - [DateTime]::UtcNow).TotalMilliseconds)
  if ($limit -le 0) { throw "Feed check of $Url was not started: the hop deadline has passed." }
  $cts = [Threading.CancellationTokenSource]::new($limit)
  try {
    $resp = $http.GetAsync($Url + '?cb=' + [Guid]::NewGuid().ToString('N'), $cts.Token).GetAwaiter().GetResult()
    try {
      if (-not $resp.IsSuccessStatusCode) { throw "Feed check HTTP $([int]$resp.StatusCode) for $Url" }
      $served = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($resp.Content.ReadAsByteArrayAsync($cts.Token).GetAwaiter().GetResult()))
    } finally { $resp.Dispose() }
  } catch {
    if (-not $cts.IsCancellationRequested) { throw }
    Write-CmpgnRecord 'timeouts.jsonl' ([ordered]@{ label = "feed-check $Url"; utc = [DateTime]::UtcNow.ToString('o'); limitSec = [int]($limit / 1000) })
    throw "Feed check of $Url timed out and was cancelled."
  } finally { $cts.Dispose() }
  if ($served -ne $Sha256) { throw "Feed serves different bytes at $Url" }
}
# -Staged uploads under a name no manifest points at; Invoke-CmpgnFeedSwap later moves it over the served name.
function Invoke-CmpgnPublish([string]$Local, [string]$Url, [string]$Sha256, [switch]$Staged) {
  $remote = Get-CmpgnRemote $Url
  if ($Staged) { $remote += $StagedSuffix }
  if ((Get-FileHash -LiteralPath $Local -Algorithm SHA256).Hash -ne $Sha256) { throw "Local file differs from the campaign record: $(Split-Path $Local -Leaf)" }
  Invoke-CmpgnFeedTool 'publish' @{ local = $Local; remote = $remote }
  if (-not $Staged) { Assert-CmpgnServed $Url $Sha256 }
  [DateTime]::UtcNow.ToString('o')
}
function Invoke-CmpgnFeedSwap([string]$Url, [string]$Sha256) {
  $remote = Get-CmpgnRemote $Url; Invoke-CmpgnFeedTool 'rename' @{ from = $remote + $StagedSuffix; to = $remote }
  $utc = [DateTime]::UtcNow.ToString('o'); Assert-CmpgnServed $Url $Sha256; $utc
}
function ConvertTo-CmpgnPackedGuid([string]$Guid) {
  $g = $Guid.Trim('{}').Replace('-', '').ToUpperInvariant()
  $rev = { param($s) -join ($s.ToCharArray()[($s.Length - 1)..0]) }
  $tail = -join (0..7 | ForEach-Object { $p = $g.Substring(16 + 2 * $_, 2); $p[1] + $p[0] })
  (& $rev $g.Substring(0, 8)) + (& $rev $g.Substring(8, 4)) + (& $rev $g.Substring(12, 4)) + $tail
}
function Test-CmpgnHoldRegistered {
  $packed = ConvertTo-CmpgnPackedGuid $HoldProductCode
  $keys = @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$HoldProductCode", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$HoldProductCode",
    "HKLM:\SOFTWARE\Classes\Installer\Products\$packed", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\$packed")
  [bool](@($keys | Where-Object { Test-Path -LiteralPath $_ }).Count)
}
function Start-CmpgnHold([int]$Hop) {
  $flag = Join-Path $custody "release-$cid-hop$Hop.flag"
  if (Test-Path -LiteralPath $flag) { throw 'Hold release flag already exists.' }
  $log = Join-Path $receipts "hold-hop$Hop.log"
  $p = Start-Process -FilePath $Msiexec -PassThru -ArgumentList @('/i', "`"$holdMsi`"", '/qn', '/norestart', "HOLDRELEASE=`"$flag`"", '/l*v', "`"$log`"")
  $deadline = [DateTime]::UtcNow.AddSeconds(60)
  while (-not (Test-CmpgnInstallerBusy)) {
    if ($p.HasExited -or [DateTime]::UtcNow -gt $deadline) {
      Set-Content -LiteralPath $flag -Value 'release'
      $exited = $p.WaitForExit(90000)
      throw "Hold installer did not make Windows Installer busy (exited $exited, exit code $(if ($exited) { $p.ExitCode }), registered $(Test-CmpgnHoldRegistered))."
    }
    Start-Sleep -Milliseconds 250
  }
  [pscustomobject]@{ process = $p; flag = $flag; startedUtc = [DateTime]::UtcNow }
}
function Stop-CmpgnHold($Hold) {
  if (-not (Test-Path -LiteralPath $Hold.flag)) { Set-Content -LiteralPath $Hold.flag -Value 'release' }
  if (-not $Hold.process.WaitForExit(90000)) { throw 'Hold installer did not exit after release.' }
  $code = $Hold.process.ExitCode; $registered = Test-CmpgnHoldRegistered
  if ($code -ne 1603 -or $registered) { throw "Hold installer did not roll back cleanly (exit $code, expected 1603; registered $registered)." }
  [ordered]@{ holdExitCode = $code; holdProductRegistered = $registered; releasedUtc = [DateTime]::UtcNow.ToString('o') }
}
function Stop-CmpgnServicePid {
  $s = Get-CimInstance Win32_Service -Filter "Name='$($Pinned.serviceName)'"
  $svcPid = [int]$s.ProcessId
  if ($svcPid -le 0) { throw 'Service has no process to stop.' }
  $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$svcPid"
  if (-not $proc -or -not [string]::Equals($proc.ExecutablePath, (Get-CmpgnServiceExe $s), [StringComparison]::OrdinalIgnoreCase)) { throw 'Service PID does not belong to the service image.' }
  $j = Read-CmpgnJson (Join-Path $root 'transaction.json')
  Stop-Process -Id $svcPid -Force
  [ordered]@{ utc = [DateTime]::UtcNow.ToString('o'); killedPid = $svcPid; phaseAtKill = [string]$j.phase; revisionAtKill = [long]$j.revision }
}
function Invoke-CmpgnBackendQuery([string]$Label, [DateTime]$Deadline) {
  if (-not $cfg.backendQueryCommand) { return $null }
  try { Invoke-CmpgnBounded (@((Get-CmpgnTool 'backendQuery')) + @(Get-CmpgnToolArgs 'backendQuery')) "backend-$Label" $Deadline }
  catch { [ordered]@{ label = "backend-$Label"; error = $_.Exception.Message } }
}
# One watcher per hop: records every phase/PID/binary change as a recovery event and enforces the hop deadline.
function Wait-CmpgnState([scriptblock]$Done, [scriptblock]$Fatal, [string]$What, [int]$PollMs = 1000) {
  while ($true) {
    $o = Get-CmpgnObservation
    $key = "$($o.phase)|$($o.attemptId)|$($o.svcPid)|$($o.svcState)|$($o.binaryVersion)|$($o.failureCode)|$($o.msiExit)"
    if ($key -cne $script:lastKey) {
      $script:lastKey = $key
      $script:events.Add([ordered]@{ utc = $o.utc; phase = $o.phase; attempt = $o.attemptId; pid = $o.svcPid; service = $o.svcState; binary = $o.binaryVersion
        failureCode = $o.failureCode; msiExit = $o.msiExit })
    }
    # Attempt folders can be removed after install; keep the agent's plan as soon as it appears (in capture order).
    if ($o.attemptId -and -not $script:plans.Contains($o.attemptId) -and ($p = Get-CmpgnAgentPlan $o.attemptId)) { $script:plans[$o.attemptId] = $p }
    if (& $Done $o) { return $o }
    if ($Fatal -and ($reason = & $Fatal $o)) { throw "$What`: $reason" }
    if ($o.phase -cin 'quarantined', 'blocked') { throw "$What`: journal phase $($o.phase)" }
    if ([DateTime]::UtcNow -gt $script:deadline) { throw "$What`: hop timeout (last phase $($o.phase))" }
    Start-Sleep -Milliseconds $PollMs
  }
}
# A failure is new when it belongs to another attempt or installer result, or the journal left 'failed' and came back.
# It is judged once the agent has bound a code to it; only the codes the injected fault explains are tolerated.
function New-CmpgnFatal($Pre, [string[]]$Allowed, [bool]$AllowRecovery) {
  $seen = @{ active = $Pre.phase -cne 'failed' }
  {
    param($o)
    if ($o.phase -ceq 'recovery_required' -and -not $AllowRecovery) { return 'recovery_required' }
    if ($o.phase -cne 'failed') { $seen.active = $true; return $null }
    if (-not ($seen.active -or $o.attemptId -cne $Pre.attemptId -or $o.resultId -cne $Pre.resultId) -or -not $o.failureCode) { return $null }
    if ($o.failureCode -cnotin $Allowed) { "failed with $($o.failureCode) (msi $($o.msiExit))" }
  }.GetNewClosure()
}
function Assert-CmpgnPrecondition([string]$Prev, [bool]$AfterBootstrap) {
  $o = Get-CmpgnObservation
  if ($o.svcState -cne 'Running' -or $o.binaryVersion -cne $Prev) { throw "Precondition: service is not running $Prev." }
  if (Test-CmpgnInstallerBusy) { throw 'Precondition: Windows Installer is busy.' }
  if ($AfterBootstrap) {
    # The bootstrap MSI never sets healthyInstalledVersion; its commit is recorded in bootstrap.json instead.
    $b = Read-CmpgnJson (Join-Path $labRoot 'installer-transactions\bootstrap.json')
    if ($b.campaignId -cne $cid -or $b.state -cne 'committed') { throw 'Precondition: bootstrap is not committed.' }
    if ($o.phase -cnotin 'installed', 'current', 'not_checked', 'failed') { throw "Precondition: journal phase $($o.phase)." }
  } elseif ($o.phase -cne 'installed' -or $o.healthy -cne $Prev) { throw "Precondition: journal does not show $Prev installed." }
  $o
}
function Get-CmpgnAgentPlan([string]$AttemptId) {
  if (-not $AttemptId -or $AttemptId -notmatch '\A[0-9a-fA-F]{32}\z' -or -not ($p = Read-CmpgnJson (Join-Path $root "attempts\attempt-$AttemptId\update-plan.json"))) { return $null }
  # The agent writes a plan only after the manifest signature and channel checks pass; this flag is derived from that.
  [ordered]@{ attemptId = $AttemptId; version = $p.version; sequence = $p.sequence; sha256 = $p.sha256; artifactLength = $p.artifactLength
    signerKeyIdentity = $p.signerKeyIdentity; manifestDigest = $p.manifestDigest; signatureVerified = [bool]($p.signerKeyIdentity -and $p.manifestDigest) }
}
function Invoke-CmpgnBootstrap {
  $a = $arts[0]
  $script:events = [Collections.Generic.List[object]]::new(); $script:plans = [ordered]@{}; $script:lastKey = ''; $script:deadline = [DateTime]::UtcNow.Add($HopTimeout)
  $rec = [ordered]@{ step = 'bootstrap'; index = 0; counted = $false; targetIdHash = $targetHash; candidateHead = $camp.source; campaignId = $cid
    toVersion = $a.version; artifactSha256 = $a.sha256; artifactBytes = $a.bytes; startedUtc = [DateTime]::UtcNow.ToString('o'); manualIntervention = 0 }
  Write-CmpgnRecord 'bootstrap.jsonl' ([ordered]@{ step = 'bootstrap'; event = 'started'; utc = $rec.startedUtc })
  try {
    $pre = Get-CmpgnObservation
    $rec.fromVersion = $pre.binaryVersion
    if ($pre.phase -cnotin 'installed', 'current', 'not_checked', 'failed') { throw "Journal has an unfinished attempt ($($pre.phase))." }
    if (Test-CmpgnInstallerBusy) { throw 'Windows Installer is busy.' }
    # Install from the protected custody folder, never from the writable build output.
    $msi = Join-Path $custody ("bootstrap-$($a.version).msi")
    Copy-Item -LiteralPath $a.msi -Destination $msi -Force
    if ((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash -ne $a.sha256 -or (Get-Item -LiteralPath $msi).Length -ne [long]$a.bytes) { throw 'Bootstrap MSI differs from the campaign record.' }
    $tx = [Guid]::NewGuid().ToString('D')
    $r = Invoke-CmpgnBounded @($Msiexec, '/i', $msi, '/qn', '/norestart', "CERBERUS_LAB_TRANSACTION=$tx", '/l*v', (Join-Path $receipts 'bootstrap-msi.log')) 'bootstrap-msiexec' $script:deadline
    $rec.installerResult = [ordered]@{ msiExitCode = $r.exitCode; source = 'msiexec' }
    if ($r.exitCode -ne 0) { throw "Bootstrap MSI exit $($r.exitCode)." }
    $null = Wait-CmpgnState -What 'bootstrap' -Done { param($o) $o.svcState -ceq 'Running' -and $o.binaryVersion -ceq $a.version -and
      (Read-CmpgnJson (Join-Path $labRoot 'installer-transactions\bootstrap.json')).state -ceq 'committed' }
    $o = Get-CmpgnObservation
    $rec.runningService = [ordered]@{ binaryVersion = $o.binaryVersion; pid = $o.svcPid }
    $rec.readiness = Read-CmpgnReadiness $o.svcPid
    $rec.result = 'pass'
  } catch { $rec.result = 'fail'; $rec.failureReason = $_.Exception.Message }
  $rec.machineHealth = Test-CmpgnMachineHealth; $rec.recoveryEvents = $script:events; $rec.endedUtc = [DateTime]::UtcNow.ToString('o')
  Write-CmpgnRecord 'bootstrap.jsonl' $rec
  $rec.result -ceq 'pass'
}
function Get-CmpgnUtcSeconds([string]$From, [string]$To) { [int]([DateTimeOffset]::Parse($To).UtcDateTime - [DateTimeOffset]::Parse($From).UtcDateTime).TotalSeconds }
function Invoke-CmpgnHop([int]$Hop, [string]$Fault) {
  $a = $arts[$Hop]; $from = $arts[$Hop - 1].version; $to = $a.version; $m = $a.manifests[$ti]
  $script:events = [Collections.Generic.List[object]]::new(); $script:plans = [ordered]@{}; $script:lastKey = ''; $start = [DateTime]::UtcNow; $script:deadline = $start.Add($HopTimeout)
  $rec = [ordered]@{ step = 'hop'; index = $Hop; mode = $cfg.mode; counted = ($cfg.mode -ceq 'counted'); targetIdHash = $targetHash; candidateHead = $camp.source
    campaignId = $cid; holdMsiSha256 = [string]$launch.files.'hold-installer.msi'.actual; fromVersion = $from; toVersion = $to; manifestUrl = $m.manifestUrl
    artifactUrl = $m.artifactUrl; artifactBytes = $a.bytes; artifactSha256 = $a.sha256; manifestSha256 = $m.sha256; fault = [ordered]@{ kind = $Fault }
    startedUtc = $start.ToString('o'); manualIntervention = 0 }
  Write-CmpgnRecord 'hops.jsonl' ([ordered]@{ step = 'hop'; index = $Hop; event = 'started'; fault = $Fault; utc = $rec.startedUtc })
  $hold = $null
  try {
    $pre = Assert-CmpgnPrecondition $from ($Hop -eq 1)
    $startPid = $pre.svcPid; $preResult = $pre.resultId
    $installed = { param($o) $o.phase -ceq 'installed' -and $o.healthy -ceq $to -and $o.svcState -ceq 'Running' -and $o.binaryVersion -ceq $to }
    $allowed = if ($ExpectedFailures.ContainsKey($Fault)) { $ExpectedFailures[$Fault] } else { @() }
    $fatal = New-CmpgnFatal $pre $allowed ($Fault -ceq 'updater-pre-installer-exit')
    switch ($Fault) {
      'installer-busy-1618' {
        # Hold once the agent's download moves: Windows can pause background downloads before the first byte (BITS in
        # Game Mode), and that pause must not spend the hold's cap. A pause after the transfer starts still can.
        $rec.artifactPublishedUtc = Invoke-CmpgnPublish $a.msi $m.artifactUrl $a.sha256
        if (Test-CmpgnInstallerBusy) { throw 'Windows Installer is already busy before the hold.' }
        $rec.manifestPublishedUtc = Invoke-CmpgnPublish $m.path $m.manifestUrl $m.sha256
        $seen = @{}
        $moving = Wait-CmpgnState -What 'agent download start' -Fatal $fatal -PollMs 250 -Done { param($o)
          if ($o.attemptId -and $o.attemptId -cne $pre.attemptId -and $o.phase -cnotin 'checking', 'downloading') { throw "Agent left downloading ($($o.phase)) before the hold." }
          if ($o.phase -cne 'downloading' -or $o.attemptId -ceq $pre.attemptId) { return $false }
          $b = Get-CmpgnBitsBytes $o.attemptId; $p = $seen[$o.attemptId]; $seen[$o.attemptId] = $b
          $null -ne $p -and $p -ge 0 -and $b -gt $p }
        $rec.fault.downloadMovingUtc = $moving.utc
        try { $hold = Start-CmpgnHold $Hop } catch { $rec.fault.delivered = $false; $rec.fault.notDeliveredReason = 'hold_start_failed'; throw }
        $rec.fault.utc = $hold.startedUtc.ToString('o')
        # Busy can also be the agent's own msiexec: the hold counts only while the same attempt is still downloading.
        $chk = Get-CmpgnObservation
        if ($chk.attemptId -cne $moving.attemptId -or $chk.phase -cne 'downloading') {
          $rec.fault.delivered = $false; $rec.fault.notDeliveredReason = 'download_finished_before_hold'; throw 'Agent left downloading before the hold was in place.' }
        $script:deadline = $hold.startedUtc.Add($HoldCap)
        try {
          $busy = Wait-CmpgnState -What 'installer busy (fault not delivered)' -Fatal $fatal -Done { param($o)
            $o.resultId -cne $preResult -and ($o.phase -ceq 'retryable_busy' -or $o.msiExit -eq 1618) }
        } catch {
          if ($_.Exception.Message -clike '*hop timeout*') {
            # Fallback evidence only when the agent reached its installer step during the hold and the hold still ran at the cap.
            $reached = @($script:events | Where-Object { $_.phase -cin 'launch_requested', 'installer_started', 'installing' -and
              [DateTimeOffset]::Parse($_.utc).UtcDateTime -ge $hold.startedUtc })
            $rec.fault.delivered = $false; $rec.fault.agentReachedInstallerDuringHold = [bool]$reached.Count
            $rec.fault.notDeliveredReason = if ($reached.Count -and -not $hold.process.HasExited -and (Test-CmpgnInstallerBusy)) { 'agent_never_saw_1618_while_hold_running' } else { 'hop_timeout' }
          }
          throw
        }
        $rec.fault.delivered = $true; $rec.fault.agentSaw1618Utc = $busy.utc
        $rec.fault.marginToHoldCapSec = [int]($hold.startedUtc.Add($HoldCap) - [DateTime]::UtcNow).TotalSeconds
        $rec.fault.hold = Stop-CmpgnHold $hold; $hold = $null
        $script:deadline = $start.Add($HopTimeout)
        $done = Wait-CmpgnState -What 'install after 1618' -Fatal $fatal -Done $installed
      }
      'feed-truncated-artifact' {
        $t = $m.truncated
        if (-not $t) { throw "No truncated copy for hop $Hop in campaign-artifacts.json." }
        $rec.fault.fullStagedUtc = Invoke-CmpgnPublish $a.msi $m.artifactUrl $a.sha256 -Staged
        $rec.fault.utc = Invoke-CmpgnPublish $t.path $m.artifactUrl $t.sha256
        $rec.manifestPublishedUtc = Invoke-CmpgnPublish $m.path $m.manifestUrl $m.sha256
        # The rejection is a new attempt closed by the stager, with no installer result and a short-artifact code. The
        # install request retries 30 s later (lab build), so the full artifact must be in place before that.
        # A download stalled to the agent's 900 s no-progress limit closes the same way; only a quicker failure is the truncation.
        $rej = Wait-CmpgnState -What 'truncated download rejection' -Fatal $fatal -PollMs 250 -Done { param($o)
          if (-not ($o.phase -ceq 'failed' -and $o.attemptId -and $o.attemptId -cne $pre.attemptId -and -not $o.resultId)) { return $false }
          if ((Get-CmpgnAttemptAgeSec $o.attemptId) -ge 840) { throw 'Download stalled to the no-progress limit; not a truncation rejection.' }
          $o.failureCode -cin $ExpectedFailures['feed-truncated-artifact'] }
        if ($script:plans.Contains($rej.attemptId)) { throw 'The rejected attempt has a staged plan.' }
        $rec.fault.rejectedUtc = $rej.utc; $rec.fault.rejectionCode = $rej.failureCode; $rec.fault.rejectedAttemptId = $rej.attemptId
        $rec.artifactPublishedUtc = Invoke-CmpgnFeedSwap $m.artifactUrl $a.sha256
        $rec.fault.swapSecondsAfterRejection = Get-CmpgnUtcSeconds $rej.utc $rec.artifactPublishedUtc
        $done = Wait-CmpgnState -What 'install after full artifact' -Done $installed -Fatal (New-CmpgnFatal $rej @() $false)
      }
      'kill-health-pending' {
        $rec.artifactPublishedUtc = Invoke-CmpgnPublish $a.msi $m.artifactUrl $a.sha256
        $rec.manifestPublishedUtc = Invoke-CmpgnPublish $m.path $m.manifestUrl $m.sha256
        # The precondition proved the previous hop installed, so any health_pending after publication is this hop's attempt.
        $null = Wait-CmpgnState -What 'health_pending' -Fatal $fatal -PollMs 250 -Done { param($o) $o.phase -ceq 'health_pending' -or (& $installed $o) }
        $kill = Stop-CmpgnServicePid; foreach ($k in $kill.Keys) { $rec.fault[$k] = $kill[$k] }
        $rec.fault.window = switch ($kill.phaseAtKill) { 'health_pending' { 'health_pending' } 'installed' { 'missed_after_installed' } default { "other:$_" } }
        if ($rec.fault.window -cne 'health_pending') { $rec.fault.note = 'Service crash and SCM restart only; the record was not health_pending at the kill.' }
        $done = Wait-CmpgnState -What 'restart and close as installed' -Fatal $fatal -Done { param($o) (& $installed $o) -and $o.svcPid -ne $kill.killedPid }
      }
      'kill-during-msi-health' {
        # Recorded, not asserted: the generation may move on a lifecycle boundary during the rollback restart.
        $rec.fault.lifecycleGenerationBefore = (Read-CmpgnReadiness $startPid).lifecycleGeneration
        $preLc = Get-CmpgnLifecycleDigest; $rec.fault.lifecycleBefore = $preLc; $rec.fault.agentIdDigestBefore = Get-CmpgnIdentityDigest
        $rec.artifactPublishedUtc = Invoke-CmpgnPublish $a.msi $m.artifactUrl $a.sha256
        $rec.manifestPublishedUtc = Invoke-CmpgnPublish $m.path $m.manifestUrl $m.sha256
        $first = Wait-CmpgnState -What 'new service answers' -Fatal $fatal -Done { param($o) (& $installed $o) -or
          ($o.phase -ceq 'installing' -and $o.svcPid -ne $startPid -and $o.binaryVersion -ceq $to -and (Read-CmpgnReadiness $o.svcPid)) }
        if (-not (& $installed $first)) {
          $rec.fault.newServiceAnsweredUtc = $first.utc
          $at = [DateTime]::UtcNow.AddSeconds((Get-Random -Minimum 20 -Maximum 61))
          $o = Wait-CmpgnState -What 'kill window' -Fatal $fatal -Done { param($o) [DateTime]::UtcNow -ge $at -or $o.phase -cne 'installing' -or $o.svcPid -ne $first.svcPid }
          if ($o.phase -ceq 'installing' -and $o.svcPid -eq $first.svcPid) {
            $kill = Stop-CmpgnServicePid; foreach ($k in $kill.Keys) { $rec.fault[$k] = $kill[$k] }
            $rec.fault.secondsAfterAnswer = Get-CmpgnUtcSeconds $first.utc $kill.utc
          }
        }
        if (-not $rec.fault.killedPid) {
          $rec.result = 'missed'; $rec.failureReason = 'MSI health check ended before the kill.'
          $done = Wait-CmpgnState -What 'install after missed kill' -Fatal $fatal -Done $installed
        }
        else {
          $done = Wait-CmpgnState -What 'rollback to previous version' -Fatal (New-CmpgnFatal $pre @('msi_failed') $true) -Done { param($o) (& $installed $o) -or
            ($o.phase -ceq 'failed' -and $o.resultId -and $o.resultId -cne $preResult -and $o.svcState -ceq 'Running' -and $o.binaryVersion -ceq $from) }
          if (& $installed $done) { $rec.result = 'missed'; $rec.failureReason = 'Install completed despite the kill.' }
          else {
            $rec.rollback = [ordered]@{ msiExitCode = $done.msiExit; errorCode = $done.errorCode; failureCode = $done.failureCode; restoredVersion = $done.binaryVersion }
            if ($done.msiExit -ne 1603 -or $done.errorCode -cne 'msi_failed') { throw "Rollback is not msi_failed 1603 (exit $($done.msiExit), code $($done.errorCode))." }
            # Identity continuity: readiness with a backend contact after the rollback, and no re-enrollment (same nonce digest).
            # Contact time is process-local and the pipe is pinned to the answering PID, so it postdates the restart.
            $null = Wait-CmpgnState -What 'backend contact after rollback' -Done { param($o)
              $script:ready = Read-CmpgnReadiness $o.svcPid; $script:ready.success -and $script:ready.lastBackendContactUtc }
            $postLc = Get-CmpgnLifecycleDigest
            $rec.rollback.backendContactUtc = $script:ready.lastBackendContactUtc; $rec.rollback.pid = $script:ready.pid
            $rec.rollback.lifecycleGenerationAfter = $script:ready.lifecycleGeneration; $rec.rollback.lifecycleAfter = $postLc
            $rec.rollback.agentIdDigestAfter = Get-CmpgnIdentityDigest
            $rec.rollback.identityProof = if ($preLc.status -ceq 'available' -and $postLc.status -ceq 'available') {
              if ($preLc.enrollmentNonceDigest -cne $postLc.enrollmentNonceDigest) { throw 'The agent re-enrolled across the rollback (enrollment nonce changed).' }
              'readiness, backend contact, unchanged enrollment nonce'
            } else { 'readiness and backend contact; lifecycle record unavailable' }
            $rec.result = 'rolled_back'
          }
        }
      }
      { $_ -cin $InProductFaults } {
        $rec.artifactPublishedUtc = Invoke-CmpgnPublish $a.msi $m.artifactUrl $a.sha256
        $rec.manifestPublishedUtc = Invoke-CmpgnPublish $m.path $m.manifestUrl $m.sha256
        $done = Wait-CmpgnState -What 'install with in-product fault' -Fatal $fatal -Done $installed
        $r = Read-CmpgnJson (Join-Path $labRoot "$to.json")
        if (-not $r -or $r.fault -cne $Fault -or $r.version -cne $to) { throw "In-product fault $Fault was not recorded for $to." }
        $rec.fault.name = $r.fault; $rec.fault.utc = $r.utc
        # The exit happens before download, so the restarted process still runs the previous binary.
        if ($Fault -ceq 'service-pre-download-exit' -and -not ($script:events | Where-Object { $_.pid -gt 0 -and $_.pid -ne $startPid -and $_.binary -ceq $from })) { throw 'No service restart on the previous version observed.' }
      }
      default { throw "Unknown fault $Fault." }
    }
    $final = Get-CmpgnObservation
    if ($final.attemptId -and -not $script:plans.Contains($final.attemptId) -and ($p = Get-CmpgnAgentPlan $final.attemptId)) { $script:plans[$final.attemptId] = $p }
    $plans = @($script:plans.Values | Where-Object { $_.version -ceq $to })
    if (-not $plans.Count) { throw "No agent update plan for $to was captured." }
    foreach ($p in $plans) { if ($p.sha256 -ne $a.sha256 -or [long]$p.artifactLength -ne [long]$a.bytes) { throw "Agent plan $($p.attemptId) differs from the campaign record (sha256 or length)." } }
    # The plan of the attempt that installed; the newest captured plan when that attempt's plan was not seen.
    $rec.agentPlan = @($plans | Where-Object { $_.attemptId -ceq $final.attemptId })[0]
    if (-not $rec.agentPlan) { $rec.agentPlan = $plans[-1] }
    $rec.installerResult = [ordered]@{ msiExitCode = $final.msiExit; resultId = $final.resultId; errorCode = $final.errorCode; phase = $final.phase; failureCode = $final.failureCode }
    $rec.runningService = [ordered]@{ binaryVersion = $final.binaryVersion; pid = $final.svcPid }
    if ($rec.counted -and -not $rec.result) {
      # Contact time is process-local and the pipe is pinned to the answering PID, so it postdates that process's start.
      $null = Wait-CmpgnState -What 'readiness and backend contact after the last restart' -Done { param($o)
        $script:ready = Read-CmpgnReadiness $o.svcPid; $script:ready.success -and $script:ready.lastBackendContactUtc }
      $rec.readiness = $script:ready
    } else { $rec.readiness = Read-CmpgnReadiness $final.svcPid }
    $rec.lastBackendContactUtc = $rec.readiness.lastBackendContactUtc
    if (-not $rec.result) { $rec.result = 'pass' }
  } catch {
    $rec.result = 'fail'; $rec.failureReason = $_.Exception.Message
  } finally {
    if ($hold) { try { $rec.fault.hold = Stop-CmpgnHold $hold } catch { $rec.result = 'fail'; $rec.failureReason += " | hold: $($_.Exception.Message)" } }
  }
  $rec.machineHealth = Test-CmpgnMachineHealth
  if (@($rec.machineHealth.Values | Where-Object { $_ -cne 'Running' }).Count -and $rec.result -cne 'fail') { $rec.result = 'fail'; $rec.failureReason = 'Machine health service not running.' }
  try {
    $since = $start.ToLocalTime(); $svc = Get-CimInstance Win32_Service -Filter "Name='$($Pinned.serviceName)'"
    $rec.scmCrashEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7031, 7034; StartTime = $since } -MaxEvents 64 -ErrorAction Stop |
      Where-Object { $_.Properties[0].Value -ceq $svc.DisplayName } | ForEach-Object { $_.TimeCreated.ToUniversalTime().ToString('o') })
  } catch { $rec.scmCrashEvents = @() }
  if ($cfg.backendQueryPerHop) { $rec.backendQuery = Invoke-CmpgnBackendQuery "hop$Hop" $script:deadline }
  $rec.recoveryEvents = $script:events; $rec.endedUtc = [DateTime]::UtcNow.ToString('o'); $rec.durationSec = [int]([DateTime]::UtcNow - $start).TotalSeconds
  Write-CmpgnRecord 'hops.jsonl' $rec
  $rec
}
