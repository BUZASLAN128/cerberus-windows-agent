#requires -Version 7.5
<#
  Protected launcher for invoke-update-campaign.ps1 (repo rule 10). Trusted entry:
    1. Open an elevated PowerShell 7 prompt yourself (Run as administrator); do not start it from another tool.
    2. Check out the frozen commit, then run this file from that checkout:
       pwsh -NoProfile -File <repo>\scripts\campaign\start-update-campaign.ps1 -Commit <40-hex> -ConfigPath <config.json>
         -ConfigSha256 <hex> -ArtifactsSha256 <hex> -HoldMsiSha256 <hex> -Step Bootstrap
       and later the same with -Step Hops. -InstallerBusyFallback is accepted only when a trial D1 receipt under the
       receipts root shows that 1618 could not be produced.
  It refuses unless its own bytes match the frozen commit, reads the runner and campaign-lib.ps1 from re-hashed git
  objects, copies each input into a new SYSTEM/Administrators-only custody folder, checks the copy against the SHA-256
  pinned by a parameter or by the hash-pinned config, and parses only the copy. Tools run from custody or
  System32/Program Files, always matching their pinned SHA-256; script interpreters are refused. A Basic User token must
  fail to create, overwrite or rename in custody. Receipts live in a fixed folder under ProgramData. #>
param(
  [Parameter(Mandatory)][ValidatePattern('^[0-9a-f]{40}$')][string]$Commit,
  [Parameter(Mandatory)][string]$ConfigPath,
  [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ConfigSha256,
  [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ArtifactsSha256,
  [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$HoldMsiSha256,
  [ValidateSet('Bootstrap', 'Hops', 'All')][string]$Step = 'All',
  [switch]$InstallerBusyFallback
)
$env:PSModulePath = Join-Path $PSHOME 'Modules'
$ErrorActionPreference = 'Stop'
$Step = @('Bootstrap', 'Hops', 'All') | Where-Object { $_ -ieq $Step } | Select-Object -First 1   # canonical casing, as in the runner
$Allowed = @('S-1-5-18', 'S-1-5-32-544')   # SYSTEM, Administrators
$Pinned = [ordered]@{ serviceName = 'CerberusServerAgent'; controlPipeName = 'CerberusServerAgent.Control.v1'
  privilegedUpdateRoot = 'C:\ProgramData\CerberusServerAgent\Privileged\Updates' }   # same values in the runner
$RunnerName = 'invoke-update-campaign.ps1'; $LibName = 'campaign-lib.ps1'; $SelfRel = 'scripts/campaign/start-update-campaign.ps1'
$CustodyRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'cerberus-campaign-custody'
$ReceiptsRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'cerberus-campaign-receipts'   # same in the runner
$Interpreters = @('pwsh', 'powershell', 'powershell_ise', 'cmd', 'python', 'python3', 'pythonw', 'py', 'pyw', 'wscript', 'cscript', 'bash', 'sh', 'wsl', 'node')
$FallbackReasons = @('hold_start_failed', 'agent_never_saw_1618_while_hold_running')
# A tool argument names a file when it holds a drive path (C:\ or C:/ anywhere, URLs excepted) or a UNC path, starts with
# .\ or ..\, / or ~ (also after =), or exists relative to here. Such an argument must be pinned in config.
$FileArgPattern = '[A-Za-z]:\\|[A-Za-z]:/(?!/)|\\\\|(^|[=@])\.{1,2}[\\/]|^\\|(^|=)[/~]'
$TrustedDirs = @([Environment]::GetFolderPath('System'), [Environment]::GetFolderPath('ProgramFiles')) | ForEach-Object { $_.TrimEnd('\') + '\' }
$Git = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Git\cmd\git.exe'
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run from an elevated prompt.' }
if (-not (Test-Path -LiteralPath $Git -PathType Leaf)) { throw "git was not found at $Git." }
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
function Get-CmpgnCustodyHash([string]$Path) { (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() }
function Get-CmpgnCustodyDigest([byte[]]$Bytes) { [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant() }
function Test-CmpgnCustodyTrusted([string]$Path) { $full = [IO.Path]::GetFullPath($Path); [bool]@($TrustedDirs | Where-Object { $full.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }).Count }
function Invoke-CmpgnCustodyGit([string[]]$GitArgs) {
  $psi = [Diagnostics.ProcessStartInfo]::new($Git)
  foreach ($a in @('-C', $repo) + $GitArgs) { $psi.ArgumentList.Add($a) }
  $psi.RedirectStandardOutput = $true; $psi.UseShellExecute = $false
  $p = [Diagnostics.Process]::Start($psi); $ms = [IO.MemoryStream]::new()
  $p.StandardOutput.BaseStream.CopyTo($ms); $p.WaitForExit()
  if ($p.ExitCode -ne 0) { throw "git $($GitArgs[0]) failed ($($p.ExitCode))." }
  , $ms.ToArray()
}
# Every object is re-hashed as "<type> <length>\0<content>", so a forged object store cannot pass.
function Get-CmpgnCustodyObject([string]$Type, [string]$Id) {
  $body = Invoke-CmpgnCustodyGit @('cat-file', $Type, $Id)
  $head = [Text.Encoding]::ASCII.GetBytes("$Type $($body.Length)`0")
  $all = [byte[]]::new($head.Length + $body.Length)
  [Array]::Copy($head, $all, $head.Length); [Array]::Copy($body, 0, $all, $head.Length, $body.Length)
  if ([Convert]::ToHexString([Security.Cryptography.SHA1]::HashData($all)).ToLowerInvariant() -cne $Id) { throw "git $Type $Id does not hash to its id." }
  , $body
}
function Get-CmpgnCustodyBlob([string]$Rel) {
  $commitText = [Text.Encoding]::UTF8.GetString((Get-CmpgnCustodyObject 'commit' $Commit))
  if ($commitText -cnotmatch '\Atree ([0-9a-f]{40})\n') { throw 'The commit object has no tree.' }
  $id = $Matches[1]; $parts = $Rel.Split('/')
  for ($k = 0; $k -lt $parts.Count; $k++) {
    $tree = Get-CmpgnCustodyObject 'tree' $id; $id = $null; $i = 0
    $want = if ($k -lt $parts.Count - 1) { @('40000') } else { @('100644', '100755') }
    while ($i -lt $tree.Length -and -not $id) {
      $sp = [Array]::IndexOf($tree, [byte]32, $i); $nul = [Array]::IndexOf($tree, [byte]0, $sp)
      if ($sp -lt 0 -or $nul -lt 0) { throw 'Malformed tree object.' }
      $mode = [Text.Encoding]::ASCII.GetString($tree, $i, $sp - $i)
      if ([Text.Encoding]::UTF8.GetString($tree, $sp + 1, $nul - $sp - 1) -ceq $parts[$k] -and $mode -cin $want) {
        $id = [Convert]::ToHexString($tree, $nul + 1, 20).ToLowerInvariant()
      }
      $i = $nul + 21
    }
    if (-not $id) { throw "$Rel is not in commit $Commit." }
  }
  Get-CmpgnCustodyObject 'blob' $id
}
# The checkout may have CRLF line ends (core.autocrlf); compare raw bytes and LF-normalised bytes.
function Test-CmpgnCustodySame([byte[]]$Blob, [string]$Path) {
  $raw = [IO.File]::ReadAllBytes($Path); $latin = [Text.Encoding]::Latin1
  $norm = $latin.GetBytes($latin.GetString($raw).Replace("`r`n", "`n"))
  $want = Get-CmpgnCustodyDigest $Blob
  (Get-CmpgnCustodyDigest $raw) -ceq $want -or (Get-CmpgnCustodyDigest $norm) -ceq $want
}
function Assert-CmpgnCustodyAcl([string]$Path) {
  $item = Get-Item -LiteralPath $Path -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$Path is a reparse point." }
  $acl = Get-Acl -LiteralPath $Path
  if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $Allowed) { throw "$Path has an untrusted owner." }
  if (-not $acl.AreAccessRulesProtected) { throw "$Path inherits permissions." }
  foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Value -notin $Allowed) { throw "$Path grants access to $($r.IdentityReference.Value)." }
  }
}
# Created with its final owner and protected DACL in one call; an existing folder must already be protected.
function New-CmpgnCustodyDir([string]$Path) {
  if (-not [IO.Directory]::Exists($Path)) {
    $sec = [Security.AccessControl.DirectorySecurity]::new()
    $sec.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
    $sec.SetAccessRuleProtection($true, $false)
    foreach ($sid in $Allowed) {
      $sec.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
    }
    $null = [IO.FileSystemAclExtensions]::CreateDirectory($sec, $Path)
  }
  Assert-CmpgnCustodyAcl $Path
}
# A Basic User (restricted) token tries to create, overwrite and rename in custody, then writes a marker where it may
# write. The marker proves the probe ran, so a probe that never started cannot pass as a denial.
function Test-CmpgnCustodyDenial([string]$Custody, [string]$Runner) {
  $control = Join-Path ([IO.Path]::GetTempPath()) ('cmpgn-probe-' + [Guid]::NewGuid().ToString('N'))
  $denied = Join-Path $Custody 'restricted-probe.txt'; $ran = Join-Path $control 'probe-ran.txt'
  $runnerLeaf = 'probe-renamed.ps1'; $custodyLeaf = (Split-Path -Leaf $Custody) + '-probe'; $before = Get-CmpgnCustodyHash $Runner
  if ("$denied$ran$Runner" -match '\s') { throw 'Probe paths must not contain spaces.' }
  $cmd = "cmd.exe /d /c (echo x>$denied) & (echo x>$Runner) & (ren $Runner $runnerLeaf) & (ren $Custody $custodyLeaf) & echo ok>$ran"
  $null = New-Item -ItemType Directory -Path $control
  try {
    Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\runas.exe') -ArgumentList @('/trustlevel:0x20000', "`"$cmd`"") -WindowStyle Hidden -Wait
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while (-not (Test-Path -LiteralPath $ran) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 250 }
    $result = [ordered]@{ probeRan = (Test-Path -LiteralPath $ran); trustLevel = '0x20000'; created = (Test-Path -LiteralPath $denied)
      runnerOverwritten = (-not (Test-Path -LiteralPath $Runner)) -or (Get-CmpgnCustodyHash $Runner) -cne $before
      runnerRenamed = (Test-Path -LiteralPath (Join-Path $Custody $runnerLeaf))
      custodyRenamed = (-not (Test-Path -LiteralPath $Custody)) -or (Test-Path -LiteralPath (Join-Path $CustodyRoot $custodyLeaf)) }
  } finally { Remove-Item -LiteralPath $ran -ErrorAction SilentlyContinue; Remove-Item -LiteralPath $control -ErrorAction SilentlyContinue }
  if (-not $result.probeRan) { throw 'Restricted-token probe did not run; denial is not proven.' }
  foreach ($k in 'created', 'runnerOverwritten', 'runnerRenamed', 'custodyRenamed') { if ($result[$k]) { throw "A restricted token could change custody ($k)." } }
  $result
}
if (-not (Test-CmpgnCustodySame (Get-CmpgnCustodyBlob $SelfRel) $PSCommandPath)) { throw 'This launcher differs from the frozen commit.' }
New-CmpgnCustodyDir $CustodyRoot
$custody = Join-Path $CustodyRoot ([DateTime]::UtcNow.ToString('yyyyMMddHHmmss') + "-$($Step.ToLowerInvariant())-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
if (Test-Path -LiteralPath $custody) { throw 'Custody folder already exists.' }
New-CmpgnCustodyDir $custody
$files = [ordered]@{}
# Copy first, then hash the copy against its pinned SHA-256; only the custody copy is ever parsed or executed.
function Copy-CmpgnCustodyInput([string]$Name, [string]$Source, [string]$Expected) {
  if (-not $Source -or -not [IO.Path]::IsPathFullyQualified($Source)) { throw "$Name needs an absolute source path." }
  if ($Expected -notmatch '\A[0-9a-fA-F]{64}\z') { throw "$Name has no pinned SHA-256." }
  $dest = Join-Path $custody $Name
  Copy-Item -LiteralPath $Source -Destination $dest
  $actual = Get-CmpgnCustodyHash $dest
  if ($actual -cne $Expected.ToLowerInvariant()) { throw "$Name does not match its pinned SHA-256." }
  $files[$Name] = [ordered]@{ source = $Source; expected = $Expected.ToLowerInvariant(); actual = $actual }
  $dest
}
# The runner and its functions come from the commit's re-hashed blobs, never from the checkout.
foreach ($name in $RunnerName, $LibName) {
  $bytes = Get-CmpgnCustodyBlob "scripts/campaign/$name"; $dest = Join-Path $custody $name
  [IO.File]::WriteAllBytes($dest, $bytes)
  $files[$name] = [ordered]@{ source = "$Commit`:scripts/campaign/$name"; expected = (Get-CmpgnCustodyDigest $bytes); actual = (Get-CmpgnCustodyHash $dest) }
  if ($files[$name].expected -cne $files[$name].actual) { throw "$name copy differs from the commit blob." }
}
$runner = Join-Path $custody $RunnerName
$cfg = Get-Content -LiteralPath (Copy-CmpgnCustodyInput 'campaign-config.json' $ConfigPath $ConfigSha256) -Raw | ConvertFrom-Json -DateKind String
foreach ($k in $Pinned.Keys) { if (-not [string]::Equals([string]$cfg.$k, $Pinned[$k], [StringComparison]::OrdinalIgnoreCase)) { throw "Config $k must be $($Pinned[$k])." } }
if ($cfg.mode -cnotin 'trial', 'counted') { throw 'Config mode must be trial or counted.' }
if (-not $cfg.feed.publishCommand) { throw 'Config feed.publishCommand is missing.' }
if ($null -ne $cfg.receiptsRoot -and -not [string]::Equals([string]$cfg.receiptsRoot, $ReceiptsRoot, [StringComparison]::OrdinalIgnoreCase)) { throw "Config receiptsRoot must be omitted or be $ReceiptsRoot." }
$camp = Get-Content -LiteralPath (Copy-CmpgnCustodyInput 'campaign-artifacts.json' ([string]$cfg.campaignArtifactsPath) $ArtifactsSha256) -Raw | ConvertFrom-Json -DateKind String
$cid = [string]$camp.campaignId
if ($cid -notmatch '\A[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\z') { throw 'campaign-artifacts.json has no campaign id.' }
if ($camp.source -cne $Commit) { throw 'Campaign packages were built from another commit.' }
$arts = @($camp.artifacts)
foreach ($a in $arts) { if ([string]$a.version -cnotmatch '\A[0-9]+\.[0-9]+\.[0-9]+\z') { throw 'campaign-artifacts.json has an invalid version string.' } }
if ($arts.Count -ne [int]$camp.packageCount -or ($cfg.mode -ceq 'counted' -and $arts.Count -ne 11) -or ($cfg.mode -ceq 'trial' -and $arts.Count -lt 5)) {
  throw "A counted campaign needs all 11 packages, a trial at least 5; this one has $($arts.Count)."
}
$ti = [int]$cfg.targetIndex
if ($ti -lt 0 -or $ti -ge @($arts[0].manifests).Count) { throw 'Config targetIndex is outside the campaign targets.' }
# Same digest as the runner's targetIdHash: first 16 hex digits of SHA-256 over the tagged agent id.
$targetHash = (Get-CmpgnCustodyDigest ([Text.Encoding]::UTF8.GetBytes('cerberus-campaign-target:' + $arts[0].manifests[$ti].agentId))).Substring(0, 16)
$null = Copy-CmpgnCustodyInput 'hold-installer.msi' ([string]$cfg.holdInstallerPath) $HoldMsiSha256
if ($cfg.feed.rootCertFile) { $null = Copy-CmpgnCustodyInput 'feed-root.cer' ([string]$cfg.feed.rootCertFile) ([string]$cfg.feed.rootCertSha256) }
# Files named in tool arguments are pinned in config (toolFiles), copied into custody, and the argument points at the copy.
$argFiles = @{}; $n = 0
foreach ($tf in @($cfg.toolFiles)) {
  if (-not $tf) { continue }
  $n++; $copy = Copy-CmpgnCustodyInput ("toolfile-$n" + [IO.Path]::GetExtension([string]$tf.path)) ([string]$tf.path) ([string]$tf.sha256)
  $argFiles[[IO.Path]::GetFullPath([string]$tf.path)] = $copy
}
function Convert-CmpgnCustodyArg([string]$Tool, [string]$Arg) {
  $cut = if ($Arg.StartsWith('@')) { 1 } else { $Arg.IndexOf('=') + 1 }
  $prefix = $Arg.Substring(0, $cut); $file = $Arg.Substring($cut)
  if (-not ($Arg -match $FileArgPattern -or ($file -and (Test-Path -LiteralPath $file)) -or ($Arg -and (Test-Path -LiteralPath $Arg)))) { return $Arg }
  $key = if ([IO.Path]::IsPathFullyQualified($file)) { [IO.Path]::GetFullPath($file) }
  if (-not $key -or -not $argFiles.ContainsKey($key)) { throw "Tool $Tool argument names a file that campaign-config.json toolFiles does not pin: $Arg" }
  $prefix + $argFiles[$key]
}
$tools = [ordered]@{}
$toolCommands = [ordered]@{ publish = $cfg.feed.publishCommand; rename = $cfg.feed.renameCommand; backendQuery = $cfg.backendQueryCommand }
foreach ($name in $toolCommands.Keys) {
  $command = @($toolCommands[$name]); $exe = [string]$command[0]
  if (-not $exe) { continue }
  if (-not [IO.Path]::IsPathFullyQualified($exe)) { throw "Tool $name needs an absolute path." }
  if ([IO.Path]::GetExtension($exe) -ine '.exe' -or [IO.Path]::GetFileNameWithoutExtension($exe) -iin $Interpreters) { throw "Tool $name must be a program, not a script or script interpreter: $exe" }
  $expected = ([string]$cfg.toolSha256.$name).ToLowerInvariant()
  $toolArgs = @(foreach ($x in @($command | Select-Object -Skip 1)) { Convert-CmpgnCustodyArg $name ([string]$x) })
  if (Test-CmpgnCustodyTrusted $exe) {
    # System32/Program Files tools run in place (they may need their own folder) but must match the pinned hash too.
    if ($expected -notmatch '\A[0-9a-f]{64}\z') { throw "Tool $name has no pinned SHA-256 (toolSha256.$name)." }
    $actual = Get-CmpgnCustodyHash $exe
    if ($actual -cne $expected) { throw "Tool $name does not match its pinned SHA-256." }
    $tools[$name] = [ordered]@{ path = $exe; location = 'system'; expected = $expected; actual = $actual; args = $toolArgs }
  } else {
    $copy = Copy-CmpgnCustodyInput "tool-$name.exe" $exe $expected
    $tools[$name] = [ordered]@{ path = $copy; location = 'custody'; source = $exe; expected = $expected; actual = $files["tool-$name.exe"].actual; args = $toolArgs }
  }
}
New-CmpgnCustodyDir $ReceiptsRoot
$receipts = Join-Path $ReceiptsRoot $cid
New-CmpgnCustodyDir $receipts
$fallback = $null
if ($InstallerBusyFallback) {
  $holdHash = $files['hold-installer.msi'].actual
  foreach ($d in Get-ChildItem -LiteralPath $ReceiptsRoot -Directory) {
    $hops = Join-Path $d.FullName 'hops.jsonl'
    if (-not (Test-Path -LiteralPath $hops)) { continue }
    try { Assert-CmpgnCustodyAcl $d.FullName } catch { continue }
    # Only a trial D1 of this commit, target and hold MSI that could not deliver 1618 for a qualifying reason.
    $hit = Get-Content -LiteralPath $hops | ForEach-Object { ConvertFrom-Json -InputObject $_ -DateKind String } |
      Where-Object { $_.mode -ceq 'trial' -and $_.index -eq 1 -and $_.fault.kind -ceq 'installer-busy-1618' -and $_.fault.delivered -eq $false -and
        $_.fault.notDeliveredReason -cin $FallbackReasons -and $_.candidateHead -ceq $Commit -and $_.targetIdHash -ceq $targetHash -and $_.holdMsiSha256 -ceq $holdHash } |
      Select-Object -First 1
    if ($hit) { $fallback = [ordered]@{ evidenceCampaignId = $d.Name; receipt = $hops; reason = $hit.fault.notDeliveredReason; failureReason = $hit.failureReason }; break }
  }
  if (-not $fallback) { throw 'No trial D1 receipt for this commit, target and hold MSI shows that 1618 could not be produced; -InstallerBusyFallback is refused.' }
}
$probe = Test-CmpgnCustodyDenial $custody $runner
foreach ($f in $files.GetEnumerator()) { if ((Get-CmpgnCustodyHash (Join-Path $custody $f.Key)) -cne $f.Value.actual) { throw "Custody file changed: $($f.Key)" } }
[ordered]@{ commit = $Commit; campaignId = $cid; step = $Step; custody = $custody; receipts = $receipts
  git = [ordered]@{ path = $Git; sha256 = (Get-CmpgnCustodyHash $Git) }; files = $files; tools = $tools
  installerBusyFallback = $fallback; restrictedTokenProbe = $probe; launchedUtc = [DateTime]::UtcNow.ToString('o')
} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $custody 'launch.json') -Encoding utf8
$argv = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $runner, '-Step', $Step)
if ($InstallerBusyFallback) { $argv += '-InstallerBusyFallback' }
Set-Location -LiteralPath $custody
& (Join-Path $PSHOME 'pwsh.exe') @argv
exit $LASTEXITCODE
