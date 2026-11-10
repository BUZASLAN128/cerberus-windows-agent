# Fixture checks for the CI ready-status classification (ci-ready-status.ps1) and the publish guard
# (test-no-release-on-push.ps1). No network: both scripts run with fixture inputs.
$ErrorActionPreference = 'Stop'
$failures = [Collections.Generic.List[string]]::new()
function Check([string]$Name, [scriptblock]$Test) {
  try { if (-not (& $Test)) { $failures.Add($Name) } } catch { $failures.Add("$Name ($($_.Exception.Message))") }
}
function Get-Status([string[]]$Files, [hashtable]$Outcomes = @{ tests = 'success'; updateTests = 'success'; packages = 'success'; releaseGate = 'success'; publishGuard = 'success' }, [string]$JobResult = 'success') {
  & (Join-Path $PSScriptRoot 'ci-ready-status.ps1') -Repository o/r -PullRequest 1 -HeadSha h -RunUrl https://x -Outcomes $Outcomes -JobResult $JobResult -ChangedFiles $Files -DryRun
}

Check 'docs-only PR keeps the agent unchanged' { (Get-Status @('AGENTS.md', 'tests/X.cs', 'scripts/test-a.ps1')) -match 'ajanın durumu bu PR ile değişmez' }
Check 'CI workflow change is not an agent change' { (Get-Status @('.github/workflows/ci.yml')) -notmatch 'Ajan tamam' }
Check 'release workflow is an agent change' { (Get-Status @('.github/workflows/auto-publish-exe.yml')) -match '10\+10, ' }
foreach ($f in 'src/Cerberus.Agent.Updater/A.cs', 'src/Cerberus.Agent.Core/AgentVersionComparer.cs', 'src/Cerberus.Agent.Core/AgentInstallerInvocation.cs',
               'src/Cerberus.Agent.Core/BackendTrust.cs', 'scripts/resign-agent-update-manifest.ps1', 'scripts/update-lab.ps1', 'Directory.Build.props') {
  Check "$f requires 10+10" { (Get-Status @($f)) -match 'NOT RUN \(gerekli' }
}
Check 'other source change may need 10+10' { (Get-Status @('src/Cerberus.Agent.App/MainWindow.cs')) -match 'güncellemeyi etkiliyorsa gerekli' }
Check 'agent change always lists the official unsigned build' { (Get-Status @('src/Cerberus.Agent.App/MainWindow.cs')) -match 'Eksik: resmi imzasız build' }
Check 'failed job without a FAIL row is shown' { (Get-Status @('AGENTS.md') -JobResult 'failure') -match '\| Diğer CI adımları \| FAIL \|' }
Check 'failed step is listed first' { (Get-Status @('src/A.cs') -Outcomes @{ tests = 'failure' }) -match 'Eksik: Build ve testler' }
Check 'publish-guard FAIL does not hide a failed build job' {
  (Get-Status @('AGENTS.md') -Outcomes @{ tests = 'success'; updateTests = 'success'; packages = 'success'; releaseGate = 'skipped'; publishGuard = 'failure' } -JobResult 'failure') -match '\| Diğer CI adımları \| FAIL \|' }
Check 'update keyword in a folder name requires 10+10' { (Get-Status @('src/Cerberus.Agent.Core/Updates/Foo.cs')) -match 'NOT RUN \(gerekli' }

$guard = Join-Path $PSScriptRoot 'test-no-release-on-push.ps1'
$dir = Join-Path ([IO.Path]::GetTempPath()) "ready-guard-$PID"
function Test-Guard([string]$Yaml, [hashtable]$State = @{}) {
  Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
  $null = New-Item -ItemType Directory -Path $dir
  Set-Content -LiteralPath (Join-Path $dir 'w.yml') -Value $Yaml
  try { & $guard -WorkflowDir $dir -WorkflowState $State *> $null; return 'pass' } catch { return 'fail' }
}
$job = "jobs:`n  p:`n    runs-on: ubuntu-latest`n    steps:`n"
Check 'block push + gh release create fails' { (Test-Guard "on:`n  push:`n    branches: [dev]`n$job      - run: gh release create v1") -eq 'fail' }
Check 'inline on: push + release-action fails' { (Test-Guard "on: push`n$job      - uses: ncipollo/release-action@v1") -eq 'fail' }
Check 'on: [push, pull_request] + create-release fails' { (Test-Guard "on: [push, pull_request]`n$job      - uses: actions/create-release@v1") -eq 'fail' }
Check 'flow-map push trigger fails' { (Test-Guard "on:`n  pull_request:`n  push: {branches: [dev]}`n$job      - run: gh release upload v1 a.zip") -eq 'fail' }
Check 'list push trigger fails' { (Test-Guard "on:`n  - push`n$job      - uses: softprops/action-gh-release@v2") -eq 'fail' }
Check 'gh api with -X after the path fails' { (Test-Guard "on: push`n$job      - run: gh api repos/o/r/releases -X POST -f tag_name=v1") -eq 'fail' }
Check 'disabled publishing workflow passes' { (Test-Guard "on:`n  push:`n$job      - run: gh release create v1" @{ '.github/workflows/w.yml' = 'disabled_manually' }) -eq 'pass' }
Check 'push: true input is not a trigger' { (Test-Guard "on: pull_request`n$job      - uses: docker/build-push-action@v6`n        with:`n          push: true`n      - run: gh release create v1") -eq 'pass' }
Check 'reading releases is not publishing' { (Test-Guard "on:`n  push:`n$job      - run: gh api repos/o/r/releases/latest") -eq 'pass' }
Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue

if ($failures.Count) { throw "CI ready-check fixtures failed: $($failures -join '; ')" }
Write-Host 'CI ready-check fixtures passed.'
