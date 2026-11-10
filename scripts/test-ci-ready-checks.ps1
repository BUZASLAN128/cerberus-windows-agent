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
# Fail closed: paths outside the short non-agent list count, including release inputs outside src/ and scripts/.
foreach ($f in 'docs/legal/PRIVACY-NOTICE.md', 'tests/fixtures/agent-command-test-anchors.b64', 'Cerberus.WindowsAgent.slnx',
               'Directory.Packages.props', '.github/workflows/release.yml', '.editorconfig') {
  Check "$f is an agent change" { (Get-Status @($f)) -match 'Ajan tamam: hayır' }
}
Check 'a file moved from src/ to tests/ counts by its old path' { (Get-Status @('tests/Moved.cs', 'src/Cerberus.Agent.Core/Moved.cs')) -match 'Ajan tamam: hayır' }
Check 'a 3000-file listing counts as an update change' { (Get-Status @(1..3000 | ForEach-Object { "docs/f$_.md" })) -match 'NOT RUN \(gerekli' }

$guard = Join-Path $PSScriptRoot 'test-no-release-on-push.ps1'
$dir = Join-Path ([IO.Path]::GetTempPath()) "ready-guard-$PID"
function Test-Guard([string]$Yaml, [hashtable]$State = @{}) {
  Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
  $null = New-Item -ItemType Directory -Path $dir
  Set-Content -LiteralPath (Join-Path $dir 'w.yml') -Value $Yaml
  try { & $guard -WorkflowDir $dir -WorkflowState $State *> $null; return 'pass' } catch { return 'fail' }
}
# Read-only token in the shared job header, so these fixtures exercise the release-command patterns.
$job = "permissions:`n  contents: read`njobs:`n  p:`n    runs-on: ubuntu-latest`n    steps:`n"
Check 'block push + gh release create fails' { (Test-Guard "on:`n  push:`n    branches: [dev]`n$job      - run: gh release create v1") -eq 'fail' }
Check 'inline on: push + release-action fails' { (Test-Guard "on: push`n$job      - uses: ncipollo/release-action@v1") -eq 'fail' }
Check 'on: [push, pull_request] + create-release fails' { (Test-Guard "on: [push, pull_request]`n$job      - uses: actions/create-release@v1") -eq 'fail' }
Check 'flow-map push trigger fails' { (Test-Guard "on:`n  pull_request:`n  push: {branches: [dev]}`n$job      - run: gh release upload v1 a.zip") -eq 'fail' }
Check 'list push trigger fails' { (Test-Guard "on:`n  - push`n$job      - uses: softprops/action-gh-release@v2") -eq 'fail' }
Check 'gh api with -X after the path fails' { (Test-Guard "on: push`n$job      - run: gh api repos/o/r/releases -X POST -f tag_name=v1") -eq 'fail' }
Check 'disabled publishing workflow passes' { (Test-Guard "on:`n  push:`n$job      - run: gh release create v1" @{ '.github/workflows/w.yml' = 'disabled_manually' }) -eq 'pass' }
Check 'push: true input is not a trigger' { (Test-Guard "on: pull_request`n$job      - uses: docker/build-push-action@v6`n        with:`n          push: true`n      - run: gh release create v1") -eq 'pass' }
Check 'reading releases is not publishing' { (Test-Guard "on:`n  push:`n$job      - run: gh api repos/o/r/releases/latest") -eq 'pass' }
Check 'read-only push workflow passes' { (Test-Guard "on: push`n$job      - run: echo hi") -eq 'pass' }
Check 'push workflow without a permissions block fails' { (Test-Guard "on: push`njobs:`n  p:`n    runs-on: x`n    steps:`n      - run: echo hi") -eq 'fail' }
Check 'job-level contents: write fails' { (Test-Guard "on: push`npermissions: {}`njobs:`n  p:`n    permissions:`n      contents: write`n    runs-on: x`n    steps:`n      - run: echo hi") -eq 'fail' }
Check 'an unknown state such as deleted is not disabled' { (Test-Guard "on: push`n$job      - run: gh release create v1" @{ '.github/workflows/w.yml' = 'deleted' }) -eq 'fail' }
Check 'workflow_run trigger fails' { (Test-Guard "on:`n  workflow_run:`n    workflows: [windows-agent-ci]`n$job      - run: gh release create v1") -eq 'fail' }
Check 'quoted on with a flow map and github-script fails' { (Test-Guard "`"on`": {push: {branches: [dev]}}`n$job      - uses: actions/github-script@v7`n        with:`n          script: github.rest.repos.createRelease({})") -eq 'fail' }
Check 'gh api releases with -f fails' { (Test-Guard "on: push`n$job      - run: gh api repos/o/r/releases -f tag_name=v1") -eq 'fail' }
Check 'multi-line gh api fails' { (Test-Guard "on: push`n$job      - run: |`n          gh api repos/o/r/releases \`n            -X POST") -eq 'fail' }
Check 'reusable workflow call on push fails' { (Test-Guard "on: push`npermissions:`n  contents: read`njobs:`n  r:`n    uses: ./.github/workflows/release.yml") -eq 'fail' }
Check 'column-0 trigger list fails' { (Test-Guard "on:`n- push`n- pull_request`n$job      - run: gh release create v1") -eq 'fail' }
Check 'blank line before a trigger list fails' { (Test-Guard "on:`n`n- push`n$job      - run: gh release create v1") -eq 'fail' }
Check 'flow list continued at column 0 fails' { (Test-Guard "on: [`npull_request,`npush`n]`n$job      - run: gh release create v1") -eq 'fail' }
Check 'column-0 list without push passes' { (Test-Guard "on:`n- pull_request`n$job      - run: gh release create v1") -eq 'pass' }
Check 'quoted contents: write fails' { (Test-Guard "on: push`npermissions:`n  `"contents`": `"write`"`njobs:`n  p:`n    runs-on: x`n    steps:`n      - run: ./scripts/publish.ps1") -eq 'fail' }
Check 'gh api -X=POST fails' { (Test-Guard "on: push`n$job      - run: gh api -X=POST repos/o/r/releases") -eq 'fail' }
Check 'push outside the on block is not a trigger' { (Test-Guard "on: pull_request`n$job      - run: gh release create v1`n        with:`n          modes:`n            - push") -eq 'pass' }
Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue

if ($failures.Count) { throw "CI ready-check fixtures failed: $($failures -join '; ')" }
Write-Host 'CI ready-check fixtures passed.'
