# Posts (or updates) one PR comment with the Work Rules stage table (AGENTS.md) for the head CI just checked.
# CI fills the rows it can run; the official unsigned build, VM smoke, signing, 10+10, return/feed and publication
# stay NOT RUN here. A run for a head that is no longer the PR head writes nothing.
param(
  [Parameter(Mandatory)][string]$Repository, [Parameter(Mandatory)][int]$PullRequest,
  [Parameter(Mandatory)][string]$HeadSha, [string]$BuildSha = '', [Parameter(Mandatory)][string]$RunUrl,
  [hashtable]$Outcomes = @{}, [string]$JobResult = 'success', [string[]]$ChangedFiles = $null, [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
$marker = '<!-- cerberus-agent-ready-status -->'

function Get-Mark([string]$Outcome) {
  switch ($Outcome) { 'success' { 'PASS' } 'failure' { 'FAIL' } default { 'NOT RUN' } }
}

if (-not $DryRun) {
  $live = gh api "repos/$Repository/pulls/$PullRequest" --jq .head.sha
  if ($LASTEXITCODE -ne 0) { throw 'Could not read the PR head.' }
  if ($live -ne $HeadSha) { Write-Host "PR head is $live, this run checked $HeadSha; status not written."; return }
}
if ($null -eq $ChangedFiles) {
  $ChangedFiles = @(gh api "repos/$Repository/pulls/$PullRequest/files" --paginate --jq '.[].filename')
  if ($LASTEXITCODE -ne 0) { throw 'Could not list the changed files.' }
}
# Fail closed: everything that builds or ships the agent counts, except tests and these CI check scripts.
$harness = '^tests/|^scripts/test-|^scripts/ci-ready-status\.ps1$'
$agentChange = @($ChangedFiles | Where-Object {
  $_ -notmatch $harness -and ($_ -match '^(src|scripts)/|^Directory\.Build\.(props|targets)$|^global\.json$|^\.github/workflows/auto-publish') })
$updateChange = @($agentChange | Where-Object {
  $_ -match '^src/Cerberus\.Agent\.(Updater|Installer|Service)/|^src/.*(Update|Version|Channel|Installer|ServiceImage|Manifest|Trust)|^scripts/|^Directory\.Build\.props$|^\.github/workflows/' })

$ci = [ordered]@{
  'Build ve testler'                  = Get-Mark $Outcomes.tests
  'Updater kurtarma testleri'         = Get-Mark $Outcomes.updateTests
  'CI inceleme paketleri (imzasız MSI ve setup)' = Get-Mark $Outcomes.packages
  'Release gate (lab metadata yok)'   = Get-Mark $Outcomes.releaseGate
  "Dev push'unda yayın yok"           = Get-Mark $Outcomes.publishGuard
}
# The build job failed on a step without its own row (the publish guard runs in another job).
$buildRows = @($Outcomes.tests, $Outcomes.updateTests, $Outcomes.packages, $Outcomes.releaseGate)
if ($JobResult -notin 'success', 'skipped' -and $buildRows -notcontains 'failure') { $ci['Diğer CI adımları'] = 'FAIL' }
$buildNote = if ($BuildSha -and $BuildSha -ne $HeadSha) { " (CI birleştirme commit'i ``$BuildSha``)" } else { '' }
$lines = @('## Ajan hazırlık durumu', "Head ``$HeadSha``$buildNote · [CI çalışması ve paketler]($RunUrl)", '', '| Aşama | Durum |', '|---|---|')
foreach ($k in $ci.Keys) { $lines += "| $k | $($ci[$k]) |" }
$failed = @($ci.Keys | Where-Object { $ci[$_] -ne 'PASS' })
if ($agentChange.Count) {
  $tenTen = if ($updateChange.Count) { 'NOT RUN (gerekli: güncellemeyi etkileyebilecek değişiklik)' } else { 'NOT RUN (güncellemeyi etkiliyorsa gerekli)' }
  $lines += '| Resmi imzasız build (build-agent-public-release.ps1) | NOT RUN |', '| VM106 smoke | NOT RUN |', '| İmza | NOT RUN |',
    "| PC n/10, VM n/10 | $tenTen |", '| Normal dönüş ve feed | NOT RUN |', '| Yayın | NOT RUN |', ''
  $missing = @($failed) + @('resmi imzasız build', 'VM106 smoke', 'imza') + @(if ($updateChange.Count) { '10+10' } else { '10+10 (gerekiyorsa)' }) + @('dönüş ve feed', 'yayın')
  $lines += "**Ajan tamam: hayır.** Eksik: $($missing -join ', ')."
} else {
  $lines += '', 'Bu PR ajan kodunu ve paketlemeyi değiştirmiyor; ajanın durumu bu PR ile değişmez.'
  if ($failed.Count) { $lines += "CI eksik: $($failed -join ', ')." }
}
$lines += '', $marker
$body = $lines -join "`n"
if ($DryRun) { return $body }

$existing = @(gh api "repos/$Repository/issues/$PullRequest/comments" --paginate `
  --jq ".[] | select(.user.login == ""github-actions[bot]"" and (.body | contains(""$marker""))) | .id")
if ($LASTEXITCODE -ne 0) { throw 'Could not list the PR comments.' }
$payload = Join-Path ([IO.Path]::GetTempPath()) "ready-status-$PullRequest.json"
@{ body = $body } | ConvertTo-Json | Set-Content -LiteralPath $payload -Encoding utf8NoBOM
if ($existing.Count) { gh api -X PATCH "repos/$Repository/issues/comments/$($existing[-1])" --input $payload | Out-Null }
else { gh api -X POST "repos/$Repository/issues/$PullRequest/comments" --input $payload | Out-Null }
if ($LASTEXITCODE -ne 0) { throw 'Could not write the status comment.' }
