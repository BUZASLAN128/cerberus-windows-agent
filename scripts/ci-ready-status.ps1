# Posts (or updates) one PR comment with the Work Rules stage table (AGENTS.md) for the head CI just checked.
# CI fills the rows it can run; VM smoke, signing, 10+10, return/feed and publication stay NOT RUN here.
param(
  [Parameter(Mandatory)][string]$Repository, [Parameter(Mandatory)][int]$PullRequest,
  [Parameter(Mandatory)][string]$HeadSha, [Parameter(Mandatory)][string]$RunUrl,
  [hashtable]$Outcomes = @{}, [string[]]$ChangedFiles = $null, [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
$marker = '<!-- cerberus-agent-ready-status -->'

function Get-Mark([string]$Outcome) {
  switch ($Outcome) { 'success' { 'PASS' } 'failure' { 'FAIL' } default { 'NOT RUN' } }
}

if ($null -eq $ChangedFiles) {
  $ChangedFiles = @(gh api "repos/$Repository/pulls/$PullRequest/files" --paginate --jq '.[].filename')
  if ($LASTEXITCODE -ne 0) { throw 'Could not list the changed files.' }
}
# Agent code, packaging or build inputs; update-affecting = updater, installer, service, update code, release tooling.
$agentChange = @($ChangedFiles | Where-Object { $_ -match '^src/|^scripts/(build-agent-|release-)|^Directory\.Build\.(props|targets)$|^global\.json$' })
$updateChange = @($ChangedFiles | Where-Object {
  $_ -match '^src/Cerberus\.Agent\.(Updater|Installer|Service)/|^src/[^/]+/.*Update[^/]*$|^scripts/(build-agent-|release-)|^Directory\.Build\.props$' })

$ci = [ordered]@{
  'Build ve testler'                 = Get-Mark $Outcomes.tests
  'Updater kurtarma testleri'        = Get-Mark $Outcomes.updateTests
  'İmzasız desktop/server MSI ve setup' = Get-Mark $Outcomes.packages
  'Release gate (lab metadata yok)'  = Get-Mark $Outcomes.releaseGate
  "Dev push'unda yayın yok"          = Get-Mark $Outcomes.publishGuard
}
$lines = @('## Ajan hazırlık durumu', "Head ``$HeadSha`` · [CI çalışması ve imzasız paketler]($RunUrl)", '', '| Aşama | Durum |', '|---|---|')
foreach ($k in $ci.Keys) { $lines += "| $k | $($ci[$k]) |" }
$failed = @($ci.Keys | Where-Object { $ci[$_] -ne 'PASS' })
if ($agentChange.Count) {
  $tenTen = if ($updateChange.Count) { 'NOT RUN (gerekli: güncellemeyi etkileyen değişiklik)' } else { 'gerekli değil' }
  $lines += '| VM106 smoke | NOT RUN |', '| İmza | NOT RUN |', "| PC n/10, VM n/10 | $tenTen |", '| Normal dönüş ve feed | NOT RUN |', '| Yayın | NOT RUN |', ''
  $missing = @($failed) + @('VM106 smoke', 'imza') + @(if ($updateChange.Count) { '10+10' }) + @('dönüş ve feed', 'yayın')
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
