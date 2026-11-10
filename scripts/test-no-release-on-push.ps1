# Work rule 13 (AGENTS.md): no workflow may publish a GitHub release from a branch push.
# Fails when a workflow that is active, or not yet known to GitHub (new in this branch), has a push trigger and a
# release-publishing command. Disabled workflows are reported, not failed.
param([string]$Repository = $env:GITHUB_REPOSITORY)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

$state = @{}
$rows = gh api "repos/$Repository/actions/workflows" --paginate --jq '.workflows[] | "\(.path)\t\(.state)"'
if ($LASTEXITCODE -ne 0) { throw 'Could not list the repository workflows.' }
foreach ($row in $rows) { $path, $s = $row -split "`t", 2; $state[$path] = $s }

$publishing = 'gh release (create|upload|edit)|action-gh-release|repos/[^ ]+/releases'
$bad = [Collections.Generic.List[string]]::new()
foreach ($file in Get-ChildItem -LiteralPath (Join-Path $repoRoot '.github/workflows') -File | Where-Object { $_.Extension -in '.yml', '.yaml' }) {
  $rel = ".github/workflows/$($file.Name)"
  $text = Get-Content -LiteralPath $file.FullName -Raw
  if ($text -notmatch '(?m)^\s+push:' -or $text -notmatch $publishing) { continue }
  if ($state.ContainsKey($rel) -and $state[$rel] -ne 'active') { Write-Host "$rel publishes on push but is $($state[$rel])."; continue }
  $bad.Add($rel)
}
if ($bad.Count) { throw "Active workflows publish a release on push: $($bad -join ', ')" }
Write-Host 'No active workflow publishes a release on push.'
