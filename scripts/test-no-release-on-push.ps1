# Work rule 13 (AGENTS.md): no workflow may publish a GitHub release from a branch push.
# Fails when a workflow that is active, or not yet known to GitHub (new in this branch), has a push trigger and a
# release-publishing step. Disabled workflows are reported, not failed. -WorkflowState skips the API (tests).
param([string]$Repository = $env:GITHUB_REPOSITORY, [string]$WorkflowDir = '', [hashtable]$WorkflowState = $null)
$ErrorActionPreference = 'Stop'
if (-not $WorkflowDir) { $WorkflowDir = Join-Path (Split-Path -Parent $PSScriptRoot) '.github/workflows' }

function Test-WorkflowPublishesOnPush([string]$Text) {
  # Block form "  push:" (no value), or inline "on: push" / "on: [push, ...]".
  $onPush = $Text -match '(?m)^\s+push:\s*(#.*)?$' -or $Text -match '(?m)^"?on"?:\s*(push\b|\[[^\]]*\bpush\b)'
  $publishes = $Text -match 'gh release (create|upload|edit)|ncipollo/release-action|actions/create-release|softprops/action-gh-release|gh api (-X|--method) (POST|PATCH)\b[^\r\n]*/releases'
  return ($onPush -and $publishes)
}

$state = $WorkflowState
if ($null -eq $state) {
  $state = @{}
  $rows = gh api "repos/$Repository/actions/workflows" --paginate --jq '.workflows[] | "\(.path)\t\(.state)"'
  if ($LASTEXITCODE -ne 0) { throw 'Could not list the repository workflows; publish guard not evaluated.' }
  foreach ($row in $rows) { $path, $s = $row -split "`t", 2; $state[$path] = $s }
}

$bad = [Collections.Generic.List[string]]::new()
foreach ($file in Get-ChildItem -LiteralPath $WorkflowDir -File | Where-Object { $_.Extension -in '.yml', '.yaml' }) {
  $rel = ".github/workflows/$($file.Name)"
  if (-not (Test-WorkflowPublishesOnPush (Get-Content -LiteralPath $file.FullName -Raw))) { continue }
  if ($state.ContainsKey($rel) -and $state[$rel] -ne 'active') { Write-Host "$rel publishes on push but is $($state[$rel])."; continue }
  $bad.Add($rel)
}
if ($bad.Count) { throw "Active workflows publish a release on push: $($bad -join ', ')" }
Write-Host 'No active workflow publishes a release on push.'
