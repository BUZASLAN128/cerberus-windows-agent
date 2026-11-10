# Work rule 13 (AGENTS.md): no workflow may publish a GitHub release from a branch push.
# A workflow fails the guard when it can run after a push (push or workflow_run in its 'on' block, or no 'on' block this
# script can read) and can publish: no top-level permissions (the repository's default token writes), contents: write or
# write-all, a release command or action, or a reusable-workflow call. Only workflows GitHub lists as disabled pass.
# This is a text scan, not a YAML parser. Not detected: a publish through a token other than the workflow's own, whether
# from a called script or a command spelling not listed here. -WorkflowState skips the API (tests).
param([string]$Repository = $env:GITHUB_REPOSITORY, [string]$WorkflowDir = '', [hashtable]$WorkflowState = $null)
$ErrorActionPreference = 'Stop'
if (-not $WorkflowDir) { $WorkflowDir = Join-Path (Split-Path -Parent $PSScriptRoot) '.github/workflows' }
$disabled = 'disabled_manually', 'disabled_inactivity', 'disabled_fork'

function Test-WorkflowPublishesOnPush([string]$Text) {
  $Text = $Text -replace '[`\\]\r?\n\s*', ' '   # join shell continuation lines
  # The 'on' block runs to the next top-level key; any push or workflow_run inside it counts, in any YAML form.
  $on = [regex]::Match($Text, '(?ms)^["'']?on["'']?\s*:(.*?)(?=^["'']?[\w-]+["'']?\s*:|\z)')
  $onPush = -not $on.Success -or $on.Groups[1].Value -match '\b(push|workflow_run)\b'
  $write = '(-X[\s=]*|--method[ =])(POST|PATCH|PUT|DELETE)\b'
  $canPublish = $Text -notmatch '(?m)^permissions\s*:' -or $Text -match 'contents["'']?\s*:\s*["'']?write\b|\bwrite-all\b' -or
    $Text -match 'gh release (create|upload|edit|delete)|ncipollo/release-action|actions/create-release|softprops/action-gh-release|\b(createRelease|updateRelease|uploadReleaseAsset)\b|uses:\s*\S*\.github/workflows/' -or
    $Text -match "gh api\b[^\r\n]*($write[^\r\n]*/releases\b|/releases\b[^\r\n]*\s($write|-[fF]\s|--(raw-)?field\b|--input\b))" -or
    $Text -match 'curl\b[^\r\n]*/releases\b'
  return ($onPush -and $canPublish)
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
  if ($state.ContainsKey($rel) -and $state[$rel] -in $disabled) { Write-Host "$rel can publish on push but is $($state[$rel])."; continue }
  $bad.Add($rel)
}
if ($bad.Count) { throw "Workflows that are not disabled can publish a release on push: $($bad -join ', ')" }
Write-Host 'No workflow that can run on push and publish a release is enabled.'
