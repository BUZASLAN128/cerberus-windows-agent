#Requires -Version 7
# Invoke only against the final release candidate source at freeze.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'release-trust-lib.ps1')
$repoRoot = Split-Path -Parent $PSScriptRoot
$lockPath = Join-Path $repoRoot 'src/Cerberus.Agent.Update.Core/updater-contract.lock'
$version = Get-UpdaterSourceVersion $repoRoot
$fingerprint = Get-UpdaterSourceFingerprint $repoRoot
$lines = [IO.File]::ReadAllLines($lockPath)
foreach ($line in $lines) {
  if ($line.EndsWith(" $fingerprint", [StringComparison]::Ordinal)) {
    throw 'The updater source fingerprint has already been stamped.'
  }
}
Add-Content -LiteralPath $lockPath -Value "$version $fingerprint" -Encoding utf8
