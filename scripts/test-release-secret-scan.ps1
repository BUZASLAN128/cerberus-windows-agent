# Support-tier checks for Invoke-SecretScan in scripts/release-publish-lib.ps1: the WiX attribute
# Password="yes"/"no" is not a secret; any other quoted password value and real key material still are.
# Files are written to a fresh folder under -WorkRoot. Exit code = number of failed checks.
param([string]$WorkRoot = (Join-Path ([System.IO.Path]::GetTempPath()) "cerberus-secret-scan-test"))
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "release-publish-lib.ps1")

$work = Join-Path $WorkRoot ([guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work | Out-Null

try {
  # Fixture text is assembled at run time so this file itself does not match the repo-wide scan.
  $pw = "Pass" + "word"
  $cases = [ordered]@{
    "wix-yes"        = @{ Text = "<Edit Id=`"Pin`" $pw=`"yes`" />"; Hit = $false }
    "single-no"      = @{ Text = "$($pw.ToLower())='no'"; Hit = $false }
    "plain-hunter2"  = @{ Text = "$($pw.ToLower())=`"hunter2`""; Hit = $true }
    "yes-suffix"     = @{ Text = "<Edit $pw=`"yes1`" />"; Hit = $true }
    "no-secret"      = @{ Text = "$($pw.ToLower())=`"no-secret`""; Hit = $true }
    "Yes123"         = @{ Text = "$pw=`"Yes123`""; Hit = $true }
    "refresh-token"  = @{ Text = "refresh_" + "token: `"abc`""; Hit = $true }
    "mismatched-yes" = @{ Text = "$($pw.ToLower())=`"yes'"; Hit = $true }
    "json-password"  = @{ Text = "{ `"$($pw.ToLower())`": `"x`" }"; Hit = $true }
    "private-key"    = @{ Text = "-----BEGIN RSA PRIV" + "ATE KEY-----"; Hit = $true }
  }
  foreach ($name in $cases.Keys) {
    Set-Content -LiteralPath (Join-Path $work "$name.txt") -Value $cases[$name].Text -Encoding utf8
  }

  $hits = @(Invoke-SecretScan -Path $work | ForEach-Object { [System.IO.Path]::GetFileNameWithoutExtension($_) })
  $failures = 0
  foreach ($name in $cases.Keys) {
    $isHit = $hits -contains $name
    if ($isHit -eq $cases[$name].Hit) { Write-Host "ok   $name" } else { Write-Host "FAIL $name (hit=$isHit)"; $failures++ }
  }
} finally {
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "release secret scan: $($cases.Count - $failures)/$($cases.Count) passed, $failures failed"
exit $failures
