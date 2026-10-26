# Multi-file token signing checks, dot-sourced by scripts/test-release-signing.ps1 (shares Check/Throws, $failures, $work, $thumbprint).
# Arguments only plus a recording stub in place of signtool; no token, certificate store or network.
Check "signtool batch: flags first in order, files last in the given order, one element per file" {
  $files = @("C:\x\a.exe", "C:\x y\b b.dll", "C:\x\c.msi")
  $a = @(Get-SignToolTokenSignArguments -Thumbprint $thumbprint -TimestampUrl "http://ts.example" -FilePath $files)
  $flags = @("sign", "/fd", "SHA256", "/td", "SHA256", "/tr", "http://ts.example", "/sha1", $thumbprint.ToUpperInvariant())
  $a.Count -eq ($flags.Count + 3) -and
    (($a[0..8] -join "`n") -ceq ($flags -join "`n")) -and
    (($a[9..11] -join "`n") -ceq ($files -join "`n"))
}
Check "signtool arguments: an empty file list fails closed" {
  Throws { Get-SignToolTokenSignArguments -Thumbprint $thumbprint -TimestampUrl "http://ts.example" -FilePath @() } "FilePath"
}
# Invoke-TokenFileSigning with a recording stub instead of signtool (no token, no certificate store)
$stubLog = Join-Path $work "signtool-calls.log"
$stubSigntool = Join-Path $work "stub-signtool.ps1"
Set-Content -LiteralPath $stubSigntool -Value @'
# A native exe receives an array argument as separate arguments; flatten the same way here.
$argv = @($args | ForEach-Object { $_ })
Add-Content -LiteralPath $env:STUB_SIGNTOOL_LOG -Value ($argv -join "|")
if ($argv[0] -eq "sign" -and $env:STUB_SIGNTOOL_SIGN_EXIT) { exit [int]$env:STUB_SIGNTOOL_SIGN_EXIT }
exit 0
'@
$env:STUB_SIGNTOOL_LOG = $stubLog
$tokenFiles = @("C:\x\a.exe", "C:\x y\b b.dll")
$script:pinChecked = @()
$originalPinCheck = (Get-Item -LiteralPath Function:\Assert-SignedFileSignerPin).ScriptBlock
function Assert-SignedFileSignerPin([string]$Path, [string[]]$AllowedPins) { $script:pinChecked += $Path }
try {
  Check "token signing: one sign call with all files, then one verify and pin check per file" {
    Remove-Item -LiteralPath $stubLog -ErrorAction SilentlyContinue; $script:pinChecked = @()
    Invoke-TokenFileSigning -SigntoolPath $stubSigntool -Thumbprint $thumbprint -TimestampUrl "http://ts.example" -FilePath $tokenFiles -AllowedPins @("sha256:" + ("ab" * 32)) 6>$null | Out-Null
    $calls = @(Get-Content -LiteralPath $stubLog)
    $calls.Count -eq 3 -and
      ($calls[0] -ceq ("sign|/fd|SHA256|/td|SHA256|/tr|http://ts.example|/sha1|" + $thumbprint.ToUpperInvariant() + "|" + ($tokenFiles -join "|"))) -and
      ($calls[1] -ceq "verify|/pa|/v|$($tokenFiles[0])") -and ($calls[2] -ceq "verify|/pa|/v|$($tokenFiles[1])") -and
      (($script:pinChecked -join "|") -ceq ($tokenFiles -join "|"))
  }
  Check "token signing: a failed sign call throws before any verify or pin check" {
    Remove-Item -LiteralPath $stubLog -ErrorAction SilentlyContinue; $script:pinChecked = @()
    $env:STUB_SIGNTOOL_SIGN_EXIT = "1"
    try {
      $threw = Throws { Invoke-TokenFileSigning -SigntoolPath $stubSigntool -Thumbprint $thumbprint -TimestampUrl "http://ts.example" -FilePath $tokenFiles -AllowedPins @("sha256:" + ("ab" * 32)) 6>$null } "Authenticode signing or verification failed"
    } finally { Remove-Item -LiteralPath Env:STUB_SIGNTOOL_SIGN_EXIT -ErrorAction SilentlyContinue }
    $threw -and @(Get-Content -LiteralPath $stubLog).Count -eq 1 -and $script:pinChecked.Count -eq 0
  }
} finally {
  Set-Item -LiteralPath Function:\Assert-SignedFileSignerPin -Value $originalPinCheck
  Remove-Item -LiteralPath Env:STUB_SIGNTOOL_LOG -ErrorAction SilentlyContinue
}
