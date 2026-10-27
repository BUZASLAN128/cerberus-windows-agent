# Test-anchor fixture detection and backend TLS anchor input checks, dot-sourced by scripts/test-release-signing.ps1
# before the fake-root case (shares Check, Throws and $work). Runs against the real tests/fixtures/agent-command-test-anchors.b64.
. (Join-Path $PSScriptRoot "release-profile-lib.ps1")
$anchorFixtureLines = @([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Get-Content -LiteralPath (Join-Path $repoRoot "tests/fixtures/agent-command-test-anchors.b64") -Raw).Trim())).Split("`n") |
  ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 })
function ConvertTo-AnchorList([string[]]$InnerLines) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($InnerLines -join "`n"))) }
Check "test anchors: a fixture line with embedded whitespace is still the fixture" {
  $padded = $anchorFixtureLines[0].Insert(8, " ").Insert(20, "`t")
  Test-CommandAnchorsAreTestFixture (ConvertTo-AnchorList @($padded))
}
Check "test anchors: a different anchor is not the fixture" {
  -not (Test-CommandAnchorsAreTestFixture (ConvertTo-AnchorList @([Convert]::ToBase64String([byte[]](1..64)))))
}
Check "test anchors: an undecodable line next to a fixture line still reports the fixture" {
  Test-CommandAnchorsAreTestFixture (ConvertTo-AnchorList @("!!not-base64!!", $anchorFixtureLines[0]))
}

# Backend TLS anchors: only whole certificates are embedded, read with the loader the agent uses.
function New-BackendAnchor([int]$FromDays = -1, [int]$ToDays = 365) {
  $rsa = [System.Security.Cryptography.RSA]::Create(2048)
  $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
    "CN=backend-anchor-test", $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
  return $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays($FromDays), [DateTimeOffset]::UtcNow.AddDays($ToDays))
}
function Write-AnchorFile([string]$Name, $Content) {
  $path = Join-Path $work $Name
  if ($Content -is [byte[]]) { [IO.File]::WriteAllBytes($path, $Content) } else { [IO.File]::WriteAllText($path, $Content) }
  return $path
}
function Get-AnchorEntries([string]$Path) { @((Get-BackendTrustAnchorsValue $Path 6>$null) -split '%2C' | Where-Object { $_ }) }
$anchorA = New-BackendAnchor
$anchorB = New-BackendAnchor
$anchorAB64 = [Convert]::ToBase64String($anchorA.RawData)
Check "backend anchors: no file argument embeds nothing" { (Get-BackendTrustAnchorsValue "") -eq "" }
Check "backend anchors: one PEM certificate" {
  $e = @(Get-AnchorEntries (Write-AnchorFile "one.pem" $anchorA.ExportCertificatePem()))
  $e.Count -eq 1 -and $e[0] -eq $anchorAB64
}
Check "backend anchors: two PEM certificates with text around them" {
  $e = @(Get-AnchorEntries (Write-AnchorFile "two.pem" ("subject=a`n" + $anchorA.ExportCertificatePem() + "`nsubject=b`n" + $anchorB.ExportCertificatePem())))
  $e.Count -eq 2 -and $e[0] -eq $anchorAB64 -and $e[1] -eq [Convert]::ToBase64String($anchorB.RawData)
}
Check "backend anchors: one DER certificate from a path relative to the current location" {
  $null = Write-AnchorFile "one.cer" $anchorA.RawData
  Push-Location -LiteralPath $work
  try { $e = @(Get-AnchorEntries "one.cer") } finally { Pop-Location }
  $e.Count -eq 1 -and $e[0] -eq $anchorAB64
}
Check "backend anchors: concatenated DER is rejected" {
  Throws { Get-BackendTrustAnchorsValue (Write-AnchorFile "two.cer" ([byte[]]($anchorA.RawData + $anchorB.RawData))) } "data after a certificate"
}
Check "backend anchors: a PFX is rejected" {
  Throws { Get-BackendTrustAnchorsValue (Write-AnchorFile "one.pfx" $anchorA.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)) } "not a certificate"
}
Check "backend anchors: a key block next to a certificate is rejected" {
  # Split so the release secret scan does not match this placeholder (no key material).
  $pem = $anchorA.ExportCertificatePem() + "`n-----BEGIN PRIV" + "ATE KEY-----`nMIIB`n-----END PRIV" + "ATE KEY-----`n"
  Throws { Get-BackendTrustAnchorsValue (Write-AnchorFile "with-key.pem" $pem) } "not a readable certificate"
}
Check "backend anchors: a malformed second PEM block is rejected" {
  $pemB = $anchorB.ExportCertificatePem()
  $pem = $anchorA.ExportCertificatePem() + "`n" + $pemB.Substring(0, 40) + "*" + $pemB.Substring(40)
  Throws { Get-BackendTrustAnchorsValue (Write-AnchorFile "bad-second.pem" $pem) } "not a readable certificate"
}
Check "backend anchors: an expired certificate is rejected" {
  Throws { Get-BackendTrustAnchorsValue (Write-AnchorFile "expired.cer" (New-BackendAnchor -FromDays -30 -ToDays -1).RawData) } "not valid at build time"
}
Check "backend anchors: a missing file is rejected" { Throws { Get-BackendTrustAnchorsValue (Join-Path $work "missing.cer") } "not found" }
Check "backend anchors: an anchor that expires within 60 days is embedded with a warning" {
  $out = @(Get-BackendTrustAnchorsValue (Write-AnchorFile "soon.cer" (New-BackendAnchor -ToDays 30).RawData) 3>&1 6>$null)
  @($out | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }).Count -eq 1 -and
    @($out | Where-Object { $_ -is [string] -and $_.Length -gt 100 }).Count -eq 1
}
