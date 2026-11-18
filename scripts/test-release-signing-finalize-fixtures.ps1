  # Finalize (step 2): Complete-ExternalManifestSigning in-process against a fixture publish directory.
  # The signature check is replaced through the function's test seam; the build script never passes it.
  . (Join-Path $PSScriptRoot "test-release-signing-fixture.ps1")
  $keyListB64 = ConvertTo-ManifestPublicKeyListB64 @($pemA, $pemB)
  $assetBase = "Cerberus.Agent.Bundle-stable-9.9.9"
  $installerBase = "Cerberus.Agent-stable-9.9.9"
  $payloadName = "$assetBase.update-manifest.v2.payload.bin"
  $pendingName = "$assetBase.update-manifest.v2.pending.json"
  $manifestName = "$assetBase.update-manifest.v2.json"
  $gateName = "$assetBase.release-gate.json"
  $latestName = "Cerberus.Agent.Bundle-stable-latest.update-manifest.v2.json"
  $sigFile = Join-Path $work "manifest.sig"
  function New-Fixture([string]$Dir = "", [hashtable]$Options = @{}, [string[]]$Keys = @()) {
    if ([string]::IsNullOrWhiteSpace($Dir)) { $Dir = Join-Path $work ("pub-" + [guid]::NewGuid().ToString("N").Substring(0, 8)) }
    $fixtureKeys = if ($Keys.Count -gt 0) { $Keys } else { $keyListB64 }
    New-FinalizeFixture -PublishDir $Dir -UpdaterVerifierDll $CoreDll -KeyListB64 $fixtureKeys -SignerPin $pin -Prefix $prefix @Options
  }
  function Write-FixtureSignature($Fixture, [string]$Signature = "") {
    if ([string]::IsNullOrEmpty($Signature)) { $Signature = Sign-ManifestPayloadWithCertificate -CanonicalPayload $Fixture.Canonical -Certificate $certB }
    if ($Signature -eq "<none>") { Remove-Item -LiteralPath $sigFile -ErrorAction SilentlyContinue } else { Set-Content -LiteralPath $sigFile -Value $Signature }
  }
  function Invoke-Finalize($Fixture, [scriptblock]$SignatureCheck, [string]$Version = "9.9.9", [string]$Signature = "", [string]$KeyFile = $keyB, [string]$Channel = "stable", [scriptblock]$PayloadCheck = {}) {
    Write-FixtureSignature $Fixture $Signature
    Complete-ExternalManifestSigning -PublishDir $Fixture.Publish -Channel $Channel -Version $Version -AssetBase $assetBase -InstallerBase $installerBase `
      -SignaturePath $sigFile -PublicKeyPath $KeyFile -FileSignatureCheck $SignatureCheck -SetupPayloadCheck $PayloadCheck 6>$null | Out-Null
  }
  function Test-NothingPublished([string]$Dir) {
    -not (Test-Path -LiteralPath (Join-Path $Dir $manifestName)) -and -not (Test-Path -LiteralPath (Join-Path $Dir $gateName)) -and
      -not (Test-Path -LiteralPath (Join-Path $Dir $latestName)) -and
      (Test-Path -LiteralPath (Join-Path $Dir $payloadName)) -and (Test-Path -LiteralPath (Join-Path $Dir $pendingName))
  }

  $script:checked = @()
  $script:checkedPins = @()
  $recordAll = { param($Path, $AllowedPins) $script:checked += $Path; $script:checkedPins += (@($AllowedPins) -join "|") }
  $good = New-Fixture
  $goodRuntime = Join-Path $good.Publish 'runtime'
  $expectedRuntime = @('Cerberus.Agent.dll', 'Cerberus.Agent.exe', 'Cerberus.Agent.Runtime.dll',
    'Cerberus.Agent.Service.exe', 'Cerberus.Agent.Uninstall.exe', 'Cerberus.Agent.Update.Core.dll',
    'Cerberus.Agent.Updater.dll', 'Cerberus.Agent.Updater.exe', 'tr\Cerberus.Agent.resources.dll')
  $expectedChecks = $expectedRuntime.Count + 2
  Invoke-Finalize $good $recordAll
  $gate = Get-Content -Raw -LiteralPath (Join-Path $good.Publish $gateName) | ConvertFrom-Json
  Check "finalize with a good detached signature writes the manifest, gate and latest alias" {
    (Test-Path -LiteralPath (Join-Path $good.Publish $manifestName)) -and (Test-Path -LiteralPath (Join-Path $good.Publish $latestName))
  }
  Check "finalize checks every first-party PE (incl. satellite) in ordinal order, skips third-party, and both installers" {
    $runtimeChecked = @($script:checked | Where-Object { $_ -notin @($good.Msi, $good.Setup) } |
      ForEach-Object { [IO.Path]::GetRelativePath($goodRuntime, $_) })
    $script:checked.Count -eq $expectedChecks -and ($script:checked -contains $good.Msi) -and ($script:checked -contains $good.Setup) -and
      (($runtimeChecked -join '|') -ceq ($expectedRuntime -join '|'))
  }
  Check "finalize hands the embedded signer pins to every signature check" {
    $script:checkedPins.Count -eq $expectedChecks -and (@($script:checkedPins | Where-Object { $_ -ceq $pin }).Count -eq $expectedChecks)
  }
  Check "payload gate rejects an unsigned first-party PE and ignores third-party files" {
    Throws { Assert-FirstPartyPeFilesSigned (Join-Path $good.Publish "runtime") } "Unsigned first-party file\(s\).*Cerberus\.Agent\.dll"
  }
  Check "payload gate lists the satellite assembly by relative path" {
    Throws { Assert-FirstPartyPeFilesSigned (Join-Path $good.Publish "runtime") } "tr\\Cerberus\.Agent\.resources\.dll"
  }
  Check "payload gate covers the installer helper executable" {
    $helperDir = Join-Path $work "installer-helper"; New-Item -ItemType Directory -Path $helperDir -Force | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $helperDir "Cerberus.Agent.Installer.Helper.exe"), [byte[]](1, 2, 3))
    Throws { Assert-FirstPartyPeFilesSigned $helperDir } "Unsigned first-party file\(s\).*Cerberus\.Agent\.Installer\.Helper\.exe"
  }
  Check "an undecodable test-anchor fixture fails closed" {
    $fakeRoot = Join-Path $work "fixture-root"; New-Item -ItemType Directory -Path (Join-Path $fakeRoot "scripts"), (Join-Path $fakeRoot "tests/fixtures") -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot "release-profile-lib.ps1") -Destination (Join-Path $fakeRoot "scripts")
    Set-Content -LiteralPath (Join-Path $fakeRoot "tests/fixtures/agent-command-test-anchors.b64") -Value "!!not-base64!!"
    . (Join-Path $fakeRoot "scripts/release-profile-lib.ps1")
    Throws { Test-CommandAnchorsAreTestFixture "QQ==" } "cannot be decoded"
  }
  Check "gate reports the signature as measured" { $gate.authenticode_signature_present -eq $true -and $gate.installer.authenticode_signature_present -eq $true }
  Check "finalize removes the pending payload and state" {
    -not (Test-Path -LiteralPath (Join-Path $good.Publish $payloadName)) -and -not (Test-Path -LiteralPath (Join-Path $good.Publish $pendingName))
  }
  Check "finalized manifest is accepted by the agent verifier" {
    $written = Get-Content -Raw -LiteralPath (Join-Path $good.Publish $manifestName)
    Assert-ManifestAcceptedByAgentVerifier -ManifestJson $written -PublicKeyPems @($pemB) -Channel stable -ArtifactPrefixes @($prefix) -ExpectedCanonicalPayload $good.Canonical; $true
  }

  function Assert-FinalizeRefused([string]$Name, [string]$Pattern, $Fixture, [scriptblock]$SignatureCheck, [hashtable]$Extra = @{}) {
    $message = $null
    try { Invoke-Finalize $Fixture $SignatureCheck @Extra } catch { $message = $_.Exception.Message }
    Check $Name { ($null -ne $message) -and ($message -match $Pattern) -and (Test-NothingPublished $Fixture.Publish) }
  }
  $accept = { param($Path, $AllowedPins) }
  $f = New-Fixture
  Assert-FinalizeRefused "finalize refuses a signature made by another key" "rejected by the agent verifier" $f $accept @{
    Signature = (Sign-ManifestPayloadWithCertificate -CanonicalPayload $f.Canonical -Certificate $certA) }
  $f = New-Fixture; [IO.File]::WriteAllBytes((Join-Path $f.Publish $payloadName), [Text.Encoding]::UTF8.GetBytes($f.Canonical + "x"))
  Assert-FinalizeRefused "finalize refuses a changed payload" "payload hash" $f $accept
  $otherKey = Join-Path $work "other.pem"; Set-Content -LiteralPath $otherKey -Value (Get-RsaPublicKeyPem (New-TestCertificate))
  Assert-FinalizeRefused "finalize refuses an expected key that is not embedded" "not among the keys embedded" (New-Fixture) $accept @{ KeyFile = $otherKey }
  Assert-FinalizeRefused "finalize refuses a signature that is not base64" "base64" (New-Fixture) $accept @{ Signature = "not base64 !!" }
  Assert-FinalizeRefused "finalize refuses a missing signature file" "signature file was not found" (New-Fixture) $accept @{ Signature = "<none>" }
  Assert-FinalizeRefused "finalize refuses a missing public key file" "Manifest public key file was not found" (New-Fixture) $accept @{ KeyFile = (Join-Path $work "missing.pem") }
  $f = New-Fixture; Set-Content -LiteralPath $f.Msi -Value "a different msi"
  Assert-FinalizeRefused "finalize refuses a swapped MSI (hash)" "MSI hash does not match" $f $accept
  Assert-FinalizeRefused "finalize refuses a changed artifact length" "MSI length does not match" (New-Fixture -Options @{ LengthDelta = 1 }) $accept
  Assert-FinalizeRefused "finalize refuses a payload version that differs from -Version" "does not match -Version" (New-Fixture -Options @{ PayloadVersion = "9.9.8" }) $accept
  Assert-FinalizeRefused "finalize refuses when the signature check fails on a runtime executable" "runtime signature check failed" (New-Fixture) { param($Path, $AllowedPins) throw "runtime signature check failed" }
  Assert-FinalizeRefused "finalize refuses when only the MSI fails the signature check" "msi signature check failed" (New-Fixture) {
    param($Path, $AllowedPins) if ($Path -like "*.msi") { throw "msi signature check failed" } }
  Assert-FinalizeRefused "finalize refuses when only setup fails the signature check" "setup signature check failed" (New-Fixture) {
    param($Path, $AllowedPins) if ($Path -like "*stable-9.9.9.exe") { throw "setup signature check failed" } }
  Assert-FinalizeRefused "finalize refuses a setup payload mismatch before publication" "setup payload mismatch" (New-Fixture) $accept @{
    PayloadCheck = { param($Msi, $Setup) throw 'setup payload mismatch' }
  }
