# Support-tier checks for scripts/release-signing-lib.ps1 and the two-step manifest path of
# scripts/build-agent-public-release.ps1. Keys and certificates are generated in memory; no certificate
# store, token, signtool or network is used. Exit code = number of failed checks.
param([string]$CoreDll = "")
$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($CoreDll)) {
  $CoreDll = Join-Path $repoRoot "src/Cerberus.Agent.Core/bin/Release/net8.0/Cerberus.Agent.Core.dll"
}
if (-not (Test-Path -LiteralPath $CoreDll -PathType Leaf)) {
  throw "Build the solution in Release first (agent verifier assembly not found: $CoreDll)."
}
$CoreDll = (Resolve-Path -LiteralPath $CoreDll).Path
. (Join-Path $PSScriptRoot "release-signing-lib.ps1")
. (Join-Path $PSScriptRoot "release-publish-lib.ps1")
. (Join-Path $PSScriptRoot "release-token-lib.ps1")
Import-AgentManifestVerifier $CoreDll
$mainScript = Join-Path $PSScriptRoot "build-agent-public-release.ps1"

$script:failures = 0
function Check([string]$Name, [scriptblock]$Test) {
  try {
    if ((& $Test) -eq $true) { Write-Host "ok   $Name" } else { Write-Host "FAIL $Name"; $script:failures++ }
  } catch { Write-Host "FAIL $Name : $($_.Exception.Message)"; $script:failures++ }
}
function Throws([scriptblock]$Test, [string]$Pattern) {
  try { & $Test | Out-Null; return $false } catch { return ($_.Exception.Message -match $Pattern) }
}
function New-TestCertificate {
  $rsa = [System.Security.Cryptography.RSA]::Create(2048)
  $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
    "CN=release-signing-test", $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
  return $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(30))
}
function Invoke-Release([string[]]$Arguments) {
  $output = & pwsh -NoProfile -File $mainScript @Arguments 2>&1
  return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Text = ($output | Out-String) }
}

# The child process must not see ambient signing material.
foreach ($name in @("WINDOWS_SIGNING_CERT_BASE64", "WINDOWS_SIGNING_CERT_PASSWORD", "AGENT_UPDATE_MANIFEST_PRIVATE_KEY_PEM")) {
  Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
}

$certA = New-TestCertificate
$certB = New-TestCertificate
$thumbprint = "ab" * 20

# Signer pin
Check "pin is sha256 of the SPKI, independent computation" {
  (Get-SignerSpkiPin $certA) -ceq ("sha256:" + [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($certA.PublicKey.ExportSubjectPublicKeyInfo())).ToLowerInvariant())
}
Check "pin equals AgentUpdateAuthenticode.PublisherSpkiSha256" {
  (Get-SignerSpkiPin $certA) -ceq [Cerberus.Agent.Core.AgentUpdateAuthenticode]::PublisherSpkiSha256($certA)
}
Check "different keys give different pins" { (Get-SignerSpkiPin $certA) -cne (Get-SignerSpkiPin $certB) }
Check "pin list is normalized and de-duplicated" {
  $pins = ConvertTo-NormalizedSignerPins @((Get-SignerSpkiPin $certA), (Get-SignerSpkiPin $certA).ToUpperInvariant(), (Get-SignerSpkiPin $certB))
  $pins.Count -eq 2
}
Check "malformed pin is rejected" { Throws { ConvertTo-NormalizedSignerPins @("sha256:abc") } "Signer pin" }

# List escaping (the agent splits pins and prefixes on ',', public keys on ',' and ';')
Check "list items are joined with an escaped comma" { (ConvertTo-MsBuildListValue @("a", "b")) -ceq "a%2Cb" }
Check "separator characters inside an item are escaped" { (ConvertTo-MsBuildListValue @("a,b", "c;d")) -ceq "a%2Cb%2Cc%3Bd" }
Check "single default URL is unchanged" {
  (ConvertTo-MsBuildListValue @("https://github.com/org/repo/releases/download/")) -ceq "https://github.com/org/repo/releases/download/"
}
Check "escaped list round-trips to the original items" {
  $items = @("sha256:aa", "sha256:bb", "sha256:cc")
  ([uri]::UnescapeDataString((ConvertTo-MsBuildListValue $items)) -split ',') -join '|' -ceq ($items -join '|')
}

# Mode selection
Check "default Pfx mode with no token input" { (Assert-ReleaseSigningInputs -Mode Pfx).Mode -eq "Pfx" }
Check "Pfx mode with the unsigned dev switch stays on the Pfx path" {
  (Assert-ReleaseSigningInputs -Mode Pfx -AllowUnsignedDevBuild $true -AllowEphemeralManifestKey $true).Mode -eq "Pfx"
}
Check "Pfx mode rejects token inputs" { Throws { Assert-ReleaseSigningInputs -Mode Pfx -SigningCertThumbprint $thumbprint } "Token signing inputs" }
Check "token mode rejects ambient Pfx material" {
  Throws { Assert-ReleaseSigningInputs -Mode Token -SigningCertThumbprint $thumbprint -ManifestSigningCertThumbprint $thumbprint -PfxCertificatePresent $true } "cannot be combined"
}
Check "token mode rejects ambient manifest private key" {
  Throws { Assert-ReleaseSigningInputs -Mode Token -SigningCertThumbprint $thumbprint -ManifestSigningCertThumbprint $thumbprint -ManifestPrivateKeyPemPresent $true } "cannot be combined"
}
Check "token mode rejects the unsigned dev switch" {
  Throws { Assert-ReleaseSigningInputs -Mode Token -SigningCertThumbprint $thumbprint -ManifestSigningCertThumbprint $thumbprint -AllowUnsignedDevBuild $true } "always signs"
}
Check "token mode requires a signing thumbprint" { Throws { Assert-ReleaseSigningInputs -Mode Token -ManifestSigningCertThumbprint $thumbprint } "requires -SigningCertThumbprint" }
Check "token mode rejects a malformed thumbprint" { Throws { Assert-ReleaseSigningInputs -Mode Token -SigningCertThumbprint "xyz" -ManifestSigningCertThumbprint $thumbprint } "40 hexadecimal" }
Check "token mode needs exactly one manifest signer (none)" { Throws { Assert-ReleaseSigningInputs -Mode Token -SigningCertThumbprint $thumbprint } "exactly one" }

$work = Join-Path ([IO.Path]::GetTempPath()) ("release-signing-test-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work | Out-Null
$outRoot = "out/test-release-signing-" + [guid]::NewGuid().ToString("N").Substring(0, 8)
$outRootFull = Join-Path $repoRoot $outRoot
try {
  $pemA = Get-RsaPublicKeyPem $certA
  $pemB = Get-RsaPublicKeyPem $certB
  $keyA = Join-Path $work "a.pem"; Set-Content -LiteralPath $keyA -Value $pemA
  $keyB = Join-Path $work "b.pem"; Set-Content -LiteralPath $keyB -Value $pemB
  $privateKey = Join-Path $work "private.pem"
  Set-Content -LiteralPath $privateKey -Value ([System.Security.Cryptography.RSA]::Create(2048).ExportPkcs8PrivateKeyPem())

  Check "token mode needs exactly one manifest signer (both)" {
    Throws { Assert-ReleaseSigningInputs -Mode Token -SigningCertThumbprint $thumbprint -ManifestSigningCertThumbprint $thumbprint -ManifestSigningPublicKeyFile $keyA } "exactly one"
  }
  Check "token mode with a CNG manifest signer" { (Assert-ReleaseSigningInputs -Mode Token -SigningCertThumbprint $thumbprint -ManifestSigningCertThumbprint $thumbprint).ManifestSigning -eq "Cng" }
  Check "token mode with an external manifest signer" { (Assert-ReleaseSigningInputs -Mode Token -SigningCertThumbprint $thumbprint -ManifestSigningPublicKeyFile $keyA).ManifestSigning -eq "External" }
  Check "missing extra public key file is rejected" {
    Throws { Assert-ReleaseSigningInputs -Mode Token -SigningCertThumbprint $thumbprint -ManifestSigningCertThumbprint $thumbprint -ExtraManifestPublicKeyFiles (Join-Path $work "missing.pem") } "not found"
  }
  Check "finalize requires the expected public key" { Throws { Assert-ReleaseSigningInputs -Mode Token -ManifestSignatureFile $keyA } "requires -ManifestSigningPublicKeyFile" }

  # signtool command line (dry run: arguments only, signtool is never started)
  Check "signtool selects the certificate with /sha1 and carries no PFX or password flags" {
    $a = Get-SignToolTokenSignArguments -Thumbprint $thumbprint -TimestampUrl "http://ts.example" -FilePath "C:\x\a.exe"
    ($a -join " ") -ceq ("sign /fd SHA256 /td SHA256 /tr http://ts.example /sha1 " + $thumbprint.ToUpperInvariant() + " C:\x\a.exe") -and
      ($a -notcontains "/f") -and ($a -notcontains "/p")
  }
  Check "hash and timestamp flags match the PFX path" {
    $text = Get-Content -Raw -LiteralPath $mainScript
    $text -match 'sign /fd SHA256 /td SHA256 /tr \$TimestampUrl /f \$certPath /p \$certPassword \$runtimeExe' -and
      ((Get-SignToolTokenSignArguments -Thumbprint $thumbprint -TimestampUrl '$TimestampUrl' -FilePath 'F')[0..6] -join " ") -ceq 'sign /fd SHA256 /td SHA256 /tr $TimestampUrl'
  }

  # Sequence and validity helpers mirror the agent ceilings
  $nowMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  Check "sequence at the ceiling is accepted" { Assert-ManifestSequenceInRange ($nowMs + 24L * 3600 * 1000 - 5000); $true }
  Check "sequence beyond the ceiling is rejected" { Throws { Assert-ManifestSequenceInRange ($nowMs + 24L * 3600 * 1000 + 5000) } "24 hours" }
  Check "non-positive sequence is rejected" { Throws { Assert-ManifestSequenceInRange 0 } "positive" }
  Check "45 day window is accepted" { $t = [DateTimeOffset]::UtcNow; Assert-ManifestValidityWindow $t $t.AddDays(45); $true }
  Check "45 day window plus one tick is rejected" { $t = [DateTimeOffset]::UtcNow; Throws { Assert-ManifestValidityWindow $t $t.AddDays(45).AddTicks(1) } "exceeds" }

  # Manifest signing with an in-memory key, verified by the agent's own validator
  $now = [DateTimeOffset]::UtcNow
  $prefix = "https://releases.example/package/"
  $pin = Get-SignerSpkiPin $certA
  function New-Canonical([DateTimeOffset]$Expires, [long]$Sequence = $now.ToUnixTimeMilliseconds()) {
    @("msi", "9.9.9", "stable", "${prefix}a.msi", ("a" * 64), "Cerberus Agent Release", $now.AddMinutes(-1).ToString("O"),
      "agent.heartbeat.v1", "false", "agent.update.manifest.v2", $Sequence.ToString(), $Expires.ToString("O"), "1234", $pin) -join "`n"
  }
  function ConvertTo-ManifestJson([string]$Canonical, [string]$Signature) {
    (ConvertFrom-ManifestPayloadV2 -Canonical $Canonical -Signature $Signature) | ConvertTo-Json -Depth 8
  }
  $canonical = New-Canonical $now.AddDays(30)
  $signature = Sign-ManifestPayloadWithCertificate -CanonicalPayload $canonical -Certificate $certB
  $json = ConvertTo-ManifestJson $canonical $signature
  Check "agent verifier accepts a manifest signed in memory" {
    Assert-ManifestAcceptedByAgentVerifier -ManifestJson $json -PublicKeyPems @($pemB) -Channel stable -ArtifactPrefixes @($prefix) -ExpectedCanonicalPayload $canonical; $true
  }
  Check "agent verifier accepts any key of a two-key list" {
    Assert-ManifestAcceptedByAgentVerifier -ManifestJson $json -PublicKeyPems @($pemA, $pemB) -Channel stable -ArtifactPrefixes @($prefix) -ExpectedCanonicalPayload $canonical; $true
  }
  Check "agent verifier rejects a different key" {
    Throws { Assert-ManifestAcceptedByAgentVerifier -ManifestJson $json -PublicKeyPems @($pemA) -Channel stable -ArtifactPrefixes @($prefix) -ExpectedCanonicalPayload $canonical } "rejected by the agent verifier"
  }
  Check "agent verifier rejects a tampered field" {
    Throws { Assert-ManifestAcceptedByAgentVerifier -ManifestJson ($json -replace "9\.9\.9", "9.9.8") -PublicKeyPems @($pemB) -Channel stable -ArtifactPrefixes @($prefix) -ExpectedCanonicalPayload $canonical } "rejected"
  }
  Check "agent verifier rejects a 46 day window" {
    $long = New-Canonical $now.AddDays(46)
    $longJson = ConvertTo-ManifestJson $long (Sign-ManifestPayloadWithCertificate -CanonicalPayload $long -Certificate $certB)
    Throws { Assert-ManifestAcceptedByAgentVerifier -ManifestJson $longJson -PublicKeyPems @($pemB) -Channel stable -ArtifactPrefixes @($prefix) -ExpectedCanonicalPayload $long } "validity window"
  }
  Check "manifest JSON keeps the agent field names and types" {
    $m = ConvertFrom-ManifestPayloadV2 -Canonical $canonical -Signature $signature
    ($m.Keys -join ",") -ceq "schema_version,artifact_kind,version,channel,artifact_url,sha256,signing_identity,released_at_utc,minimum_protocol_version,rollback_allowed,sequence,expires_at_utc,artifact_length,signer_key_identity,signature" -and
      $m.sequence -is [long] -and $m.rollback_allowed -is [bool]
  }

  # Public key files and lists
  Check "public key file: PEM is read back" { (Read-ManifestPublicKeyFile $keyA).Trim() -ceq $pemA.Trim() }
  Check "public key file: certificate is reduced to its public key" {
    $cer = Join-Path $work "b.cer"; [IO.File]::WriteAllBytes($cer, $certB.Export("Cert"))
    (Read-ManifestPublicKeyFile $cer).Trim() -ceq $pemB.Trim()
  }
  Check "public key file: private key is refused" { Throws { Read-ManifestPublicKeyFile $privateKey } "private key" }
  Check "key list is de-duplicated and carries both keys" { (ConvertTo-ManifestPublicKeyListB64 @($pemA, $pemA, $pemB)).Count -eq 2 }

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
  function New-Fixture([string]$Dir = "", [hashtable]$Options = @{}) {
    if ([string]::IsNullOrWhiteSpace($Dir)) { $Dir = Join-Path $work ("pub-" + [guid]::NewGuid().ToString("N").Substring(0, 8)) }
    New-FinalizeFixture -PublishDir $Dir -CoreDll $CoreDll -KeyListB64 $keyListB64 -SignerPin $pin -Prefix $prefix @Options
  }
  function Write-FixtureSignature($Fixture, [string]$Signature = "") {
    if ([string]::IsNullOrEmpty($Signature)) { $Signature = Sign-ManifestPayloadWithCertificate -CanonicalPayload $Fixture.Canonical -Certificate $certB }
    if ($Signature -eq "<none>") { Remove-Item -LiteralPath $sigFile -ErrorAction SilentlyContinue } else { Set-Content -LiteralPath $sigFile -Value $Signature }
  }
  function Invoke-Finalize($Fixture, [scriptblock]$SignatureCheck, [string]$Version = "9.9.9", [string]$Signature = "", [string]$KeyFile = $keyB) {
    Write-FixtureSignature $Fixture $Signature
    Complete-ExternalManifestSigning -PublishDir $Fixture.Publish -Channel stable -Version $Version -AssetBase $assetBase -InstallerBase $installerBase `
      -SignaturePath $sigFile -PublicKeyPath $KeyFile -FileSignatureCheck $SignatureCheck 6>$null | Out-Null
  }
  function Test-NothingPublished([string]$Dir) {
    -not (Test-Path -LiteralPath (Join-Path $Dir $manifestName)) -and -not (Test-Path -LiteralPath (Join-Path $Dir $gateName)) -and
      -not (Test-Path -LiteralPath (Join-Path $Dir $latestName)) -and
      (Test-Path -LiteralPath (Join-Path $Dir $payloadName)) -and (Test-Path -LiteralPath (Join-Path $Dir $pendingName))
  }

  $script:checked = @()
  $recordAll = { param($Path, $AllowedPins) $script:checked += $Path }
  $good = New-Fixture
  Invoke-Finalize $good $recordAll
  $gate = Get-Content -Raw -LiteralPath (Join-Path $good.Publish $gateName) | ConvertFrom-Json
  Check "finalize with a good detached signature writes the manifest, gate and latest alias" {
    (Test-Path -LiteralPath (Join-Path $good.Publish $manifestName)) -and (Test-Path -LiteralPath (Join-Path $good.Publish $latestName))
  }
  Check "finalize checks the four runtime executables and the MSI" {
    $script:checked.Count -eq 5 -and ($script:checked -contains $good.Msi) -and (@($script:checked | Where-Object { $_ -like "*runtime*" }).Count -eq 4)
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

  # Extra or conflicting token parameters and the real signature check, through the real script
  $childPublish = Join-Path $outRootFull "publish"
  $childFixture = New-Fixture $childPublish
  Write-FixtureSignature $childFixture
  $finalizeArgs = @("-Version", "9.9.9", "-Channel", "stable", "-OutputRoot", $outRoot, "-SigningMode", "Token", "-ManifestSigningPublicKeyFile", $keyB, "-ManifestSignatureFile", $sigFile)
  $r = Invoke-Release ($finalizeArgs + @("-SigningCertThumbprint", $thumbprint, "-ExtraSignerPins", $pin))
  Check "script: finalize with extra token parameters is refused and names them" {
    $r.ExitCode -ne 0 -and ($r.Text -match "accepts only") -and ($r.Text -match "-SigningCertThumbprint") -and ($r.Text -match "-ExtraSignerPins") -and (Test-NothingPublished $childPublish)
  }
  $r = Invoke-Release $finalizeArgs
  Check "script: finalize on an unsigned fixture MSI is refused by the real signature check" {
    $r.ExitCode -ne 0 -and ($r.Text -match "Authenticode") -and (Test-NothingPublished $childPublish)
  }

  # Pfx path: a legacy manifest is still written and aliased
  $pfxFixture = New-Fixture
  $pfxManifest = [ordered]@{ sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $pfxFixture.Msi).Hash.ToLowerInvariant(); sequence = 1; expires_at_utc = "2030-01-01T00:00:00Z"; signer_key_identity = $pin }
  Publish-ReleaseOutputs -PublishDir $pfxFixture.Publish -Channel stable -AssetBase $assetBase -InstallerBase $installerBase `
    -Manifest $pfxManifest -LegacyManifest ([ordered]@{ version = "9.9.9"; legacy = $true }) -AllowUnsignedBuildMetadata $true -Signed $false
  Check "Pfx path writes the legacy manifest and its latest alias" {
    $legacy = Join-Path $pfxFixture.Publish "$assetBase.update-manifest.json"
    $alias = Join-Path $pfxFixture.Publish "Cerberus.Agent.Bundle-stable-latest.update-manifest.json"
    (Test-Path -LiteralPath $legacy) -and (Test-Path -LiteralPath $alias) -and
      ((Get-Content -Raw -LiteralPath $alias | ConvertFrom-Json).legacy -eq $true) -and
      (Test-Path -LiteralPath (Join-Path $pfxFixture.Publish "Cerberus.Agent-stable-latest.msi")) -and
      (Test-Path -LiteralPath (Join-Path $pfxFixture.Publish $latestName))
  }
  Check "Pfx path gate carries the passed signature state" {
    $g = Get-Content -Raw -LiteralPath (Join-Path $pfxFixture.Publish $gateName) | ConvertFrom-Json
    $g.unsigned_dev_build_allowed -eq $true -and $g.authenticode_signature_present -eq $false
  }

  # Mode selection through the real script: fail before any build output exists
  Remove-Item -LiteralPath $outRootFull -Recurse -Force -ErrorAction SilentlyContinue
  $r = Invoke-Release @("-Version", "9.9.9", "-Channel", "stable", "-OutputRoot", $outRoot, "-SigningMode", "Token")
  Check "script: token mode without a signing thumbprint stops before any output" {
    $r.ExitCode -ne 0 -and ($r.Text -match "requires -SigningCertThumbprint") -and -not (Test-Path -LiteralPath $outRootFull)
  }
  $r = Invoke-Release @("-Version", "9.9.9", "-Channel", "stable", "-OutputRoot", $outRoot, "-SigningCertThumbprint", $thumbprint)
  Check "script: token input in Pfx mode stops before any output" {
    $r.ExitCode -ne 0 -and ($r.Text -match "Token signing inputs") -and -not (Test-Path -LiteralPath $outRootFull)
  }
  $r = Invoke-Release @("-Version", "9.9.9", "-Channel", "stable", "-OutputRoot", $outRoot, "-SigningMode", "Token", "-SigningCertThumbprint", $thumbprint, "-ManifestSigningCertThumbprint", $thumbprint, "-AllowUnsignedDevBuild")
  Check "script: unsigned dev switch in token mode is refused" {
    $r.ExitCode -ne 0 -and ($r.Text -match "always signs") -and -not (Test-Path -LiteralPath $outRootFull)
  }
  $r = Invoke-Release @("-Version", "9.9.9", "-Channel", "stable", "-OutputRoot", $outRoot, "-SigningMode", "Token", "-ManifestSigningPublicKeyFile", $keyB, "-ManifestSignatureFile", (Join-Path $work "none.sig"))
  Check "script: finalize without a pending release stops with a clear error" {
    $r.ExitCode -ne 0 -and ($r.Text -match "No pending manifest") -and -not (Test-Path -LiteralPath (Join-Path $outRootFull "publish/$manifestName"))
  }
} finally {
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $outRootFull -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "failures=$script:failures"
exit $script:failures
