# Support-tier checks for scripts/release-signing-lib.ps1 and the two-step manifest path of
# scripts/build-agent-public-release.ps1. Keys and certificates are generated in memory; no certificate
# store, token or network is used. The case that exercises the real signature check runs signtool verify and
# needs the Windows SDK signtool.exe. Exit code = number of failed checks.
param([string]$CoreDll = "")
$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($CoreDll)) {
  $CoreDll = Join-Path $repoRoot "src/Cerberus.Agent.Core/bin/Release/net10.0/Cerberus.Agent.Core.dll"
}
if (-not (Test-Path -LiteralPath $CoreDll -PathType Leaf)) {
  throw "Build the solution in Release first (agent verifier assembly not found: $CoreDll)."
}
$CoreDll = (Resolve-Path -LiteralPath $CoreDll).Path
. (Join-Path $PSScriptRoot "release-signing-lib.ps1")
. (Join-Path $PSScriptRoot "release-trust-lib.ps1")
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
  Check "hash and timestamp flags match the PFX path" {
    $text = Get-Content -Raw -LiteralPath $mainScript
    $text -match 'sign /fd SHA256 /td SHA256 /tr \$TimestampUrl /f \$certPath /p \$certPassword \$peFile' -and
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
  Check "agent verifier refuses an expected payload that differs only in case" {
    Throws { Assert-ManifestAcceptedByAgentVerifier -ManifestJson $json -PublicKeyPems @($pemB) -Channel stable -ArtifactPrefixes @($prefix) -ExpectedCanonicalPayload ($canonical -replace "Cerberus Agent Release", "cerberus agent release") } "does not match the signed payload"
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

  # String sets compare ordinally and by count, like the agent
  Check "string sets: one newline-joined item is not two items" { -not (Test-SameStringSet @("a`nb") @("a", "b")) }
  Check "string sets: items that differ only in case differ" { -not (Test-SameStringSet @("Ab") @("aB")) }
  Check "string sets: a soft hyphen makes an item differ" { -not (Test-SameStringSet @("ab") @("a$([char]0xAD)b")) }
  Check "string sets: a repeated item changes the count" { -not (Test-SameStringSet @("a", "a") @("a")) }
  Check "string sets: the same items in another order are equal" { Test-SameStringSet @("a", "b") @("b", "a") }

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
    New-FinalizeFixture -PublishDir $Dir -CoreDll $CoreDll -KeyListB64 $fixtureKeys -SignerPin $pin -Prefix $prefix @Options
  }
  function Write-FixtureSignature($Fixture, [string]$Signature = "") {
    if ([string]::IsNullOrEmpty($Signature)) { $Signature = Sign-ManifestPayloadWithCertificate -CanonicalPayload $Fixture.Canonical -Certificate $certB }
    if ($Signature -eq "<none>") { Remove-Item -LiteralPath $sigFile -ErrorAction SilentlyContinue } else { Set-Content -LiteralPath $sigFile -Value $Signature }
  }
  function Invoke-Finalize($Fixture, [scriptblock]$SignatureCheck, [string]$Version = "9.9.9", [string]$Signature = "", [string]$KeyFile = $keyB, [string]$Channel = "stable") {
    Write-FixtureSignature $Fixture $Signature
    Complete-ExternalManifestSigning -PublishDir $Fixture.Publish -Channel $Channel -Version $Version -AssetBase $assetBase -InstallerBase $installerBase `
      -SignaturePath $sigFile -PublicKeyPath $KeyFile -FileSignatureCheck $SignatureCheck 6>$null | Out-Null
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
  Invoke-Finalize $good $recordAll
  $gate = Get-Content -Raw -LiteralPath (Join-Path $good.Publish $gateName) | ConvertFrom-Json
  Check "finalize with a good detached signature writes the manifest, gate and latest alias" {
    (Test-Path -LiteralPath (Join-Path $good.Publish $manifestName)) -and (Test-Path -LiteralPath (Join-Path $good.Publish $latestName))
  }
  Check "finalize checks every first-party PE (incl. satellite) in ordinal order, skips third-party, and the MSI" {
    $runtimeChecked = @($script:checked | Where-Object { $_ -like "*runtime*" })
    $sorted = @($runtimeChecked); [Array]::Sort($sorted, [StringComparer]::OrdinalIgnoreCase)
    $script:checked.Count -eq 9 -and ($script:checked -contains $good.Msi) -and $runtimeChecked.Count -eq 8 -and
      (@($runtimeChecked | Where-Object { $_ -like "*Fixture.dll" }).Count -eq 0) -and
      (@($runtimeChecked | Where-Object { $_ -like "*resources.dll" }).Count -eq 1) -and
      (($runtimeChecked -join "|") -ceq ($sorted -join "|"))
  }
  Check "finalize hands the embedded signer pins to every signature check" {
    $script:checkedPins.Count -eq 9 -and (@($script:checkedPins | Where-Object { $_ -ceq $pin }).Count -eq 9)
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

  # Binding of the pending payload and of both runtime assemblies to what the build embeds
  $pinB = Get-SignerSpkiPin $certB
  $keysAOnlyList = ConvertTo-ManifestPublicKeyListB64 @($pemA)
  $keysAOnly = @($keysAOnlyList)
  $otherPrefix = "https://other.example/package/"
  function Get-Pairs([string[]]$Keys = $keyListB64, [string[]]$Pins = @($pin), [string]$Prefix = $prefix, [string]$Channel = "stable") {
    Get-TrustPairs -Keys $Keys -Pins $Pins -Prefix $Prefix -Channel $Channel
  }
  $both = { param($Pairs) @{ AgentPairs = $Pairs; RuntimePairs = $Pairs } }
  Assert-FinalizeRefused "finalize refuses pending keys that differ from the embedded keys" "Pending manifest keys do not match" (New-Fixture -Options (& $both (Get-Pairs -Keys $keysAOnly))) $accept
  Assert-FinalizeRefused "finalize refuses pending signer pins that differ from the embedded pins" "Pending signer pins do not match" (New-Fixture -Options (& $both (Get-Pairs -Pins @($pinB)))) $accept
  $f = New-Fixture
  $pendingFile = Join-Path $f.Publish $pendingName
  $pendingObject = Get-Content -Raw -LiteralPath $pendingFile | ConvertFrom-Json
  $pendingObject.PSObject.Properties.Remove("signer_pins")
  $pendingObject | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $pendingFile -Encoding utf8
  Assert-FinalizeRefused "finalize refuses a pending state without signer pins" "Pending signer pins do not match" $f $accept
  Assert-FinalizeRefused "finalize refuses a manifest signer identity that is not an embedded pin" "signer identity is not among the signer pins" (New-Fixture -Options @{ CanonicalSignerPin = $pinB }) $accept
  Assert-FinalizeRefused "finalize refuses an embedded channel that differs from -Channel" "Embedded release channel does not match" (New-Fixture -Options @{ EmbeddedChannel = "preview" }) $accept
  Assert-FinalizeRefused "finalize refuses an embedded channel outside dev, preview and stable" "must be lowercase dev, preview or stable" (New-Fixture -Options @{ EmbeddedChannel = "beta" }) $accept
  Assert-FinalizeRefused "finalize refuses embedded prefixes that differ from the pending prefixes" "Pending artifact prefixes do not match" (New-Fixture -Options @{ EmbeddedPrefix = $otherPrefix }) $accept
  Assert-FinalizeRefused "finalize refuses a runtime assembly without metadata" "carries no manifest public key" (New-Fixture -Options @{ RuntimePairs = @() }) $accept
  Assert-FinalizeRefused "finalize refuses a runtime assembly with a malformed key" "malformed manifest public key" (New-Fixture -Options @{ RuntimePairs = (Get-Pairs -Keys @("***")) }) $accept
  Assert-FinalizeRefused "finalize refuses embedded keys joined by a space (single unusable entry)" "malformed manifest public key" (New-Fixture -Options (& $both (Get-Pairs -Keys @($keyListB64 -join " ")))) $accept
  Assert-FinalizeRefused "finalize refuses a payload channel that differs from -Channel" "Pending manifest channel does not match" (New-Fixture -Options @{ CanonicalChannel = "preview" }) $accept
  Assert-FinalizeRefused "finalize refuses an embedded channel that differs only in case" "must be lowercase dev, preview or stable" (New-Fixture -Options @{ EmbeddedChannel = "Stable" }) $accept
  Assert-FinalizeRefused "finalize with embedded and -Channel 'Stable' is refused" "must be lowercase dev, preview or stable" (New-Fixture -Options @{ EmbeddedChannel = "Stable" }) $accept @{ Channel = "Stable" }
  Assert-FinalizeRefused "finalize refuses a soft-hyphen embedded channel even with the same -Channel" "must be lowercase" (New-Fixture -Options @{ EmbeddedChannel = "sta$([char]0xAD)ble" }) $accept @{ Channel = "sta$([char]0xAD)ble" }
  Assert-FinalizeRefused "finalize refuses -Channel that differs from a valid embedded channel only in case" "Embedded release channel does not match" (New-Fixture) $accept @{ Channel = "Stable" }
  Assert-FinalizeRefused "finalize refuses embedded prefixes that differ only in case" "Pending artifact prefixes do not match" (New-Fixture -Options @{ EmbeddedPrefix = $prefix.ToUpperInvariant() }) $accept
  Assert-FinalizeRefused "finalize refuses a payload version that differs from -Version only in case" "does not match -Version" (New-Fixture -Options @{ PayloadVersion = "9.9.9-rc" }) $accept @{ Version = "9.9.9-RC" }
  Assert-FinalizeRefused "finalize refuses a runtime prefix containing a soft hyphen" "embed different ArtifactPrefixes" (New-Fixture -Options @{ RuntimePairs = (Get-Pairs -Prefix $prefix.Insert(8, [string][char]0xAD)) }) $accept
  Assert-FinalizeRefused "finalize refuses a runtime channel that differs only in case" "embed different release channels" (New-Fixture -Options @{ RuntimePairs = (Get-Pairs -Channel "Stable") }) $accept
  $urlA = @("AgentUpdateManifestUrl", "https://updates.example/a.json")
  $urlB = @("AgentUpdateManifestUrl", "https://updates.example/b.json")
  Assert-FinalizeRefused "finalize refuses different update manifest URLs in the two assemblies" "different update manifest URLs" (New-Fixture -Options @{
    AgentPairs = (@(Get-Pairs) + ,$urlA); RuntimePairs = (@(Get-Pairs) + ,$urlB) }) $accept
  foreach ($label in "AgentPairs", "RuntimePairs") {
    $unsigned = @{ $label = (@(Get-Pairs) + ,@("AllowUnsignedDevBuild", "true")) }
    Assert-FinalizeRefused "finalize refuses AllowUnsignedDevBuild=true in $label" "carries AllowUnsignedDevBuild='true'" (New-Fixture -Options $unsigned) $accept
  }
  Assert-FinalizeRefused "finalize refuses an AllowUnsignedDevBuild value that is not a boolean" "carries AllowUnsignedDevBuild='x'" (New-Fixture -Options @{
    RuntimePairs = (@(Get-Pairs) + ,@("AllowUnsignedDevBuild", "x")) }) $accept
  $sameUrl = @(Get-Pairs) + ,$urlA + ,@("AllowUnsignedDevBuild", "False")
  $withUrl = New-Fixture -Options @{ AgentPairs = $sameUrl; RuntimePairs = $sameUrl }
  Invoke-Finalize $withUrl $recordAll
  Check "finalize accepts one shared manifest URL and AllowUnsignedDevBuild=False" { Test-Path -LiteralPath (Join-Path $withUrl.Publish $manifestName) }
  Assert-FinalizeRefused "finalize refuses a runtime assembly with a repeated metadata key" "Duplicate assembly metadata key 'AgentReleaseChannel'" (New-Fixture -Options @{
    RuntimePairs = @(Get-Pairs) + ,@("AgentReleaseChannel", "stable") }) $accept
  Assert-FinalizeRefused "finalize ignores metadata attributes outside System.Reflection" "carries no manifest public key" (New-Fixture -Options @{ RuntimeNamespace = "Fixture.Other" }) $accept
  Assert-FinalizeRefused "finalize refuses runtime keys that differ from the app assembly" "embed different PublicKeyPems" (New-Fixture -Options @{ RuntimePairs = (Get-Pairs -Keys $keysAOnly) }) $accept
  Assert-FinalizeRefused "finalize refuses runtime signer pins that differ from the app assembly" "embed different SignerPins" (New-Fixture -Options @{ RuntimePairs = (Get-Pairs -Pins @($pinB)) }) $accept
  Assert-FinalizeRefused "finalize refuses runtime prefixes that differ from the app assembly" "embed different ArtifactPrefixes" (New-Fixture -Options @{ RuntimePairs = (Get-Pairs -Prefix $otherPrefix) }) $accept
  Assert-FinalizeRefused "finalize refuses a runtime channel that differs from the app assembly" "embed different release channels" (New-Fixture -Options @{ RuntimePairs = (Get-Pairs -Channel "beta") }) $accept
  # Two signer pins: every signature check must receive both
  $script:checkedPins = @()
  $twoPinError = $null
  try { Invoke-Finalize (New-Fixture -Options @{ ExtraPins = @($pinB) }) $recordAll } catch { $twoPinError = $_.Exception.Message }
  Check "finalize with two embedded signer pins is accepted" { if ($twoPinError) { throw $twoPinError }; $true }
  Check "finalize hands both embedded signer pins to each of the nine signature checks" {
    $want = (@($pin, $pinB) | Sort-Object) -join "|"
    $script:checkedPins.Count -eq 9 -and (@($script:checkedPins | Where-Object { ((($_ -split '\|') | Sort-Object) -join "|") -ceq $want }).Count -eq 9)
  }
  # Expected key that differs from an embedded key only in base64 letter case (still a valid RSA public key)
  $lines = $pemB.Trim() -split "\r?\n"
  $chars = $lines[3].ToCharArray()
  $at = 0; while (-not [char]::IsLetter($chars[$at])) { $at++ }
  $chars[$at] = if ([char]::IsUpper($chars[$at])) { [char]::ToLowerInvariant($chars[$at]) } else { [char]::ToUpperInvariant($chars[$at]) }
  $lines[3] = -join $chars
  $caseVariantPem = $lines -join "`n"
  $caseKey = Join-Path $work "case-variant.pem"; Set-Content -LiteralPath $caseKey -Value $caseVariantPem
  Check "key case variant: differs from the embedded key only in case and imports as RSA" {
    $rsa = [System.Security.Cryptography.RSA]::Create()
    try { $rsa.ImportFromPem($caseVariantPem) } finally { $rsa.Dispose() }
    ($caseVariantPem -cne $pemB.Trim()) -and ($caseVariantPem -ieq $pemB.Trim())
  }
  Assert-FinalizeRefused "finalize refuses an expected key that differs from an embedded key only in case" "not among the keys embedded" (New-Fixture) $accept @{ KeyFile = $caseKey }
  # Per-key RSA check: an ECDSA public key next to a valid RSA key
  $ecdsa = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve]::CreateFromFriendlyName("nistP256"))
  $mixedKeys = @([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($pemB.Trim())), [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($ecdsa.ExportSubjectPublicKeyInfoPem())))
  $ecdsa.Dispose()
  Assert-FinalizeRefused "finalize refuses an embedded and pending key list with a non-RSA key" "malformed manifest public key" (New-Fixture -Keys $mixedKeys) $accept
  foreach ($output in @("$assetBase.zip","$assetBase.sbom.json", "$assetBase.provenance.json")) {
    $f = New-Fixture; Remove-Item -LiteralPath (Join-Path $f.Publish $output)
    Assert-FinalizeRefused "finalize with $output deleted refuses and publishes nothing" "Release output was not found" $f $accept
  }
  Check "metadata keys are case-sensitive; a case variant is not a repeated key" {
    $caseDll = Join-Path $work "case.dll"
    New-MetadataAssembly -Path $caseDll -AssemblyName "Case" -Pairs @(@("AgentReleaseChannel", "stable"), @("agentreleasechannel", "beta"))
    $m = Read-AssemblyMetadataValues $caseDll
    $m.Count -eq 2 -and $m["AgentReleaseChannel"] -ceq "stable"
  }

  # CNG flow: the declared lists must equal what the build embeds
  $cng = New-Fixture
  $cngRuntime = Join-Path $cng.Publish "runtime"
  function Invoke-CngCheck([string[]]$Keys = $keyListB64, [string[]]$Pins = @($pin), [string[]]$Prefixes = @($prefix), [string]$Channel = "stable") {
    New-CngSignedManifest -Canonical $cng.Canonical -Certificate $certB -RuntimeDir $cngRuntime -Channel $Channel -ArtifactPrefixes $Prefixes -KeyListB64 $Keys -SignerPins $Pins
  }
  Check "CNG self-check accepts declared values equal to the embedded ones" { (Invoke-CngCheck)["version"] -ceq "9.9.9" }
  Check "CNG self-check refuses declared keys that differ from the embedded keys" { Throws { Invoke-CngCheck -Keys $keysAOnly } "Declared manifest keys do not match" }
  Check "CNG self-check refuses declared pins that differ from the embedded pins" { Throws { Invoke-CngCheck -Pins @($pinB) } "Declared signer pins do not match" }
  Check "CNG self-check refuses declared prefixes that differ from the embedded prefixes" { Throws { Invoke-CngCheck -Prefixes @($otherPrefix) } "Declared artifact prefixes do not match" }
  Check "CNG self-check refuses a channel that differs from the embedded channel" { Throws { Invoke-CngCheck -Channel "beta" } "Embedded release channel does not match" }

  Check "CNG self-check refuses an embedded and declared channel 'Stable'" {
    $upper = New-Fixture -Options @{ EmbeddedChannel = "Stable" }
    Throws { New-CngSignedManifest -Canonical $upper.Canonical -Certificate $certB -RuntimeDir (Join-Path $upper.Publish "runtime") -Channel "Stable" `
      -ArtifactPrefixes @($prefix) -KeyListB64 $keyListB64 -SignerPins @($pin) } "must be lowercase dev, preview or stable"
  }
  Check "CNG trust check refuses before the token is asked to sign" {
    & {
      function Sign-ManifestPayloadWithCertificate { throw "token was asked to sign" }
      Throws { Invoke-CngCheck -Keys $keysAOnly } "Declared manifest keys do not match"
    }
  }

  # Token initialization with an extra manifest key (certificate lookup stubbed; no certificate store)
  function Find-CertificateByThumbprint([string]$Thumbprint) { return $certA }
  $tokenInit = Initialize-TokenSigning -SigningPlan ([pscustomobject]@{ ManifestSigning = "External" }) -SigningCertThumbprint $thumbprint `
    -ManifestSigningPublicKeyFile $keyB -ExtraManifestPublicKeyFiles @($keyA)
  Check "token init: two manifest keys give a flat two-element key list" { $tokenInit.KeyListB64.Count -eq 2 -and $tokenInit.KeyListB64[0] -is [string] }
  Check "token init: the MSBuild key list value separates the keys with an escaped comma" { (ConvertTo-MsBuildListValue $tokenInit.KeyListB64) -match "%2C" }
  Check "token init: the pending state carries two public keys" {
    $pendingDir = Join-Path $work "pending-init"; New-Item -ItemType Directory -Path $pendingDir | Out-Null
    Write-PendingExternalManifest -PublishDir $pendingDir -AssetBase $assetBase -Canonical "x" -KeyListB64 $tokenInit.KeyListB64 -ArtifactPrefixes @($prefix) -SignerPins @($pin) 6>$null
    @((Get-Content -Raw -LiteralPath (Join-Path $pendingDir $pendingName) | ConvertFrom-Json).public_keys_b64).Count -eq 2
  }

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
    # A failure here (for example signtool.exe missing) must show the child's error text, not only the case name.
    if ($r.ExitCode -ne 0 -and ($r.Text -match "Authenticode") -and (Test-NothingPublished $childPublish)) { return $true }
    $tail = (($r.Text -split "\r?\n" | Where-Object { $_.Trim() } | Select-Object -Last 4) -join " | ")
    throw "exit $($r.ExitCode); child output: $tail"
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
  foreach ($badChannel in @("Stable", "sta$([char]0xAD)ble")) {
    $r = Invoke-Release @("-Version", "9.9.9", "-Channel", $badChannel, "-OutputRoot", $outRoot)
    Check "script: -Channel '$($badChannel -replace [char]0xAD, '<U+00AD>')' is refused at binding before any output" {
      $r.ExitCode -ne 0 -and ($r.Text -match "must be lowercase dev, preview or stable") -and -not (Test-Path -LiteralPath $outRootFull)
    }
  }
} finally {
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $outRootFull -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "failures=$script:failures"
exit $script:failures
