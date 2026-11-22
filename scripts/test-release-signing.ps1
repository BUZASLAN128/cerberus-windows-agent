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

. (Join-Path $PSScriptRoot "test-release-signing-continuity.ps1")

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
$fixtureRepo = Join-Path $work 'repo'
$fixtureScripts = Join-Path $fixtureRepo 'scripts'
$mainScript = Join-Path $fixtureScripts 'build-agent-public-release.ps1'
$outRoot = 'out/test-release-signing'
$outRootFull = Join-Path $fixtureRepo $outRoot
try {
  # Run both finalize entry points from an isolated source tree.
  $fixtureCore = Join-Path $fixtureRepo 'src/Cerberus.Agent.Core'
  New-Item -ItemType Directory -Path $fixtureScripts, $fixtureCore -Force | Out-Null
  Copy-Item -Path (Join-Path $PSScriptRoot '*.ps1') -Destination $fixtureScripts
  Copy-Item -LiteralPath (Join-Path $repoRoot 'Directory.Build.props') -Destination $fixtureRepo
  Copy-Item -LiteralPath (Join-Path $repoRoot 'src/Cerberus.Agent.Core/AgentSingleFileBundle.cs') -Destination $fixtureCore
  . (Join-Path $fixtureScripts 'release-publish-lib.ps1')
  . (Join-Path $fixtureScripts 'release-token-lib.ps1')

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
  . (Join-Path $PSScriptRoot "test-release-signing-token.ps1")
  . (Join-Path $PSScriptRoot "test-release-signing-anchors.ps1")
  Check "hash and timestamp flags match the PFX path" {
    $text = (Get-Command Invoke-FirstPartySigning -CommandType Function).ScriptBlock.ToString()
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

  . (Join-Path $PSScriptRoot "test-release-signing-finalize-fixtures.ps1")

  # Bind the pending payload to the trust values embedded in all three assemblies.
  $pinB = Get-SignerSpkiPin $certB
  $keysAOnlyList = ConvertTo-ManifestPublicKeyListB64 @($pemA)
  $keysAOnly = @($keysAOnlyList)
  $otherPrefix = "https://other.example/package/"
  function Get-Pairs([string[]]$Keys = $keyListB64, [string[]]$Pins = @($pin), [string]$Prefix = $prefix, [string]$Channel = "stable") {
    Get-TrustPairs -Keys $Keys -Pins $Pins -Prefix $Prefix -Channel $Channel
  }
  $allAssemblies = { param($Pairs) @{ AgentPairs = $Pairs; RuntimePairs = $Pairs; UpdaterPairs = $Pairs } }
  Assert-FinalizeRefused "finalize refuses pending keys that differ from the embedded keys" "Pending manifest keys do not match" (New-Fixture -Options (& $allAssemblies (Get-Pairs -Keys $keysAOnly))) $accept
  Assert-FinalizeRefused "finalize refuses pending signer pins that differ from the embedded pins" "Pending signer pins do not match" (New-Fixture -Options (& $allAssemblies (Get-Pairs -Pins @($pinB)))) $accept
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
  Assert-FinalizeRefused "finalize refuses embedded keys joined by a space (single unusable entry)" "malformed manifest public key" (New-Fixture -Options (& $allAssemblies (Get-Pairs -Keys @($keyListB64 -join " ")))) $accept
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
  foreach ($label in "AgentPairs", "RuntimePairs", "UpdaterPairs") {
    $unsigned = @{ $label = (@(Get-Pairs) + ,@("AllowUnsignedDevBuild", "true")) }
    Assert-FinalizeRefused "finalize refuses AllowUnsignedDevBuild=true in $label" "carries AllowUnsignedDevBuild='true'" (New-Fixture -Options $unsigned) $accept
  }
  Assert-FinalizeRefused "finalize refuses an AllowUnsignedDevBuild value that is not a boolean" "carries AllowUnsignedDevBuild='x'" (New-Fixture -Options @{
    RuntimePairs = (@(Get-Pairs) + ,@("AllowUnsignedDevBuild", "x")) }) $accept
  $sameUrl = @(Get-Pairs) + ,$urlA + ,@("AllowUnsignedDevBuild", "False")
  $withUrl = New-Fixture -Options (& $allAssemblies $sameUrl)
  Invoke-Finalize $withUrl $recordAll
  Check "finalize accepts one shared manifest URL and AllowUnsignedDevBuild=False" { Test-Path -LiteralPath (Join-Path $withUrl.Publish $manifestName) }
  Assert-FinalizeRefused "finalize refuses a runtime assembly with a repeated metadata key" "Duplicate assembly metadata key 'AgentReleaseChannel'" (New-Fixture -Options @{
    RuntimePairs = @(Get-Pairs) + ,@("AgentReleaseChannel", "stable") }) $accept
  Assert-FinalizeRefused "finalize ignores metadata attributes outside System.Reflection" "carries no manifest public key" (New-Fixture -Options @{ RuntimeNamespace = "Fixture.Other" }) $accept
  Assert-FinalizeRefused "finalize refuses runtime keys that differ from the app assembly" "embed different PublicKeyPems" (New-Fixture -Options @{ RuntimePairs = (Get-Pairs -Keys $keysAOnly) }) $accept
  Assert-FinalizeRefused "finalize refuses runtime signer pins that differ from the app assembly" "embed different SignerPins" (New-Fixture -Options @{ RuntimePairs = (Get-Pairs -Pins @($pinB)) }) $accept
  Assert-FinalizeRefused "finalize refuses runtime prefixes that differ from the app assembly" "embed different ArtifactPrefixes" (New-Fixture -Options @{ RuntimePairs = (Get-Pairs -Prefix $otherPrefix) }) $accept
  Assert-FinalizeRefused "finalize refuses a runtime channel that differs from the app assembly" "embed different release channels" (New-Fixture -Options @{ RuntimePairs = (Get-Pairs -Channel "beta") }) $accept
  $updaterDifferences = [ordered]@{
    PublicKeyPems = (Get-Pairs -Keys $keysAOnly)
    SignerPins = (Get-Pairs -Pins @($pinB))
    ArtifactPrefixes = (Get-Pairs -Prefix $otherPrefix)
    'release channels' = (Get-Pairs -Channel 'preview')
    'update manifest URLs' = (@(Get-Pairs) + ,$urlB)
  }
  foreach ($different in $updaterDifferences.GetEnumerator()) {
    $f = New-Fixture -Options @{ UpdaterPairs = $different.Value }
    Assert-FinalizeRefused "finalize refuses Updater.dll-only mismatch in $($different.Key)" `
      "Cerberus\.Agent\.Updater\.dll embed different $($different.Key)" $f $accept
  }
  # Two signer pins: every signature check must receive both
  $script:checkedPins = @()
  $twoPinError = $null
  try { Invoke-Finalize (New-Fixture -Options @{ ExtraPins = @($pinB) }) $recordAll } catch { $twoPinError = $_.Exception.Message }
  Check "finalize with two embedded signer pins is accepted" { if ($twoPinError) { throw $twoPinError }; $true }
  Check "finalize hands both embedded signer pins to every signature check" {
    $want = (@($pin, $pinB) | Sort-Object) -join "|"
    $script:checkedPins.Count -eq $expectedChecks -and
      (@($script:checkedPins | Where-Object { ((($_ -split '\|') | Sort-Object) -join "|") -ceq $want }).Count -eq $expectedChecks)
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
  Check 'unsigned dev build passes its runtime gates' {
    $devPairs = @(Get-Pairs -Channel dev -Pins @('unsigned-dev')) + ,@('AllowUnsignedDevBuild', 'true')
    $dev = New-Fixture -Options (& $allAssemblies $devPairs)
    $devRuntime = Join-Path $dev.Publish 'runtime'
    $depsName = 'Cerberus.Agent.Updater.deps.json'
    Set-Content -LiteralPath (Join-Path $devRuntime $depsName) -Value `
      '{"libraries":{"Cerberus.Agent.Updater/1.0":{},"Cerberus.Agent.Core/1.0":{}}}'
    # Supply runtime outputs at the compiler boundary and stop when the real dev path reaches packaging.
    function dotnet {
      if ($args[0] -cne 'publish') { throw 'Unexpected compiler command in unsigned dev fixture.' }
      if ([IO.Path]::GetFileName($args[1]) -ceq 'Cerberus.Agent.Installer.Helper.csproj') {
        throw 'Unsigned dev fixture reached installer helper publish.'
      }
      $outputArg = [array]::IndexOf($args, '-o')
      $output = Join-Path $fixtureRepo 'out/unsigned-dev-fixture/publish/runtime'
      if ($outputArg -lt 0 -or [IO.Path]::GetFullPath($args[$outputArg + 1]) -cne [IO.Path]::GetFullPath($output)) {
        throw 'Unexpected runtime output path in unsigned dev fixture.'
      }
      if (-not (Test-Path -LiteralPath (Join-Path $output $depsName))) {
        Copy-Item -Path (Join-Path $devRuntime '*') -Destination $output -Recurse
      }
      Set-Variable -Name LASTEXITCODE -Value 0 -Scope 1
    }
    $previousActions = $env:GITHUB_ACTIONS
    $previousArtifactBase = $env:AGENT_RELEASE_ARTIFACT_BASE_URL
    try {
      $env:GITHUB_ACTIONS = $null
      $env:AGENT_RELEASE_ARTIFACT_BASE_URL = $prefix
      try {
        & $mainScript -Version '9.9.9' -Channel dev -OutputRoot 'out/unsigned-dev-fixture' -SkipTests `
          -AllowUnsignedDevBuild -AllowEphemeralManifestKey -UpdateAllowedArtifactPrefixes $prefix 6>$null | Out-Null
      } catch {
        if ($_.Exception.Message -cne 'Unsigned dev fixture reached installer helper publish.') { throw }
        return $true
      }
      $false
    } finally {
      $env:GITHUB_ACTIONS = $previousActions
      $env:AGENT_RELEASE_ARTIFACT_BASE_URL = $previousArtifactBase
    }
  }
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
  $previousActions = $env:GITHUB_ACTIONS
  try {
    $env:GITHUB_ACTIONS = $null
    $r = Invoke-Release $finalizeArgs
  } finally {
    $env:GITHUB_ACTIONS = $previousActions
  }
  Check "script: finalize on an unsigned fixture MSI is refused by the real signature check" {
    # A failure here (for example signtool.exe missing) must show the child's error text, not only the case name.
    if ($r.ExitCode -ne 0 -and ($r.Text -match "Authenticode") -and (Test-NothingPublished $childPublish)) { return $true }
    $tail = (($r.Text -split "\r?\n" | Where-Object { $_.Trim() } | Select-Object -Last 4) -join " | ")
    throw "exit $($r.ExitCode); child output: $tail"
  }

  # Pfx path: a legacy manifest is still written and aliased
  $pfxFixture = New-Fixture
  $pfxManifest = [ordered]@{ sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $pfxFixture.Msi).Hash.ToLowerInvariant(); sequence = 1; expires_at_utc = "2030-01-01T00:00:00Z"; signer_key_identity = $pin
    version = "9.9.9"; artifact_url = "https://feed.example.test/stable/$installerBase.msi"; artifact_length = (Get-Item -LiteralPath $pfxFixture.Msi).Length }
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
