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

  # Two-step external path through the real build script (finalize step), fixture publish directory
  $payloadName = "Cerberus.Agent.Bundle-stable-9.9.9.update-manifest.v2.payload.bin"
  $pendingName = "Cerberus.Agent.Bundle-stable-9.9.9.update-manifest.v2.pending.json"
  $manifestName = "Cerberus.Agent.Bundle-stable-9.9.9.update-manifest.v2.json"
  function Reset-Fixture([string]$PayloadText) {
    Remove-Item -LiteralPath $outRootFull -Recurse -Force -ErrorAction SilentlyContinue
    $publish = Join-Path $outRootFull "publish"
    New-Item -ItemType Directory -Path (Join-Path $publish "runtime") -Force | Out-Null
    Copy-Item -LiteralPath $CoreDll -Destination (Join-Path $publish "runtime/Cerberus.Agent.Core.dll")
    foreach ($file in @("Cerberus.Agent-stable-9.9.9.msi", "Cerberus.Agent.Bundle-stable-9.9.9.zip",
        "Cerberus.Agent.Bundle-stable-9.9.9.sbom.json", "Cerberus.Agent.Bundle-stable-9.9.9.provenance.json")) {
      Set-Content -LiteralPath (Join-Path $publish $file) -Value "fixture $file"
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($PayloadText)
    $keyList = ConvertTo-ManifestPublicKeyListB64 @($pemA, $pemB)
    [IO.File]::WriteAllBytes((Join-Path $publish $payloadName), $bytes)
    [ordered]@{
      schema = "cerberus.agent.manifest_pending.v1"
      payload_sha256 = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
      public_keys_b64 = @($keyList)
      allowed_artifact_prefixes = @($prefix)
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $publish $pendingName) -Encoding utf8
    return $publish
  }
  function Invoke-Finalize([string]$SignatureValue, [string]$KeyFile) {
    $signatureFile = Join-Path $work "manifest.sig"
    if ($SignatureValue -ne "<none>") { Set-Content -LiteralPath $signatureFile -Value $SignatureValue } else { Remove-Item -LiteralPath $signatureFile -ErrorAction SilentlyContinue }
    Invoke-Release @("-Version", "9.9.9", "-Channel", "stable", "-OutputRoot", $outRoot, "-SigningMode", "Token",
      "-ManifestSigningPublicKeyFile", $KeyFile, "-ManifestSignatureFile", $signatureFile)
  }

  $publish = Reset-Fixture $canonical
  $result = Invoke-Finalize ($signature -replace '(.{64})', "`$1`n") $keyB
  Check "finalize with a good detached signature writes the manifest and gate" {
    $m = Join-Path $publish $manifestName
    $result.ExitCode -eq 0 -and (Test-Path -LiteralPath $m) -and
      (Test-Path -LiteralPath (Join-Path $publish "Cerberus.Agent.Bundle-stable-9.9.9.release-gate.json")) -and
      (Test-Path -LiteralPath (Join-Path $publish "Cerberus.Agent.Bundle-stable-latest.update-manifest.v2.json")) -and
      ((Get-Content -Raw -LiteralPath $m | ConvertFrom-Json).signature -ceq $signature)
  }
  Check "finalize removes the pending payload and state" {
    -not (Test-Path -LiteralPath (Join-Path $publish $payloadName)) -and -not (Test-Path -LiteralPath (Join-Path $publish $pendingName))
  }
  Check "finalized manifest is accepted by the agent verifier" {
    $written = Get-Content -Raw -LiteralPath (Join-Path $publish $manifestName)
    Assert-ManifestAcceptedByAgentVerifier -ManifestJson $written -PublicKeyPems @($pemB) -Channel stable -ArtifactPrefixes @($prefix) -ExpectedCanonicalPayload $canonical; $true
  }

  function Assert-FinalizeRefused([string]$Name, [string]$Pattern, [scriptblock]$Arrange) {
    $dir = Reset-Fixture $canonical
    $args2 = & $Arrange $dir
    $r = Invoke-Finalize $args2.Signature $args2.KeyFile
    Check $Name {
      $r.ExitCode -ne 0 -and ($r.Text -match $Pattern) -and
        -not (Test-Path -LiteralPath (Join-Path $dir $manifestName)) -and
        -not (Test-Path -LiteralPath (Join-Path $dir "Cerberus.Agent.Bundle-stable-9.9.9.release-gate.json")) -and
        (Test-Path -LiteralPath (Join-Path $dir $payloadName))
    }
  }
  $wrongKeySignature = Sign-ManifestPayloadWithCertificate -CanonicalPayload $canonical -Certificate $certA
  Assert-FinalizeRefused "finalize refuses a signature made by another key" "rejected by the agent verifier" {
    param($dir) @{ Signature = $wrongKeySignature; KeyFile = $keyB } }
  Assert-FinalizeRefused "finalize refuses a changed payload" "payload hash" {
    param($dir) [IO.File]::WriteAllBytes((Join-Path $dir $payloadName), [Text.Encoding]::UTF8.GetBytes($canonical + "x")); @{ Signature = $signature; KeyFile = $keyB } }
  Assert-FinalizeRefused "finalize refuses an expected key that is not embedded" "not among the keys embedded" {
    param($dir) $other = Join-Path $work "other.pem"; Set-Content -LiteralPath $other -Value (Get-RsaPublicKeyPem (New-TestCertificate)); @{ Signature = $signature; KeyFile = $other } }
  Assert-FinalizeRefused "finalize refuses a signature that is not base64" "base64" {
    param($dir) @{ Signature = "not base64 !!"; KeyFile = $keyB } }
  Assert-FinalizeRefused "finalize refuses a missing signature file" "signature file was not found" {
    param($dir) @{ Signature = "<none>"; KeyFile = $keyB } }
  Assert-FinalizeRefused "finalize refuses a missing public key file" "Manifest public key file was not found" {
    param($dir) @{ Signature = $signature; KeyFile = (Join-Path $work "missing.pem") } }

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
