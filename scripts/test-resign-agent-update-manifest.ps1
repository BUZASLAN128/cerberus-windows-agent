# Support-tier end-to-end checks for scripts/resign-agent-update-manifest.ps1. Keys and certificates are generated
# in memory at test time; no hardware token, certificate store or network is used. Needs the Release build of
# Cerberus.Agent.Core.dll (agent validator). Exit code = number of failed checks.
param([string]$CoreDll = "")
$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($CoreDll)) { $CoreDll = Join-Path $repoRoot "src/Cerberus.Agent.Core/bin/Release/net10.0/Cerberus.Agent.Core.dll" }
if (-not (Test-Path -LiteralPath $CoreDll -PathType Leaf)) { throw "Build the solution in Release first (agent verifier assembly not found: $CoreDll)." }
$CoreDll = (Resolve-Path -LiteralPath $CoreDll).Path
. (Join-Path $PSScriptRoot "release-signing-lib.ps1")
. (Join-Path $PSScriptRoot "release-trust-lib.ps1")
$resign = Join-Path $PSScriptRoot "resign-agent-update-manifest.ps1"

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
    "CN=resign-test", $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
  return $request.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddDays(30))
}

$work = Join-Path ([IO.Path]::GetTempPath()) ("cerberus-resign-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $work | Out-Null
$certA = New-TestCertificate
$certB = New-TestCertificate
try {
  $keyA = Join-Path $work "a.pem"; Set-Content -LiteralPath $keyA -Value (Get-RsaPublicKeyPem $certA)
  $keyB = Join-Path $work "b.pem"; Set-Content -LiteralPath $keyB -Value (Get-RsaPublicKeyPem $certB)
  $pin = Get-SignerSpkiPin $certA
  $now = [DateTimeOffset]::UtcNow
  $prefix = "https://releases.example/download/preview-latest/"
  $sha = ("ab" * 32)

  function New-Input([string]$Name, [hashtable]$Override = @{}, [System.Security.Cryptography.X509Certificates.X509Certificate2]$Signer = $certA, [bool]$Resign = $true) {
    $f = [ordered]@{
      schema_version = "agent.update.manifest.v2"; artifact_kind = "msi"; version = "0.2.1013"; channel = "preview"
      artifact_url = "${prefix}Cerberus.Agent-preview-0.2.1013-server.msi"; sha256 = $sha; signing_identity = "Cerberus Agent Release"
      released_at_utc = $now.AddDays(-10).UtcDateTime.ToString("O"); minimum_protocol_version = "agent.heartbeat.v1"; rollback_allowed = $false
      sequence = $now.AddDays(-10).ToUnixTimeMilliseconds(); expires_at_utc = $now.AddDays(20).UtcDateTime.ToString("O")
      artifact_length = 123456; signer_key_identity = $pin; signature = ""
    }
    foreach ($k in $Override.Keys) { $f[$k] = $Override[$k] }
    $canonical = ConvertTo-CanonicalForTest $f
    $f["signature"] = Sign-ManifestPayloadWithCertificate -CanonicalPayload $canonical -Certificate $Signer
    $path = Join-Path $work "$Name.json"
    $f | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding utf8
    return $path
  }
  function ConvertTo-CanonicalForTest($f) {
    @($f.artifact_kind, $f.version, $f.channel, $f.artifact_url, $f.sha256, $f.signing_identity, $f.released_at_utc, $f.minimum_protocol_version,
      ($f.rollback_allowed.ToString().ToLowerInvariant()), $f.schema_version, ([string]$f.sequence), $f.expires_at_utc, ([string]$f.artifact_length), $f.signer_key_identity) -join "`n"
  }
  function Edit-Json([string]$Path, [string]$Name, $Value) {
    $o = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable -DateKind String
    $o[$Name] = $Value
    $tampered = Join-Path $work ("t-" + [guid]::NewGuid().ToString("N").Substring(0, 6) + ".json")
    $o | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tampered -Encoding utf8
    return $tampered
  }
  function Invoke-Resign([string]$In, [hashtable]$Extra = @{}) {
    $out = Join-Path $work ("out-" + [guid]::NewGuid().ToString("N").Substring(0, 6) + ".json")
    $args = @{ ManifestPath = $In; PublicKeyFile = $keyA; OutputPath = $out; SigningCertificate = $certA; CoreAssembly = $CoreDll
      AllowFailedAgentsToRetry = $true }
    foreach ($k in $Extra.Keys) { $args[$k] = $Extra[$k] }
    $null = & $resign @args 6>$null
    return $out
  }
  function Read-Manifest([string]$Path) { Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable -DateKind String }
  function Test-NoOutput([scriptblock]$Run, [string]$Pattern) {
    $before = @(Get-ChildItem -LiteralPath $work -Filter "out-*.json").Count
    (Throws $Run $Pattern) -and (@(Get-ChildItem -LiteralPath $work -Filter "out-*.json").Count -eq $before)
  }

  $source = New-Input "source"
  $oldM = Read-Manifest $source
  $outPath = Invoke-Resign $source
  $newM = Read-Manifest $outPath
  Check "all fields except sequence, released_at, expires_at and signature are preserved" {
    $same = $oldM.Keys | Where-Object { $_ -notin "sequence", "released_at_utc", "expires_at_utc", "signature" }
    $newM.Count -eq $oldM.Count -and -not @($same | Where-Object { $newM[$_] -cne $oldM[$_] })
  }
  Check "sequence is strictly higher and within the agent's range" {
    $newM.sequence -gt $oldM.sequence -and $newM.sequence -le ([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() + 60000)
  }
  Check "released_at is now and expires_at is 30 days later" {
    $released = [DateTimeOffset]::Parse($newM.released_at_utc); $expires = [DateTimeOffset]::Parse($newM.expires_at_utc)
    ([DateTimeOffset]::UtcNow - $released).TotalMinutes -lt 5 -and ($expires - $released) -eq [TimeSpan]::FromDays(30) -and $expires -gt [DateTimeOffset]::Parse($oldM.expires_at_utc)
  }
  Check "the new signature verifies independently against the pinned key and differs from the old one" {
    $rsa = [System.Security.Cryptography.RSA]::Create(); $rsa.ImportFromPem((Get-Content -LiteralPath $keyA -Raw))
    try { $rsa.VerifyData([Text.Encoding]::UTF8.GetBytes((ConvertTo-CanonicalForTest $newM)), [Convert]::FromBase64String($newM.signature), "SHA256", [System.Security.Cryptography.RSASignaturePadding]::Pkcs1) -and $newM.signature -cne $oldM.signature }
    finally { $rsa.Dispose() }
  }
  Check "the output is accepted by the agent validator" {
    Import-AgentManifestVerifier $CoreDll
    Assert-ManifestAcceptedByAgentVerifier -ManifestJson (Get-Content -LiteralPath $outPath -Raw) -PublicKeyPems @((Get-RsaPublicKeyPem $certA)) -Channel preview -ArtifactPrefixes @($prefix) -ExpectedCanonicalPayload (ConvertTo-CanonicalForTest $newM); $true
  }
  Check "an explicit higher sequence is used" {
    $seq = $oldM.sequence + 5000
    (Read-Manifest (Invoke-Resign $source @{ Sequence = $seq })).sequence -eq $seq
  }
  Check "an already expired input is refreshed" {
    $expired = New-Input "expired" @{ released_at_utc = $now.AddDays(-40).UtcDateTime.ToString("O"); expires_at_utc = $now.AddDays(-10).UtcDateTime.ToString("O") }
    [DateTimeOffset]::Parse((Read-Manifest (Invoke-Resign $expired)).expires_at_utc) -gt [DateTimeOffset]::UtcNow.AddDays(29)
  }

  Check "refused: tampered artifact hash (stale signature), nothing written" {
    Test-NoOutput { Invoke-Resign (Edit-Json $source "sha256" ("cd" * 32)) } "does not verify against the pinned public key"
  }
  Check "refused: tampered artifact URL (stale signature)" {
    Test-NoOutput { Invoke-Resign (Edit-Json $source "artifact_url" "${prefix}evil.msi") } "does not verify"
  }
  Check "refused: input signed by another key" {
    Test-NoOutput { Invoke-Resign (New-Input "otherkey" @{} $certB) } "does not verify"
  }
  Check "refused: retry by failed agents not acknowledged" {
    Test-NoOutput { Invoke-Resign $source @{ AllowFailedAgentsToRetry = $false } } "AllowFailedAgentsToRetry"
  }
  Check "refused: explicit sequence equal to the input" { Test-NoOutput { Invoke-Resign $source @{ Sequence = $oldM.sequence } } "must be higher" }
  Check "refused: explicit sequence lower than the input" { Test-NoOutput { Invoke-Resign $source @{ Sequence = $oldM.sequence - 1 } } "must be higher" }
  Check "refused: input sequence too far ahead for a higher one" {
    $ahead = New-Input "ahead" @{ sequence = $now.AddDays(2).ToUnixTimeMilliseconds() }
    Test-NoOutput { Invoke-Resign $ahead } "sequence must be positive and at most 24 hours ahead"
  }
  Check "refused: signing certificate does not match the pinned key" {
    Test-NoOutput { Invoke-Resign $source @{ SigningCertificate = $certB } } "does not match the pinned public key"
  }
  Check "refused: pinned key file is another key" { Test-NoOutput { Invoke-Resign $source @{ PublicKeyFile = $keyB } } "does not verify" }
  Check "refused: manifest with an extra field" {
    $extra = Edit-Json $source "extra_field" "x"
    Test-NoOutput { Invoke-Resign $extra } "differ from the v2 field set"
  }
  Check "refused: output path already exists" { Throws { Invoke-Resign $source @{ OutputPath = $source } } "new file" }
} finally {
  $certA.Dispose(); $certB.Dispose()
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "failures=$script:failures"
exit $script:failures
