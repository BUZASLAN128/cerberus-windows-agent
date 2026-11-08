# Refreshes the expiry of a published signed v2 update manifest without rebuilding the release.
# The new manifest keeps version, channel, artifact URL, sha256, length and every other field; only sequence,
# released_at_utc, expires_at_utc and the signature change. Agents that installed this version do not reinstall it;
# agents whose install of it failed (FailedInstallSequence pin) retry it, so -AllowFailedAgentsToRetry is required.
# The input signature is verified against the pinned public key first, and the new signature is verified again
# (RSA and the agent's own validator) before anything is written. Signing goes through the existing certificate path
# (CurrentUser\My, hardware token: Windows asks for the PIN/touch); this script never reads or logs a PIN or key material.
# Copy the output over the versioned and the Cerberus.Agent.Bundle-<channel>-latest*.update-manifest.v2.json assets when publishing.
param(
  [Parameter(Mandatory = $true)][string]$ManifestPath,
  # Pinned release manifest public key (PEM public key or X.509 certificate), the one embedded in the shipped agents.
  [Parameter(Mandatory = $true)][string]$PublicKeyFile,
  [Parameter(Mandatory = $true)][string]$OutputPath,
  [string]$SigningCertThumbprint = "",
  # Test seam for an in-memory certificate; the release operator uses -SigningCertThumbprint.
  [System.Security.Cryptography.X509Certificates.X509Certificate2]$SigningCertificate = $null,
  # Defaults to the directory part of the manifest's artifact_url.
  [string[]]$ArtifactPrefixes = @(),
  # Explicit sequence; must be strictly higher than the input's. Default: max(now in Unix ms, input + 1).
  [long]$Sequence = 0,
  # Acknowledges that agents whose install of this version failed will try it again.
  [switch]$AllowFailedAgentsToRetry,
  [string]$CoreAssembly = ""
)
$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSEdition -ne "Core") { throw "PowerShell 7+ (pwsh) is required for manifest signing." }
. (Join-Path $PSScriptRoot "release-signing-lib.ps1")
. (Join-Path $PSScriptRoot "release-trust-lib.ps1")
if ([string]::IsNullOrWhiteSpace($CoreAssembly)) {
  $CoreAssembly = Join-Path $PSScriptRoot "../src/Cerberus.Agent.Core/bin/Release/net10.0/Cerberus.Agent.Core.dll"
}
if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { throw "Manifest was not found: $ManifestPath" }
if ([IO.Path]::GetFullPath($OutputPath) -ceq [IO.Path]::GetFullPath($ManifestPath) -or (Test-Path -LiteralPath $OutputPath)) {
  throw "Output path must be a new file, not the input manifest: $OutputPath"
}
if ($null -eq $SigningCertificate -and [string]::IsNullOrWhiteSpace($SigningCertThumbprint)) {
  throw "Pass -SigningCertThumbprint (certificate in CurrentUser\My)."
}
if (-not $AllowFailedAgentsToRetry) {
  throw "A higher sequence makes agents whose install of this version failed and rolled back install it again. Check failed installs of this version first, then pass -AllowFailedAgentsToRetry."
}

# Read every value as the exact string in the file (no date coercion) and require exactly the v2 field set,
# so no field of the input can be dropped or reinterpreted.
$fieldNames = @("schema_version", "artifact_kind", "version", "channel", "artifact_url", "sha256", "signing_identity", "released_at_utc",
  "minimum_protocol_version", "rollback_allowed", "sequence", "expires_at_utc", "artifact_length", "signer_key_identity", "signature")
$document = [System.Text.Json.JsonDocument]::Parse([IO.File]::ReadAllText($ManifestPath))
$old = [ordered]@{}
try {
  $names = @($document.RootElement.EnumerateObject() | ForEach-Object { $_.Name })
  if ($names.Count -ne $fieldNames.Count -or (@($fieldNames | Where-Object { $names -cnotcontains $_ }).Count -gt 0)) {
    throw "Manifest fields differ from the v2 field set."
  }
  foreach ($name in $fieldNames) {
    $element = $document.RootElement.GetProperty($name)
    $old[$name] = switch ($name) {
      "rollback_allowed" { $element.GetBoolean() }
      { $_ -in "sequence", "artifact_length" } { $element.GetInt64() }
      default { $element.GetString() }
    }
  }
} finally { $document.Dispose() }
if ($old["schema_version"] -cne "agent.update.manifest.v2") { throw "Manifest is not agent.update.manifest.v2." }

function Get-CanonicalPayload($Fields) {
  # Same field order as the canonical payload in build-agent-public-release.ps1.
  return @($Fields["artifact_kind"], $Fields["version"], $Fields["channel"], $Fields["artifact_url"], $Fields["sha256"],
    $Fields["signing_identity"], $Fields["released_at_utc"], $Fields["minimum_protocol_version"],
    $(if ($Fields["rollback_allowed"]) { "true" } else { "false" }), $Fields["schema_version"],
    ([long]$Fields["sequence"]).ToString([Globalization.CultureInfo]::InvariantCulture), $Fields["expires_at_utc"],
    ([long]$Fields["artifact_length"]).ToString([Globalization.CultureInfo]::InvariantCulture), $Fields["signer_key_identity"]) -join "`n"
}

Write-Step "Verifying the input signature against the pinned public key"
$pinnedKeyPem = Read-ManifestPublicKeyFile $PublicKeyFile
$rsa = [System.Security.Cryptography.RSA]::Create()
try {
  $rsa.ImportFromPem($pinnedKeyPem)
  $signatureBytes = try { [Convert]::FromBase64String([string]$old["signature"]) } catch { throw "Input manifest signature is not base64." }
  if (-not $rsa.VerifyData([Text.Encoding]::UTF8.GetBytes((Get-CanonicalPayload $old)), $signatureBytes,
      [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)) {
    throw "Input manifest signature does not verify against the pinned public key."
  }
} finally { $rsa.Dispose() }

$now = [DateTimeOffset]::UtcNow
$newSequence = if ($Sequence -gt 0) { $Sequence } else { [Math]::Max($now.ToUnixTimeMilliseconds(), [long]$old["sequence"] + 1) }
if ($newSequence -le [long]$old["sequence"]) { throw "New sequence $newSequence must be higher than the input sequence $($old['sequence'])." }
Assert-ManifestSequenceInRange $newSequence $now
$releasedAt = $now.UtcDateTime.ToString("O")
$expiresAt = $now.UtcDateTime.AddDays($script:ManifestValidityDays).ToString("O")
Assert-ManifestValidityWindow ([DateTimeOffset]::Parse($releasedAt)) ([DateTimeOffset]::Parse($expiresAt))

$new = [ordered]@{}
foreach ($name in $fieldNames) { $new[$name] = $old[$name] }
$new["sequence"] = $newSequence
$new["released_at_utc"] = $releasedAt
$new["expires_at_utc"] = $expiresAt
$canonical = Get-CanonicalPayload $new

$certificate = if ($null -ne $SigningCertificate) { $SigningCertificate } else { Find-CertificateByThumbprint $SigningCertThumbprint }
try {
  # Checked before the token is asked to sign, so a wrong certificate does not cost a PIN entry.
  $normalize = { param($pem) ($pem -replace "`r", "").Trim() }
  if ((& $normalize (Get-RsaPublicKeyPem $certificate)) -cne (& $normalize $pinnedKeyPem)) {
    throw "The signing certificate does not match the pinned public key."
  }
  Write-Step "Signing the refreshed manifest (sequence $newSequence, expires $expiresAt)"
  $new["signature"] = Sign-ManifestPayloadWithCertificate -CanonicalPayload $canonical -Certificate $certificate
} finally {
  if ($null -eq $SigningCertificate) { $certificate.Dispose() }
}

Write-Step "Verifying the new signature with the agent validator"
$prefixes = if (@($ArtifactPrefixes).Count -gt 0) { @($ArtifactPrefixes) } else { @($old["artifact_url"].Substring(0, $old["artifact_url"].LastIndexOf('/') + 1)) }
Import-AgentManifestVerifier $CoreAssembly
$json = $new | ConvertTo-Json -Depth 8
Assert-ManifestAcceptedByAgentVerifier -ManifestJson $json -PublicKeyPems @($pinnedKeyPem) -Channel ([string]$old["channel"]) `
  -ArtifactPrefixes $prefixes -ExpectedCanonicalPayload $canonical
foreach ($name in $fieldNames) {
  if ($name -notin "sequence", "released_at_utc", "expires_at_utc", "signature" -and $new[$name] -cne $old[$name]) {
    throw "Field '$name' changed during re-signing."
  }
}
Set-Content -LiteralPath $OutputPath -Value $json -Encoding utf8
Write-Step "Refreshed manifest written: $OutputPath"
