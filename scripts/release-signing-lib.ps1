# Helpers for scripts/build-agent-public-release.ps1 token signing mode.
# Dot-source only. Loading this file has no side effects and never reads a certificate store.
# No function here prompts for, accepts or logs a PIN or password.

$script:ManifestValidityDays = 30
$script:ManifestMaxValidityDays = 45
$script:ManifestSequenceMaxLeadMilliseconds = 24L * 60 * 60 * 1000
$script:ManifestFieldCount = 14

function Get-SignerSpkiPin {
  param([Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
  # Same value as AgentUpdateAuthenticode.PublisherSpkiSha256.
  return "sha256:" + [Convert]::ToHexString(
    [System.Security.Cryptography.SHA256]::HashData($Certificate.PublicKey.ExportSubjectPublicKeyInfo())).ToLowerInvariant()
}

function ConvertTo-NormalizedSignerPins {
  param([string[]]$Pins)
  $result = New-Object System.Collections.Generic.List[string]
  foreach ($pin in @($Pins)) {
    if ([string]::IsNullOrWhiteSpace($pin)) { continue }
    $normalized = $pin.Trim().ToLowerInvariant()
    if ($normalized -notmatch '^sha256:[0-9a-f]{64}$') {
      throw "Signer pin must be 'sha256:' followed by 64 hex characters."
    }
    if (-not $result.Contains($normalized)) { $result.Add($normalized) }
  }
  return ,$result.ToArray()
}

function ConvertTo-NormalizedThumbprint {
  param([string]$Value)
  $clean = ([string]$Value) -replace "[\s$([char]0x200E)$([char]0x200F)]", ''
  if ($clean -notmatch '^[0-9A-Fa-f]{40}$') {
    throw "Certificate thumbprint must be 40 hexadecimal characters."
  }
  return $clean.ToUpperInvariant()
}

function ConvertTo-MsBuildEscapedValue {
  param([string]$Value)
  if ($null -eq $Value) { return "" }
  # MSBuild treats these characters as syntax; -p: also splits properties on ',' and ';'.
  return [regex]::Replace($Value, '[%*?@$();'',]', { param($m) '%{0:X2}' -f [int][char]$m.Value })
}

function ConvertTo-MsBuildListValue {
  param([string[]]$Items)
  # The agent parses embedded lists on ',' (and ';' for public keys), so the separator is an escaped comma.
  $escaped = foreach ($item in @($Items)) {
    if (-not [string]::IsNullOrWhiteSpace($item)) { ConvertTo-MsBuildEscapedValue $item.Trim() }
  }
  return (@($escaped) -join "%2C")
}

function Assert-ReleaseSigningInputs {
  param(
    [ValidateSet("Pfx", "Token")][string]$Mode = "Pfx",
    [string]$SigningCertThumbprint,
    [string]$ManifestSigningCertThumbprint,
    [string]$ManifestSigningPublicKeyFile,
    [string]$ManifestSignatureFile,
    [string[]]$ExtraSignerPins,
    [string[]]$ExtraManifestPublicKeyFiles,
    [bool]$PfxCertificatePresent = $false,
    [bool]$ManifestPrivateKeyPemPresent = $false,
    [bool]$AllowUnsignedDevBuild = $false,
    [bool]$AllowEphemeralManifestKey = $false
  )
  $tokenInputs = @(
    $SigningCertThumbprint, $ManifestSigningCertThumbprint, $ManifestSigningPublicKeyFile, $ManifestSignatureFile
  ) + @($ExtraSignerPins) + @($ExtraManifestPublicKeyFiles) |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

  if ($Mode -eq "Pfx") {
    if (@($tokenInputs).Count -gt 0) {
      throw "Token signing inputs were provided but -SigningMode is Pfx. Use -SigningMode Token or remove them."
    }
    return [pscustomobject]@{ Mode = "Pfx"; ManifestSigning = "Pfx"; Finalize = $false }
  }

  if ($PfxCertificatePresent -or $ManifestPrivateKeyPemPresent) {
    throw "Token mode cannot be combined with WINDOWS_SIGNING_CERT_BASE64 or AGENT_UPDATE_MANIFEST_PRIVATE_KEY_PEM. Unset them or use -SigningMode Pfx."
  }
  if ($AllowUnsignedDevBuild -or $AllowEphemeralManifestKey) {
    throw "Token mode always signs; -AllowUnsignedDevBuild and -AllowEphemeralManifestKey are not allowed."
  }

  $finalize = -not [string]::IsNullOrWhiteSpace($ManifestSignatureFile)
  if ($finalize) {
    if ([string]::IsNullOrWhiteSpace($ManifestSigningPublicKeyFile)) {
      throw "-ManifestSignatureFile requires -ManifestSigningPublicKeyFile (expected manifest public key)."
    }
    # Finalize takes exactly -ManifestSignatureFile and -ManifestSigningPublicKeyFile; trust comes from the built runtime.
    $refused = @()
    if (-not [string]::IsNullOrWhiteSpace($SigningCertThumbprint)) { $refused += "-SigningCertThumbprint" }
    if (-not [string]::IsNullOrWhiteSpace($ManifestSigningCertThumbprint)) { $refused += "-ManifestSigningCertThumbprint" }
    if (@($ExtraSignerPins | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) { $refused += "-ExtraSignerPins" }
    if (@($ExtraManifestPublicKeyFiles | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) { $refused += "-ExtraManifestPublicKeyFiles" }
    if ($refused.Count -gt 0) {
      throw "Finalize (-ManifestSignatureFile) accepts only -ManifestSigningPublicKeyFile and -ManifestSignatureFile. Remove: $($refused -join ', ')."
    }
    return [pscustomobject]@{ Mode = "Token"; ManifestSigning = "External"; Finalize = $true }
  }

  if ([string]::IsNullOrWhiteSpace($SigningCertThumbprint)) {
    throw "Token mode requires -SigningCertThumbprint (Authenticode certificate)."
  }
  [void](ConvertTo-NormalizedThumbprint $SigningCertThumbprint)
  $hasCng = -not [string]::IsNullOrWhiteSpace($ManifestSigningCertThumbprint)
  $hasExternal = -not [string]::IsNullOrWhiteSpace($ManifestSigningPublicKeyFile)
  if ($hasCng -eq $hasExternal) {
    throw "Token mode requires exactly one of -ManifestSigningCertThumbprint or -ManifestSigningPublicKeyFile (external signature)."
  }
  if ($hasCng) { [void](ConvertTo-NormalizedThumbprint $ManifestSigningCertThumbprint) }
  [void](ConvertTo-NormalizedSignerPins $ExtraSignerPins)
  foreach ($file in @($ManifestSigningPublicKeyFile) + @($ExtraManifestPublicKeyFiles)) {
    if (-not [string]::IsNullOrWhiteSpace($file) -and -not (Test-Path -LiteralPath $file -PathType Leaf)) {
      throw "Manifest public key file was not found: $file"
    }
  }
  return [pscustomobject]@{
    Mode = "Token"
    ManifestSigning = $(if ($hasCng) { "Cng" } else { "External" })
    Finalize = $false
  }
}

function Get-SignToolTokenSignArguments {
  param(
    [Parameter(Mandatory = $true)][string]$Thumbprint,
    [Parameter(Mandatory = $true)][string]$TimestampUrl,
    [Parameter(Mandatory = $true)][string]$FilePath
  )
  # Same hash/timestamp flags as the PFX path; the certificate is selected from the user store by thumbprint.
  return @("sign", "/fd", "SHA256", "/td", "SHA256", "/tr", $TimestampUrl, "/sha1", (ConvertTo-NormalizedThumbprint $Thumbprint), $FilePath)
}

function Find-CertificateByThumbprint {
  param([Parameter(Mandatory = $true)][string]$Thumbprint)
  $normalized = ConvertTo-NormalizedThumbprint $Thumbprint
  $store = [System.Security.Cryptography.X509Certificates.X509Store]::new("My", "CurrentUser")
  try {
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor
      [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
    $found = $store.Certificates.Find(
      [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $normalized, $false)
    if ($found.Count -ne 1) {
      throw "Certificate with thumbprint $normalized was not found in CurrentUser\My."
    }
    $certificate = $found[0]
    $now = [DateTime]::UtcNow
    if ($now -lt $certificate.NotBefore.ToUniversalTime() -or $now -gt $certificate.NotAfter.ToUniversalTime()) {
      throw "Certificate $normalized is outside its validity period."
    }
    return $certificate
  } finally {
    $store.Close()
  }
}

function Get-RsaPublicKeyPem {
  param([Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
  $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Certificate)
  if ($null -eq $rsa) { throw "Certificate does not contain an RSA public key." }
  try { return $rsa.ExportSubjectPublicKeyInfoPem() } finally { $rsa.Dispose() }
}

function Read-ManifestPublicKeyFile {
  param([Parameter(Mandatory = $true)][string]$Path)
  $bytes = [IO.File]::ReadAllBytes($Path)
  $text = [Text.Encoding]::UTF8.GetString($bytes)
  if ($text -match 'PRIVATE KEY') {
    throw "Manifest public key file must not contain private key material: $Path"
  }
  if ($text -match 'BEGIN PUBLIC KEY') {
    $rsa = [System.Security.Cryptography.RSA]::Create()
    try { $rsa.ImportFromPem($text); return $rsa.ExportSubjectPublicKeyInfoPem() } finally { $rsa.Dispose() }
  }
  try {
    $certificate = if ($text -match 'BEGIN CERTIFICATE') {
      [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($text)
    } else {
      [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
    }
  } catch {
    throw "Manifest public key file is not a PEM public key or X.509 certificate: $Path"
  }
  try { return Get-RsaPublicKeyPem $certificate } finally { $certificate.Dispose() }
}

function ConvertTo-ManifestPublicKeyListB64 {
  param([string[]]$PublicKeyPems)
  $seen = New-Object System.Collections.Generic.HashSet[string]
  $result = New-Object System.Collections.Generic.List[string]
  foreach ($pem in @($PublicKeyPems)) {
    if ([string]::IsNullOrWhiteSpace($pem)) { continue }
    $trimmed = $pem.Trim()
    if ($seen.Add($trimmed)) {
      $result.Add([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($trimmed)))
    }
  }
  if ($result.Count -eq 0) { throw "At least one manifest public key is required." }
  return ,$result.ToArray()
}

function Sign-ManifestPayloadWithCertificate {
  param(
    [Parameter(Mandatory = $true)][string]$CanonicalPayload,
    [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
  )
  # The key stays in the token/CSP; any PIN prompt is raised by Windows, never by this script.
  $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
  if ($null -eq $rsa) { throw "Certificate does not expose an RSA private key for manifest signing." }
  try {
    $signature = $rsa.SignData(
      [Text.Encoding]::UTF8.GetBytes($CanonicalPayload),
      [System.Security.Cryptography.HashAlgorithmName]::SHA256,
      [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    return [Convert]::ToBase64String($signature)
  } finally {
    $rsa.Dispose()
  }
}

function Assert-ManifestSequenceInRange {
  param([long]$Sequence, [DateTimeOffset]$UtcNow = [DateTimeOffset]::UtcNow)
  # Mirrors AgentUpdateSequenceStore.Accept.
  if ($Sequence -le 0 -or $Sequence -gt ($UtcNow.ToUnixTimeMilliseconds() + $script:ManifestSequenceMaxLeadMilliseconds)) {
    throw "Manifest sequence must be positive and at most 24 hours ahead of the current Unix-millisecond time."
  }
}

function Assert-ManifestValidityWindow {
  param([DateTimeOffset]$ReleasedAt, [DateTimeOffset]$ExpiresAt)
  if ($ExpiresAt - $ReleasedAt -gt [TimeSpan]::FromDays($script:ManifestMaxValidityDays)) {
    throw "Manifest validity window exceeds $($script:ManifestMaxValidityDays) days."
  }
}

function ConvertFrom-ManifestPayloadV2 {
  param([Parameter(Mandatory = $true)][string]$Canonical, [string]$Signature = "")
  $lines = $Canonical -split "`n"
  if ($lines.Count -ne $script:ManifestFieldCount -or $lines[9] -cne "agent.update.manifest.v2") {
    throw "Manifest payload is not a v2 canonical payload."
  }
  $manifest = [ordered]@{
    schema_version = $lines[9]
    artifact_kind = $lines[0]
    version = $lines[1]
    channel = $lines[2]
    artifact_url = $lines[3]
    sha256 = $lines[4]
    signing_identity = $lines[5]
    released_at_utc = $lines[6]
    minimum_protocol_version = $lines[7]
    rollback_allowed = ($lines[8] -ceq "true")
    sequence = [long]::Parse($lines[10], [Globalization.CultureInfo]::InvariantCulture)
    expires_at_utc = $lines[11]
    artifact_length = [long]::Parse($lines[12], [Globalization.CultureInfo]::InvariantCulture)
    signer_key_identity = $lines[13]
    signature = $Signature
  }
  return $manifest
}

function Import-AgentManifestVerifier {
  param([Parameter(Mandatory = $true)][string]$AssemblyPath)
  if (-not (Test-Path -LiteralPath $AssemblyPath -PathType Leaf)) {
    throw "Agent verifier assembly was not found: $AssemblyPath"
  }
  [void][System.Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
  if (-not ("Cerberus.Agent.Core.AgentUpdateManifestValidator" -as [type])) {
    throw "Agent manifest verifier type was not found in $AssemblyPath"
  }
}

function Assert-ManifestAcceptedByAgentVerifier {
  param(
    [Parameter(Mandatory = $true)][string]$ManifestJson,
    [Parameter(Mandatory = $true)][string[]]$PublicKeyPems,
    [Parameter(Mandatory = $true)][string]$Channel,
    [Parameter(Mandatory = $true)][string[]]$ArtifactPrefixes,
    [Parameter(Mandatory = $true)][string]$ExpectedCanonicalPayload
  )
  try {
    $accepted = [Cerberus.Agent.Core.AgentUpdateManifestValidator]::ParseAndValidateJson(
      $ManifestJson, [string[]]$PublicKeyPems, $Channel, [string[]]$ArtifactPrefixes)
    $actualCanonical = [Cerberus.Agent.Core.AgentUpdateManifestValidator]::CanonicalPayload($accepted)
  } catch {
    throw "Manifest was rejected by the agent verifier: $($_.Exception.GetBaseException().Message)"
  }
  if ($actualCanonical -cne $ExpectedCanonicalPayload) {
    throw "Manifest content does not match the signed payload."
  }
}

function Confirm-DetachedManifestSignature {
  param(
    [Parameter(Mandatory = $true)][string]$PayloadFile,
    [Parameter(Mandatory = $true)][string]$ExpectedPayloadSha256,
    [Parameter(Mandatory = $true)][string]$SignatureFile
  )
  # Returns the normalized base64 signature after the payload hash and encoding checks.
  # RSA verification itself is done by Assert-ManifestAcceptedByAgentVerifier.
  if (-not (Test-Path -LiteralPath $PayloadFile -PathType Leaf)) { throw "Manifest payload file was not found: $PayloadFile" }
  if (-not (Test-Path -LiteralPath $SignatureFile -PathType Leaf)) { throw "Manifest signature file was not found: $SignatureFile" }
  $payloadBytes = [IO.File]::ReadAllBytes($PayloadFile)
  $actual = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($payloadBytes)).ToLowerInvariant()
  if ($actual -ne $ExpectedPayloadSha256.ToLowerInvariant()) {
    throw "Manifest payload hash does not match the pending release."
  }
  $text = ([IO.File]::ReadAllText($SignatureFile)) -replace '\s', ''
  try {
    $signatureBytes = [Convert]::FromBase64String($text)
  } catch {
    throw "Manifest signature file must contain a base64 RSA PKCS#1 v1.5 SHA-256 signature."
  }
  if ($signatureBytes.Length -lt 128) { throw "Manifest signature is too short." }
  return [Convert]::ToBase64String($signatureBytes)
}

function Assert-SignedFileSignerPin {
  param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string[]]$AllowedPins)
  $raw = [System.Security.Cryptography.X509Certificates.X509Certificate]::CreateFromSignedFile($Path)
  $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($raw)
  try {
    # OrdinalIgnoreCase, like AgentUpdateAuthenticode's identity compare.
    $allowed = [System.Collections.Generic.HashSet[string]]::new([string[]]@($AllowedPins), [StringComparer]::OrdinalIgnoreCase)
    if (-not $allowed.Contains((Get-SignerSpkiPin $certificate))) {
      throw "Signed file signer does not match the expected signer pin: $Path"
    }
  } finally {
    $certificate.Dispose()
  }
}

function Write-Step([string]$Message) {
  Write-Host "==> $Message"
}

function Find-SignTool {
  $candidates = @(
    "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe",
    "${env:ProgramFiles}\Windows Kits\10\bin\*\x64\signtool.exe"
  )
  foreach ($pattern in $candidates) {
    $tool = Get-ChildItem -Path $pattern -ErrorAction SilentlyContinue |
      Sort-Object FullName -Descending |
      Select-Object -First 1
    if ($tool) {
      return $tool.FullName
    }
  }
  throw "signtool.exe was not found. Install Windows SDK or use windows-latest GitHub runner."
}

function Assert-ReleaseFileSigned {
  param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string[]]$AllowedPins)
  # Default signature check of the finalize step: Authenticode policy verification plus the signer pin.
  $signtool = Find-SignTool
  & $signtool verify /pa /v $Path | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "Authenticode verification failed: $Path" }
  Assert-SignedFileSignerPin -Path $Path -AllowedPins $AllowedPins
}

function Assert-ManifestAgainstBuild {
  param(
    [Parameter(Mandatory = $true)][string]$Canonical,
    [Parameter(Mandatory = $true)][string]$Signature,
    [Parameter(Mandatory = $true)][string]$ExpectedKeyPem,
    [Parameter(Mandatory = $true)]$Trust,
    [Parameter(Mandatory = $true)][string]$CoreAssembly,
    [Parameter(Mandatory = $true)][string]$Channel,
    [Parameter(Mandatory = $true)][string[]]$ArtifactPrefixes
  )
  # Self-check against what the build embeds: the signing key and signer identity must be trusted by the runtime,
  # and the agent's own validator must accept the manifest. Returns the parsed manifest.
  $normalize = { param($pem) ($pem -replace "`r", "").Trim() }
  $embeddedKeys = [System.Collections.Generic.HashSet[string]]::new([string[]]@($Trust.PublicKeyPems | ForEach-Object { & $normalize $_ }), [StringComparer]::Ordinal)
  if (-not $embeddedKeys.Contains((& $normalize $ExpectedKeyPem))) {
    throw "The expected manifest public key is not among the keys embedded in this build."
  }
  $manifest = ConvertFrom-ManifestPayloadV2 -Canonical $Canonical -Signature $Signature
  if (-not [string]::Equals([string]$manifest["channel"], $Channel, [StringComparison]::Ordinal)) { throw "Pending manifest channel does not match -Channel." }
  # OrdinalIgnoreCase, like AgentUpdateStager.ValidateSignerIdentity.
  $embeddedPins = [System.Collections.Generic.HashSet[string]]::new([string[]]@($Trust.SignerPins), [StringComparer]::OrdinalIgnoreCase)
  if (-not $embeddedPins.Contains([string]$manifest["signer_key_identity"])) {
    throw "Manifest signer identity is not among the signer pins embedded in this build."
  }
  Import-AgentManifestVerifier $CoreAssembly
  Assert-ManifestAcceptedByAgentVerifier `
    -ManifestJson ($manifest | ConvertTo-Json -Depth 8) `
    -PublicKeyPems @($ExpectedKeyPem) `
    -Channel $Channel `
    -ArtifactPrefixes $ArtifactPrefixes `
    -ExpectedCanonicalPayload $Canonical
  return $manifest
}
