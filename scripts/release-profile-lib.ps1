# Build-profile helpers for scripts/build-agent-public-release.ps1.
# Dot-source only. Loading this file has no side effects.

function ConvertTo-Base64Utf8([string]$Value) {
  if ([string]::IsNullOrWhiteSpace($Value)) {
    return ""
  }
  return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Value.Trim()))
}

function Sign-ManifestPayload([string]$CanonicalPayload, [string]$PrivateKeyPem) {
  $rsa = [System.Security.Cryptography.RSA]::Create()
  $rsa.ImportFromPem($PrivateKeyPem)
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($CanonicalPayload)
  $sig = $rsa.SignData(
    $bytes,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
  return [Convert]::ToBase64String($sig)
}

function Get-ManifestPublicKeyPem([string]$PrivateKeyPem) {
  $rsa = [System.Security.Cryptography.RSA]::Create()
  $rsa.ImportFromPem($PrivateKeyPem)
  return $rsa.ExportSubjectPublicKeyInfoPem()
}

# Applies the runtime parser rules (AgentProfileMetadata.ParseAnchors) to the anchor value:
# base64 of UTF-8 text, one base64 SPKI per LF-separated line, RSA of at least 2048 bits.
# Throws when any line is unusable or none is usable; returns the key ids (first 16 hex of
# SHA-256 over the SPKI DER). Duplicate lines collapse, as at runtime.
function Assert-ServerCommandAnchors([string]$AnchorsB64) {
  try {
    $text = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($AnchorsB64.Trim()))
  } catch {
    throw "Command trust anchors are not valid base64."
  }
  $keyIds = [System.Collections.Generic.List[string]]::new()
  $lineNo = 0
  foreach ($rawLine in $text.Split("`n")) {
    $line = $rawLine.Trim()
    if ($line.Length -eq 0) { continue }
    $lineNo++
    $rsa = $null
    try {
      $spki = [Convert]::FromBase64String($line)
      $rsa = [System.Security.Cryptography.RSA]::Create()
      $read = 0
      $rsa.ImportSubjectPublicKeyInfo($spki, [ref]$read)
      if ($read -ne $spki.Length) { throw "trailing bytes" }
      if ($rsa.KeySize -lt 2048) { throw "RSA key under 2048 bits" }
    } catch {
      throw "Command trust anchor line $lineNo is not a usable RSA public key (SPKI, at least 2048 bits)."
    } finally {
      if ($null -ne $rsa) { $rsa.Dispose() }
    }
    $keyId = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($spki)).Replace("-", "").ToLowerInvariant()).Substring(0, 16)
    if (-not $keyIds.Contains($keyId)) { $keyIds.Add($keyId) }
  }
  if ($keyIds.Count -eq 0) {
    throw "Command trust anchors contain no usable key."
  }
  return ,$keyIds.ToArray()
}

# The runtime drops a command anchor that equals an update manifest public key
# (AgentProfileMetadata.ParseAnchors), so such an anchor would authorize nothing. Rejects any
# overlap, comparing RSA modulus and exponent as the runtime does. Run after Assert-ServerCommandAnchors.
# $ManifestKeyListB64 holds base64 of each manifest public key PEM. Messages carry key ids only.
function Assert-CommandAnchorsNotManifestKeys([string]$AnchorsB64, [string[]]$ManifestKeyListB64) {
  $manifestKeys = [System.Collections.Generic.List[object]]::new()
  foreach ($item in @($ManifestKeyListB64)) {
    if ([string]::IsNullOrWhiteSpace($item)) { continue }
    $rsa = [System.Security.Cryptography.RSA]::Create()
    try {
      $rsa.ImportFromPem([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($item.Trim())))
      $manifestKeys.Add($rsa.ExportParameters($false))
    } catch {
      throw "A manifest public key could not be read for the command trust anchor overlap check."
    } finally { $rsa.Dispose() }
  }
  $text = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($AnchorsB64.Trim()))
  $overlaps = [System.Collections.Generic.List[string]]::new()
  foreach ($rawLine in $text.Split("`n")) {
    $line = $rawLine.Trim()
    if ($line.Length -eq 0) { continue }
    $spki = [Convert]::FromBase64String($line)
    $rsa = [System.Security.Cryptography.RSA]::Create()
    try {
      $read = 0
      $rsa.ImportSubjectPublicKeyInfo($spki, [ref]$read)
      $anchor = $rsa.ExportParameters($false)
    } finally { $rsa.Dispose() }
    foreach ($manifestKey in $manifestKeys) {
      if ([System.Linq.Enumerable]::SequenceEqual([byte[]]$manifestKey.Modulus, [byte[]]$anchor.Modulus) -and
          [System.Linq.Enumerable]::SequenceEqual([byte[]]$manifestKey.Exponent, [byte[]]$anchor.Exponent)) {
        $keyId = ([System.BitConverter]::ToString([System.Security.Cryptography.SHA256]::HashData($spki)).Replace("-", "").ToLowerInvariant()).Substring(0, 16)
        if (-not $overlaps.Contains($keyId)) { $overlaps.Add($keyId) }
        break
      }
    }
  }
  if ($overlaps.Count -gt 0) {
    throw "Command trust anchor(s) $($overlaps -join ', ') equal an update manifest public key; the agent drops them. Use a separate command signing key."
  }
}

$script:ReleaseTimingKeys = @(
  "AgentPollFloorSeconds", "AgentPollCeilingSeconds",
  "AgentSnapshotFloorSeconds", "AgentSnapshotCeilingSeconds", "AgentSnapshotDefaultSeconds")

# Returns the MSBuild arguments that every project of one release build must share
# (runtime publishes, the installer helper and the MSI project), the extra MSI-only
# arguments, and the asset-name suffix. The server profile needs the command trust anchors.
function Get-ReleaseProfileBuild(
  [string]$BuildProfile,
  [string]$AnchorsFile,
  [System.Collections.IDictionary]$Timing,
  [string]$ProductName,
  [string]$EulaRtf
) {
  $shared = @()
  $anchors = ""
  if (-not [string]::IsNullOrWhiteSpace($AnchorsFile)) {
    if (-not (Test-Path -LiteralPath $AnchorsFile -PathType Leaf)) {
      throw "Command trust anchors file was not found."
    }
    $anchors = (Get-Content -LiteralPath $AnchorsFile -Raw).Trim()
  }
  if ($BuildProfile -eq "server") {
    if ([string]::IsNullOrWhiteSpace($anchors)) {
      throw "The server profile requires -AgentCommandTrustAnchorsFile with at least one trust anchor."
    }
    if ($anchors -notmatch '^[A-Za-z0-9+/=]+$') { throw "Command trust anchors must be one line of base64." }
    $keyIds = Assert-ServerCommandAnchors $anchors
    Write-Host "Command trust anchors: $($keyIds -join ', ')"
    $shared += "-p:AgentBuildProfile=server"
  }
  if ($anchors) {
    if ($anchors -notmatch '^[A-Za-z0-9+/=]+$') { throw "Command trust anchors must be one line of base64." }
    $shared += "-p:AgentCommandTrustAnchorsB64=$anchors"
  }
  foreach ($key in $Timing.Keys) {
    if ($key -notin $script:ReleaseTimingKeys -or "$($Timing[$key])" -notmatch '^\d+$') {
      throw "Timing override '$key' must be one of $($script:ReleaseTimingKeys -join ', ') with an integer value."
    }
    $shared += "-p:$key=$($Timing[$key])"
  }
  $msi = @()
  if (-not [string]::IsNullOrWhiteSpace($ProductName)) { $msi += "-p:ProductName=$ProductName" }
  if (-not [string]::IsNullOrWhiteSpace($EulaRtf)) { $msi += "-p:EulaRtf=$((Resolve-Path -LiteralPath $EulaRtf).Path)" }
  return [pscustomobject]@{
    MsBuildArgs = $shared
    MsiArgs = $msi
    AnchorsB64 = $anchors
    AssetSuffix = $(if ($BuildProfile -eq "server") { "-server" } else { "" })
  }
}
