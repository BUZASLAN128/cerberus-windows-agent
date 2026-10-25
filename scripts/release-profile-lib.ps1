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
    AssetSuffix = $(if ($BuildProfile -eq "server") { "-server" } else { "" })
  }
}
