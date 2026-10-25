# Token-mode steps for scripts/build-agent-public-release.ps1.
# Dot-source only, after release-signing-lib.ps1 and release-trust-lib.ps1. Loading this file has no side effects and never reads a certificate store.
# No function here prompts for, accepts or logs a PIN or password; Windows raises any token PIN prompt.

function Initialize-TokenSigning {
  param(
    [Parameter(Mandatory = $true)]$SigningPlan,
    [Parameter(Mandatory = $true)][string]$SigningCertThumbprint,
    [string[]]$ExtraSignerPins,
    [string]$ManifestSigningCertThumbprint,
    [string]$ManifestSigningPublicKeyFile,
    [string[]]$ExtraManifestPublicKeyFiles
  )
  # Private keys stay on the token; the build embeds public keys and signer pins only.
  $authenticodeCertificate = Find-CertificateByThumbprint $SigningCertThumbprint
  $signerPins = ConvertTo-NormalizedSignerPins (@(Get-SignerSpkiPin $authenticodeCertificate) + @($ExtraSignerPins))
  $keyPems = New-Object System.Collections.Generic.List[string]
  $manifestSigningCertificate = $null
  if ($SigningPlan.ManifestSigning -eq "Cng") {
    $manifestSigningCertificate = Find-CertificateByThumbprint $ManifestSigningCertThumbprint
    $keyPems.Add((Get-RsaPublicKeyPem $manifestSigningCertificate))
  } else {
    $keyPems.Add((Read-ManifestPublicKeyFile $ManifestSigningPublicKeyFile))
  }
  foreach ($extraKeyFile in @($ExtraManifestPublicKeyFiles)) {
    if (-not [string]::IsNullOrWhiteSpace($extraKeyFile)) { $keyPems.Add((Read-ManifestPublicKeyFile $extraKeyFile)) }
  }
  $keyPemList = @($keyPems | ForEach-Object { $_.Trim() } | Select-Object -Unique)
  # Assign first: the function returns the array wrapped (return ,$array), so @(f ...) would nest it.
  $keyListB64 = ConvertTo-ManifestPublicKeyListB64 $keyPemList
  return [pscustomobject]@{
    ManifestSigningCertificate = $manifestSigningCertificate
    SignerPins = @($signerPins)
    KeyListB64 = @($keyListB64)
  }
}

function Invoke-TokenFileSigning {
  param(
    [Parameter(Mandatory = $true)][string]$SigntoolPath,
    [Parameter(Mandatory = $true)][string]$Thumbprint,
    [Parameter(Mandatory = $true)][string]$TimestampUrl,
    [Parameter(Mandatory = $true)][string]$FilePath,
    [Parameter(Mandatory = $true)][string[]]$AllowedPins
  )
  & $SigntoolPath @(Get-SignToolTokenSignArguments -Thumbprint $Thumbprint -TimestampUrl $TimestampUrl -FilePath $FilePath) | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "Authenticode signing or verification failed." }
  & $SigntoolPath verify /pa /v $FilePath | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "Authenticode signing or verification failed." }
  Assert-SignedFileSignerPin -Path $FilePath -AllowedPins $AllowedPins
}

function Write-PendingExternalManifest {
  param(
    [Parameter(Mandatory = $true)][string]$PublishDir,
    [Parameter(Mandatory = $true)][string]$AssetBase,
    [Parameter(Mandatory = $true)][string]$Canonical,
    [Parameter(Mandatory = $true)][string[]]$KeyListB64,
    [Parameter(Mandatory = $true)][string[]]$ArtifactPrefixes,
    [Parameter(Mandatory = $true)][string[]]$SignerPins
  )
  $payloadPath = Join-Path $PublishDir "$AssetBase.update-manifest.v2.payload.bin"
  $pendingPath = Join-Path $PublishDir "$AssetBase.update-manifest.v2.pending.json"
  $payloadBytes = [Text.UTF8Encoding]::new($false).GetBytes($Canonical)
  [IO.File]::WriteAllBytes($payloadPath, $payloadBytes)
  [ordered]@{
    schema = "cerberus.agent.manifest_pending.v1"
    payload_sha256 = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($payloadBytes)).ToLowerInvariant()
    public_keys_b64 = @($KeyListB64)
    allowed_artifact_prefixes = @($ArtifactPrefixes)
    signer_pins = @($SignerPins)
  } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $pendingPath -Encoding utf8
  Write-Step "Manifest payload written: $payloadPath"
  Write-Step "Sign it externally (RSA PKCS#1 v1.5, SHA-256, base64 output), then rerun with the same -Version/-Channel/-OutputRoot plus -SigningMode Token -ManifestSigningPublicKeyFile <key> -ManifestSignatureFile <signature>."
}

function New-CngSignedManifest {
  param(
    [Parameter(Mandatory = $true)][string]$Canonical,
    [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
    [Parameter(Mandatory = $true)][string]$RuntimeDir,
    [Parameter(Mandatory = $true)][string]$Channel,
    [Parameter(Mandatory = $true)][string[]]$ArtifactPrefixes,
    [Parameter(Mandatory = $true)][string[]]$KeyListB64,
    [Parameter(Mandatory = $true)][string[]]$SignerPins
  )
  # No v1 manifest in token mode: current builds require v2, and a second hardware signature adds nothing for them.
  # Trust checks run before the token is asked to sign (a refusal after signing would waste a PIN entry); verification stays after.
  $trust = Get-BuiltReleaseTrust $RuntimeDir
  $declaredKeys = @($KeyListB64 | ForEach-Object { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_)).Trim() })
  Assert-EmbeddedTrustMatches -Trust $trust -KeyPems $declaredKeys -SignerPins (ConvertTo-NormalizedSignerPins @($SignerPins)) `
    -Channel $Channel -ArtifactPrefixes $ArtifactPrefixes -Label "Declared"
  $signature = Sign-ManifestPayloadWithCertificate -CanonicalPayload $Canonical -Certificate $Certificate
  return Assert-ManifestAgainstBuild `
    -Canonical $Canonical -Signature $signature -ExpectedKeyPem (Get-RsaPublicKeyPem $Certificate) -Trust $trust `
    -CoreAssembly (Join-Path $RuntimeDir "Cerberus.Agent.Core.dll") -Channel $Channel -ArtifactPrefixes $ArtifactPrefixes
}
