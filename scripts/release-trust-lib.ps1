# Trust measurement helpers for scripts/build-agent-public-release.ps1 token signing and finalize.
# Dot-source only, after release-signing-lib.ps1 (uses ConvertTo-NormalizedSignerPins). Loading this file has no side effects.
# No function here prompts for, accepts or logs a PIN or password.

function Read-AssemblyMetadataValues {
  param([Parameter(Mandatory = $true)][string]$AssemblyPath)
  # Reads AssemblyMetadata(key, value) attributes from the file without loading the assembly.
  if (-not (Test-Path -LiteralPath $AssemblyPath -PathType Leaf)) {
    throw "Built runtime assembly was not found: $AssemblyPath"
  }
  $tokens = [System.Reflection.Metadata.Ecma335.MetadataTokens]
  $stream = [IO.File]::Open($AssemblyPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  # Ordinal keys and first-wins semantics match AgentUpdateDefaults.ReadAssemblyMetadata; a repeated key is refused.
  $values = [hashtable]::new([StringComparer]::Ordinal)
  try {
    $pe = [System.Reflection.PortableExecutable.PEReader]::new($stream)
    try {
      $reader = [System.Reflection.Metadata.PEReaderExtensions]::GetMetadataReader($pe)
      foreach ($handle in $reader.GetAssemblyDefinition().GetCustomAttributes()) {
        $attribute = $reader.GetCustomAttribute($handle)
        if ($attribute.Constructor.Kind -ne [System.Reflection.Metadata.HandleKind]::MemberReference) { continue }
        $member = $reader.GetMemberReference($tokens::MemberReferenceHandle($tokens::GetRowNumber($attribute.Constructor)))
        if ($member.Parent.Kind -ne [System.Reflection.Metadata.HandleKind]::TypeReference) { continue }
        $type = $reader.GetTypeReference($tokens::TypeReferenceHandle($tokens::GetRowNumber($member.Parent)))
        if ($reader.GetString($type.Name) -cne "AssemblyMetadataAttribute" -or $reader.GetString($type.Namespace) -cne "System.Reflection") { continue }
        $blob = $reader.GetBlobBytes($attribute.Value)
        $offset = 2  # prolog 0x0001
        $strings = @()
        for ($i = 0; $i -lt 2; $i++) {
          $first = $blob[$offset]
          if ($first -eq 0xFF) { $strings += $null; $offset++; continue }
          if (($first -band 0x80) -eq 0) { $length = $first; $offset += 1 }
          elseif (($first -band 0xC0) -eq 0x80) { $length = (($first -band 0x3F) -shl 8) -bor $blob[$offset + 1]; $offset += 2 }
          else { $length = (($first -band 0x1F) -shl 24) -bor ($blob[$offset + 1] -shl 16) -bor ($blob[$offset + 2] -shl 8) -bor $blob[$offset + 3]; $offset += 4 }
          $strings += [Text.Encoding]::UTF8.GetString($blob, $offset, $length)
          $offset += $length
        }
        if ($null -ne $strings[0]) {
          if ($values.ContainsKey([string]$strings[0])) { throw "Duplicate assembly metadata key '$($strings[0])': $AssemblyPath" }
          $values[[string]$strings[0]] = [string]$strings[1]
        }
      }
    } finally { $pe.Dispose() }
  } finally { $stream.Dispose() }
  return $values
}

function Get-EmbeddedReleaseTrust {
  param([Parameter(Mandatory = $true)][string]$AssemblyPath)
  # Manifest public keys and signer pins exactly as the shipped agent reads them (runtime assembly metadata).
  $metadata = Read-AssemblyMetadataValues $AssemblyPath
  $keys = New-Object System.Collections.Generic.List[string]
  # Same separators as AgentUpdateTrustFactory.SplitPublicKeySource. The agent silently drops a key it cannot import,
  # so every item must decode to a PEM that imports as an RSA public key; otherwise the build would carry fewer keys than declared.
  foreach ($item in ([string]$metadata["AgentUpdateManifestPublicKeysB64"]).Split([string[]]@(',', ';', "`r", "`n"), [StringSplitOptions]::RemoveEmptyEntries -bor [StringSplitOptions]::TrimEntries)) {
    $rsa = [System.Security.Cryptography.RSA]::Create()
    try {
      $pem = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($item)).Trim()
      $rsa.ImportFromPem($pem)
      $keys.Add($pem)
    }
    catch { throw "The built runtime carries a malformed manifest public key." }
    finally { $rsa.Dispose() }
  }
  if ($keys.Count -eq 0) { throw "The built runtime carries no manifest public key." }
  $pins = ConvertTo-NormalizedSignerPins @(([string]$metadata["AgentUpdateAllowedSignerKeyIdentity"]) -split ',')
  if (@($pins).Count -eq 0) { throw "The built runtime carries no signer pin." }
  $prefixes = @(([string]$metadata["AgentUpdateAllowedArtifactPrefixes"]) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  return [pscustomobject]@{
    PublicKeyPems = @($keys.ToArray()); SignerPins = @($pins)
    Channel = [string]$metadata["AgentReleaseChannel"]; ArtifactPrefixes = $prefixes
    ManifestUrl = ([string]$metadata["AgentUpdateManifestUrl"]).Trim()
    AllowUnsignedDevBuild = ([string]$metadata["AllowUnsignedDevBuild"]).Trim()
  }
}

function Assert-NoUnsignedDevBuild {
  param([Parameter(Mandatory = $true)]$Trust, [Parameter(Mandatory = $true)][string]$Label)
  # Absent or 'false' only; the agent reads the value with bool.TryParse and treats anything else as false, which is not measured here.
  $parsed = $false
  if ($Trust.AllowUnsignedDevBuild -ne "" -and (-not [bool]::TryParse($Trust.AllowUnsignedDevBuild, [ref]$parsed) -or $parsed)) {
    throw "$Label carries AllowUnsignedDevBuild='$($Trust.AllowUnsignedDevBuild)'; a signed release requires it absent or false."
  }
}

function Get-BuiltReleaseTrust {
  param([Parameter(Mandatory = $true)][string]$RuntimeDir)
  # The update path reads Cerberus.Agent.Runtime.dll, the app reads Cerberus.Agent.dll: both must carry identical trust values.
  # Only token finalize and CNG signing call this, so unsigned dev builds are refused unconditionally.
  $trust = Get-EmbeddedReleaseTrust (Join-Path $RuntimeDir "Cerberus.Agent.dll")
  $runtime = Get-EmbeddedReleaseTrust (Join-Path $RuntimeDir "Cerberus.Agent.Runtime.dll")
  foreach ($name in "PublicKeyPems", "SignerPins", "ArtifactPrefixes") {
    if (-not (Test-SameStringSet $trust.$name $runtime.$name)) { throw "Cerberus.Agent.dll and Cerberus.Agent.Runtime.dll embed different $name." }
  }
  if (-not [string]::Equals($trust.Channel, $runtime.Channel, [StringComparison]::Ordinal)) { throw "Cerberus.Agent.dll and Cerberus.Agent.Runtime.dll embed different release channels." }
  if (-not [string]::Equals($trust.ManifestUrl, $runtime.ManifestUrl, [StringComparison]::Ordinal)) { throw "Cerberus.Agent.dll and Cerberus.Agent.Runtime.dll embed different update manifest URLs." }
  Assert-NoUnsignedDevBuild $trust "Cerberus.Agent.dll"
  Assert-NoUnsignedDevBuild $runtime "Cerberus.Agent.Runtime.dll"
  return $trust
}

function Test-SameStringSet {
  param($Left, $Right)
  # Ordinal, like the agent's string comparisons. Counts must match too: the agent does not de-duplicate prefixes or pins.
  $leftItems = [string[]]@($Left)
  $rightItems = [string[]]@($Right)
  if ($leftItems.Count -ne $rightItems.Count) { return $false }
  $set = [System.Collections.Generic.HashSet[string]]::new($leftItems, [StringComparer]::Ordinal)
  return $set.SetEquals($rightItems)
}

function Assert-EmbeddedTrustMatches {
  param(
    [Parameter(Mandatory = $true)]$Trust,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$KeyPems,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$SignerPins,
    [Parameter(Mandatory = $true)][string]$Channel,
    [Parameter(Mandatory = $true)][string[]]$ArtifactPrefixes,
    [Parameter(Mandatory = $true)][string]$Label
  )
  # $Label names the source of the declared values ("Pending" or "Declared") in the refusal message.
  # The channel must be exactly dev, preview or stable: -cnotmatch is case-sensitive and culture-invariant, so U+00AD and U+200B do not pass.
  if ($Trust.Channel -cnotmatch '\A(dev|preview|stable)\z') { throw "Release channel '$($Trust.Channel)' must be lowercase dev, preview or stable." }
  if (-not (Test-SameStringSet $KeyPems $Trust.PublicKeyPems)) { throw "$Label manifest keys do not match the keys embedded in the built runtime." }
  if (-not (Test-SameStringSet $SignerPins $Trust.SignerPins)) { throw "$Label signer pins do not match the signer pins embedded in the built runtime." }
  if (-not [string]::Equals($Trust.Channel, $Channel, [StringComparison]::Ordinal)) { throw "Embedded release channel does not match -Channel." }
  if (-not (Test-SameStringSet @($ArtifactPrefixes | ForEach-Object { $_.Trim() }) $Trust.ArtifactPrefixes)) {
    throw "$Label artifact prefixes do not match the prefixes embedded in the built runtime."
  }
}

function Assert-SignerContinuity {
  param(
    [string]$SignedFile = "",
    [string]$SignerPin = "",
    [Parameter(Mandatory = $true)][string[]]$EmbeddedPins,
    [string[]]$DeployedPins = @(),
    [Parameter(Mandatory = $true)][string]$Channel,
    [switch]$AllowUnconfirmedDeployedSigners
  )
  # The Authenticode certificate of this release must be pinned (a) by this release itself, so its own next update verifies,
  # and (b) by the agents already deployed, when their pins are declared, so they accept this release.
  # -SignedFile measures the signature of a signed file; otherwise -SignerPin is the pin of the certificate about to sign.
  $accepted = {
    param([string[]]$Pins)
    if ($SignedFile) {
      try { Assert-SignedFileSignerPin -Path $SignedFile -AllowedPins $Pins; return $null } catch { return $_.Exception.Message }
    }
    if (([string[]]@($Pins)) -contains $SignerPin.ToLowerInvariant()) { return $null }
    return "signer pin $SignerPin is not in the list"
  }
  $problem = & $accepted $EmbeddedPins
  if ($problem) { throw "Signer continuity: the Authenticode certificate is not among the signer pins compiled into this release, so it could not verify its own next update ($problem)." }
  $deployed = ConvertTo-NormalizedSignerPins @(@($DeployedPins) | ForEach-Object { ([string]$_) -split ',' })
  if (@($deployed).Count -eq 0) {
    if ($Channel -ne "dev") {
      if (-not $AllowUnconfirmedDeployedSigners) { throw "Signer continuity: deployed signer pins are not set, so it cannot be confirmed that deployed agents accept this release's Authenticode certificate. Pass -DeployedSignerPins (or set CERBERUS_AGENT_DEPLOYED_SIGNER_PINS), or pass -AllowUnconfirmedDeployedSigners to release without confirmation." }
      Write-Warning "-DeployedSignerPins (or CERBERUS_AGENT_DEPLOYED_SIGNER_PINS) is not set: cannot confirm that deployed agents accept this release's Authenticode certificate."
    }
    return
  }
  $problem = & $accepted $deployed
  if ($problem) { throw "Signer continuity: deployed agents do not pin this release's Authenticode certificate and would refuse it. Sign with a deployed certificate, or ship a bridge release that carries both pins first ($problem)." }
}

function Assert-ReleaseSignerContinuity {
  param(
    [Parameter(Mandatory = $true)][ValidateSet("PreSign", "PostSign")][string]$Stage,
    [string[]]$DeployedPins = @(),
    [Parameter(Mandatory = $true)][string]$Channel,
    [string]$SignerKeyIdentity = "",
    [string[]]$TokenSignerPins = @(),
    [switch]$TokenMode,
    [string]$SignedFile = "",
    [string]$RuntimeDll = "",
    [switch]$AllowUnconfirmedDeployedSigners
  )
  # Build-script glue: -DeployedPins falls back to CERBERUS_AGENT_DEPLOYED_SIGNER_PINS.
  if (@($DeployedPins | Where-Object { $_ }).Count -eq 0 -and $env:CERBERUS_AGENT_DEPLOYED_SIGNER_PINS) { $DeployedPins = @($env:CERBERUS_AGENT_DEPLOYED_SIGNER_PINS) }
  if ($Stage -eq "PreSign") {
    # Fail before tests and signing prompts when the certificate cannot continue the update chain.
    if ($SignerKeyIdentity -notmatch '^sha256:') { return }
    Assert-SignerContinuity -SignerPin $SignerKeyIdentity -EmbeddedPins $(if ($TokenMode) { $TokenSignerPins } else { @($SignerKeyIdentity) }) -DeployedPins $DeployedPins -Channel $Channel -AllowUnconfirmedDeployedSigners:$AllowUnconfirmedDeployedSigners
    return
  }
  # Measured on the signed file against the pins read back from the built runtime, before any manifest or output is written.
  Assert-SignerContinuity -SignedFile $SignedFile -EmbeddedPins (Get-EmbeddedReleaseTrust $RuntimeDll).SignerPins -DeployedPins $DeployedPins -Channel $Channel -AllowUnconfirmedDeployedSigners:$AllowUnconfirmedDeployedSigners
}
