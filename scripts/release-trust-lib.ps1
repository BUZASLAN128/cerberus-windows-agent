# Trust measurement helpers for scripts/build-agent-public-release.ps1 token signing and finalize.
# Dot-source only, after release-signing-lib.ps1 (uses ConvertTo-NormalizedSignerPins). Loading this file has no side effects.
# No function here prompts for, accepts or logs a PIN or password.

function Import-AgentBundleReader {
  if (-not ('Cerberus.Agent.Core.AgentSingleFileBundle' -as [type])) {
    Add-Type -TypeDefinition ([IO.File]::ReadAllText((Join-Path $PSScriptRoot '../src/Cerberus.Agent.Core/AgentSingleFileBundle.cs')))
  }
}

function Assert-ServerBundleLayout([string]$RuntimeDir) {
  Import-AgentBundleReader
  foreach ($hostName in @('Cerberus.Agent', 'Cerberus.Agent.Service', 'Cerberus.Agent.Updater')) {
    $null = [Cerberus.Agent.Core.AgentSingleFileBundle]::ReadAssembly((Join-Path $RuntimeDir "$hostName.exe"), "$hostName.dll")
    if (Test-Path -LiteralPath (Join-Path $RuntimeDir "$hostName.dll")) { throw "Server entry assembly is external: $hostName" }
  }
}

function Get-ReleaseServiceAssemblyHash {
  param([string]$RuntimeDir, [string]$BuildProfile)
  if ($BuildProfile -ne 'server') {
    return (Get-FileHash -Algorithm SHA256 (Join-Path $RuntimeDir 'Cerberus.Agent.Service.dll')).Hash.ToLowerInvariant()
  }
  Import-AgentBundleReader
  $bytes = [Cerberus.Agent.Core.AgentSingleFileBundle]::ReadAssembly((Join-Path $RuntimeDir 'Cerberus.Agent.Service.exe'), 'Cerberus.Agent.Service.dll')
  return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()
}

function Read-AssemblyMetadataValues {
  param([Parameter(Mandatory = $true)][string]$AssemblyPath, [string]$BundlePath = '')
  # Reads AssemblyMetadata(key, value) attributes from the file without loading the assembly.
  $tokens = [System.Reflection.Metadata.Ecma335.MetadataTokens]
  if (-not $BundlePath) {
    $hostName = if ([IO.Path]::GetFileName($AssemblyPath) -eq 'Cerberus.Agent.Runtime.dll') { 'Cerberus.Agent.Service.exe' }
      else { [IO.Path]::GetFileNameWithoutExtension($AssemblyPath) + '.exe' }
    $candidate = Join-Path ([IO.Path]::GetDirectoryName($AssemblyPath)) $hostName
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
      Import-AgentBundleReader
      if ([Cerberus.Agent.Core.AgentSingleFileBundle]::IsBundle($candidate)) { $BundlePath = $candidate }
    }
  }
  if ($BundlePath -or -not (Test-Path -LiteralPath $AssemblyPath -PathType Leaf)) {
    if (-not $BundlePath) {
      $hostName = if ([IO.Path]::GetFileName($AssemblyPath) -eq 'Cerberus.Agent.Runtime.dll') { 'Cerberus.Agent.Service.exe' }
        else { [IO.Path]::GetFileNameWithoutExtension($AssemblyPath) + '.exe' }
      $BundlePath = Join-Path ([IO.Path]::GetDirectoryName($AssemblyPath)) $hostName
    }
    if (-not (Test-Path -LiteralPath $BundlePath -PathType Leaf)) { throw "Built runtime assembly was not found: $AssemblyPath" }
    Import-AgentBundleReader
    $stream = [IO.MemoryStream]::new([Cerberus.Agent.Core.AgentSingleFileBundle]::ReadAssembly($BundlePath, [IO.Path]::GetFileName($AssemblyPath)))
  } else {
    $stream = [IO.File]::Open($AssemblyPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  }
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
  param([Parameter(Mandatory = $true)][string]$AssemblyPath, [string]$BundlePath = '', [switch]$BuildComparison)
  # Manifest public keys and signer pins exactly as the shipped agent reads them (runtime assembly metadata).
  $metadata = Read-AssemblyMetadataValues $AssemblyPath -BundlePath $BundlePath
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
  $pins = @()
  if (-not $BuildComparison) {
    $pins = ConvertTo-NormalizedSignerPins @(([string]$metadata["AgentUpdateAllowedSignerKeyIdentity"]) -split ',')
    if (@($pins).Count -eq 0) { throw "The built runtime carries no signer pin." }
  }
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

function Assert-NoLabCampaignMetadata {
  param(
    [Parameter(Mandatory = $true)][string]$RuntimeDir,
    # Further compiler outputs that are not part of the runtime directory (for example the installer helper assembly).
    [string[]]$ExtraAssemblies = @()
  )
  # A non-lab build must not carry lab-campaign routing in any published binary. MSBuild turns environment variables into
  # properties, so a stray AgentUpdateLabPolicyB64 would otherwise be compiled in silently. A key counts even when its value is empty.
  $labKeys = @('AgentUpdateLabPolicyB64', 'AgentUpdateLabFeedRootB64', 'AgentUpdateLabRuntimeHashesB64')
  $check = {
    param($Metadata, [string]$Label)
    foreach ($key in $labKeys) {
      if ($Metadata.ContainsKey($key)) { throw "$Label carries lab-campaign metadata '$key'; a non-lab release must not." }
    }
  }
  # The metadata reader locates a bundled Runtime.dll only in Cerberus.Agent.Service.exe.
  foreach ($name in 'Cerberus.Agent.dll', 'Cerberus.Agent.Runtime.dll') {
    & $check (Read-AssemblyMetadataValues (Join-Path $RuntimeDir $name)) $name
  }
  Import-AgentBundleReader
  foreach ($hostName in 'Cerberus.Agent.exe', 'Cerberus.Agent.Service.exe', 'Cerberus.Agent.Updater.exe') {
    $hostPath = Join-Path $RuntimeDir $hostName
    if (-not (Test-Path -LiteralPath $hostPath -PathType Leaf) -or -not [Cerberus.Agent.Core.AgentSingleFileBundle]::IsBundle($hostPath)) { continue }
    $entry = [IO.Path]::GetFileNameWithoutExtension($hostName) + '.dll'
    & $check (Read-AssemblyMetadataValues (Join-Path $RuntimeDir $entry) -BundlePath $hostPath) "Bundle $hostName ($entry)"
  }
  foreach ($assembly in $ExtraAssemblies) {
    if (-not (Test-Path -LiteralPath $assembly -PathType Leaf)) { throw "Assembly to check for lab metadata was not found: $assembly" }
    & $check (Read-AssemblyMetadataValues $assembly) ([IO.Path]::GetFileName($assembly))
  }
}

function Assert-ReleaseTrustEqual($Agent, $Other, [string]$Label, [switch]$CompareSignerPins) {
  $nameSets = @('PublicKeyPems', 'ArtifactPrefixes')
  if ($CompareSignerPins) { $nameSets += 'SignerPins' }
  foreach ($name in $nameSets) {
    if (-not (Test-SameStringSet $Agent.$name $Other.$name)) { throw "Cerberus.Agent.dll and $Label embed different $name." }
  }
  if (-not (Test-SameStringSet $Agent.Channel $Other.Channel)) { throw "Cerberus.Agent.dll and $Label embed different release channels." }
  if (-not (Test-SameStringSet $Agent.ManifestUrl $Other.ManifestUrl)) { throw "Cerberus.Agent.dll and $Label embed different update manifest URLs." }
}

function Get-BuiltReleaseTrust {
  param([Parameter(Mandatory = $true)][string]$RuntimeDir)
  # Finalize and CNG signing require the app, service and updater to agree, including signer pins.
  Import-AgentBundleReader
  $agentAssembly = Join-Path $RuntimeDir 'Cerberus.Agent.dll'
  $agentHost = Join-Path $RuntimeDir 'Cerberus.Agent.exe'
  $server = (Test-Path -LiteralPath $agentHost -PathType Leaf) -and [Cerberus.Agent.Core.AgentSingleFileBundle]::IsBundle($agentHost)
  if ($server -and (Test-Path -LiteralPath $agentAssembly)) { throw 'Server bundle carries an external entry assembly.' }
  $agentBundle = if ($server) { $agentHost } else { '' }
  $trust = Get-EmbeddedReleaseTrust $agentAssembly -BundlePath $agentBundle
  Assert-NoUnsignedDevBuild $trust 'Cerberus.Agent.dll'
  foreach ($pair in @(
    @('Cerberus.Agent.Runtime.dll', 'Cerberus.Agent.Service.exe'),
    @('Cerberus.Agent.Updater.dll', 'Cerberus.Agent.Updater.exe')
  )) {
    $name, $hostName = $pair
    $bundle = if ($server) { Join-Path $RuntimeDir $hostName } else { '' }
    $label = if ($server) { $hostName } else { $name }
    $other = Get-EmbeddedReleaseTrust (Join-Path $RuntimeDir $name) -BundlePath $bundle
    Assert-ReleaseTrustEqual $trust $other $label -CompareSignerPins
    if ($server -and -not (Test-SameStringSet $trust.AllowUnsignedDevBuild $other.AllowUnsignedDevBuild)) {
      throw "Bundle $hostName embeds different AllowUnsignedDevBuild."
    }
    Assert-NoUnsignedDevBuild $other $label
  }
  return $trust
}

function ConvertTo-UpdaterContractVersion([string]$Value, [string]$Label) {
  $version = 0
  if ($Value -cnotmatch '\A[1-9][0-9]*\z' -or -not [int]::TryParse($Value, [ref]$version)) {
    throw "$Label must be a positive updater contract version."
  }
  return $version
}

function Get-UpdaterSourceVersion([string]$RepoRoot) {
  $path = Join-Path $RepoRoot 'src/Cerberus.Agent.Core/AgentUpdaterContract.cs'
  $version = [regex]::Match([IO.File]::ReadAllText($path), '(?m)^\s*public const string Version = "([0-9]+)";[ \t]*\r?$')
  if (-not $version.Success) { throw 'Updater contract source version was not found.' }
  return ConvertTo-UpdaterContractVersion $version.Groups[1].Value 'Source contract version'
}

function Get-UpdaterFingerprintFiles([string]$Directory) {
  foreach ($entry in Get-ChildItem -LiteralPath $Directory -Force) {
    if ($entry.PSIsContainer) {
      if ($entry.Name -notmatch '^(bin|obj)') { Get-UpdaterFingerprintFiles $entry.FullName }
    } elseif ($entry.Extension -in @('.cs', '.csproj', '.manifest') -and $entry.Name -cne 'UpdaterLab.Runtime.cs') {
      $entry.FullName
    }
  }
}

function Get-UpdaterSourceFingerprint([string]$RepoRoot) {
  $root = (Resolve-Path -LiteralPath $RepoRoot).Path
  $paths = [string[]]@(
    'Directory.Build.props'
    foreach ($project in 'Cerberus.Agent.Core', 'Cerberus.Agent.Updater') {
      Get-UpdaterFingerprintFiles (Join-Path $root "src/$project") |
        ForEach-Object { [IO.Path]::GetRelativePath($root, $_).Replace('\', '/') }
    }
  )
  [array]::Sort($paths, [StringComparer]::Ordinal)
  $utf8 = [Text.UTF8Encoding]::new($false, $true)
  $lines = [Text.StringBuilder]::new()
  foreach ($path in $paths) {
    $text = $utf8.GetString([IO.File]::ReadAllBytes((Join-Path $root $path))).TrimStart([char]0xFEFF).Replace("`r`n", "`n")
    $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($utf8.GetBytes($text))).ToLowerInvariant()
    [void]$lines.Append("$path`n$hash`n")
  }
  return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($utf8.GetBytes($lines.ToString()))).ToLowerInvariant()
}

function Assert-UpdaterSourceLock([string]$RepoRoot) {
  $path = Join-Path $RepoRoot 'src/Cerberus.Agent.Core/updater-contract.lock'
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Updater source lock is missing.' }
  $version = 0
  $lastHash = ''
  $hashes = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
  foreach ($line in [IO.File]::ReadAllLines($path)) {
    if ($line -cnotmatch '\A([1-9][0-9]*) ([0-9a-f]{64})\z') { throw 'Updater source lock has an invalid line.' }
    $next = ConvertTo-UpdaterContractVersion $Matches[1] 'Locked contract version'
    $lastHash = $Matches[2]
    if ($next -lt $version) { throw 'Updater source lock contract versions decrease.' }
    if (-not $hashes.Add($lastHash)) { throw 'Updater source lock has a duplicate fingerprint.' }
    $version = $next
  }
  if ($version -eq 0) { throw 'Updater source lock has no candidate stamp.' }
  if ($lastHash -cne (Get-UpdaterSourceFingerprint $RepoRoot)) { throw 'Updater source fingerprint does not match the latest lock entry.' }
  if ($version -ne (Get-UpdaterSourceVersion $RepoRoot)) { throw 'Locked updater contract version differs from source.' }
  return $version
}

function Assert-BundleEntryKinds([string]$BundlePath, [string[]]$AllowedNativeNames = @()) {
  Import-AgentBundleReader
  $remainingNativeNames = [System.Collections.Generic.HashSet[string]]::new($AllowedNativeNames, [StringComparer]::Ordinal)
  foreach ($entry in [Cerberus.Agent.Core.AgentSingleFileBundle]::ReadEntries($BundlePath)) {
    if ($entry.Kind -in @(1, 3, 4, 5)) { continue }
    if ($entry.Kind -eq 2 -and $remainingNativeNames.Remove($entry.Name)) { continue }
    throw "Bundle $BundlePath contains disallowed entry kind $($entry.Kind): $($entry.Name)."
  }
}

function Assert-UpdaterBundleHasNoNativeEntries([string]$BundlePath) {
  Assert-BundleEntryKinds $BundlePath
}

function Assert-ServerAgentBundleEntryKinds([string]$BundlePath) {
  # The server App still publishes Windows Desktop; the headless Service and Updater do not.
  Assert-BundleEntryKinds $BundlePath @('D3DCompiler_47_cor3.dll', 'PenImc_cor3.dll',
    'PresentationNative_cor3.dll', 'vcruntime140_cor3.dll', 'wpfgfx_cor3.dll')
}

function Assert-UpdaterMetadataVersion($Metadata, [int]$Expected) {
  $built = ConvertTo-UpdaterContractVersion ([string]$Metadata['AgentUpdaterContractVersion']) 'Built contract version'
  if ($built -ne $Expected) { throw "Built updater contract version $built differs from expected version $Expected." }
}

function Assert-FinalUpdaterContract([string]$RuntimeDir, [string]$RepoRoot) {
  $locked = Assert-UpdaterSourceLock $RepoRoot
  $assembly = Join-Path $RuntimeDir 'Cerberus.Agent.Core.dll'
  $hostPath = Join-Path $RuntimeDir 'Cerberus.Agent.Updater.exe'
  Import-AgentBundleReader
  $bundle = if ((Test-Path -LiteralPath $hostPath -PathType Leaf) -and
    [Cerberus.Agent.Core.AgentSingleFileBundle]::IsBundle($hostPath)) { $hostPath } else { '' }
  Assert-UpdaterMetadataVersion (Read-AssemblyMetadataValues $assembly -BundlePath $bundle) $locked
}

function Assert-UpdaterBuildContract([string]$RuntimeDir, [string]$BuildProfile, [string]$RepoRoot, [bool]$Lab, [string]$BackendAnchors) {
  $agent = Get-EmbeddedReleaseTrust (Join-Path $RuntimeDir 'Cerberus.Agent.dll') -BuildComparison
  $updater = Get-EmbeddedReleaseTrust (Join-Path $RuntimeDir 'Cerberus.Agent.Updater.dll') -BuildComparison
  Assert-ReleaseTrustEqual $agent $updater 'Cerberus.Agent.Updater.dll'

  $contractAssembly = Join-Path $RuntimeDir 'Cerberus.Agent.Core.dll'
  $expectedAnchors = $BackendAnchors.Replace('%2C', ',')
  $expectedVersion = if ($Lab) { Write-Host "Lab updater source fingerprint: $(Get-UpdaterSourceFingerprint $RepoRoot)"; 0 }
    else { Get-UpdaterSourceVersion $RepoRoot }
  $bundles = if ($BuildProfile -ceq 'server') { @('Cerberus.Agent.exe', 'Cerberus.Agent.Service.exe', 'Cerberus.Agent.Updater.exe') } else { @('') }
  foreach ($name in $bundles) {
    $bundle = ''
    if ($name) {
      $bundle = Join-Path $RuntimeDir $name
      if ($name -ceq 'Cerberus.Agent.exe') { Assert-ServerAgentBundleEntryKinds $bundle }
      else { Assert-UpdaterBundleHasNoNativeEntries $bundle }
    }
    $metadata = Read-AssemblyMetadataValues $contractAssembly -BundlePath $bundle
    if (([string]$metadata['BackendTrustAnchors']) -cne $expectedAnchors) { throw "Built BackendTrustAnchors differ from the backend anchor input in '$name'." }
    if (-not $Lab) { Assert-UpdaterMetadataVersion $metadata $expectedVersion }
  }
  if ($Lab) { return }

  $allowed = @('Cerberus.Agent.Updater', 'Cerberus.Agent.Core')
  $libraries = if ($BuildProfile -ceq 'server') {
    [Cerberus.Agent.Core.AgentSingleFileBundle]::ReadEntries((Join-Path $RuntimeDir 'Cerberus.Agent.Updater.exe')) |
      Where-Object { $_.Kind -eq 1 } | ForEach-Object { [IO.Path]::GetFileNameWithoutExtension($_.Name) }
  } else {
    $deps = Get-Content -Raw -LiteralPath (Join-Path $RuntimeDir 'Cerberus.Agent.Updater.deps.json') | ConvertFrom-Json -AsHashtable
    if (-not $deps.libraries -or $deps.libraries -isnot [System.Collections.IDictionary]) { throw 'Updater dependencies have no library map.' }
    $deps.libraries.Keys | ForEach-Object { ($_ -split '/', 2)[0] }
  }
  foreach ($library in $libraries) {
    if ($library -ilike 'Cerberus.*' -and $library -cnotin $allowed) { throw "Non-lab updater has a forbidden dependency: $library." }
  }
  foreach ($required in $allowed) {
    if ($required -cnotin $libraries) { throw "Non-lab updater is missing a required dependency: $required." }
  }
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
