# Fixture helpers for scripts/test-release-signing.ps1 (dot-source only; no side effects on load).
# Builds a publish directory that finalize can measure: Cerberus.Agent.dll and Cerberus.Agent.Runtime.dll fixtures
# carrying only AssemblyMetadata, placeholder runtime executables, a Core assembly copy, a fixture MSI and a matching
# pending payload. The assemblies are written with System.Reflection.Metadata (MetadataBuilder + ManagedPEBuilder),
# which exists unchanged in .NET 8, so no Reflection.Emit save support is required.

function ConvertTo-SerializedString([string]$Value) {
  $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
  $prefix = if ($bytes.Length -lt 0x80) { [byte[]]@($bytes.Length) }
    elseif ($bytes.Length -lt 0x4000) { [byte[]]@((0x80 -bor ($bytes.Length -shr 8)), ($bytes.Length -band 0xFF)) }
    else { throw "Fixture metadata value is too long." }
  return [byte[]](@($prefix) + @($bytes))
}

function New-MetadataAssembly {
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$AssemblyName,
    [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Pairs,
    [string]$AttributeNamespace = "System.Reflection"
  )
  # $Pairs is an ordered list of @(key, value); duplicates and case variants are written as given.
  $ns = "System.Reflection.Metadata"
  $tok = [System.Reflection.Metadata.Ecma335.MetadataTokens]
  $table = [System.Reflection.Metadata.Ecma335.TableIndex]
  $mb = [System.Reflection.Metadata.Ecma335.MetadataBuilder]::new()
  $nilString = [System.Reflection.Metadata.StringHandle]::new()
  $nilBlob = [System.Reflection.Metadata.BlobHandle]::new()
  $nilGuid = [System.Reflection.Metadata.GuidHandle]::new()
  $null = $mb.AddModule(0, $mb.GetOrAddString("$AssemblyName.dll"), $mb.GetOrAddGuid([guid]::NewGuid()), $nilGuid, $nilGuid)
  $null = $mb.AddAssembly($mb.GetOrAddString($AssemblyName), [version]::new(1, 0, 0, 0), $nilString, $nilBlob, [System.Reflection.AssemblyFlags]0, [System.Reflection.AssemblyHashAlgorithm]::None)
  $null = $mb.AddTypeDefinition([System.Reflection.TypeAttributes]::NotPublic, $nilString, $mb.GetOrAddString("<Module>"),
    $tok::EntityHandle(0), $tok::FieldDefinitionHandle(1), $tok::MethodDefinitionHandle(1))
  $token = $mb.GetOrAddBlob([byte[]]@(0xb0, 0x3f, 0x5f, 0x7f, 0x11, 0xd5, 0x0a, 0x3a))
  $null = $mb.AddAssemblyReference($mb.GetOrAddString("System.Runtime"), [version]::new(8, 0, 0, 0), $nilString, $token, [System.Reflection.AssemblyFlags]0, $nilBlob)
  $null = $mb.AddTypeReference($tok::EntityHandle($table::AssemblyRef, 1), $mb.GetOrAddString($AttributeNamespace), $mb.GetOrAddString("AssemblyMetadataAttribute"))
  # .ctor(string, string): HASTHIS, 2 parameters, void return, string, string
  $signature = $mb.GetOrAddBlob([byte[]]@(0x20, 0x02, 0x01, 0x0E, 0x0E))
  $null = $mb.AddMemberReference($tok::EntityHandle($table::TypeRef, 1), $mb.GetOrAddString(".ctor"), $signature)
  foreach ($pair in $Pairs) {
    $value = [byte[]](@(0x01, 0x00) + @(ConvertTo-SerializedString ([string]$pair[0])) + @(ConvertTo-SerializedString ([string]$pair[1])) + @(0x00, 0x00))
    $null = $mb.AddCustomAttribute($tok::EntityHandle($table::Assembly, 1), $tok::EntityHandle($table::MemberRef, 1), $mb.GetOrAddBlob($value))
  }
  $pe = [System.Reflection.PortableExecutable.ManagedPEBuilder]::new(
    [System.Reflection.PortableExecutable.PEHeaderBuilder]::CreateLibraryHeader(),
    [System.Reflection.Metadata.Ecma335.MetadataRootBuilder]::new($mb),
    [System.Reflection.Metadata.BlobBuilder]::new())
  $image = [System.Reflection.Metadata.BlobBuilder]::new()
  $null = $pe.Serialize($image)
  [IO.File]::WriteAllBytes($Path, $image.ToArray())
}

function Get-TrustPairs {
  param([string[]]$Keys, [string[]]$Pins, [string]$Prefix, [string]$Channel = "stable")
  return @(
    @("AgentUpdateManifestPublicKeysB64", ($Keys -join ",")),
    @("AgentUpdateAllowedSignerKeyIdentity", ($Pins -join ",")),
    @("AgentUpdateAllowedArtifactPrefixes", $Prefix),
    @("AgentReleaseChannel", $Channel)
  )
}

function New-FinalizeFixture {
  param(
    [Parameter(Mandatory = $true)][string]$PublishDir,
    [Parameter(Mandatory = $true)][string]$CoreDll,
    [Parameter(Mandatory = $true)][string[]]$KeyListB64,
    [Parameter(Mandatory = $true)][string]$SignerPin,
    [Parameter(Mandatory = $true)][string]$Prefix,
    [string]$PayloadVersion = "9.9.9",
    [long]$LengthDelta = 0,
    # Embedded values default to the declared ones; each override changes only the embedded side of one binding.
    [string]$EmbeddedChannel = "stable",
    [string]$EmbeddedPrefix = "",
    # Raw metadata for one DLL (replaces the default pairs); $null keeps the default.
    [object[]]$AgentPairs = $null,
    [object[]]$RuntimePairs = $null,
    [string]$RuntimeNamespace = "System.Reflection",
    # Canonical payload signer identity, when it should differ from the embedded pin.
    [string]$CanonicalSignerPin = "",
    # Channel written into the canonical payload (the pending payload), when it should differ from -Channel.
    [string]$CanonicalChannel = "stable",
    # Further signer pins, embedded and pending alongside -SignerPin.
    [string[]]$ExtraPins = @()
  )
  $runtime = Join-Path $PublishDir "runtime"
  New-Item -ItemType Directory -Path $runtime -Force | Out-Null
  Copy-Item -LiteralPath $CoreDll -Destination (Join-Path $runtime "Cerberus.Agent.Core.dll")
  $embeddedPrefix = if ($EmbeddedPrefix) { $EmbeddedPrefix } else { $Prefix }
  $default = Get-TrustPairs -Keys $KeyListB64 -Pins (@($SignerPin) + @($ExtraPins)) -Prefix $embeddedPrefix -Channel $EmbeddedChannel
  if ($null -eq $AgentPairs) { $AgentPairs = $default }
  if ($null -eq $RuntimePairs) { $RuntimePairs = $default }
  New-MetadataAssembly -Path (Join-Path $runtime "Cerberus.Agent.dll") -AssemblyName "Cerberus.Agent" -Pairs $AgentPairs
  New-MetadataAssembly -Path (Join-Path $runtime "Cerberus.Agent.Runtime.dll") -AssemblyName "Cerberus.Agent.Runtime" -Pairs $RuntimePairs -AttributeNamespace $RuntimeNamespace
  foreach ($exe in $script:ReleaseRuntimeExecutableNames) { Set-Content -LiteralPath (Join-Path $runtime $exe) -Value "fixture $exe" }
  $msi = Join-Path $PublishDir "Cerberus.Agent-stable-9.9.9.msi"
  Set-Content -LiteralPath $msi -Value "fixture msi bytes"
  foreach ($file in @("Cerberus.Agent.Bundle-stable-9.9.9.zip", "Cerberus.Agent.Bundle-stable-9.9.9.sbom.json", "Cerberus.Agent.Bundle-stable-9.9.9.provenance.json")) {
    Set-Content -LiteralPath (Join-Path $PublishDir $file) -Value "fixture $file"
  }
  $now = [DateTimeOffset]::UtcNow
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $msi).Hash.ToLowerInvariant()
  $length = (Get-Item -LiteralPath $msi).Length + $LengthDelta
  $identity = if ($CanonicalSignerPin) { $CanonicalSignerPin } else { $SignerPin }
  $canonical = @("msi", $PayloadVersion, $CanonicalChannel, "${Prefix}a.msi", $hash, "Cerberus Agent Release", $now.AddMinutes(-1).ToString("O"),
    "agent.heartbeat.v1", "false", "agent.update.manifest.v2", $now.ToUnixTimeMilliseconds().ToString(), $now.AddDays(30).ToString("O"),
    $length.ToString(), $identity) -join "`n"
  Write-PendingExternalManifest -PublishDir $PublishDir -AssetBase "Cerberus.Agent.Bundle-stable-9.9.9" -Canonical $canonical `
    -KeyListB64 $KeyListB64 -ArtifactPrefixes @($Prefix) -SignerPins (@($SignerPin) + @($ExtraPins)) 6>$null
  return [pscustomobject]@{ Publish = $PublishDir; Msi = $msi; Canonical = $canonical }
}
