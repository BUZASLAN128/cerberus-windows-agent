# Verify the artifact URL from a copy of the manifest after the public release exists.
param(
  [Parameter(Mandatory = $true)][string]$ManifestPath,
  [string]$UpdateAllowedArtifactPrefixes = $env:CERBERUS_AGENT_UPDATE_ALLOWED_ARTIFACT_PREFIXES,
  [string]$AllowedTailnetArtifactHost = "",
  # Feed publication: the one-line install scripts are served next to the MSI. GitHub releases do not carry them.
  [switch]$CheckInstallScripts
)

$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Core') { throw 'PowerShell 7+ (pwsh) is required for release artifact preflight.' }
. (Join-Path $PSScriptRoot 'release-artifact-url-lib.ps1')

try {
  $document = [System.Text.Json.JsonDocument]::Parse([IO.File]::ReadAllText((Get-Item -LiteralPath $ManifestPath).FullName))
  try {
    $properties = @($document.RootElement.EnumerateObject() | Where-Object { $_.Name.Equals('artifact_url', [StringComparison]::OrdinalIgnoreCase) })
    if ($properties.Count -ne 1 -or -not $properties[0].NameEquals('artifact_url') -or
        $properties[0].Value.ValueKind -ne [System.Text.Json.JsonValueKind]::String) { throw 'Expected one artifact_url.' }
    $artifactUrl = $properties[0].Value.GetString()
  } finally { $document.Dispose() }
} catch { throw 'Release manifest could not be read as JSON with one string artifact_url.' }

if ([string]::IsNullOrWhiteSpace($UpdateAllowedArtifactPrefixes)) {
  $UpdateAllowedArtifactPrefixes = Get-DefaultReleaseArtifactPrefix
}
$prefixes = @(Get-ReleaseArtifactPrefixes $UpdateAllowedArtifactPrefixes)
Assert-ReleaseArtifactReachable -ArtifactUrl $artifactUrl -ArtifactPrefixes $prefixes -AllowedTailnetHost $AllowedTailnetArtifactHost
if ($CheckInstallScripts) {
  if ($artifactUrl -cnotmatch '\A(?<dir>https://.+/)(?<base>Cerberus\.Agent-(?<channel>[a-z]+)-[0-9]+\.[0-9]+\.[0-9]+(?<suffix>-server)?)\.msi\z') {
    throw 'Release artifact name does not follow the installer naming; cannot derive the install script URLs.'
  }
  $scriptDir = $Matches.dir
  $scriptNames = @("$($Matches.base).install.ps1", "Cerberus.Agent-$($Matches.channel)-latest$($Matches.suffix).install.ps1")
  foreach ($scriptName in $scriptNames) {
    Assert-ReleaseArtifactReachable -ArtifactUrl ($scriptDir + $scriptName) -ArtifactPrefixes $prefixes -AllowedTailnetHost $AllowedTailnetArtifactHost
  }
}
Write-Host $(if ($CheckInstallScripts) { 'Published release artifact and install scripts passed anonymous HTTPS HEAD.' } else { 'Published release artifact passed anonymous HTTPS HEAD.' })
