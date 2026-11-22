# Verify the artifact URL from a copy of the manifest after the public release exists.
param(
  [Parameter(Mandatory = $true)][string]$ManifestPath,
  [string]$UpdateAllowedArtifactPrefixes = $env:CERBERUS_AGENT_UPDATE_ALLOWED_ARTIFACT_PREFIXES,
  [string]$AllowedTailnetArtifactHost = ""
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
Write-Host 'Published release artifact passed anonymous HTTPS HEAD.'
