#requires -Version 7.5
# Builds the 1618 hold MSI (test harness only) into the ignored out/ folder and prints its path and SHA-256.
param([string]$OutputRoot = (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'out\hold-installer'))
$ErrorActionPreference = 'Stop'
$project = Join-Path $PSScriptRoot 'hold-installer.wixproj'
# obj/ next to the project is git-ignored, so the tree stays clean for build-agent-test-campaign.ps1.
& dotnet build $project -c Release -o $OutputRoot -nologo
if ($LASTEXITCODE -ne 0) { throw "Hold installer build failed ($LASTEXITCODE)." }
$msi = Join-Path $OutputRoot 'cerberus-campaign-hold.msi'
if (-not (Test-Path -LiteralPath $msi)) { throw 'Hold installer MSI is missing after the build.' }
[pscustomobject]@{ path = $msi; sha256 = (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant() }
