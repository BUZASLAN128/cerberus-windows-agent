# Unsigned Desktop packaging for PR/push CI inspection. No release manifest or signing inputs.
param([string]$OutputRoot = 'out/ci', [string]$Configuration = 'Release')
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$outputRootPath = [IO.Path]::GetFullPath($OutputRoot, $repoRoot)
if (Test-Path -LiteralPath $outputRootPath) { throw 'CI packaging requires a fresh output directory.' }
$publishDir = Join-Path $outputRootPath 'publish'
$runtimePublishDir = Join-Path $publishDir 'runtime'
New-Item -ItemType Directory -Path $runtimePublishDir -Force | Out-Null
. (Join-Path $PSScriptRoot 'release-profile-lib.ps1')
. (Join-Path $PSScriptRoot 'release-runtime-publish-lib.ps1')
. (Join-Path $PSScriptRoot 'release-bundle-lib.ps1')
$Runtime = 'win-x64'; $Version = '0.0.0'; $Channel = 'dev'; $BuildProfile = 'desktop'
$AgentUpdateManifestPublicKeysB64 = ''; $UpdateManifestUrl = ''; $UpdateAllowedArtifactPrefixes = ''
$signerPinsForBuild = ''; $allowUnsignedBuildMetadata = $true
$DefaultBackendUrl = ''; $DefaultSsoBaseUrl = ''; $DefaultSsoClientId = ''; $DefaultSsoScope = ''
$DefaultOAuthRedirectPort = 0
$releaseProfile = [pscustomobject]@{ MsBuildArgs = @('-p:AgentBuildProfile=desktop') }
foreach ($project in @('App', 'Service', 'Updater', 'Uninstall')) {
  Publish-AgentProject "src/Cerberus.Agent.$project/Cerberus.Agent.$project.csproj"
}
Remove-Item -LiteralPath (Join-Path $runtimePublishDir 'createdump.exe') -Force -ErrorAction SilentlyContinue
$expected = @('Cerberus.Agent.exe', 'Cerberus.Agent.Service.exe', 'Cerberus.Agent.Updater.exe', 'Cerberus.Agent.Uninstall.exe')
foreach ($name in $expected) {
  if (-not (Test-Path -LiteralPath (Join-Path $runtimePublishDir $name))) { throw "Missing runtime file: $name" }
}
if (@(Get-ChildItem -LiteralPath $runtimePublishDir -Filter '*.exe' | Where-Object { $_.Name -notin $expected }).Count) {
  throw 'Unexpected executable in CI payload.'
}
$helperOutput = Join-Path $outputRootPath 'installer-helper'
& dotnet publish (Join-Path $repoRoot 'src/Cerberus.Agent.Installer/Helper/Cerberus.Agent.Installer.Helper.csproj') `
  -c $Configuration -r $Runtime --self-contained true -p:PublishSingleFile=true -p:Version=$Version `
  -p:AgentReleaseChannel=dev -p:AgentBuildProfile=desktop -o $helperOutput | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'CI installer helper publish failed.' }
$helper = Join-Path $helperOutput 'Cerberus.Agent.Installer.Helper.exe'
$exeHash = (Get-FileHash -LiteralPath (Join-Path $runtimePublishDir 'Cerberus.Agent.Service.exe')).Hash
$assemblyHash = (Get-FileHash -LiteralPath (Join-Path $runtimePublishDir 'Cerberus.Agent.Service.dll')).Hash
$base = 'Cerberus.Agent-dev-0.0.0'
$msiOutput = Join-Path $outputRootPath 'msi-build'
& dotnet build (Join-Path $repoRoot 'src/Cerberus.Agent.Installer/Cerberus.Agent.Installer.wixproj') `
  -c $Configuration -p:Version=$Version -p:MsiProductVersion=$Version -p:Channel=dev -p:AgentBuildProfile=desktop `
  "-p:AgentPublishDir=$runtimePublishDir" "-p:InstallerHelperPath=$helper" `
  "-p:ServiceExeSha256=$exeHash" "-p:ServiceAssemblySha256=$assemblyHash" `
  "-p:InstallerAssetBase=$base" -p:Cultures=en-us "-p:OutputPath=$msiOutput/" `
  "-p:BaseIntermediateOutputPath=$outputRootPath/msi-obj/" | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'CI MSI build failed.' }
$built = @(Get-ChildItem -LiteralPath $msiOutput -Recurse -Filter "$base.msi")
if ($built.Count -ne 1) { throw 'Exactly one CI MSI is required.' }
$msi = Join-Path $publishDir "$base.msi"
Copy-Item -LiteralPath $built[0].FullName -Destination $msi
$setup = New-AgentSetupBundle -MsiPath $msi -PublishDir $publishDir -BuildProfile desktop `
  -Configuration $Configuration -BuildDirectory (Join-Path $outputRootPath 'setup-build')
[pscustomobject]@{ profile = 'desktop'; version = $Version; signed = $false; releaseManifest = $false
  msi = $msi; msiSha256 = (Get-FileHash -LiteralPath $msi).Hash
  setup = $setup; setupSha256 = (Get-FileHash -LiteralPath $setup).Hash
  evidence = 'unsigned CI packaging; not updater/release or installed acceptance' } |
  ConvertTo-Json | Set-Content (Join-Path $outputRootPath 'ci-package-proof.json')
