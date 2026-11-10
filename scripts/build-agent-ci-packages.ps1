# Unsigned inspection artifacts, using public fixtures only; never a release or target candidate.
param([string]$OutputRoot = 'out/ci', [string]$Configuration = 'Release',
      [ValidateSet('desktop','server')][string]$BuildProfile = 'desktop')
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$outputRootPath = [IO.Path]::GetFullPath($OutputRoot, $repoRoot)
if (-not $outputRootPath.StartsWith(([IO.Path]::GetFullPath((Join-Path $repoRoot 'out')) + [IO.Path]::DirectorySeparatorChar), [StringComparison]::OrdinalIgnoreCase)) { throw 'CI outputs must stay inside worktree/out.' }
if (Test-Path -LiteralPath $outputRootPath) { throw 'CI packaging requires a fresh output directory.' }
$publishDir = Join-Path $outputRootPath 'publish'
$runtimePublishDir = Join-Path $publishDir 'runtime'
New-Item -ItemType Directory -Path $runtimePublishDir -Force | Out-Null
$proof = [ordered]@{ profile = $BuildProfile; version = '0.0.0'; signed = $false; releaseManifest = $false
  source = (git -C $repoRoot rev-parse HEAD).Trim(); status = 'failed'
  startedUtc = [DateTimeOffset]::UtcNow.ToString('o')
  evidence = 'unsigned CI inspection/public fixtures; process denial is not SYSTEM recovery or target self-update acceptance' }
try {
. (Join-Path $PSScriptRoot 'release-profile-lib.ps1')
. (Join-Path $PSScriptRoot 'release-runtime-publish-lib.ps1')
. (Join-Path $PSScriptRoot 'release-bundle-lib.ps1')
. (Join-Path $PSScriptRoot 'release-trust-lib.ps1')
$Runtime = 'win-x64'; $Version = '0.0.0'; $Channel = 'dev'
$AgentUpdateManifestPublicKeysB64 = ''; $UpdateManifestUrl = ''; $UpdateAllowedArtifactPrefixes = ''
$signerPinsForBuild = ''; $allowUnsignedBuildMetadata = ($BuildProfile -eq 'desktop')
$DefaultBackendUrl = ''; $DefaultSsoBaseUrl = ''; $DefaultSsoClientId = ''; $DefaultSsoScope = ''
$DefaultOAuthRedirectPort = 0
$profileArgs = @("-p:AgentBuildProfile=$BuildProfile")
if ($BuildProfile -eq 'server') {
  $anchorsPath = Join-Path $repoRoot 'tests/fixtures/agent-command-test-anchors.b64'
  $anchors = (Get-Content -LiteralPath $anchorsPath -Raw).Trim()
  $null = Assert-ServerCommandAnchors $anchors
  $proof.publicFixtureAnchorsSha256 = (Get-FileHash -LiteralPath $anchorsPath).Hash
  $profileArgs += "-p:AgentCommandTrustAnchorsB64=$anchors"
}
$releaseProfile = [pscustomobject]@{ MsBuildArgs = $profileArgs }
$projects = @('App', 'Service', 'Updater')
if ($BuildProfile -eq 'desktop') { $projects += 'Uninstall' }
foreach ($project in $projects) {
  Publish-AgentProject "src/Cerberus.Agent.$project/Cerberus.Agent.$project.csproj"
}
Remove-Item -LiteralPath (Join-Path $runtimePublishDir 'createdump.exe') -Force -ErrorAction SilentlyContinue
$expected = @($projects | ForEach-Object { "Cerberus.Agent.$_.exe" })
$expected[0] = 'Cerberus.Agent.exe'
foreach ($name in $expected) {
  if (-not (Test-Path -LiteralPath (Join-Path $runtimePublishDir $name))) { throw "Missing runtime file: $name" }
}
if (@(Get-ChildItem -LiteralPath $runtimePublishDir -Filter '*.exe' | Where-Object { $_.Name -notin $expected }).Count) {
  throw 'Unexpected executable in CI payload.'
}
if ($BuildProfile -eq 'server') { Assert-ServerBundleLayout $runtimePublishDir }
$helperOutput = Join-Path $outputRootPath 'installer-helper'
& dotnet publish (Join-Path $repoRoot 'src/Cerberus.Agent.Installer/Helper/Cerberus.Agent.Installer.Helper.csproj') `
  -c $Configuration -r $Runtime --self-contained true -p:PublishSingleFile=true -p:Version=$Version `
  -p:AgentReleaseChannel=dev @profileArgs -o $helperOutput | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'CI installer helper publish failed.' }
$helper = Join-Path $helperOutput 'Cerberus.Agent.Installer.Helper.exe'
$exeHash = (Get-FileHash -LiteralPath (Join-Path $runtimePublishDir 'Cerberus.Agent.Service.exe')).Hash
$assemblyHash = Get-ReleaseServiceAssemblyHash $runtimePublishDir $BuildProfile
$suffix = if ($BuildProfile -eq 'server') { '-server' } else { '' }
$base = 'Cerberus.Agent-dev-0.0.0' + $suffix
$msiOutput = Join-Path $outputRootPath 'msi-build'
& dotnet build (Join-Path $repoRoot 'src/Cerberus.Agent.Installer/Cerberus.Agent.Installer.wixproj') `
  -c $Configuration -p:Version=$Version -p:MsiProductVersion=$Version -p:Channel=dev "-p:AgentBuildProfile=$BuildProfile" `
  "-p:AgentPublishDir=$runtimePublishDir" "-p:InstallerHelperPath=$helper" `
  "-p:ServiceExeSha256=$exeHash" "-p:ServiceAssemblySha256=$assemblyHash" `
  "-p:InstallerAssetBase=$base" -p:Cultures=en-us "-p:OutputPath=$msiOutput/" `
  "-p:BaseIntermediateOutputPath=$outputRootPath/msi-obj/" | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'CI MSI build failed.' }
$built = @(Get-ChildItem -LiteralPath $msiOutput -Recurse -Filter "$base.msi")
if ($built.Count -ne 1) { throw 'Exactly one CI MSI is required.' }
$msi = Join-Path $publishDir "$base.msi"
Copy-Item -LiteralPath $built[0].FullName -Destination $msi
$setup = New-AgentSetupBundle -MsiPath $msi -PublishDir $publishDir -BuildProfile $BuildProfile `
  -Configuration $Configuration -BuildDirectory (Join-Path $outputRootPath 'setup-build')
$proof.msi = $msi; $proof.msiSha256 = (Get-FileHash -LiteralPath $msi).Hash
$proof.setup = $setup; $proof.setupSha256 = (Get-FileHash -LiteralPath $setup).Hash
$denyProof = $null
if ($BuildProfile -eq 'server' -and $env:GITHUB_ACTIONS -eq 'true') {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  if ($env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $identity.IsSystem) { throw 'Updater denial probe requires a disposable GitHub-hosted, non-SYSTEM runner.' }
  $updater = Join-Path $runtimePublishDir 'Cerberus.Agent.Updater.exe'
  $info = [Diagnostics.ProcessStartInfo]::new($updater)
  $info.UseShellExecute = $false
  $info.CreateNoWindow = $true
  $process = [Diagnostics.Process]::Start($info)
  $processStartedUtc = $process.StartTime.ToUniversalTime()
  try {
    if (-not $process.WaitForExit(30000)) { $process.Kill(); throw 'Unauthorized updater did not terminate within its CI bound.' }
    if ($process.ExitCode -ne 2) { throw "Expected updater LocalSystem denial (2), got $($process.ExitCode)." }
    # Read only this PID's two-line startup/denial log, never a journal or enrollment data.
    $logRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'CerberusServerAgent/Privileged/Updates/logs'
    $logs = @(Get-ChildItem -LiteralPath $logRoot -Filter "updater-*-$($process.Id).log" -File |
      Where-Object { $_.LastWriteTimeUtc -ge $processStartedUtc })
    $denial = 'Updater denied: process is not LocalSystem.'
    if ($logs.Count -ne 1 -or -not (Get-Content -LiteralPath $logs[0].FullName -Raw).Contains($denial)) { throw 'No PID-bound LocalSystem denial message; exit code alone is insufficient.' }
    $logCopy = Join-Path $outputRootPath 'updater-denial.log'
    Copy-Item -LiteralPath $logs[0].FullName -Destination $logCopy
    $denyProof = @{ exitCode = $process.ExitCode; expected = 2; processId = $process.Id
      updaterSha256 = (Get-FileHash -LiteralPath $updater).Hash; processStarted = $true; nonSystem = $true; installed = $false
      launcherIdentity = $identity.Name; launcherIdentitySid = $identity.User.Value
      startedUtc = $processStartedUtc.ToString('o'); endedUtc = [DateTimeOffset]::UtcNow.ToString('o')
      tokenMode = 'current token inherited; no alternate credentials'; message = $denial
      denialLogSha256 = (Get-FileHash -LiteralPath $logCopy).Hash }
  } finally { $process.Dispose() }
}
$proof.updaterAuthorizationDenial = $denyProof
$proof.status = 'completed'
} finally {
  $proof.endedUtc = [DateTimeOffset]::UtcNow.ToString('o')
  $proof | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $outputRootPath 'ci-package-proof.json') -Encoding utf8
}
