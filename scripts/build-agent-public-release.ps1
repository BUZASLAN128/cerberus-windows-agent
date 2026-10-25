param(
  [Parameter(Mandatory = $true)]
  [string]$Version,

  [ValidatePattern('^(dev|preview|stable)\z', Options = 'None', ErrorMessage = 'Channel must be lowercase dev, preview or stable.')]
  [string]$Channel = "dev",

  [string]$Configuration = "Release",
  [string]$Runtime = "win-x64",
  [string]$OutputRoot = "out/public-release",
  [string]$TimestampUrl = "http://timestamp.digicert.com",
  [string]$DefaultBackendUrl = "",
  [string]$DefaultSsoBaseUrl = "",
  [string]$DefaultSsoClientId = "",
  [string]$DefaultSsoScope = "",
  [string]$UpdateManifestUrl = $env:CERBERUS_AGENT_UPDATE_MANIFEST_URL,
  [string]$AgentUpdateManifestPublicKeysB64 = $env:CERBERUS_AGENT_UPDATE_MANIFEST_PUBLIC_KEYS_B64,
  [string]$UpdateManifestPublicKeyB64 = $env:CERBERUS_AGENT_UPDATE_MANIFEST_PUBLIC_KEY_B64,
  [string]$UpdateAllowedArtifactPrefixes = $env:CERBERUS_AGENT_UPDATE_ALLOWED_ARTIFACT_PREFIXES,
  [int]$DefaultOAuthRedirectPort = 0,
  [long]$ManifestSequence = 0,
  [switch]$SkipTests,
  [switch]$AllowUnsignedDevBuild,
  [switch]$AllowEphemeralManifestKey,

  # Pfx: WINDOWS_SIGNING_CERT_BASE64 + AGENT_UPDATE_MANIFEST_PRIVATE_KEY_PEM (default, CI path).
  # Token: certificates selected by thumbprint from CurrentUser\My (private keys stay on the token),
  # or a two-step external manifest signature.
  [ValidateSet("Pfx", "Token")]
  [string]$SigningMode = "Pfx",
  [string]$SigningCertThumbprint = "",
  [string[]]$ExtraSignerPins = @(),
  [string]$ManifestSigningCertThumbprint = "",
  [string]$ManifestSigningPublicKeyFile = "",
  [string]$ManifestSignatureFile = "",
  [string[]]$ExtraManifestPublicKeyFiles = @(),

  # Build profile. The server profile needs the file holding AgentCommandTrustAnchorsB64.
  [ValidateSet("desktop", "server")][string]$BuildProfile = "desktop",
  [string]$AgentCommandTrustAnchorsFile = "",
  [hashtable]$TimingOverrides = @{},
  [string]$ProductName = "",
  [string]$EulaRtf = ""
)

$ErrorActionPreference = "Stop"

if ($PSVersionTable.PSEdition -ne "Core") {
  throw "PowerShell 7+ (pwsh) is required for public release signing and manifest generation."
}

. (Join-Path $PSScriptRoot "release-signing-lib.ps1")
. (Join-Path $PSScriptRoot "release-trust-lib.ps1")
. (Join-Path $PSScriptRoot "release-publish-lib.ps1")
. (Join-Path $PSScriptRoot "release-token-lib.ps1")
. (Join-Path $PSScriptRoot "release-profile-lib.ps1")
$signingPlan = Assert-ReleaseSigningInputs `
  -Mode $SigningMode `
  -SigningCertThumbprint $SigningCertThumbprint `
  -ManifestSigningCertThumbprint $ManifestSigningCertThumbprint `
  -ManifestSigningPublicKeyFile $ManifestSigningPublicKeyFile `
  -ManifestSignatureFile $ManifestSignatureFile `
  -ExtraSignerPins $ExtraSignerPins `
  -ExtraManifestPublicKeyFiles $ExtraManifestPublicKeyFiles `
  -PfxCertificatePresent (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable("WINDOWS_SIGNING_CERT_BASE64"))) `
  -ManifestPrivateKeyPemPresent (-not [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable("AGENT_UPDATE_MANIFEST_PRIVATE_KEY_PEM"))) `
  -AllowUnsignedDevBuild ([bool]$AllowUnsignedDevBuild) `
  -AllowEphemeralManifestKey ([bool]$AllowEphemeralManifestKey)
$tokenMode = ($signingPlan.Mode -eq "Token")

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$outputRootPath = Join-Path $repoRoot $OutputRoot
$publishDir = Join-Path $outputRootPath "publish"
$releaseProfile = Get-ReleaseProfileBuild $BuildProfile $AgentCommandTrustAnchorsFile $TimingOverrides $ProductName $EulaRtf
$assetBase = "Cerberus.Agent.Bundle-$Channel-$Version$($releaseProfile.AssetSuffix)"
$installerBase = "Cerberus.Agent-$Channel-$Version$($releaseProfile.AssetSuffix)"
if ($signingPlan.Finalize) {
  Complete-ExternalManifestSigning `
    -PublishDir $publishDir -Channel $Channel -Version $Version -AssetBase $assetBase -InstallerBase $installerBase `
    -SignaturePath $ManifestSignatureFile -PublicKeyPath $ManifestSigningPublicKeyFile -BuildProfile $BuildProfile
  return
}
Remove-Item -LiteralPath $publishDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $publishDir | Out-Null
$runtimePublishDir = Join-Path $publishDir "runtime"
New-Item -ItemType Directory -Force -Path $runtimePublishDir | Out-Null

if ($DefaultOAuthRedirectPort -le 0) {
  $redirectPortFromEnv = $env:CERBERUS_OAUTH_REDIRECT_PORT
  if ($null -eq $redirectPortFromEnv) {
    $redirectPortFromEnv = ""
  }
  $redirectPortFromEnv = $redirectPortFromEnv.Trim()
  if ([int]::TryParse($redirectPortFromEnv, [ref]$DefaultOAuthRedirectPort) -and
      ($DefaultOAuthRedirectPort -le 0 -or $DefaultOAuthRedirectPort -gt 65535)) {
    $DefaultOAuthRedirectPort = 0
  }
}
if ($Channel -eq "dev") {
  if ([string]::IsNullOrWhiteSpace($DefaultBackendUrl)) { $DefaultBackendUrl = "http://127.0.0.1:8000" }
  if ([string]::IsNullOrWhiteSpace($DefaultSsoBaseUrl)) { $DefaultSsoBaseUrl = "http://localhost:18000" }
  if ([string]::IsNullOrWhiteSpace($DefaultSsoClientId)) { $DefaultSsoClientId = "610f03b77494869da4ef" }
  if ([string]::IsNullOrWhiteSpace($DefaultSsoScope)) { $DefaultSsoScope = "openid profile email groups" }
  if ($DefaultOAuthRedirectPort -le 0) { $DefaultOAuthRedirectPort = 19823 }
}
else {
  if ([string]::IsNullOrWhiteSpace($DefaultBackendUrl)) { $DefaultBackendUrl = $env:CERBERUS_BACKEND_URL }
  if ([string]::IsNullOrWhiteSpace($DefaultSsoBaseUrl)) { $DefaultSsoBaseUrl = $env:CERBERUS_SSO_BASE_URL }
  if ([string]::IsNullOrWhiteSpace($DefaultSsoClientId)) { $DefaultSsoClientId = $env:CERBERUS_SSO_CLIENT_ID }
  if ([string]::IsNullOrWhiteSpace($DefaultSsoScope)) { $DefaultSsoScope = $env:CERBERUS_SSO_SCOPE }
  if ([string]::IsNullOrWhiteSpace($DefaultBackendUrl)) { $DefaultBackendUrl = "https://app.cerberusd.com" }
  if ([string]::IsNullOrWhiteSpace($DefaultSsoBaseUrl)) { $DefaultSsoBaseUrl = "https://auth.cerberusd.com" }
  if ([string]::IsNullOrWhiteSpace($DefaultSsoClientId)) { throw "A deployment-specific public SSO client ID is required for preview/stable builds." }
  if ([string]::IsNullOrWhiteSpace($DefaultSsoScope)) { $DefaultSsoScope = "openid profile email groups" }
  if ($DefaultOAuthRedirectPort -le 0) { $DefaultOAuthRedirectPort = 19823 }
}
foreach ($endpoint in @($DefaultBackendUrl, $DefaultSsoBaseUrl)) {
  $uri = $null
  if (-not [Uri]::TryCreate($endpoint, [UriKind]::Absolute, [ref]$uri) -or
      $uri.UserInfo -or $uri.Query -or $uri.Fragment) {
    throw "Build routing requires absolute backend/SSO URLs without credentials, query or fragment."
  }
  if ($Channel -eq "dev") {
    if (-not $uri.IsLoopback -or $uri.Scheme -notin @("http", "https")) {
      throw "Dev builds require loopback backend and SSO endpoints."
    }
  } elseif ($uri.IsLoopback -or $uri.Scheme -ne "https") {
    throw "Preview/stable builds require non-loopback HTTPS backend and SSO endpoints."
  }
}

$manifestPrivateKey = $null
$tokenSigning = $null
$artifactPrefixList = @()
if ($tokenMode) {
  $tokenSigning = Initialize-TokenSigning `
    -SigningPlan $signingPlan -SigningCertThumbprint $SigningCertThumbprint -ExtraSignerPins $ExtraSignerPins `
    -ManifestSigningCertThumbprint $ManifestSigningCertThumbprint -ManifestSigningPublicKeyFile $ManifestSigningPublicKeyFile `
    -ExtraManifestPublicKeyFiles $ExtraManifestPublicKeyFiles
  $tokenSignerPins = $tokenSigning.SignerPins
  $tokenKeyListB64 = $tokenSigning.KeyListB64
  # The MSI registry value takes a single key (read on dev-channel overrides only); the full list is embedded in the binaries.
  $UpdateManifestPublicKeyB64 = $tokenKeyListB64[0]
  $AgentUpdateManifestPublicKeysB64 = ConvertTo-MsBuildListValue $tokenKeyListB64
} else {
$manifestPrivateKey = [Environment]::GetEnvironmentVariable("AGENT_UPDATE_MANIFEST_PRIVATE_KEY_PEM")
if ([string]::IsNullOrWhiteSpace($manifestPrivateKey) -and
    $Channel -eq "dev" -and
    $AllowUnsignedDevBuild -and
    $AllowEphemeralManifestKey) {
  if ([string]::Equals($env:GITHUB_ACTIONS, "true", [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "GitHub dev releases require stable AGENT_UPDATE_MANIFEST_PRIVATE_KEY_PEM; ephemeral manifest keys are local/lab only."
  }
  $ephemeralManifestKey = [System.Security.Cryptography.RSA]::Create(3072)
  $manifestPrivateKey = $ephemeralManifestKey.ExportPkcs8PrivateKeyPem()
}
if ([string]::IsNullOrWhiteSpace($manifestPrivateKey)) {
  throw "Required environment variable 'AGENT_UPDATE_MANIFEST_PRIVATE_KEY_PEM' is missing. Use -AllowEphemeralManifestKey only for local update-lab artifacts that will not be published as latest."
}
$manifestPublicKeyB64 = ConvertTo-Base64Utf8 (Get-ManifestPublicKeyPem $manifestPrivateKey)
$UpdateManifestPublicKeyB64 = $manifestPublicKeyB64
$AgentUpdateManifestPublicKeysB64 = $manifestPublicKeyB64
}
if ($BuildProfile -eq "server") {
  Assert-CommandAnchorsNotManifestKeys $releaseProfile.AnchorsB64 $(if ($tokenMode) { $tokenKeyListB64 } else { @($manifestPublicKeyB64) })
}
if ([string]::IsNullOrWhiteSpace($UpdateManifestUrl)) {
  $manifestRepo = if ([string]::IsNullOrWhiteSpace($env:GITHUB_REPOSITORY)) { "BUZASLAN128/cerberus-windows-agent" } else { $env:GITHUB_REPOSITORY }
  $UpdateManifestUrl = if ($Channel -eq "stable") {
    "https://github.com/$manifestRepo/releases/latest/download/Cerberus.Agent.Bundle-stable-latest.update-manifest.v2.json".Replace("-latest.update", "-latest$($releaseProfile.AssetSuffix).update")
  } else {
    "https://github.com/$manifestRepo/releases/download/$Channel-latest/Cerberus.Agent.Bundle-$Channel-latest.update-manifest.v2.json".Replace("-latest.update", "-latest$($releaseProfile.AssetSuffix).update")
  }
}
if ([string]::IsNullOrWhiteSpace($UpdateAllowedArtifactPrefixes)) {
  $artifactRepo = if ([string]::IsNullOrWhiteSpace($env:GITHUB_REPOSITORY)) { "BUZASLAN128/cerberus-windows-agent" } else { $env:GITHUB_REPOSITORY }
  $UpdateAllowedArtifactPrefixes = "https://github.com/$artifactRepo/releases/download/"
}
# The agent splits this list on ','; MSBuild -p: needs the separator and other syntax characters escaped.
$artifactPrefixList = @($UpdateAllowedArtifactPrefixes -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$UpdateAllowedArtifactPrefixes = ConvertTo-MsBuildListValue $artifactPrefixList

$artifactUrlBase = [Environment]::GetEnvironmentVariable("AGENT_RELEASE_ARTIFACT_BASE_URL")
if ([string]::IsNullOrWhiteSpace($artifactUrlBase) -and $Channel -eq "dev" -and -not [string]::IsNullOrWhiteSpace($env:GITHUB_REPOSITORY)) {
  $releaseTag = if ($Version.StartsWith("v")) { $Version } else { "v$Version" }
  $artifactUrlBase = "https://github.com/$env:GITHUB_REPOSITORY/releases/download/$releaseTag"
}
if ([string]::IsNullOrWhiteSpace($artifactUrlBase)) {
  throw "Required environment variable 'AGENT_RELEASE_ARTIFACT_BASE_URL' is missing."
}

$signerKeyIdentity = if ($Channel -eq "dev" -and $AllowUnsignedDevBuild) { "unsigned-dev" } else { "" }
$allowUnsignedBuildMetadata = ($Channel -eq "dev" -and $AllowUnsignedDevBuild)
$certBase64ForMetadata = [Environment]::GetEnvironmentVariable("WINDOWS_SIGNING_CERT_BASE64")
$certPasswordForMetadata = [Environment]::GetEnvironmentVariable("WINDOWS_SIGNING_CERT_PASSWORD")
if (-not [string]::IsNullOrWhiteSpace($certBase64ForMetadata)) {
  try {
    $certificateForMetadata = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
      [Convert]::FromBase64String($certBase64ForMetadata),
      $certPasswordForMetadata,
      [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
    $signerKeyIdentity = "sha256:" + [Convert]::ToHexString(
      [System.Security.Cryptography.SHA256]::HashData($certificateForMetadata.PublicKey.ExportSubjectPublicKeyInfo())).ToLowerInvariant()
  } catch {
    throw "Windows signing certificate identity could not be read."
  }
}
$signerPinsForBuild = $signerKeyIdentity
if ($tokenMode) {
  # The manifest carries the pin of the certificate that signs this release; the build embeds every accepted pin.
  $signerKeyIdentity = $tokenSignerPins[0]
  $signerPinsForBuild = ConvertTo-MsBuildListValue $tokenSignerPins
  $allowUnsignedBuildMetadata = $false
}
if ($ManifestSequence -le 0) {
  $ManifestSequence = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
}
if ($ManifestSequence -le 0) {
  throw "Manifest sequence must be positive."
}
Assert-ManifestSequenceInRange $ManifestSequence

if (-not $SkipTests) {
  Write-Step "Running dotnet tests"
  dotnet test (Join-Path $repoRoot "Cerberus.WindowsAgent.slnx") -c $Configuration
  if ($LASTEXITCODE -ne 0) { throw "Release tests failed." }
}

function Publish-AgentProject([string]$Project) {
  $args = @(
    "publish",
    (Join-Path $repoRoot $Project),
    "-c", $Configuration,
    "-r", $Runtime,
    "--self-contained", "true",
    "-p:PublishSingleFile=false",
    "-p:DebugType=None",
    "-p:DebugSymbols=false",
    "-p:Version=$Version",
    "-p:AgentUpdateManifestPublicKeysB64=$AgentUpdateManifestPublicKeysB64",
    "-p:AgentUpdateManifestUrl=$UpdateManifestUrl",
    "-p:AgentUpdateAllowedArtifactPrefixes=$UpdateAllowedArtifactPrefixes",
    "-p:AgentReleaseChannel=$Channel",
    "-p:AgentUpdateAllowedSignerKeyIdentity=$signerPinsForBuild",
    "-p:AllowUnsignedDevBuild=$($allowUnsignedBuildMetadata.ToString().ToLowerInvariant())",
    "-o", $runtimePublishDir
  )
  # Every publish must pass the same routing metadata to the shared runtime project.
  # Otherwise later service/updater publishes overwrite it with an unconfigured runtime.
  $args += @(
      "-p:AgentDefaultBackendUrlBase64=$(ConvertTo-Base64Utf8 $DefaultBackendUrl)",
      "-p:AgentDefaultSsoBaseUrlBase64=$(ConvertTo-Base64Utf8 $DefaultSsoBaseUrl)",
      "-p:AgentDefaultSsoClientIdBase64=$(ConvertTo-Base64Utf8 $DefaultSsoClientId)",
      "-p:AgentDefaultSsoScopeBase64=$(ConvertTo-Base64Utf8 $DefaultSsoScope)",
      "-p:AgentDefaultOAuthRedirectPort=$DefaultOAuthRedirectPort"
  ) + $releaseProfile.MsBuildArgs
  dotnet @args
  if ($LASTEXITCODE -ne 0) { throw "Runtime publish failed." }
}

Write-Step "Publishing split agent runtime"
Publish-AgentProject "src/Cerberus.Agent.App/Cerberus.Agent.App.csproj"
Publish-AgentProject "src/Cerberus.Agent.Service/Cerberus.Agent.Service.csproj"
Publish-AgentProject "src/Cerberus.Agent.Updater/Cerberus.Agent.Updater.csproj"
if ($BuildProfile -ne "server") { Publish-AgentProject "src/Cerberus.Agent.Uninstall/Cerberus.Agent.Uninstall.csproj" }

$versionWithoutPrefix = if ($Version.StartsWith("v")) { $Version.Substring(1) } else { $Version }
if ($versionWithoutPrefix -notmatch "^(\d+\.\d+\.\d+)") {
  throw "Release version '$Version' must start with a numeric major.minor.patch version for MSI ProductVersion."
}
$msiProductVersion = $Matches[1]
$runtimeExecutables = @(
  (Join-Path $runtimePublishDir "Cerberus.Agent.exe"),
  (Join-Path $runtimePublishDir "Cerberus.Agent.Service.exe"),
  (Join-Path $runtimePublishDir "Cerberus.Agent.Updater.exe"),
  (Join-Path $runtimePublishDir "Cerberus.Agent.Uninstall.exe")
)
$allowedRuntimeExeNames = @(
  "Cerberus.Agent.exe",
  "Cerberus.Agent.Service.exe",
  "Cerberus.Agent.Updater.exe",
  "Cerberus.Agent.Uninstall.exe"
)
if ($BuildProfile -eq "server") { # the server package has no desktop uninstaller
  $runtimeExecutables = @($runtimeExecutables | Where-Object { $_ -notlike "*Uninstall.exe" })
  $allowedRuntimeExeNames = @($allowedRuntimeExeNames | Where-Object { $_ -ne "Cerberus.Agent.Uninstall.exe" })
}
Remove-Item -LiteralPath (Join-Path $runtimePublishDir "createdump.exe") -Force -ErrorAction SilentlyContinue
foreach ($runtimeExe in $runtimeExecutables) {
  if (-not (Test-Path -LiteralPath $runtimeExe)) {
    throw "Expected runtime executable was not produced: $runtimeExe"
  }
}
$unexpectedRuntimeExecutables = Get-ChildItem -LiteralPath $runtimePublishDir -Filter "*.exe" |
  Where-Object { $allowedRuntimeExeNames -notcontains $_.Name } |
  Select-Object -ExpandProperty Name
if ($unexpectedRuntimeExecutables.Count -gt 0) {
  throw "Unexpected runtime executable(s) produced: $($unexpectedRuntimeExecutables -join ', ')"
}

$certBase64 = [Environment]::GetEnvironmentVariable("WINDOWS_SIGNING_CERT_BASE64")
$certPassword = [Environment]::GetEnvironmentVariable("WINDOWS_SIGNING_CERT_PASSWORD")
$signed = $false
if ($tokenMode) {
  Write-Step "Signing runtime executables with the token certificate"
  $signtool = Find-SignTool
  foreach ($runtimeExe in $runtimeExecutables) {
    Invoke-TokenFileSigning -SigntoolPath $signtool -Thumbprint $SigningCertThumbprint -TimestampUrl $TimestampUrl `
      -FilePath $runtimeExe -AllowedPins $tokenSignerPins
  }
  $signed = $true
}
elseif (-not [string]::IsNullOrWhiteSpace($certBase64)) {
  Write-Step "Signing runtime executables"
  $certPath = Join-Path $env:RUNNER_TEMP "cerberus-agent-signing.pfx"
  if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    $certPath = Join-Path $outputRootPath "cerberus-agent-signing.pfx"
  }
  [IO.File]::WriteAllBytes($certPath, [Convert]::FromBase64String($certBase64))
  $signtool = Find-SignTool
  foreach ($runtimeExe in $runtimeExecutables) {
    & $signtool sign /fd SHA256 /td SHA256 /tr $TimestampUrl /f $certPath /p $certPassword $runtimeExe
    if ($LASTEXITCODE -ne 0) { throw "Authenticode signing or verification failed." }
    & $signtool verify /pa /v $runtimeExe
    if ($LASTEXITCODE -ne 0) { throw "Authenticode signing or verification failed." }
  }
  Remove-Item -LiteralPath $certPath -Force -ErrorAction SilentlyContinue
  $signed = $true
}

if (-not $signed -and -not ($Channel -eq "dev" -and $AllowUnsignedDevBuild)) {
  throw "Unsigned public agent release denied. Configure WINDOWS_SIGNING_CERT_BASE64 and WINDOWS_SIGNING_CERT_PASSWORD."
}

Write-Step "Building MSI installer"
$installerHelperOutput = Join-Path $outputRootPath "installer-helper"
dotnet publish (Join-Path $repoRoot "src/Cerberus.Agent.Installer/Helper/Cerberus.Agent.Installer.Helper.csproj") `
  -c $Configuration -r $Runtime --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true `
  -p:Version=$Version @($releaseProfile.MsBuildArgs) -o $installerHelperOutput
if ($LASTEXITCODE -ne 0) { throw "Installer helper publish failed." }
$installerHelperPath = Join-Path $installerHelperOutput "Cerberus.Agent.Installer.Helper.exe"
$serviceExeSha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $runtimePublishDir "Cerberus.Agent.Service.exe")).Hash.ToLowerInvariant()
$serviceAssemblySha256 = (Get-FileHash -Algorithm SHA256 (Join-Path $runtimePublishDir "Cerberus.Agent.Service.dll")).Hash.ToLowerInvariant()
$installerProject = Join-Path $repoRoot "src/Cerberus.Agent.Installer/Cerberus.Agent.Installer.wixproj"
$installerProjectDir = Split-Path -Parent $installerProject
Remove-Item -LiteralPath (Join-Path $installerProjectDir "obj") -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath (Join-Path $installerProjectDir "bin") -Recurse -Force -ErrorAction SilentlyContinue
$installerBuildBase = "Cerberus.Agent"
dotnet build $installerProject `
  -c $Configuration `
  -p:Version=$Version `
  -p:MsiProductVersion=$msiProductVersion `
  -p:Channel=$Channel `
  -p:AgentPublishDir=$runtimePublishDir `
  -p:InstallerHelperPath=$installerHelperPath `
  -p:ServiceExeSha256=$serviceExeSha256 `
  -p:ServiceAssemblySha256=$serviceAssemblySha256 `
  -p:InstallerAssetBase=$installerBuildBase `
  -p:UpdateManifestUrl=$UpdateManifestUrl `
  -p:UpdateManifestPublicKeyB64=$UpdateManifestPublicKeyB64 `
  -p:UpdateAllowedArtifactPrefixes=$UpdateAllowedArtifactPrefixes `
  @($releaseProfile.MsBuildArgs) @($releaseProfile.MsiArgs) `
  -p:OutputPath="$publishDir\"
if ($LASTEXITCODE -ne 0) { throw "MSI package build failed." }

$msi = Join-Path $publishDir "$installerBase.msi"
$builtMsi = Join-Path $publishDir "$installerBuildBase.msi"
if ((Test-Path -LiteralPath $builtMsi) -and ($builtMsi -ne $msi)) {
  Move-Item -LiteralPath $builtMsi -Destination $msi -Force
}
if (-not (Test-Path -LiteralPath $msi)) {
  $localizedMsi = Get-ChildItem -LiteralPath $publishDir -Recurse -Filter "$installerBuildBase.msi" |
    Where-Object { $_.FullName -notmatch "\\(bin|obj|runtime)\\" } |
    Sort-Object FullName |
    Select-Object -First 1
  if ($localizedMsi) {
    Copy-Item -LiteralPath $localizedMsi.FullName -Destination $msi -Force
  }
}
if (-not (Test-Path -LiteralPath $msi)) {
  throw "MSI installer was not produced: $msi"
}

if ($signed) {
  Write-Step "Signing MSI installer"
  $signtool = Find-SignTool
  if ($tokenMode) {
    Invoke-TokenFileSigning -SigntoolPath $signtool -Thumbprint $SigningCertThumbprint -TimestampUrl $TimestampUrl `
      -FilePath $msi -AllowedPins $tokenSignerPins
  } else {
  $certPath = Join-Path $env:RUNNER_TEMP "cerberus-agent-signing.pfx"
  if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    $certPath = Join-Path $outputRootPath "cerberus-agent-signing.pfx"
  }
  [IO.File]::WriteAllBytes($certPath, [Convert]::FromBase64String($certBase64))
  & $signtool sign /fd SHA256 /td SHA256 /tr $TimestampUrl /f $certPath /p $certPassword $msi
    if ($LASTEXITCODE -ne 0) { throw "Authenticode signing or verification failed." }
  & $signtool verify /pa /v $msi
    if ($LASTEXITCODE -ne 0) { throw "Authenticode signing or verification failed." }
  Remove-Item -LiteralPath $certPath -Force -ErrorAction SilentlyContinue
  }
}

Write-Step "Creating checksums, SBOM, provenance, manifest"
$zip = Join-Path $publishDir "$assetBase.zip"
Compress-Archive -Path (Join-Path $runtimePublishDir "*") -DestinationPath $zip -Force
$zipHash = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
$msiHash = (Get-FileHash -Algorithm SHA256 $msi).Hash.ToLowerInvariant()
$checksums = Join-Path $publishDir "$assetBase.sha256"
@(
  "$zipHash  $assetBase.zip",
  "$msiHash  $installerBase.msi"
) | Set-Content -LiteralPath $checksums -Encoding utf8

$sbom = Join-Path $publishDir "$assetBase.sbom.json"
$provenance = Join-Path $publishDir "$assetBase.provenance.json"
New-MinimalSbom -RepoRoot $repoRoot -OutputFile $sbom
New-Provenance -RepoRoot $repoRoot -OutputFile $provenance -ArtifactName "$installerBase.msi" -ArtifactSha $msiHash

$secretHits = Invoke-SecretScan -Path $repoRoot
if ($secretHits.Count -gt 0) {
  $preview = ($secretHits | Select-Object -First 10) -join "`n"
  throw "Release secret scan failed:`n$preview"
}

$artifactUrl = ($artifactUrlBase.TrimEnd("/") + "/$installerBase.msi")
$releasedAt = (Get-Date).ToUniversalTime().ToString("O")
$expiresAt = (Get-Date).ToUniversalTime().AddDays(30).ToString("O")
$artifactLength = (Get-Item -LiteralPath $msi).Length
$canonical = @(
  "msi",
  $Version,
  $Channel,
  $artifactUrl,
  $msiHash,
  "Cerberus Agent Release",
  $releasedAt,
  "agent.heartbeat.v1",
  "false",
  "agent.update.manifest.v2",
  $ManifestSequence.ToString([System.Globalization.CultureInfo]::InvariantCulture),
  $expiresAt,
  $artifactLength.ToString([System.Globalization.CultureInfo]::InvariantCulture),
  $signerKeyIdentity
) -join "`n"
Assert-ManifestValidityWindow ([DateTimeOffset]::Parse($releasedAt)) ([DateTimeOffset]::Parse($expiresAt))
$legacyManifest = $null
if ($tokenMode) {
  if ($signingPlan.ManifestSigning -eq "External") {
    Write-PendingExternalManifest `
      -PublishDir $publishDir -AssetBase $assetBase -Canonical $canonical -KeyListB64 $tokenKeyListB64 `
      -ArtifactPrefixes $artifactPrefixList -SignerPins $tokenSignerPins
    return
  }
  $manifest = New-CngSignedManifest `
    -Canonical $canonical -Certificate $tokenSigning.ManifestSigningCertificate -RuntimeDir $runtimePublishDir `
    -Channel $Channel -ArtifactPrefixes $artifactPrefixList -KeyListB64 $tokenKeyListB64 -SignerPins $tokenSignerPins
} else {
$manifestSignature = Sign-ManifestPayload -CanonicalPayload $canonical -PrivateKeyPem $manifestPrivateKey
$manifest = [ordered]@{
  schema_version = "agent.update.manifest.v2"
  artifact_kind = "msi"
  version = $Version
  channel = $Channel
  artifact_url = $artifactUrl
  sha256 = $msiHash
  signing_identity = "Cerberus Agent Release"
  released_at_utc = $releasedAt
  minimum_protocol_version = "agent.heartbeat.v1"
  rollback_allowed = $false
  sequence = $ManifestSequence
  expires_at_utc = $expiresAt
  artifact_length = $artifactLength
  signer_key_identity = $signerKeyIdentity
  signature = $manifestSignature
}

# Keep the historical v1 endpoint for legacy clients; fixed clients embed the v2 endpoint.
$legacyManifest = [ordered]@{}
foreach ($name in @("artifact_kind", "version", "channel", "artifact_url", "sha256", "signing_identity", "released_at_utc", "minimum_protocol_version", "rollback_allowed")) {
  $legacyManifest[$name] = $manifest[$name]
}
$legacyCanonical = ($canonical -split "`n" | Select-Object -First 9) -join "`n"
$legacyManifest["signature"] = Sign-ManifestPayload -CanonicalPayload $legacyCanonical -PrivateKeyPem $manifestPrivateKey
}

Publish-ReleaseOutputs `
  -PublishDir $publishDir -Channel $Channel -AssetBase $assetBase -InstallerBase $installerBase `
  -Manifest $manifest -LegacyManifest $legacyManifest `
  -AllowUnsignedBuildMetadata $allowUnsignedBuildMetadata -Signed $signed -BuildProfile $BuildProfile

Write-Step "Release bundle ready: $publishDir"
