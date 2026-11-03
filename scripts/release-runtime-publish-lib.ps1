# Shared runtime publish command; dot-sourcing has no side effects.
function Publish-AgentProject([string]$Project) {
  $args = @(
    "publish",
    (Join-Path $repoRoot $Project),
    "-c", $Configuration,
    "-r", $Runtime,
    "--self-contained", "true",
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
  ) + $releaseProfile.MsBuildArgs + @(Get-RuntimeBundlePublishArgs $BuildProfile)
  dotnet @args
  if ($LASTEXITCODE -ne 0) { throw "Runtime publish failed." }
}
