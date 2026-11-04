param(
  [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$ExpectedHead,
  [Parameter(Mandatory)][string]$PolicyFile,
  [Parameter(Mandatory)][string]$FeedRootFile,
  [Parameter(Mandatory)][string]$AgentCommandTrustAnchorsFile,
  [Parameter(Mandatory)][string]$BackendTrustAnchorsFile,
  [string]$DefaultSsoClientId='server-profile-none',
  [string]$OutputRoot='out/test-campaign',
  [switch]$SkipTests
)
$ErrorActionPreference='Stop'
if($PSVersionTable.PSEdition -ne 'Core'){throw 'PowerShell7 is required.'}
$repoRoot=Split-Path -Parent $PSScriptRoot
if((git -C $repoRoot rev-parse HEAD).Trim() -cne $ExpectedHead -or @(git -C $repoRoot status --porcelain).Count -ne 0){throw 'Freeze a clean exact source head before campaign packaging.'}
foreach($name in @('AGENT_UPDATE_MANIFEST_PRIVATE_KEY_PEM','WINDOWS_SIGNING_CERT_BASE64','WINDOWS_SIGNING_CERT_PASSWORD')){
  if(Test-Path -LiteralPath "env:$name"){throw 'Campaign packaging requires a process without existing signing credentials.'}
}
if([string]::Equals($env:GITHUB_ACTIONS,'true',[StringComparison]::OrdinalIgnoreCase)){throw 'Test campaigns are local only; no public CI release.'}
. (Join-Path $PSScriptRoot 'release-lab-lib.ps1')
. (Join-Path $PSScriptRoot 'release-signing-lib.ps1')
. (Join-Path $PSScriptRoot 'release-trust-lib.ps1')
. (Join-Path $PSScriptRoot 'release-publish-lib.ps1')
$policy=Get-Content -LiteralPath $PolicyFile -Raw|ConvertFrom-Json -DateKind String
$lab=Read-ReleaseLabPolicy -PolicyFile $PolicyFile -FeedRootFile $FeedRootFile -Version $policy.versions[0] `
  -Channel dev -BuildProfile server -SigningMode Pfx -AllowUnsigned $true
$output=[IO.Path]::GetFullPath($OutputRoot,$repoRoot)
$allowedRoot=[IO.Path]::GetFullPath((Join-Path $repoRoot 'out'))+[IO.Path]::DirectorySeparatorChar
if(-not $output.StartsWith($allowedRoot,[StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $output)){throw 'Use a fresh output directory inside this worktree/out; existing artifacts are preserved.'}
$null=New-Item -ItemType Directory -Path $output
$frozenPolicy=Join-Path $output 'campaign-policy.json'
$frozenRoot=Join-Path $output 'feed-root.pem'
Copy-Item -LiteralPath $PolicyFile -Destination $frozenPolicy
Copy-Item -LiteralPath $FeedRootFile -Destination $frozenRoot
$frozenLab=Read-ReleaseLabPolicy -PolicyFile $frozenPolicy -FeedRootFile $frozenRoot -Version $lab.Policy.versions[0] `
  -Channel dev -BuildProfile server -SigningMode Pfx -AllowUnsigned $true
if($frozenLab.PolicyB64 -cne $lab.PolicyB64 -or $frozenLab.RootB64 -cne $lab.RootB64){throw 'Public campaign inputs changed while being frozen.'}
$lab=$frozenLab
$policyHash=(Get-FileHash -LiteralPath $frozenPolicy).Hash
$rootHash=(Get-FileHash -LiteralPath $frozenRoot).Hash
$key=[Security.Cryptography.RSA]::Create(3072)
$rows=[Collections.Generic.List[object]]::new()
$oldArtifactBase=$env:AGENT_RELEASE_ARTIFACT_BASE_URL
try{
  # One memory-held campaign key for bootstrap plus ten variants; never persist/export it to a file or log.
  $env:AGENT_UPDATE_MANIFEST_PRIVATE_KEY_PEM=$key.ExportPkcs8PrivateKeyPem()
  $publicKey=$key.ExportSubjectPublicKeyInfoPem()
  $publicKey|Set-Content -LiteralPath (Join-Path $output 'manifest-public.pem') -Encoding ascii
  $variantIndex=0
  foreach($version in $lab.Policy.versions){
    if((Get-FileHash -LiteralPath $frozenPolicy).Hash -cne $policyHash -or (Get-FileHash -LiteralPath $frozenRoot).Hash -cne $rootHash){throw 'Frozen public campaign inputs changed.'}
    $versionOutput=Join-Path $output $version
    $skipVariantTests=[bool]$SkipTests -or $variantIndex -gt 0
    $env:AGENT_RELEASE_ARTIFACT_BASE_URL=$lab.Policy.targets[0].artifactPrefix+'packages/'+$version
    & (Join-Path $PSScriptRoot 'build-agent-public-release.ps1') -Version $version -Channel dev -BuildProfile server `
      -DefaultBackendUrl $lab.Policy.backendUrl -DefaultSsoBaseUrl $lab.Policy.ssoBaseUrl -DefaultSsoClientId $DefaultSsoClientId `
      -AgentCommandTrustAnchorsFile $AgentCommandTrustAnchorsFile -BackendTrustAnchorsFile $BackendTrustAnchorsFile `
      -UpdateManifestUrl $lab.Policy.targets[0].manifestUrl `
      -UpdateAllowedArtifactPrefixes (($lab.Policy.targets|ForEach-Object artifactPrefix|Sort-Object -Unique)-join ',') `
      -UpdateLabPolicyFile $frozenPolicy -UpdateLabFeedRootFile $frozenRoot -AllowUnsignedDevBuild `
      -SkipTests:$skipVariantTests -OutputRoot $versionOutput
    $publish=Join-Path $versionOutput 'publish'
    $name="Cerberus.Agent-dev-$version-server.msi"
    $msi=Join-Path $publish $name
    $msiHash=(Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant()
    $msiLength=(Get-Item -LiteralPath $msi).Length
    $runtime=Join-Path $publish 'runtime'
    foreach($assembly in @('Cerberus.Agent.dll','Cerberus.Agent.Runtime.dll')){
      $metadata=Read-AssemblyMetadataValues (Join-Path $runtime $assembly)
      if($metadata['AgentUpdateLabPolicyB64'] -cne $lab.PolicyB64 -or $metadata['AgentUpdateLabFeedRootB64'] -cne $lab.RootB64){throw 'Built lab metadata does not match the frozen campaign.'}
      if($metadata['AgentUpdateManifestPublicKeysB64'] -cne [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($publicKey.Trim())) -or
         $metadata['AgentUpdateAllowedSignerKeyIdentity'] -cne 'unsigned-dev' -or $metadata['AllowUnsignedDevBuild'] -cne 'true'){throw 'Built campaign trust differs from its ephemeral manifest key and unsigned dev policy.'}
    }
    foreach($hostName in @('Cerberus.Agent.exe','Cerberus.Agent.Service.exe','Cerberus.Agent.Updater.exe')){
      $hostPath=Join-Path $runtime $hostName
      if(-not [Cerberus.Agent.Core.AgentSingleFileBundle]::IsBundle($hostPath)){throw 'Server campaign hosts must retain the verified single-file layout.'}
      $hostAssembly=if($hostName -ceq 'Cerberus.Agent.exe'){'Cerberus.Agent.dll'}else{'Cerberus.Agent.Runtime.dll'}
      $metadata=Read-AssemblyMetadataValues (Join-Path $runtime $hostAssembly) -BundlePath $hostPath
      if($metadata['AgentUpdateLabPolicyB64'] -cne $lab.PolicyB64 -or $metadata['AgentUpdateLabFeedRootB64'] -cne $lab.RootB64 -or
         $metadata['AgentUpdateManifestPublicKeysB64'] -cne [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($publicKey.Trim()))){throw 'A host embedded different campaign trust.'}
    }
    $helperMetadata=Read-AssemblyMetadataValues (Join-Path $versionOutput 'installer-helper/Cerberus.Agent.Installer.Helper.dll')
    if($helperMetadata['AgentUpdateLabPolicyB64'] -cne $lab.PolicyB64 -or $helperMetadata['AllowUnsignedDevBuild'] -cne 'true' -or
       $helperMetadata['AgentUpdateAllowedSignerKeyIdentity'] -cne 'unsigned-dev'){throw 'Installer helper did not retain protected lab admission metadata.'}
    $expectedHashes=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($helperMetadata['AgentUpdateLabRuntimeHashesB64']))|ConvertFrom-Json -AsHashtable
    $payloadFiles=@(Get-FirstPartyPeFiles $runtime)
    if($expectedHashes.Count -ne $payloadFiles.Count){throw 'Installer helper payload hash coverage differs from the built runtime.'}
    foreach($file in $payloadFiles){
      $relative=[IO.Path]::GetRelativePath($runtime,$file).Replace('\','/')
      if($expectedHashes[$relative] -cne (Get-FileHash -LiteralPath $file).Hash.ToLowerInvariant()){throw 'Installer helper runtime hash differs from the built payload.'}
    }
    $sourceManifest=Join-Path $publish "Cerberus.Agent.Bundle-dev-$version-server.update-manifest.v2.json"
    $original=Get-Content -LiteralPath $sourceManifest -Raw|ConvertFrom-Json -AsHashtable -DateKind String
    $targetIndex=0
    $manifests=@(foreach($target in $lab.Policy.targets){
      $copy=[ordered]@{};foreach($field in $original.Keys){$copy[$field]=$original[$field]}
      $copy.artifact_url=$target.artifactPrefix+'packages/'+$version+'/'+$name
      if($copy.sha256 -cne $msiHash -or $copy.artifact_length -ne $msiLength){throw 'Manifest MSI hash/length mismatch.'}
      $canonical=@($copy.artifact_kind,$copy.version,$copy.channel,$copy.artifact_url,$copy.sha256,$copy.signing_identity,
        $copy.released_at_utc,$copy.minimum_protocol_version,([bool]$copy.rollback_allowed).ToString().ToLowerInvariant(),
        $copy.schema_version,([long]$copy.sequence).ToString([Globalization.CultureInfo]::InvariantCulture),$copy.expires_at_utc,
        ([long]$copy.artifact_length).ToString([Globalization.CultureInfo]::InvariantCulture),$copy.signer_key_identity)-join "`n"
      $bytes=[Text.Encoding]::UTF8.GetBytes($canonical)
      $signature=$key.SignData($bytes,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)
      if(-not $key.VerifyData($bytes,$signature,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)){throw 'Campaign manifest signature self-check failed.'}
      $copy.signature=[Convert]::ToBase64String($signature)
      $targetRoot=Join-Path $versionOutput ('target-'+$targetIndex)
      $targetIndex++
      $null=New-Item -ItemType Directory -Path $targetRoot
      $manifest=Join-Path $targetRoot 'Cerberus.Agent.Bundle-dev-latest-server.update-manifest.v2.json'
      $copy|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $manifest -Encoding utf8
      [pscustomobject]@{agentId=$target.agentId;manifestUrl=$target.manifestUrl;path=$manifest;sha256=(Get-FileHash -LiteralPath $manifest).Hash.ToLowerInvariant();artifactUrl=$copy.artifact_url}
    })
    $rows.Add([pscustomobject]@{version=$version;source=$ExpectedHead;msi=$msi;sha256=$msiHash;bytes=$msiLength;bootstrap=($version -ceq $lab.Policy.versions[0]);manifests=$manifests})
    $variantIndex++
  }
  [pscustomobject]@{source=$ExpectedHead;campaignId=$lab.Policy.campaignId;policySha256=$policyHash.ToLowerInvariant();
    feedRootSha256=$rootHash.ToLowerInvariant();artifacts=$rows.ToArray();
    signedPayload=$false;manifestSignature='RSA3072/PKCS1-SHA256; one ephemeral campaign key';initialTestsSkipped=[bool]$SkipTests;
    laterVariantTests='reuse unchanged frozen functional candidate';uploaded=$false;installed=$false;acceptanceTransitions=0}|
    ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $output 'campaign-artifacts.json') -Encoding utf8
}finally{
  Remove-Item -LiteralPath env:AGENT_UPDATE_MANIFEST_PRIVATE_KEY_PEM -ErrorAction SilentlyContinue
  if($null -eq $oldArtifactBase){Remove-Item -LiteralPath env:AGENT_RELEASE_ARTIFACT_BASE_URL -ErrorAction SilentlyContinue}else{$env:AGENT_RELEASE_ARTIFACT_BASE_URL=$oldArtifactBase}
  $key.Dispose()
}
