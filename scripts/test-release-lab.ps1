param([string]$ArtifactRoot='')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'release-lab-lib.ps1')
if(-not $ArtifactRoot){$ArtifactRoot=Join-Path ([IO.Path]::GetTempPath()) ('cerberus-release-lab-'+[guid]::NewGuid().ToString('N'))}
if(Test-Path -LiteralPath $ArtifactRoot){throw 'Use a fresh public-fixture directory.'}
$null=New-Item -ItemType Directory -Path $ArtifactRoot
$rootFile=Join-Path $ArtifactRoot 'root.pem'
$policyFile=Join-Path $ArtifactRoot 'policy.json'
$key=[Security.Cryptography.ECDsa]::Create([Security.Cryptography.ECCurve+NamedCurves]::nistP256)
$request=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=ReleaseLabUnitRoot',$key,[Security.Cryptography.HashAlgorithmName]::SHA256)
$request.CertificateExtensions.Add([Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($true,$false,0,$true))
$now=[DateTimeOffset]::UtcNow
$certificate=$request.CreateSelfSigned($now.AddMinutes(-5),$now.AddDays(3))
try{
  $certificate.ExportCertificatePem()|Set-Content -LiteralPath $rootFile -Encoding ascii
  $p=[ordered]@{schemaVersion='agent.update.lab.v1';campaignId=[guid]::NewGuid().ToString('D');
    notBeforeUtc=$now.AddMinutes(-1).ToString('o');expiresAtUtc=$now.AddHours(24).ToString('o');
    backendUrl='https://collector.example.invalid';ssoBaseUrl='https://sso.invalid';
    versions=@(1012..1022|ForEach-Object {"0.2.$_"});targets=@(
      @{agentId='pc';tenantId='tenant';keyFingerprint=('sha256:'+('a'*64));manifestUrl='https://feed.example.invalid/updates/devtest/pc/latest.json';artifactPrefix='https://feed.example.invalid/updates/devtest/';bootstrapSourceVersion='0.2.1010'},
      @{agentId='vm';tenantId='tenant';keyFingerprint=('sha256:'+('b'*64));manifestUrl='https://feed.example.invalid/updates/devtest/vm106/latest.json';artifactPrefix='https://feed.example.invalid/updates/devtest/';bootstrapSourceVersion='0.2.1011'}
    )}
  $p|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $policyFile -Encoding utf8
  $buildInputs=@{PolicyFile=$policyFile;FeedRootFile=$rootFile;Version='0.2.1012';Channel='dev';BuildProfile='server';SigningMode='Pfx';AllowUnsigned=$true}
  $accepted=Read-ReleaseLabPolicy @buildInputs
  if($accepted.Policy.targets.Count -ne 2 -or -not $accepted.RootB64 -or -not $accepted.PolicyB64){throw 'Valid public lab inputs were rejected.'}
  function Require-Rejection([hashtable]$InputArgs){
    $rejected=$false
    try{$null=Read-ReleaseLabPolicy @InputArgs}catch{$rejected=$true}
    if(-not $rejected){throw 'An invalid lab build input was accepted.'}
  }
  foreach($override in @(@{Channel='preview'},@{BuildProfile='desktop'},@{SigningMode='Token'},@{AllowUnsigned=$false},@{Version='0.2.9999'})){
    $bad=$buildInputs.Clone();foreach($name in $override.Keys){$bad[$name]=$override[$name]};Require-Rejection $bad
  }
  $p.expiresAtUtc=$now.AddHours(49).ToString('o')
  $p|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $policyFile -Encoding utf8
  Require-Rejection $buildInputs
  if($null -ne (Read-ReleaseLabPolicy -PolicyFile '' -FeedRootFile '' -Version '0.2.1012' -Channel preview -BuildProfile server -SigningMode Pfx -AllowUnsigned $false)){throw 'Normal build without a lab policy was changed.'}
  [pscustomobject]@{result='PASS';checks=8;level='unit/support';artifactRoot=$ArtifactRoot;certificateStoreChanged=$false;privateKeyPersisted=$false}|ConvertTo-Json
}finally{$certificate.Dispose();$key.Dispose()}
