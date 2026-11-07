# Public, bounded lab-policy inputs only. No token, credential, private-key or machine-trust access.
function Read-ReleaseLabPolicy {
  param([string]$PolicyFile, [string]$FeedRootFile, [string]$Version, [string]$Channel,
    [string]$BuildProfile, [string]$SigningMode, [bool]$AllowUnsigned)
  if (-not $PolicyFile) {
    if ($FeedRootFile) { throw 'A lab feed root requires a lab policy.' }
    return $null
  }
  if ($Channel -cne 'dev' -or $BuildProfile -cne 'server' -or $SigningMode -cne 'Pfx' -or -not $AllowUnsigned -or
      [string]::Equals($env:GITHUB_ACTIONS, 'true', [StringComparison]::OrdinalIgnoreCase) -or
      -not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable('WINDOWS_SIGNING_CERT_BASE64'))) {
    throw 'Lab policy builds are local unsigned dev/server candidates only.'
  }
  if (-not $FeedRootFile -or -not (Test-Path -LiteralPath $PolicyFile -PathType Leaf) -or
      -not (Test-Path -LiteralPath $FeedRootFile -PathType Leaf)) { throw 'Public lab policy and feed root are required.' }
  $json=[IO.File]::ReadAllText((Resolve-Path -LiteralPath $PolicyFile).Path)
  if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 12288) { throw 'Lab policy exceeds the runtime size limit.' }
  $p=$json|ConvertFrom-Json -AsHashtable -DateKind String
  $from=[DateTimeOffset]::Parse($p.notBeforeUtc,[Globalization.CultureInfo]::InvariantCulture)
  $until=[DateTimeOffset]::Parse($p.expiresAtUtc,[Globalization.CultureInfo]::InvariantCulture)
  $now=[DateTimeOffset]::UtcNow
  $campaign=[guid]::Empty
  if ($p.schemaVersion -cne 'agent.update.lab.v1' -or -not [guid]::TryParseExact($p.campaignId,'D',[ref]$campaign) -or
      $from.Offset -ne [TimeSpan]::Zero -or $until.Offset -ne [TimeSpan]::Zero -or
      $now -lt $from -or $now -ge $until -or $until -le $from -or $until-$from -gt [TimeSpan]::FromHours(48) -or
      @($p.targets).Count -ne 2 -or @($p.versions).Count -ne 11 -or $p.versions -cnotcontains $Version) { throw 'Lab campaign scope is invalid.' }
  $previous=$null
  foreach($v in $p.versions){
    $parsed=$null
    if(-not [version]::TryParse($v,[ref]$parsed) -or $parsed.Build -lt 0 -or $parsed.Revision -ne -1 -or
       $parsed.ToString(3) -cne $v -or ($null -ne $previous -and $parsed -le $previous)){throw 'Lab versions must be eleven distinct increasing MSI versions.'}
    $previous=$parsed
  }
  foreach($t in $p.targets){
    $baseline=$null
    if(-not $t.agentId -or -not $t.tenantId -or $t.keyFingerprint -cnotmatch '^sha256:[0-9a-f]{64}$' -or
       -not [version]::TryParse($t.bootstrapSourceVersion,[ref]$baseline) -or $baseline.Build -lt 0 -or $baseline.Revision -ne -1 -or
       $baseline.ToString(3) -cne $t.bootstrapSourceVersion -or $p.versions -ccontains $t.bootstrapSourceVersion){throw 'Lab registration or installed bootstrap baseline binding is missing.'}
    foreach($u in @($t.manifestUrl,$t.artifactPrefix)){
      $uri=$null
      if(-not [Uri]::TryCreate($u,[UriKind]::Absolute,[ref]$uri) -or $uri.Scheme -cne 'https' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or
         -not $uri.AbsolutePath.StartsWith('/updates/devtest/',[StringComparison]::Ordinal)){throw 'Lab feed must stay in its isolated HTTPS prefix.'}
    }
    $manifest=[Uri]$t.manifestUrl;$prefix=[Uri]$t.artifactPrefix
    if(-not $t.artifactPrefix.EndsWith('/') -or $manifest.Host -cne $prefix.Host -or $manifest.Port -ne $prefix.Port -or
       -not $manifest.AbsolutePath.StartsWith($prefix.AbsolutePath,[StringComparison]::Ordinal)){throw 'Lab manifest is outside its artifact prefix.'}
  }
  foreach($field in @('agentId','keyFingerprint','manifestUrl')){
    if(@($p.targets|ForEach-Object {$_[$field]}|Sort-Object -Unique).Count -ne 2){throw 'Lab targets must be distinct.'}
  }
  $certificate=[Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem([IO.File]::ReadAllText((Resolve-Path -LiteralPath $FeedRootFile).Path))
  try{
    if($certificate.HasPrivateKey -or $certificate.NotBefore.ToUniversalTime() -gt $now.UtcDateTime -or
       $certificate.NotAfter.ToUniversalTime() -lt $until.UtcDateTime -or
       -not @($certificate.Extensions|Where-Object {$_ -is [Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] -and $_.CertificateAuthority}).Count){throw 'Lab feed root is not a valid public CA for this window.'}
    return [pscustomobject]@{Policy=$p;PolicyB64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json));RootB64=[Convert]::ToBase64String($certificate.RawData)}
  }finally{$certificate.Dispose()}
}
