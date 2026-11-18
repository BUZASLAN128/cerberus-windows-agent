# Offline script checks. All DNS and HTTP results are fixtures, and no release artifacts are built or written.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'release-artifact-url-lib.ps1')
. (Join-Path $PSScriptRoot 'release-signing-lib.ps1')

$script:checks = 0
function Check([string]$Name, [scriptblock]$Test) {
  & $Test
  $script:checks++
  Write-Host "ok $Name"
}
function Assert-Refused([scriptblock]$Test, [string]$Message) {
  try { & $Test }
  catch {
    if (-not $_.Exception.Message.Contains($Message)) { throw }
    return
  }
  throw "Expected refusal containing '$Message'."
}
function Read-ScriptAst([string]$Name) {
  $tokens = $null
  $errors = $null
  $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $Name), [ref]$tokens, [ref]$errors)
  if ($errors.Count) { throw ($errors -join "`n") }
  return $ast
}

$githubPrefix = 'https://github.com/BUZASLAN128/cerberus-windows-agent/releases/download/'
$githubAsset = $githubPrefix + 'v0.2.1013/Cerberus.Agent-preview-0.2.1013-server.msi'
$mirrorPrefix = 'https://release.example/agent'
$mirrorAsset = $mirrorPrefix + '/v1.2.3/agent.msi'
$fakeAddress = [Net.IPAddress]'8.8.4.4'
Check 'canonical GitHub URL and explicit mirror directory both pass offline URL policy' {
  Assert-ReleaseArtifactUrl $githubAsset @($githubPrefix)
  Assert-ReleaseArtifactUrl $mirrorAsset @($githubPrefix, $mirrorPrefix)
}
Check 'an empty or malformed allowlist fails closed' {
  Assert-Refused { Assert-ReleaseArtifactUrl $mirrorAsset @() } 'allowlist is empty'
  Assert-Refused { Assert-ReleaseArtifactUrl $mirrorAsset @($mirrorPrefix, 'http://release.example/agent') } 'well-formed HTTPS'
}
foreach ($url in @('https://release.example/agent-other/agent.msi', 'https://release.example/Agent/agent.msi',
    'https://release.example:444/agent/agent.msi', 'https://release.example.other/agent/agent.msi')) {
  Check "allowlist denies sibling or different origin $url" {
    Assert-Refused { Assert-ReleaseArtifactUrl $url @($mirrorPrefix) } 'outside the allowed HTTPS path prefixes'
  }
}
Check 'reject HTTP, URL credentials, manifest query and fragment' {
  foreach ($url in @('http://release.example/agent/a.msi', 'https://operator@release.example/agent/a.msi',
    "$($mirrorAsset)?token=fixture", "$($mirrorAsset)#fragment")) {
    Assert-Refused { Assert-ReleaseArtifactUrl $url @($mirrorPrefix) } 'well-formed HTTPS'
  }
}
Check 'reject ambiguous traversal paths before URI normalization' {
  foreach ($path in @('/agent/../agent/a.msi', '/agent/%2E%2e/agent/a.msi', '/agent/v1%2Fa.msi', '/agent/v1%255ca.msi')) {
    Assert-Refused { Assert-ReleaseArtifactUrl "https://release.example$path" @($mirrorPrefix) } 'ambiguous path'
  }
}
foreach ($hostName in @('localhost', 'releases', 'release.local', 'release.internal', 'relay.tailnet.ts.net', '127.0.0.1',
    '10.5.1.2', '172.31.0.1', '192.168.0.1', '100.64.0.1', '169.254.169.254', '[::1]', '[::ffff:127.0.0.1]', '[fd00::1]', '[fe80::1]')) {
  Check "deny explicitly listed non-public host $hostName" {
    $prefix = "https://$hostName/agent/"
    Assert-Refused { Assert-ReleaseArtifactUrl ($prefix + 'agent.msi') @($prefix) } 'host must be public'
  }
}

$resolvePublic = { param($Uri) $fakeAddress }
Check 'approved URL receives one HEAD and only the checked IP set is forwarded' {
  $requests = [Collections.Generic.List[uri]]::new()
  Assert-ReleaseArtifactReachable $mirrorAsset @($mirrorPrefix) $resolvePublic {
    param($Uri, $Addresses)
    $requests.Add($Uri)
    if ($Addresses.Count -ne 1 -or -not $Addresses[0].Equals($fakeAddress)) { throw 'Unexpected addresses.' }
    [pscustomobject]@{ StatusCode = 200; Locations = @() }
  }
  if ($requests.Count -ne 1 -or $requests[0].AbsoluteUri -cne $mirrorAsset) { throw 'Expected one request to the artifact.' }
}
Check 'denied URLs never reach DNS or HEAD' {
  $unexpected = { throw 'Unexpected network stage.' }
  Assert-Refused { Assert-ReleaseArtifactReachable 'https://unlisted.example/agent/a.msi' @($mirrorPrefix) $unexpected $unexpected } 'outside the allowed HTTPS path prefixes'
}
Check 'DNS failure, no results and a mixed public/private answer stop before HEAD' {
  $unexpected = { throw 'Unexpected HEAD.' }
  Assert-Refused { Assert-ReleaseArtifactReachable $mirrorAsset @($mirrorPrefix) { throw 'resolver offline' } $unexpected } 'DNS resolution failed'
  Assert-Refused { Assert-ReleaseArtifactReachable $mirrorAsset @($mirrorPrefix) {} $unexpected } 'DNS returned no addresses'
  Assert-Refused { Assert-ReleaseArtifactReachable $mirrorAsset @($mirrorPrefix) { $fakeAddress; [Net.IPAddress]'::ffff:10.0.0.1' } $unexpected } 'DNS returned a non-public address'
}
Check 'HEAD accepts 2xx and rejects auth, missing artifacts, unsupported methods and transport failures' {
  Assert-ReleaseArtifactReachable $mirrorAsset @($mirrorPrefix) $resolvePublic { [pscustomobject]@{ StatusCode = 204; Locations = @() } }
  foreach ($status in 401, 403, 404, 405, 503) {
    Assert-Refused { Assert-ReleaseArtifactReachable $mirrorAsset @($mirrorPrefix) $resolvePublic {
      [pscustomobject]@{ StatusCode = $status; Locations = @() }
    } } "returned HTTP $status"
  }
  Assert-Refused { Assert-ReleaseArtifactReachable $mirrorAsset @($mirrorPrefix) $resolvePublic { throw 'transport failure' } } 'HEAD failed'
}
Check 'GitHub Release asset redirect is separately resolved and verified by HEAD' {
  $resolved = [Collections.Generic.List[string]]::new()
  $requests = [Collections.Generic.List[uri]]::new()
  $cdnAsset = 'https://release-assets.githubusercontent.com/github-production-release-asset/123/fixture?sig=provider-fixture'
  Assert-ReleaseArtifactReachable $githubAsset @($githubPrefix) { param($Uri) $resolved.Add($Uri.Host); $fakeAddress } {
    param($Uri, $Addresses)
    $requests.Add($Uri)
    if ($requests.Count -eq 1) { [pscustomobject]@{ StatusCode = 302; Locations = @($cdnAsset) } }
    else { [pscustomobject]@{ StatusCode = 200; Locations = @() } }
  }
  if ($requests.Count -ne 2 -or $requests[1].AbsoluteUri -cne $cdnAsset -or
      ($resolved -join ',') -cne 'github.com,release-assets.githubusercontent.com') { throw 'Expected one independently resolved CDN hop.' }
}
Check 'redirect rejects an unlisted authority or path before DNS and rejects private DNS before HEAD' {
  foreach ($destination in @('https://unlisted.example/agent/a.msi', '/other/a.msi', 'https://release.example/agent/a.msi?token=fixture')) {
    $resolutions = [Collections.Generic.List[uri]]::new()
    $requests = [Collections.Generic.List[uri]]::new()
    Assert-Refused { Assert-ReleaseArtifactReachable $mirrorAsset @($mirrorPrefix) {
      param($Uri)
      $resolutions.Add($Uri)
      $fakeAddress
    } {
      param($Uri)
      $requests.Add($Uri)
      [pscustomobject]@{ StatusCode = 302; Locations = @($destination) }
    } } $(if ($destination.Contains('?')) { 'well-formed HTTPS' } else { 'outside the allowed HTTPS path prefixes' })
    if ($resolutions.Count -ne 1 -or $requests.Count -ne 1) { throw 'Unexpected redirect DNS or HEAD request.' }
  }
  $requests = [Collections.Generic.List[uri]]::new()
  Assert-Refused { Assert-ReleaseArtifactReachable $githubAsset @($githubPrefix) {
    param($Uri)
    if ($Uri.Host -ceq 'github.com') { $fakeAddress } else { [Net.IPAddress]'169.254.1.2' }
  } {
    param($Uri)
    $requests.Add($Uri)
    [pscustomobject]@{ StatusCode = 302; Locations = @('https://release-assets.githubusercontent.com/github-production-release-asset/123/fixture') }
  } } 'DNS returned a non-public address'
  if ($requests.Count -ne 1) { throw 'The redirect was contacted despite private DNS.' }
}
Check 'same-prefix root-relative redirect works and redirect loops terminate' {
  $requests = [Collections.Generic.List[uri]]::new()
  Assert-ReleaseArtifactReachable $mirrorAsset @($mirrorPrefix) $resolvePublic {
    param($Uri)
    $requests.Add($Uri)
    if ($requests.Count -eq 1) { [pscustomobject]@{ StatusCode = 307; Locations = @('/agent/new.msi') } }
    else { [pscustomobject]@{ StatusCode = 200; Locations = @() } }
  }
  if ($requests.Count -ne 2 -or $requests[1].AbsolutePath -cne '/agent/new.msi') { throw 'Expected the same-prefix redirect.' }
  Assert-Refused { Assert-ReleaseArtifactReachable $mirrorAsset @($mirrorPrefix) $resolvePublic {
    [pscustomobject]@{ StatusCode = 302; Locations = @('/agent/new.msi') }
  } } 'exceeded three hops'
  Assert-Refused { Assert-ReleaseArtifactReachable $mirrorAsset @($mirrorPrefix) $resolvePublic {
    [pscustomobject]@{ StatusCode = 302; Locations = @() }
  } } 'invalid Location headers'
}

Check 'real client sends only an anonymous HEAD and returns raw redirect metadata' {
  Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

public sealed class ReleaseArtifactTestHandler : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        if (request.Method != HttpMethod.Head || request.Content != null || request.Headers.Authorization != null ||
            request.Headers.Contains("Cookie") || request.Headers.Contains("Proxy-Authorization"))
            throw new InvalidOperationException("Expected one anonymous HEAD request.");

        var response = new HttpResponseMessage(HttpStatusCode.Redirect);
        response.Headers.Location = new Uri("/agent/new.msi", UriKind.Relative);
        return Task.FromResult(response);
    }
}
'@
  $handler = New-ReleaseArtifactHeadHandler @($fakeAddress)
  try {
    if ($handler.AllowAutoRedirect -or $handler.UseCookies -or $handler.UseProxy -or $handler.Credentials -or -not $handler.ConnectCallback) {
      throw 'Expected direct address pinning without redirects, cookies, proxies or credentials.'
    }
  } finally { $handler.Dispose() }
  $head = Invoke-ReleaseArtifactHead ([Uri]$mirrorAsset) @($fakeAddress) ([ReleaseArtifactTestHandler]::new())
  if ($head.StatusCode -ne 302 -or $head.Locations.Count -ne 1 -or $head.Locations[0] -cne '/agent/new.msi') { throw 'Unexpected HEAD response.' }
}

Check 'canonical build checks URL before output mutation and retains its local lab contract' {
  $ast = Read-ScriptAst 'build-agent-public-release.ps1'
  $statements = @($ast.EndBlock.Statements)
  $begin = [array]::FindIndex($statements, [Predicate[object]]{ $args[0].Extent.Text.StartsWith('if ([string]::IsNullOrWhiteSpace($UpdateAllowedArtifactPrefixes))') })
  $end = [array]::FindIndex($statements, [Predicate[object]]{ $args[0].Extent.Text.StartsWith('Assert-ReleaseArtifactUrl ') })
  $firstWrite = [array]::FindIndex($statements, [Predicate[object]]{ $args[0].Extent.Text.StartsWith('Remove-Item -LiteralPath $publishDir ') })
  if ($begin -lt 0 -or $end -le $begin -or $firstWrite -le $end) { throw 'Expected URL policy before the first output mutation.' }
  $checkBuildUrl = [scriptblock]::Create(($statements[$begin..$end].Extent.Text -join "`n"))
  $dnsMode = $statements | Where-Object { $_.Extent.Text.StartsWith('$requirePublicDns = ') }
  $selectDnsMode = [scriptblock]::Create($dnsMode.Extent.Text)
  $dnsAnswers = [Collections.Generic.List[Net.IPAddress]]::new()
  function Resolve-ReleaseArtifactAddresses($Uri) { $dnsAnswers.ToArray() }
  $savedBase = $env:AGENT_RELEASE_ARTIFACT_BASE_URL
  $savedActions = $env:GITHUB_ACTIONS
  try {
    $env:AGENT_RELEASE_ARTIFACT_BASE_URL = 'https://release.example/agent/v1.2.3'
    $env:GITHUB_ACTIONS = 'true'
    . $selectDnsMode
    $installerBase = 'agent'
    $labBuild = $null
    $Channel = 'stable'
    $AllowUnsignedDevBuild = $false
    $AllowEphemeralManifestKey = $false
    $UpdateAllowedArtifactPrefixes = $mirrorPrefix
    $dnsAnswers.Add([Net.IPAddress]'10.0.0.1')
    Assert-Refused { . $checkBuildUrl } 'DNS returned a non-public address'
    $dnsAnswers[0] = $fakeAddress
    . $checkBuildUrl
    if ($artifactUrl -cne $mirrorAsset) { throw 'Public build URL changed.' }

    $env:AGENT_RELEASE_ARTIFACT_BASE_URL = 'https://127.0.0.1:8443/agent/v1.2.3'
    $UpdateAllowedArtifactPrefixes = 'https://127.0.0.1:8443/agent/'
    $Channel = 'dev'
    $AllowUnsignedDevBuild = $true
    $AllowEphemeralManifestKey = $true
    Assert-Refused { . $checkBuildUrl } 'host must be public'
    $env:GITHUB_ACTIONS = ''
    . $selectDnsMode
    . $checkBuildUrl
    if ($artifactUrl -cne 'https://127.0.0.1:8443/agent/v1.2.3/agent.msi') { throw 'Local lab URL changed.' }
  } finally {
    $env:AGENT_RELEASE_ARTIFACT_BASE_URL = $savedBase
    $env:GITHUB_ACTIONS = $savedActions
  }
}

Check 'standalone parser uses the exact manifest field and rejects ambiguous input before HEAD' {
  $ast = Read-ScriptAst 'test-agent-published-manifest-artifact.ps1'
  $entry = [scriptblock]::Create(($ast.EndBlock.Statements[3..($ast.EndBlock.Statements.Count - 1)].Extent.Text -join "`n"))
  $fixturePath = [IO.Path]::GetTempFileName()
  $calls = [Collections.Generic.List[string]]::new()
  function Assert-ReleaseArtifactReachable($ArtifactUrl, $ArtifactPrefixes) {
    Assert-ReleaseArtifactUrl $ArtifactUrl $ArtifactPrefixes
    $calls.Add($ArtifactUrl)
  }
  try {
    $ManifestPath = $fixturePath
    $UpdateAllowedArtifactPrefixes = $mirrorPrefix
    [IO.File]::WriteAllText($fixturePath, ('{"artifact_url":"' + $mirrorAsset + '"}'))
    . $entry
    foreach ($json in @('{"artifact_url":null}', '{"artifact_url":"x","artifact_url":"y"}', '{"artifact_url":"x","ARTIFACT_URL":"y"}')) {
      [IO.File]::WriteAllText($fixturePath, $json)
      Assert-Refused { . $entry } 'one string artifact_url'
    }
    if ($calls.Count -ne 1 -or $calls[0] -cne $mirrorAsset) { throw 'Expected exactly one valid manifest URL sent to the HEAD probe.' }
  } finally { Remove-Item -LiteralPath $fixturePath -Force }
}

Check 'detached finalize checks the signed URL against measured trust before writing release outputs' {
  $ast = Read-ScriptAst 'release-publish-lib.ps1'
  $finalize = $ast.EndBlock.Statements | Where-Object { $_.Name -ceq 'Complete-ExternalManifestSigning' }
  $statements = @($finalize.Body.EndBlock.Statements)
  $policy = $statements | Where-Object { $_.Extent.Text.StartsWith('Assert-ReleaseArtifactUrl ') }
  $publish = $statements | Where-Object { $_.Extent.Text.StartsWith('Publish-ReleaseOutputs ') }
  if (-not $policy -or -not $publish -or $policy.Extent.StartOffset -ge $publish.Extent.StartOffset) { throw 'Expected URL validation before release outputs.' }
  $checkFinalizeUrl = [scriptblock]::Create($policy.Extent.Text)
  $trust = @{ ArtifactPrefixes = @($mirrorPrefix) }
  $manifest = @{ artifact_url = $mirrorAsset }
  . $checkFinalizeUrl
  $manifest.artifact_url = 'https://release.example/agent-other/agent.msi'
  Assert-Refused { . $checkFinalizeUrl } 'outside the allowed HTTPS path prefixes'
}

Write-Host "Release artifact preflight support checks passed: $script:checks"
