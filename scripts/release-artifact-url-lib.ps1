# The build and post-publish probe use the same allowlist that is embedded in the agent.
function Get-DefaultReleaseArtifactPrefix {
  $repo = if ([string]::IsNullOrWhiteSpace($env:GITHUB_REPOSITORY)) { 'BUZASLAN128/cerberus-windows-agent' } else { $env:GITHUB_REPOSITORY }
  return "https://github.com/$repo/releases/download/"
}

function Get-ReleaseArtifactPrefixes([string]$ConfiguredPrefixes) {
  $ConfiguredPrefixes -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

function Test-PublicReleaseAddress([Net.IPAddress]$Address) {
  if ($null -eq $Address) { return $false }
  if ($Address.IsIPv4MappedToIPv6) { $Address = $Address.MapToIPv4() }
  $bytes = $Address.GetAddressBytes()
  $a = $bytes[0]
  $b = $bytes[1]
  $c = $bytes[2]
  if ($Address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) {
    return -not ($a -in 0, 10, 127 -or $a -ge 224 -or
      ($a -eq 100 -and $b -ge 64 -and $b -le 127) -or ($a -eq 169 -and $b -eq 254) -or
      ($a -eq 172 -and $b -ge 16 -and $b -le 31) -or
      ($a -eq 192 -and ($b -eq 168 -or ($b -eq 0 -and $c -in 0, 2) -or ($b -eq 88 -and $c -eq 99))) -or
      ($a -eq 198 -and ($b -in 18, 19 -or ($b -eq 51 -and $c -eq 100))) -or
      ($a -eq 203 -and $b -eq 0 -and $c -eq 113))
  }
  # Only global unicast. Exclude protocol assignments, transition and documentation ranges.
  return ($Address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6 -and $Address.ScopeId -eq 0 -and
    ($a -band 0xe0) -eq 0x20 -and -not (
      ($a -eq 0x20 -and ($b -eq 2 -or ($b -eq 1 -and ($c -le 1 -or ($c -eq 0x0d -and $bytes[3] -eq 0xb8))))) -or
      ($a -eq 0x3f -and $b -eq 0xff -and $c -lt 0x10)))
}

function ConvertTo-ReleaseArtifactUri([string]$Value, [switch]$AllowLocalHost, [switch]$AllowProviderQuery) {
  $uri = $null
  $parts = [regex]::Match($Value, '\Ahttps://(?<authority>[^/?#]+)(?<path>[^?#]*)', 'IgnoreCase,CultureInvariant')
  if (-not $parts.Success -or $parts.Groups['authority'].Value.Contains('@') -or $Value -match '[\s\p{C}\\#]' -or
      (-not $AllowProviderQuery -and $Value.Contains('?')) -or
      -not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -or -not $uri.IsWellFormedOriginalString() -or $uri.Port -le 0) {
    throw 'Release artifact URLs require well-formed HTTPS without credentials or fragments. Manifest URLs and prefixes also forbid queries.'
  }
  if ($parts.Groups['path'].Value -match '(^|/)\.{1,2}(/|$)|%(2e|2f|5c|25|23|3f|0[0-9a-f]|1[0-9a-f]|7f)') {
    throw 'Release artifact URL contains an ambiguous path segment or escape.'
  }
  if (-not $AllowLocalHost) {
    $hostname = $uri.IdnHost
    $address = $null
    if ([Net.IPAddress]::TryParse($hostname, [ref]$address)) {
      if (-not (Test-PublicReleaseAddress $address)) { throw 'Release artifact URL host must be public.' }
    } elseif ($uri.IsLoopback -or $uri.HostNameType -ne [UriHostNameType]::Dns -or
        $hostname -notmatch '\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z' -or
        $hostname -match '\.(localhost|local|localdomain|internal|intranet|lan|home|corp|home\.arpa|ts\.net)\z') {
      throw 'Release artifact URL host must be public.'
    }
  }
  return $uri
}

function Test-ReleaseArtifactPrefix([Uri]$Uri, [Uri[]]$Prefixes) {
  foreach ($prefix in $Prefixes) {
    if (-not $Uri.Host.Equals($prefix.Host, [StringComparison]::Ordinal) -or $Uri.Port -ne $prefix.Port) { continue }
    $directory = if ($prefix.AbsolutePath.EndsWith('/')) { $prefix.AbsolutePath } else { $prefix.AbsolutePath + '/' }
    if ($Uri.AbsolutePath.Equals($prefix.AbsolutePath, [StringComparison]::Ordinal) -or
        $Uri.AbsolutePath.StartsWith($directory, [StringComparison]::Ordinal)) { return $true }
  }
  return $false
}

function Assert-ReleaseArtifactUrl(
  [string]$ArtifactUrl, [string[]]$ArtifactPrefixes, [switch]$AllowLocalHost, [switch]$RequirePublicDns, [switch]$PassThru
) {
  if (-not $ArtifactPrefixes.Count) { throw 'Release artifact URL allowlist is empty.' }
  $prefixes = @(foreach ($prefix in $ArtifactPrefixes) { ConvertTo-ReleaseArtifactUri $prefix -AllowLocalHost:$AllowLocalHost })
  $uri = ConvertTo-ReleaseArtifactUri $ArtifactUrl -AllowLocalHost:$AllowLocalHost
  if (-not (Test-ReleaseArtifactPrefix $uri $prefixes)) { throw 'Release artifact URL is outside the allowed HTTPS path prefixes.' }
  if ($RequirePublicDns) { $null = Get-PublicReleaseArtifactAddresses $uri }
  if ($PassThru) { return [pscustomobject]@{ Uri = $uri; Prefixes = $prefixes } }
}

function Resolve-ReleaseArtifactAddresses([Uri]$Uri) {
  $address = $null
  if ([Net.IPAddress]::TryParse($Uri.IdnHost, [ref]$address)) { return $address }
  [Net.Dns]::GetHostAddressesAsync($Uri.IdnHost + '.').WaitAsync([TimeSpan]::FromSeconds(5)).GetAwaiter().GetResult()
}

function Get-PublicReleaseArtifactAddresses([Uri]$Uri, [scriptblock]$ResolveAddresses = ${function:Resolve-ReleaseArtifactAddresses}) {
  try { $addresses = @(& $ResolveAddresses $Uri) }
  catch { throw "Release artifact DNS resolution failed for $($Uri.IdnHost)." }
  if (-not $addresses.Count) { throw "Release artifact DNS returned no addresses for $($Uri.IdnHost)." }
  foreach ($address in $addresses) {
    if ($address -isnot [Net.IPAddress] -or -not (Test-PublicReleaseAddress $address)) {
      throw "Release artifact DNS returned a non-public address for $($Uri.IdnHost)."
    }
  }
  return $addresses
}

function New-ReleaseArtifactHeadHandler([Net.IPAddress[]]$Addresses) {
  # Pin the checked addresses to the connection while preserving HTTPS hostname verification.
  if (-not ('Cerberus.ReleaseArtifactHeadTransport' -as [type])) {
    Add-Type -TypeDefinition @'
using System.Net;
using System.Net.Http;
using System.Net.Sockets;

namespace Cerberus
{
    public static class ReleaseArtifactHeadTransport
    {
        public static SocketsHttpHandler CreateHandler(IPAddress[] addresses) => new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            Credentials = null,
            ConnectCallback = async (context, cancellationToken) =>
            {
                var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    await socket.ConnectAsync(addresses, context.DnsEndPoint.Port, cancellationToken);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch
                {
                    socket.Dispose();
                    throw;
                }
            }
        };
    }
}
'@
  }
  return [Cerberus.ReleaseArtifactHeadTransport]::CreateHandler($Addresses)
}

function Invoke-ReleaseArtifactHead([Uri]$Uri, [Net.IPAddress[]]$Addresses, [Net.Http.HttpMessageHandler]$Handler = $null) {
  if ($null -eq $Handler) { $Handler = New-ReleaseArtifactHeadHandler $Addresses }
  $client = [Net.Http.HttpClient]::new($Handler)
  $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Head, $Uri)
  try {
    $client.Timeout = [TimeSpan]::FromSeconds(10)
    $response = $client.SendAsync($request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
    try {
      $locations = $null
      $null = $response.Headers.TryGetValues('Location', [ref]$locations)
      return [pscustomobject]@{ StatusCode = [int]$response.StatusCode; Locations = @($locations | Where-Object { $null -ne $_ }) }
    } finally { $response.Dispose() }
  } finally {
    $request.Dispose()
    $client.Dispose()
  }
}

function Assert-ReleaseArtifactReachable(
  [string]$ArtifactUrl, [string[]]$ArtifactPrefixes,
  [scriptblock]$ResolveAddresses = ${function:Resolve-ReleaseArtifactAddresses},
  [scriptblock]$SendHead = ${function:Invoke-ReleaseArtifactHead}
) {
  $policy = Assert-ReleaseArtifactUrl $ArtifactUrl $ArtifactPrefixes -PassThru
  $uri = $policy.Uri
  for ($hop = 0; $hop -le 3; $hop++) {
    $addresses = @(Get-PublicReleaseArtifactAddresses $uri $ResolveAddresses)
    try { $head = & $SendHead $uri $addresses }
    catch { throw "Anonymous release artifact HEAD failed for $($uri.IdnHost)." }
    if ($head.StatusCode -ge 200 -and $head.StatusCode -lt 300) { return }
    if ($head.StatusCode -notin 301, 302, 303, 307, 308) {
      throw "Anonymous release artifact HEAD for $($uri.IdnHost) returned HTTP $($head.StatusCode). Expected 2xx."
    }
    if ($hop -eq 3 -or $head.Locations.Count -ne 1 -or [string]::IsNullOrWhiteSpace($head.Locations[0])) {
      throw 'Release artifact HEAD redirect has invalid Location headers or exceeded three hops.'
    }
    $location = [string]$head.Locations[0]
    if ($location.StartsWith('/') -and -not $location.StartsWith('//')) { $location = $uri.GetLeftPart([UriPartial]::Authority) + $location }
    # An allowlisted GitHub release download can delegate to GitHub's release asset service.
    # Its short-lived, server-issued query stays in memory and only travels to that destination.
    $fromGithubRelease = $uri.Host -ceq 'github.com' -and $uri.IsDefaultPort -and $uri.AbsolutePath -cmatch '\A/[^/]+/[^/]+/releases/download/'
    $next = ConvertTo-ReleaseArtifactUri $location -AllowProviderQuery:$fromGithubRelease
    $githubAsset = $fromGithubRelease -and $next.Host -cin 'release-assets.githubusercontent.com', 'objects.githubusercontent.com' -and
      $next.IsDefaultPort -and $next.AbsolutePath -cmatch '\A/github-production-release-asset(?:-[a-f0-9]+)?/[^/]+/.+'
    if (-not $githubAsset -and ($location.Contains('?') -or -not (Test-ReleaseArtifactPrefix $next $policy.Prefixes))) {
      throw 'Release artifact HEAD redirect is outside the allowed HTTPS path prefixes.'
    }
    $uri = $next
  }
}
