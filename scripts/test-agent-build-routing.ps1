$ErrorActionPreference = "Stop"
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
  (Join-Path $PSScriptRoot "build-agent-public-release.ps1"), [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw ($parseErrors -join "`n") }
# Evaluate only the real routing statements; signing, deletion, publishing and installation never run.
$routing = $ast.EndBlock.Statements | Where-Object {
  $_.Extent.Text.StartsWith('if ($Channel -eq "dev")') -or
  $_.Extent.Text.StartsWith('foreach ($endpoint in @($DefaultBackendUrl, $DefaultSsoBaseUrl))')
}
if ($routing.Count -ne 2) { throw "Expected build routing and validation statements." }
$resolve = [scriptblock]::Create(($routing.Extent.Text -join "`n"))

function Assert-Routing([string]$Channel, [string]$Backend = "", [string]$Sso = "", [string]$Client = "", [bool]$Reject = $false) {
  $DefaultBackendUrl = $Backend
  $DefaultSsoBaseUrl = $Sso
  $DefaultSsoClientId = $Client
  $DefaultSsoScope = ""
  $DefaultOAuthRedirectPort = 0
  try { . $resolve } catch {
    if ($Reject) { return }
    throw
  }
  if ($Reject) { throw "Expected routing rejection for $Channel." }
  if ($Channel -eq "dev" -and ($DefaultBackendUrl -ne "http://127.0.0.1:8000" -or
      $DefaultSsoBaseUrl -ne "http://localhost:18000" -or $DefaultSsoClientId -ne "610f03b77494869da4ef")) {
    throw "Ambient production settings contaminated dev defaults."
  }
  if ($Channel -eq "stable" -and ($DefaultBackendUrl -ne "https://app.cerberusd.com" -or
      $DefaultSsoBaseUrl -ne "https://auth.cerberusd.com")) { throw "Stable defaults differ from primary deployment." }
}

$saved = @{}
foreach ($name in @("CERBERUS_BACKEND_URL", "CERBERUS_SSO_BASE_URL", "CERBERUS_SSO_CLIENT_ID")) {
  $saved[$name] = [Environment]::GetEnvironmentVariable($name)
}
try {
  $env:CERBERUS_BACKEND_URL = "https://other.example"
  $env:CERBERUS_SSO_BASE_URL = "https://other-auth.example"
  $env:CERBERUS_SSO_CLIENT_ID = "other-client"
  Assert-Routing dev
  Assert-Routing dev -Backend "https://other.example" -Reject $true
  Assert-Routing dev -Sso "https://other-auth.example" -Reject $true
  $env:CERBERUS_BACKEND_URL = ""
  $env:CERBERUS_SSO_BASE_URL = ""
  $env:CERBERUS_SSO_CLIENT_ID = ""
  Assert-Routing stable -Client "explicit-primary-client"
  Assert-Routing stable -Reject $true
  Assert-Routing stable -Backend "http://127.0.0.1:8000" -Client "explicit-primary-client" -Reject $true
  Assert-Routing stable -Sso "http://auth.example" -Client "explicit-primary-client" -Reject $true
  Write-Output "Build routing: 7 support cases passed; no artifact or host mutation."
} finally {
  foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $saved[$name]) }
}
