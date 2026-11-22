# One-line installer written with every release: "irm <url> | iex" downloads this release's MSI, checks it against
# the URL, length and SHA-256 from the release manifest and opens it with the MSI's own UI. The values are validated
# before they are embedded; the build calls the generator before the manifest is signed, so a bad value stops it early.

$script:AgentInstallTemplatePath = Join-Path $PSScriptRoot "agent-install.template.ps1"

function New-AgentInstallScriptText([System.Collections.IDictionary]$Manifest, [string]$BuildProfile) {
  if ($BuildProfile -cnotmatch '\A(server|desktop)\z') { throw "Install script: invalid build profile '$BuildProfile'." }
  $version = [string]$Manifest["version"]
  $url = [string]$Manifest["artifact_url"]
  $sha256 = [string]$Manifest["sha256"]
  $length = [string]$Manifest["artifact_length"]
  if ($version -cnotmatch '\Av?[0-9]+(\.[0-9]+){2,3}([-+][0-9A-Za-z.+-]+)?\z') { throw "Install script: invalid version '$version'." }
  $uri = $null
  if ($url -cnotmatch "\A[A-Za-z0-9._~:/?#\[\]@!&()*+,;=%-]+\z" -or -not [Uri]::TryCreate($url, [UriKind]::Absolute, [ref]$uri) -or
      $uri.Scheme -cne "https" -or -not $uri.AbsolutePath.EndsWith(".msi", [StringComparison]::OrdinalIgnoreCase)) {
    throw "Install script: artifact URL must be an https URL of an .msi file."
  }
  if ($sha256 -cnotmatch '\A[0-9a-f]{64}\z') { throw "Install script: invalid artifact SHA-256." }
  if ($length -cnotmatch '\A[1-9][0-9]{0,11}\z') { throw "Install script: invalid artifact length." }

  $text = [IO.File]::ReadAllText($script:AgentInstallTemplatePath)
  $values = [ordered]@{ "__VERSION__" = $version; "__PROFILE__" = $BuildProfile; "__ARTIFACT_URL__" = $url; "__SHA256__" = $sha256; "__LENGTH__" = $length }
  foreach ($key in $values.Keys) {
    if (-not $text.Contains($key)) { throw "Install script template lacks $key." }
    $text = $text.Replace($key, $values[$key])
  }
  if ($text -cmatch '__[A-Z0-9_]+__') { throw "Install script has an unresolved placeholder." }
  # Windows PowerShell 5.1 decodes "irm" text without a charset as ISO-8859-1: ASCII only, no BOM.
  if ($text -cmatch '[^\x09\x0A\x0D\x20-\x7E]') { throw "Install script must be ASCII." }
  $errors = $null
  [void][Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$errors)
  if (@($errors).Count -gt 0) { throw "Install script does not parse: $($errors[0].Message)" }
  return $text
}

function Write-AgentInstallScript([string]$Path, [string]$Text) {
  [IO.File]::WriteAllText($Path, $Text, [Text.ASCIIEncoding]::new())
  return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

# Adds or replaces the line for one file in a "<sha256>  <name>" checksum list.
function Set-ChecksumLine([string]$Path, [string]$Hash, [string]$Name) {
  $lines = if (Test-Path -LiteralPath $Path) { @(Get-Content -LiteralPath $Path | Where-Object { $_ -and -not $_.EndsWith("  $Name") }) } else { @() }
  @($lines) + "$Hash  $Name" | Set-Content -LiteralPath $Path -Encoding utf8
}
