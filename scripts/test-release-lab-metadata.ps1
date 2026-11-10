# Support-tier checks for Assert-NoLabCampaignMetadata (scripts/release-trust-lib.ps1) and its wiring in
# scripts/build-agent-public-release.ps1. Fixture assemblies are written to a temp directory; no token,
# certificate store or network is used. Exit code = number of failed checks.
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "release-trust-lib.ps1")
. (Join-Path $PSScriptRoot "test-release-signing-fixture.ps1")

$script:failures = 0
function Check([string]$Name, [scriptblock]$Test) {
  try {
    if ((& $Test) -eq $true) { Write-Host "ok   $Name" } else { Write-Host "FAIL $Name"; $script:failures++ }
  } catch { Write-Host "FAIL $Name : $($_.Exception.Message)"; $script:failures++ }
}
function Throws([scriptblock]$Test, [string]$Pattern) {
  try { & $Test | Out-Null; return $false } catch { return ($_.Exception.Message -match $Pattern) }
}

$work = Join-Path ([IO.Path]::GetTempPath()) ("cerberus-lab-metadata-" + [guid]::NewGuid().ToString("N"))
try {
  $trust = @(@("AgentReleaseChannel", "preview"), @("AgentUpdateAllowedArtifactPrefixes", "https://releases.example/"))
  $lab = @(@("AgentUpdateLabPolicyB64", "e30="), @("AgentUpdateLabFeedRootB64", "AAAA"))
  function New-RuntimeDir([object[]]$AgentPairs = $trust, [object[]]$RuntimePairs = $trust) {
    $dir = Join-Path $work ([guid]::NewGuid().ToString("N").Substring(0, 8))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    New-MetadataAssembly -Path (Join-Path $dir "Cerberus.Agent.dll") -AssemblyName "Cerberus.Agent" -Pairs $AgentPairs
    New-MetadataAssembly -Path (Join-Path $dir "Cerberus.Agent.Runtime.dll") -AssemblyName "Cerberus.Agent.Runtime" -Pairs $RuntimePairs
    return $dir
  }

  Check "runtime without lab metadata passes" { Assert-NoLabCampaignMetadata (New-RuntimeDir); $true }
  Check "lab policy in Cerberus.Agent.Runtime.dll is refused" {
    Throws { Assert-NoLabCampaignMetadata (New-RuntimeDir -RuntimePairs ($trust + $lab)) } "Cerberus\.Agent\.Runtime\.dll carries lab-campaign metadata 'AgentUpdateLabPolicyB64'"
  }
  Check "lab feed root in Cerberus.Agent.dll is refused" {
    Throws { Assert-NoLabCampaignMetadata (New-RuntimeDir -AgentPairs ($trust + @(, @("AgentUpdateLabFeedRootB64", "AAAA")))) } "Cerberus\.Agent\.dll carries lab-campaign metadata 'AgentUpdateLabFeedRootB64'"
  }
  Check "a lab key with an empty value is still refused" {
    Throws { Assert-NoLabCampaignMetadata (New-RuntimeDir -RuntimePairs ($trust + @(, @("AgentUpdateLabRuntimeHashesB64", "")))) } "AgentUpdateLabRuntimeHashesB64"
  }
  $helper = Join-Path $work "helper-clean.dll"
  New-MetadataAssembly -Path $helper -AssemblyName "Cerberus.Agent.Installer.Helper" -Pairs $trust
  $helperLab = Join-Path $work "helper-lab.dll"
  New-MetadataAssembly -Path $helperLab -AssemblyName "Cerberus.Agent.Installer.Helper" -Pairs ($trust + $lab + @(, @("AllowUnsignedDevBuild", "true")))
  Check "clean extra assembly passes" { Assert-NoLabCampaignMetadata (New-RuntimeDir) -ExtraAssemblies @($helper); $true }
  Check "lab metadata in an extra assembly (installer helper) is refused" {
    Throws { Assert-NoLabCampaignMetadata (New-RuntimeDir) -ExtraAssemblies @($helperLab) } "helper-lab\.dll carries lab-campaign metadata"
  }
  Check "a missing extra assembly fails closed" {
    Throws { Assert-NoLabCampaignMetadata (New-RuntimeDir) -ExtraAssemblies @((Join-Path $work "absent.dll")) } "was not found"
  }
  Check "a missing runtime assembly fails closed" {
    $dir = New-RuntimeDir; Remove-Item -LiteralPath (Join-Path $dir "Cerberus.Agent.Runtime.dll")
    Throws { Assert-NoLabCampaignMetadata $dir } "was not found"
  }
  Check "release build script runs the gate for non-lab builds before signing and for the helper" {
    $text = Get-Content -LiteralPath (Join-Path $PSScriptRoot "build-agent-public-release.ps1") -Raw
    $gate = [regex]::Matches($text, 'if \(\$null -eq \$labBuild\) \{ Assert-NoLabCampaignMetadata \$runtimePublishDir')
    $gate.Count -eq 2 -and $gate[0].Index -lt $text.IndexOf('Invoke-FirstPartySigning $firstPartyPeFiles') -and
      $gate[1].Index -lt $text.IndexOf('Invoke-FirstPartySigning @(Get-FirstPartyPeFiles $installerHelperOutput)')
  }
} finally {
  Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "failures=$script:failures"
exit $script:failures
