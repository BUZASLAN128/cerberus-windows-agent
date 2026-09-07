#Requires -Version 7.4
<#
.SYNOPSIS
Validates a candidate AD opt-in policy using the built agent's canonical decoder.
.DESCRIPTION
Read-only: does not install policy, repair ACLs, contact AD, grant delegation, or change services.
Use a trusted repository-built output directory containing the Core and Integrations.Ad assemblies.
Schema validation is support evidence, not proof of OU delegation or live AD readiness.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PolicyPath,
    [Parameter(Mandatory)][string]$AgentBuildDirectory,
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$AgentId
)
$ErrorActionPreference = 'Stop'
$policyFile = Get-Item -LiteralPath $PolicyPath
if ($policyFile.PSIsContainer -or $policyFile.Length -le 0 -or $policyFile.Length -gt 65536) {
    throw 'Policy must be a nonempty file no larger than 65536 bytes.'
}
$buildDirectory = (Get-Item -LiteralPath $AgentBuildDirectory).FullName
$coreAssembly = Join-Path $buildDirectory 'Cerberus.Agent.Core.dll'
$adAssembly = Join-Path $buildDirectory 'Cerberus.Agent.Integrations.Ad.dll'
[void][System.Reflection.Assembly]::LoadFrom($coreAssembly)
[void][System.Reflection.Assembly]::LoadFrom($adAssembly)
$bytes = [System.IO.File]::ReadAllBytes($policyFile.FullName)
try {
    $identity = [Cerberus.Agent.Core.AgentIdentity]::new($AgentId, $TenantId)
    $scopeCount = [Cerberus.Agent.Integrations.Ad.ProtectedAdScopePolicy]::Decode($bytes, $identity).Count
    [pscustomobject]@{ Result = 'POLICY_SCHEMA_VALID'; EnabledScopes = $scopeCount; LiveAD = 'NOT_VERIFIED'; Installed = $false }
}
catch {
    # Do not echo candidate file contents or exception chains containing input.
    throw 'AD policy validation failed. Check the canonical schema, identity binding, scope pins, and acknowledgments.'
}
