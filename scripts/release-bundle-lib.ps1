# Burn wrapper helpers. Dot-sourcing this file has no build or signing side effects.
function Invoke-AgentBurnTool([string[]]$Arguments) {
  $project = Join-Path $PSScriptRoot '../src/Cerberus.Agent.Setup/Cerberus.Agent.Setup.wixproj'
  $directory = & dotnet msbuild $project -getProperty:WixBinDir -nologo
  if ($LASTEXITCODE -ne 0) { throw 'Could not locate the pinned WiX SDK.' }
  $tool = Join-Path ($directory.Trim()) 'wix.dll'
  if (-not (Test-Path -LiteralPath $tool)) { throw 'The pinned WiX CLI was not found.' }
  & dotnet $tool @Arguments -acceptEula wix7 | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "WiX Burn command failed: $($Arguments[0]) $($Arguments[1])" }
}

function New-AgentSetupBundle {
  param(
    [Parameter(Mandatory)][string]$MsiPath,
    [Parameter(Mandatory)][string]$PublishDir,
    [Parameter(Mandatory)][string]$BuildProfile,
    [Parameter(Mandatory)][string]$Configuration,
    [Parameter(Mandatory)][string]$BuildDirectory,
    [bool]$Signed = $false,
    [scriptblock]$SignFile = $null
  )
  if ($Signed -and $null -eq $SignFile) { throw 'Signed setup requires the release signer.' }
  $staging = Join-Path $BuildDirectory 'staged'
  $setup = & (Join-Path $PSScriptRoot 'build-agent-setup.ps1') -MsiPath $MsiPath `
    -OutputDirectory $staging -BuildProfile $BuildProfile -Configuration $Configuration -BuildDirectory $BuildDirectory
  if ($Signed) {
    # The caller has already signed and verified the MSI. Never rebuild it after this point.
    $engine = Join-Path $BuildDirectory 'burn-engine.exe'
    $reattached = Join-Path $BuildDirectory 'setup-reattached.exe'
    Invoke-AgentBurnTool @('burn', 'detach', $setup, '-engine', $engine)
    & $SignFile $engine | Out-Host
    Invoke-AgentBurnTool @('burn', 'reattach', $setup, '-engine', $engine, '-o', $reattached)
    & $SignFile $reattached | Out-Host
    Move-Item -LiteralPath $reattached -Destination $setup -Force
  }
  Assert-AgentSetupPayload -MsiPath $MsiPath -SetupPath $setup -WorkDirectory $BuildDirectory
  New-Item -ItemType Directory -Path $PublishDir -Force | Out-Null
  $published = Join-Path $PublishDir ([IO.Path]::GetFileName($setup))
  Copy-Item -LiteralPath $setup -Destination $published -Force
  $symbols = [IO.Path]::GetFileNameWithoutExtension($setup) + '.setup.wixpdb'
  Copy-Item -LiteralPath (Join-Path $staging $symbols) -Destination (Join-Path $PublishDir $symbols) -Force
  return $published
}

function Assert-AgentSetupPayload([string]$MsiPath, [string]$SetupPath, [string]$WorkDirectory) {
  $extract = Join-Path $WorkDirectory ('payload-check-' + [guid]::NewGuid().ToString('N'))
  Invoke-AgentBurnTool @('burn', 'extract', $SetupPath, '-o', $extract)
  $files = @(Get-ChildItem -LiteralPath $extract -Recurse -File)
  $expected = (Get-FileHash -LiteralPath $MsiPath -Algorithm SHA256).Hash
  if ($files.Count -ne 1 -or (Get-FileHash -LiteralPath $files[0].FullName -Algorithm SHA256).Hash -cne $expected) {
    throw 'Setup payload does not match the published MSI.'
  }
}

function Get-AgentPublicSetupAsset([string]$GatePath, [string]$SetupPath) {
  $gate = Get-Content -LiteralPath $GatePath -Raw | ConvertFrom-Json
  if ($gate.setup.authenticode_signature_present -isnot [bool] -or -not $gate.setup.authenticode_signature_present) {
    Write-Host 'Unsigned setup.exe stays in the CI artifact; public EXE upload skipped.'
    return ''
  }
  if (-not (Test-Path -LiteralPath $SetupPath -PathType Leaf)) { throw 'Signed setup asset is missing.' }
  return $SetupPath
}
