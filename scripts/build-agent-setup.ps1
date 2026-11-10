param(
  [Parameter(Mandatory)][string]$MsiPath,
  [Parameter(Mandatory)][string]$OutputDirectory,
  [ValidateSet('desktop', 'server')][string]$BuildProfile = 'desktop',
  [string]$Configuration = 'Release',
  [string]$BuildDirectory = ''
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$msi = (Resolve-Path -LiteralPath $MsiPath).Path
$output = [IO.Path]::GetFullPath($OutputDirectory)
$setupBase = [IO.Path]::GetFileNameWithoutExtension($msi)
if ([string]::IsNullOrWhiteSpace($BuildDirectory)) {
  $BuildDirectory = Join-Path $repoRoot "out/setup/$BuildProfile/$setupBase"
}
$build = [IO.Path]::GetFullPath($BuildDirectory)
New-Item -ItemType Directory -Path $output, $build -Force | Out-Null

# OpenDatabase mode 0 is read-only. This does not install or execute the MSI.
$installer = New-Object -ComObject WindowsInstaller.Installer
$database = $installer.OpenDatabase($msi, 0)
try {
  $metadata = @{}
  foreach ($property in @('ProductName', 'Manufacturer', 'ProductVersion', 'UpgradeCode')) {
    $view = $database.OpenView("SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = '$property'")
    try {
      [void]$view.Execute()
      $record = $view.Fetch()
      if ($null -eq $record) { throw "MSI property is missing: $property" }
      $metadata[$property] = $record.StringData(1)
      [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record)
    } finally {
      [void]$view.Close()
      [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
    }
  }
} finally {
  [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)
  [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
}
$expectedUpgrade = if ($BuildProfile -eq 'server') { [guid]'686EF4F7-AC5C-4459-B2B9-540920991AAF' } else { [guid]'8F7E4C22-4D3E-4D50-9B31-0D969B3D0D1E' }
$actualUpgrade = [guid]::Empty
# ProductName is customizable; the profile is bound to the MSI's stable upgrade identity.
if (-not [guid]::TryParse($metadata.UpgradeCode, [ref]$actualUpgrade) -or $actualUpgrade -ne $expectedUpgrade -or
    [string]::IsNullOrWhiteSpace($metadata.ProductName) -or $metadata.Manufacturer -cne 'Cerberus' -or
    $metadata.ProductVersion -notmatch '^\d+\.\d+\.\d+(\.\d+)?$') {
  throw "MSI metadata does not match the $BuildProfile agent package."
}
$before = (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash
$project = Join-Path $repoRoot 'src/Cerberus.Agent.Setup/Cerberus.Agent.Setup.wixproj'
& dotnet build $project -c $Configuration --nologo `
  "-p:AgentBuildProfile=$BuildProfile" "-p:SetupMsiPath=$msi" "-p:SetupBase=$setupBase" `
  "-p:SetupProductName=$($metadata.ProductName)" "-p:SetupManufacturer=$($metadata.Manufacturer)" `
  "-p:SetupVersion=$($metadata.ProductVersion)" "-p:OutputPath=$build/" `
  "-p:BaseIntermediateOutputPath=$build/obj/" | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Burn setup build failed.' }
if ((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash -cne $before) {
  throw 'MSI payload changed during setup build.'
}
$setup = Join-Path $output "$setupBase.exe"
Copy-Item -LiteralPath (Join-Path $build "$setupBase.exe") -Destination $setup -Force
# Keep the bundle symbols separate from the MSI's identically named wixpdb.
Copy-Item -LiteralPath (Join-Path $build "$setupBase.wixpdb") -Destination (Join-Path $output "$setupBase.setup.wixpdb") -Force
Write-Output $setup
