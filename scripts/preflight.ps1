param(
  [string]$Configuration = "Release",
  [string]$OutDir = "out\\preflight",
  [switch]$SkipPublish,
  [switch]$SkipSelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
  $ts = Get-Date -Format "yyyyMMdd-HHmmss"
  $runDir = Join-Path $repoRoot (Join-Path $OutDir $ts)
  New-Item -ItemType Directory -Force -Path $runDir | Out-Null

  # Avoid file locks from a running tray exe by redirecting bin/obj for this run.
  $baseOut = "out\\bin\\preflight\\$ts\\"
  $intOut = "obj\\_int\\preflight\\$ts\\"

  Write-Host "== build =="
  dotnet build Cerberus.WindowsAgent.slnx -c $Configuration `
    -p:UseSharedCompilation=false `
    -p:BaseOutputPath=$baseOut `
    -p:IntermediateOutputPath=$intOut `
    --disable-build-servers

  Write-Host "== test =="
  dotnet test Cerberus.WindowsAgent.slnx -c $Configuration `
    -p:UseSharedCompilation=false `
    -p:IntermediateOutputPath=$intOut `
    -p:BaseOutputPath=bin\\_testout_preflight\\ `
    --disable-build-servers

  if (-not $SkipPublish) {
    Write-Host "== publish =="
    $pubDir = Join-Path $runDir "publish"
    dotnet publish src\\Cerberus.Agent.App\\Cerberus.Agent.App.csproj -c $Configuration -o $pubDir `
      -p:UseSharedCompilation=false `
      -p:BaseOutputPath=$baseOut `
      -p:IntermediateOutputPath=$intOut `
      -r win-x64 `
      --self-contained true `
      -p:PublishSingleFile=true `
      -p:IncludeNativeLibrariesForSelfExtract=true `
      -p:EnableCompressionInSingleFile=true `
      --disable-build-servers
  }

  if (-not $SkipSelfTest) {
    Write-Host "== self-test =="
    $selfTestOut = Join-Path $runDir "selftest.json"
    $exe = if ($SkipPublish) {
      # Build output is redirected via BaseOutputPath, so pick it up from there.
      Join-Path $repoRoot ("src\\Cerberus.Agent.App\\" + $baseOut + $Configuration + "\\net8.0-windows\\Cerberus.Agent.App.exe")
    } else {
      Join-Path (Join-Path $runDir "publish") "Cerberus.Agent.App.exe"
    }

    if (-not (Test-Path $exe)) {
      throw "Self-test exe not found: $exe"
    }

    & $exe --self-test --self-test-json --self-test-out $selfTestOut
    $rc = $LASTEXITCODE
    Write-Host "self-test exit code: $rc"
    if ($rc -ne 0) {
      Write-Host "Self-test failed. See: $selfTestOut"
      exit $rc
    }
  }

  Write-Host "OK. Artifacts: $runDir"
} finally {
  Pop-Location
}
