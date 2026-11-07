# Runs existing production updater/server tests; never installs an agent or changes privileges.
param([string]$OutputRoot = 'out/ci-test-results/server', [string]$Configuration = 'Release',
    [string]$DotNetExecutable = 'dotnet.exe', [switch]$UseImplementationReferences)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$out = [IO.Path]::GetFullPath($OutputRoot, $repoRoot)
$allowed = [IO.Path]::GetFullPath((Join-Path $repoRoot 'out')) + [IO.Path]::DirectorySeparatorChar
if (-not $out.StartsWith($allowed, [StringComparison]::OrdinalIgnoreCase) -or (Test-Path -LiteralPath $out)) {
    throw 'Use a fresh directory inside worktree/out for CI evidence.'
}
$null = New-Item -ItemType Directory -Path $out
$proof = [ordered]@{
    source = (git -C $repoRoot rev-parse HEAD).Trim()
    profile = 'server'; startedUtc = [DateTimeOffset]::UtcNow.ToString('o'); status = 'failed'
    elevatedAdministrator = $false; testExitCode = $null; total = 0; passed = 0
    nativeRequiredCases = 27; nativeObservedCases = 0
    level = 'Windows native storage guards and updater/server unit/support; not installed service recovery or PC/VM self-update acceptance'
    installs = 0; targetAccess = $false
}
try {
    if (-not $IsWindows) { throw 'Native updater checks require Windows.' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $proof.elevatedAdministrator = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $proof.elevatedAdministrator) { throw 'Native storage checks require an already elevated runner; this script never self-elevates.' }
    $dotnet = (Get-Command $DotNetExecutable -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    if ([IO.Path]::GetExtension($dotnet) -ine '.exe') { throw 'Use the native dotnet executable, not a command wrapper.' }
    $proof.dotNetExecutable = $dotnet
    $referenceArgs = @()
    if ($UseImplementationReferences) {
        $referenceArgs = @('-p:ProduceReferenceAssembly=false', '-p:CompileUsingReferenceAssemblies=false')
    }
    $proof.referenceMode = if ($UseImplementationReferences) { 'implementation' } else { 'sdk-default' }
    $selectionPath = Join-Path $repoRoot 'tests/fixtures/agent-update-ci-native-cases.json'
    $selection = Get-Content -LiteralPath $selectionPath -Raw | ConvertFrom-Json
    $anchorsPath = Join-Path $repoRoot 'tests/fixtures/agent-command-test-anchors.b64'
    $anchors = (Get-Content -LiteralPath $anchorsPath -Raw).Trim()
    $proof.selectionSha256 = (Get-FileHash -LiteralPath $selectionPath).Hash
    $proof.publicFixtureAnchorsSha256 = (Get-FileHash -LiteralPath $anchorsPath).Hash
    $filter = 'FullyQualifiedName~AgentUpdate|FullyQualifiedName~AgentInstallerInvocationTests|FullyQualifiedName~AgentServerManualUpdatePolicyTests|FullyQualifiedName~ServerServiceStartupTests|FullyQualifiedName~ServiceWorkerFailureTests|FullyQualifiedName~CompiledServiceHost_ActuallyCallsTheSharedCacheLifecycleInThisProfile'
    $project = Join-Path $repoRoot 'tests/Cerberus.Agent.Core.Tests/Cerberus.Agent.Core.Tests.csproj'
    $proof.filter = $filter
    # Same isolated public-anchor server compilation used by preflight.ps1. No release trust inputs.
    & $dotnet test $project -c $Configuration -p:AgentBuildProfile=server "-p:AgentCommandTrustAnchorsB64=$anchors" @referenceArgs `
        -p:UseSharedCompilation=false -p:IntermediateOutputPath=obj/_int/ci-server/ `
        -p:BaseOutputPath=bin/_testout_ci_server/ --disable-build-servers --filter $filter `
        --logger 'trx;LogFileName=server-updater.trx' --results-directory $out *> (Join-Path $out 'test.log')
    $proof.testExitCode = $LASTEXITCODE
    $trxPath = Join-Path $out 'server-updater.trx'
    if (-not (Test-Path -LiteralPath $trxPath)) { throw 'Server updater test run produced no TRX.' }
    [xml]$trx = Get-Content -LiteralPath $trxPath -Raw
    $rows = @($trx.TestRun.Results.UnitTestResult | Where-Object { $null -ne $_ })
    $proof.trxSha256 = (Get-FileHash -LiteralPath $trxPath).Hash
    $proof.total = $rows.Count
    $proof.passed = @($rows | Where-Object outcome -eq 'Passed').Count
    $nativeRows = @()
    foreach ($case in $selection.cases) {
        $matches = @($rows | Where-Object { $_.testName -ceq $case })
        if ($matches.Count -ne 1) { throw "Required native case is missing or duplicated: $case" }
        $nativeRows += $matches
    }
    $proof.nativeObservedCases = $nativeRows.Count
    $serverStartup = @($rows | Where-Object { $_.testName.Contains('.ServerServiceStartupTests.') }).Count
    $adapter = @($rows | Where-Object { $_.testName.Contains('.AgentUpdateLabRemediationTests.') }).Count
    $proof.serverStartupCases = $serverStartup
    $proof.versionAdapterCases = $adapter
    $diagnostics = @($rows | Where-Object { $_.testName.Contains('.ServiceWorkerFailureTests.') }).Count
    $proof.workerFailureCases = $diagnostics
    if ($proof.testExitCode -ne 0 -or $proof.total -eq 0 -or $proof.passed -ne $proof.total -or
        $selection.schemaVersion -ne 1 -or @($selection.cases | Sort-Object -Unique).Count -ne 27 -or $nativeRows.Count -ne 27 -or
        @($nativeRows | Where-Object outcome -ne 'Passed').Count -ne 0 -or $serverStartup -eq 0 -or $adapter -eq 0 -or $diagnostics -eq 0) {
        throw 'Updater/server checks are failed, missing or skipped; preserve evidence and stop.'
    }
    $proof.status = 'completed'
} finally {
    $proof.endedUtc = [DateTimeOffset]::UtcNow.ToString('o')
    $proof | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $out 'server-updater-proof.json') -Encoding utf8
}
