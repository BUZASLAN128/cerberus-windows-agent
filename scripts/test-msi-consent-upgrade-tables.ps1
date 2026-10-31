param(
    [Parameter(Mandatory=$true)][string]$ServerMsi,
    [Parameter(Mandatory=$true)][string]$DesktopMsi
)
$ErrorActionPreference = 'Stop'
$installer = New-Object -ComObject WindowsInstaller.Installer
function Query($db, $sql, $columns) {
    $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @($sql))
    $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
    while ($row = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)) {
        $result = @()
        for ($i = 1; $i -le $columns; $i++) {
            $result += $row.GetType().InvokeMember('StringData', 'GetProperty', $null, $row, @($i))
        }
        ,$result
    }
}
foreach ($profile in @('server','desktop')) {
    $path = (Resolve-Path -LiteralPath $(if ($profile -eq 'server') { $ServerMsi } else { $DesktopMsi })).Path
    $db = $installer.OpenDatabase($path, 0)
    $component = if ($profile -eq 'server') { 'ServerLegalConsentRegistryComponent' } else { 'LegalConsentRegistryComponent' }
    $guid = if ($profile -eq 'server') { '{D3741C30-B58B-4F95-940E-F51B5BA80F84}' } else { '{6FD72DD1-B76B-4E07-94A2-4355A5FB403D}' }
    $componentRows = @(Query $db "SELECT ``ComponentId``, ``Attributes``, ``Condition``, ``KeyPath`` FROM ``Component`` WHERE ``Component`` = '$component'" 4)
    if ($componentRows.Count -ne 1 -or $componentRows[0][0] -ne $guid -or ([int]$componentRows[0][1] -band 128) -eq 0 -or $componentRows[0][2] -ne '(CERBERUS_EXPLICIT_CONSENT = 1 AND NOT Installed AND NOT WIX_UPGRADE_DETECTED) OR WIX_UPGRADE_DETECTED') { throw "Bad component table: $profile" }
    $registryRows = @(Query $db "SELECT ``Registry``, ``Name``, ``Value`` FROM ``Registry`` WHERE ``Component_`` = '$component'" 3)
    if (@($registryRows | Where-Object { $_[0] -eq $componentRows[0][3] -and $_[1] -eq 'accepted' -and $_[2] -eq '#1' }).Count -ne 1) { throw "Bad key path: $profile" }
    if (@($registryRows | Where-Object { $_[1] -eq 'acceptanceEvidence' -and $_[2] -eq '[CERBERUS_EXPLICIT_CONSENT]' }).Count -ne 1) { throw "Bad marker: $profile" }
    $actions = @(Query $db "SELECT ``Action``, ``Condition``, ``Sequence`` FROM ``InstallExecuteSequence`` WHERE ``Action`` = 'FindRelatedProducts' OR ``Action`` = 'SetCERBERUS_EXPLICIT_CONSENT' OR ``Action`` = 'CostFinalize' OR ``Action`` = 'RemoveExistingProducts'" 3)
    $sequence = @{}
    foreach ($action in $actions) { $sequence[$action[0]] = [int]$action[2] }
    if ($sequence.Count -ne 4 -or -not ($sequence['FindRelatedProducts'] -lt $sequence['SetCERBERUS_EXPLICIT_CONSENT'] -and $sequence['SetCERBERUS_EXPLICIT_CONSENT'] -lt $sequence['CostFinalize'] -and $sequence['CostFinalize'] -lt $sequence['RemoveExistingProducts'])) { throw "Bad sequence: $profile" }
    if (@($actions | Where-Object { $_[0] -eq 'SetCERBERUS_EXPLICIT_CONSENT' -and $_[1] -eq 'WIX_UPGRADE_DETECTED' }).Count -ne 1) { throw "Bad setter condition: $profile" }
    $setter = @(Query $db "SELECT ``Type``, ``Source``, ``Target`` FROM ``CustomAction`` WHERE ``Action`` = 'SetCERBERUS_EXPLICIT_CONSENT'" 3)
    if ($setter.Count -ne 1 -or $setter[0][0] -ne '51' -or $setter[0][1] -ne 'CERBERUS_EXPLICIT_CONSENT' -or $setter[0][2] -ne '0') { throw "Bad setter: $profile" }
    Write-Output "PROFILE $profile"
    foreach ($spec in @(
        @("SELECT ``ComponentId``, ``Attributes``, ``Condition``, ``KeyPath`` FROM ``Component`` WHERE ``Component`` = '$component'", 4),
        @("SELECT ``Registry``, ``Root``, ``Key``, ``Name``, ``Value`` FROM ``Registry`` WHERE ``Component_`` = '$component'", 5),
        @("SELECT ``Action``, ``Condition``, ``Sequence`` FROM ``InstallExecuteSequence`` WHERE ``Action`` = 'FindRelatedProducts' OR ``Action`` = 'SetCERBERUS_EXPLICIT_CONSENT' OR ``Action`` = 'CostFinalize' OR ``Action`` = 'RemoveExistingProducts'", 3),
        @("SELECT ``Action``, ``Type``, ``Source``, ``Target`` FROM ``CustomAction`` WHERE ``Action`` = 'SetCERBERUS_EXPLICIT_CONSENT'", 4),
        @("SELECT ``Dialog_``, ``Control_``, ``Event``, ``Argument``, ``Condition``, ``Ordering`` FROM ``ControlEvent`` WHERE ``Dialog_`` = 'LicenseAgreementDlg' AND ``Control_`` = 'Next'", 6)
    )) { Query $db $spec[0] $spec[1] | ForEach-Object { $_ -join ' | ' } }
}
