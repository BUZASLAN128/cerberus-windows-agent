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

    $upgradeRows = @(Query $db 'SELECT `UpgradeCode`, `VersionMin`, `VersionMax`, `Attributes`, `ActionProperty` FROM `Upgrade`' 5)
    $grantActions = @(Query $db "SELECT ``Type``, ``Source``, ``Target`` FROM ``CustomAction`` WHERE ``Action`` = 'RequireRollbackGrant'" 3)
    $rollbackRows = @($upgradeRows | Where-Object { $_[4] -eq 'CERBERUS_NEWER_DETECTED' })
    $secureRows = @(Query $db "SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = 'SecureCustomProperties'" 1)
    $secure = $secureRows[0][0] -split ';'
    $grantSequence = @(Query $db 'SELECT `Action`, `Condition`, `Sequence` FROM `InstallExecuteSequence`' 3)
    $grantScheduled = @($grantSequence | Where-Object { $_[0] -eq 'RequireRollbackGrant' })
    $removalGuard = @($grantSequence | Where-Object { $_[0] -eq 'BlockNewServerDowngradeWithRemoval' })
    if ($profile -eq 'server') {
        $version = @(Query $db "SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = 'ProductVersion'" 1)[0][0]
        $major = @($upgradeRows | Where-Object { $_[4] -eq 'WIX_UPGRADE_DETECTED' })
        if ($major.Count -ne 1 -or $major[0][2] -or ([int]$major[0][3] -band 2)) { throw 'Bad server major-upgrade row' }
        if ($rollbackRows.Count -ne 1 -or $rollbackRows[0][0] -ne $major[0][0] -or $rollbackRows[0][1] -ne $version -or
            $rollbackRows[0][2] -or ([int]$rollbackRows[0][3] -band 258) -ne 2) { throw 'Bad server newer-version detection row' }
        if ('CERBERUS_NEWER_DETECTED' -notin $secure -or 'CERBERUS_ROLLBACK_ATTEMPT' -notin $secure) { throw 'Bad server rollback secure properties' }
        $target = '^require-rollback-grant "\[ProductCode\]" "\[APPFOLDER\]\." "[^"]+" "\[RollbackServiceExeSha256\]" "\[RollbackServiceAssemblySha256\]" "\[CERBERUS_NEWER_DETECTED\]" "\[CERBERUS_ROLLBACK_ATTEMPT\]" "\[OriginalDatabase\]"$'
        if ($grantActions.Count -ne 1 -or [int]$grantActions[0][0] -ne 0x2C02 -or $grantActions[0][1] -ne 'CerberusInstallerHelper' -or
            $grantActions[0][2] -notmatch $target -or $grantActions[0][2].Length -gt 255) { throw 'Bad deferred server rollback grant action' }
        foreach ($property in @('RollbackServiceExeSha256', 'RollbackServiceAssemblySha256')) {
            $hashRows = @(Query $db "SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = '$property'" 1)
            if ($hashRows.Count -ne 1 -or $hashRows[0][0] -notmatch '^[a-f0-9]{64}$') { throw "Bad rollback hash property: $property" }
        }

        $actionOrder = @{}
        foreach ($row in $grantSequence) { $actionOrder[$row[0]] = [int]$row[2] }
        $initialize = $actionOrder['InstallInitialize']
        $guard = $actionOrder['RequireRollbackGrant']
        if ($grantScheduled.Count -ne 1 -or $grantScheduled[0][1] -ne 'CERBERUS_NEWER_DETECTED AND NOT REMOVE' -or
            -not ($initialize -lt $guard -and $guard -lt $actionOrder['StopServices'] -and
                $guard -lt $actionOrder['BootstrapCerberusMachineNamespace'])) { throw 'Bad server rollback grant sequence' }
        if ($removalGuard.Count -ne 1 -or $removalGuard[0][1] -ne 'CERBERUS_NEWER_DETECTED AND REMOVE AND NOT Installed' -or
            [int]$removalGuard[0][2] -ge $initialize) { throw 'A feature-removal request can skip grant admission' }
        $customActions = @(Query $db 'SELECT `Action`, `Type` FROM `CustomAction`' 2)
        $beforeGuard = @($customActions | Where-Object { ([int]$_[1] -band 0x400) -and
            $actionOrder.ContainsKey($_[0]) -and $actionOrder[$_[0]] -lt $guard })
        if ($beforeGuard.Count -ne 0) { throw 'The rollback grant must be the first in-script server custom action' }
        Write-Output ('SERVER UPGRADE ' + ($major[0] -join ' | '))
        Write-Output ('SERVER DETECT ' + ($rollbackRows[0] -join ' | '))
        Write-Output ('SERVER ROLLBACK ' + ($grantScheduled[0] -join ' | '))
    } elseif ($rollbackRows.Count -or $grantActions.Count -or $grantScheduled.Count -or $removalGuard.Count -or
        'CERBERUS_NEWER_DETECTED' -in $secure -or 'CERBERUS_ROLLBACK_ATTEMPT' -in $secure) {
        throw 'Desktop MSI contains server rollback authoring'
    }

    Write-Output "PROFILE $profile"
    foreach ($spec in @(
        @("SELECT ``ComponentId``, ``Attributes``, ``Condition``, ``KeyPath`` FROM ``Component`` WHERE ``Component`` = '$component'", 4),
        @("SELECT ``Registry``, ``Root``, ``Key``, ``Name``, ``Value`` FROM ``Registry`` WHERE ``Component_`` = '$component'", 5),
        @("SELECT ``Action``, ``Condition``, ``Sequence`` FROM ``InstallExecuteSequence`` WHERE ``Action`` = 'FindRelatedProducts' OR ``Action`` = 'SetCERBERUS_EXPLICIT_CONSENT' OR ``Action`` = 'CostFinalize' OR ``Action`` = 'RemoveExistingProducts'", 3),
        @("SELECT ``Action``, ``Type``, ``Source``, ``Target`` FROM ``CustomAction`` WHERE ``Action`` = 'SetCERBERUS_EXPLICIT_CONSENT'", 4),
        @("SELECT ``Dialog_``, ``Control_``, ``Event``, ``Argument``, ``Condition``, ``Ordering`` FROM ``ControlEvent`` WHERE ``Dialog_`` = 'LicenseAgreementDlg' AND ``Control_`` = 'Next'", 6)
    )) { Query $db $spec[0] $spec[1] | ForEach-Object { $_ -join ' | ' } }
}
