# Signer continuity checks, dot-sourced by scripts/test-release-signing.ps1 (shares Check/Throws, $certA, $certB).
# Signer continuity (the Authenticode certificate must be pinned by the new build and by the deployed agents)
$pinA = Get-SignerSpkiPin $certA
$pinB = Get-SignerSpkiPin $certB
function Get-ContinuityWarnings([scriptblock]$Call) { $w = @(& $Call 3>&1 | Where-Object { $_ -is [System.Management.Automation.WarningRecord] }); return $w }
Check "continuity: pin in the embedded and deployed sets passes" {
  Assert-SignerContinuity -SignerPin $pinA -EmbeddedPins @($pinA, $pinB) -DeployedPins @($pinA) -Channel stable; $true
}
Check "continuity: deployed pins given as one comma list are accepted" {
  Assert-SignerContinuity -SignerPin $pinA -EmbeddedPins @($pinA) -DeployedPins @("$pinB,$pinA") -Channel stable; $true
}
Check "continuity: certificate missing from the embedded pins is refused" {
  Throws { Assert-SignerContinuity -SignerPin $pinA -EmbeddedPins @($pinB) -DeployedPins @($pinA) -Channel stable } "compiled into this release"
}
Check "continuity: certificate missing from the deployed pins is refused" {
  Throws { Assert-SignerContinuity -SignerPin $pinA -EmbeddedPins @($pinA) -DeployedPins @($pinB) -Channel stable } "deployed agents do not pin"
}
foreach ($channel in @("preview", "stable")) {
  Check "continuity: no deployed pins on $channel only warns" {
    $w = Get-ContinuityWarnings { Assert-SignerContinuity -SignerPin $pinA -EmbeddedPins @($pinA) -Channel $channel }
    $w.Count -eq 1 -and "$($w[0].Message)" -match "DeployedSignerPins"
  }
}
Check "continuity: no deployed pins on dev is silent" {
  (Get-ContinuityWarnings { Assert-SignerContinuity -SignerPin $pinA -EmbeddedPins @($pinA) -Channel dev }).Count -eq 0
}
Check "continuity: a signed file is measured against both sets" {
  $stub = { param($Path, $AllowedPins) if (@($AllowedPins) -notcontains $pinA) { throw "Signed file signer does not match the expected signer pin: $Path" } }
  & {
    Set-Item -Path Function:Assert-SignedFileSignerPin -Value $stub
    Assert-SignerContinuity -SignedFile "x.msi" -EmbeddedPins @($pinA) -DeployedPins @($pinA) -Channel stable
    (Throws { Assert-SignerContinuity -SignedFile "x.msi" -EmbeddedPins @($pinB) -DeployedPins @($pinA) -Channel stable } "compiled into this release") -and
    (Throws { Assert-SignerContinuity -SignedFile "x.msi" -EmbeddedPins @($pinA) -DeployedPins @($pinB) -Channel stable } "deployed agents do not pin")
  }
}
