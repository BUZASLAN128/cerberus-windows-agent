# Test-anchor fixture detection checks, dot-sourced by scripts/test-release-signing.ps1 before the fake-root case
# (shares Check). Runs against the real tests/fixtures/agent-command-test-anchors.b64.
. (Join-Path $PSScriptRoot "release-profile-lib.ps1")
$anchorFixtureLines = @([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Get-Content -LiteralPath (Join-Path $repoRoot "tests/fixtures/agent-command-test-anchors.b64") -Raw).Trim())).Split("`n") |
  ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 })
function ConvertTo-AnchorList([string[]]$InnerLines) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($InnerLines -join "`n"))) }
Check "test anchors: a fixture line with embedded whitespace is still the fixture" {
  $padded = $anchorFixtureLines[0].Insert(8, " ").Insert(20, "`t")
  Test-CommandAnchorsAreTestFixture (ConvertTo-AnchorList @($padded))
}
Check "test anchors: a different anchor is not the fixture" {
  -not (Test-CommandAnchorsAreTestFixture (ConvertTo-AnchorList @([Convert]::ToBase64String([byte[]](1..64)))))
}
Check "test anchors: an undecodable line next to a fixture line still reports the fixture" {
  Test-CommandAnchorsAreTestFixture (ConvertTo-AnchorList @("!!not-base64!!", $anchorFixtureLines[0]))
}
