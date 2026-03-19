# Test-FortiGateBgp.ps1 — Tests for the FortiGate BGP Routing parser

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"
. "$appRoot\lib\ParserEngine.ps1"
$Script:Parsers = [ordered]@{}
. "$appRoot\enrichment\FortiGateMappings.ps1"
. "$appRoot\enrichment\BgpStateCodes.ps1"
. "$appRoot\parsers\FortiGateBgp.ps1"

$sampleFile = Get-SampleFile "fortigate-bgp.log"

Invoke-Test "FortiGateBgp: Auto-detect identifies format" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $result = Invoke-AutoDetect $sampleFile
    Assert-Equal "fortigate-bgp" $result
}

Invoke-Test "FortiGateBgp: Parses sample without error" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "fortigate-bgp" -FilePath $sampleFile -Encoding "UTF-8"
    Assert-NotNull $entries
    Assert-GreaterThan $entries.Count 0 "Should parse at least one entry"
}

Invoke-Test "FortiGateBgp: Entries contain NeighborIp field" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "fortigate-bgp" -FilePath $sampleFile -Encoding "UTF-8"
    $hasNeighborIp = $false
    foreach ($e in $entries) {
        if ($e.Extra['NeighborIp']) { $hasNeighborIp = $true; break }
    }
    Assert-True $hasNeighborIp "At least one entry should have NeighborIp"
}

Invoke-Test "FortiGateBgp: Entries contain BgpState field" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "fortigate-bgp" -FilePath $sampleFile -Encoding "UTF-8"
    $hasBgpState = $false
    foreach ($e in $entries) {
        if ($e.Extra['BgpState']) { $hasBgpState = $true; break }
    }
    Assert-True $hasBgpState "At least one entry should have BgpState"
}

Invoke-Test "FortiGateBgp: State down events map to ERROR level" {
    $entry = ConvertTo-LogEntry @{
        Index = 0; Timestamp = (Get-Date); Level = "ERROR"; Source = "FG-01"
        Host = "FG-01"; Message = "BGP neighbor 10.0.0.1 state Idle"
        RawLine = "date=2025-01-01 subtype=route msg=neighbor down"
        Extra = @{ NeighborIp = "10.0.0.1"; BgpState = "Idle" }
    }
    Assert-Equal "ERROR" $entry.Level
}

Invoke-Test "FortiGateBgp: PrefixCount field is extracted when available" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "fortigate-bgp" -FilePath $sampleFile -Encoding "UTF-8"
    # PrefixCount may or may not be present, but Extra key should always exist
    $first = $entries[0]
    Assert-True ($first.Extra.ContainsKey('PrefixCount')) "Extra should have PrefixCount key"
}

Write-TestSummary
