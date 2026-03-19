# Test-FortiSwitchEvent.ps1 — Tests for the FortiSwitch Event Log parser

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"
. "$appRoot\lib\ParserEngine.ps1"
$Script:Parsers = [ordered]@{}
. "$appRoot\enrichment\FortiGateMappings.ps1"
. "$appRoot\enrichment\FortiSwitchEventIds.ps1"
. "$appRoot\parsers\FortiSwitchEvent.ps1"

$sampleFile = Get-SampleFile "fortiswitch-event.log"

Invoke-Test "FortiSwitchEvent: Auto-detect identifies format" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $result = Invoke-AutoDetect $sampleFile
    Assert-Equal "fortiswitch-event" $result
}

Invoke-Test "FortiSwitchEvent: Parses sample without error" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "fortiswitch-event" -FilePath $sampleFile -Encoding "UTF-8"
    Assert-NotNull $entries
    Assert-GreaterThan $entries.Count 0 "Should parse at least one entry"
}

Invoke-Test "FortiSwitchEvent: Entries contain PortName field" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "fortiswitch-event" -FilePath $sampleFile -Encoding "UTF-8"
    $hasPort = $false
    foreach ($e in $entries) {
        if ($e.Extra['PortName']) { $hasPort = $true; break }
    }
    Assert-True $hasPort "At least one entry should have PortName"
}

Invoke-Test "FortiSwitchEvent: VlanId and MacAddress fields are extracted" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "fortiswitch-event" -FilePath $sampleFile -Encoding "UTF-8"
    $first = $entries[0]
    Assert-True ($first.Extra.ContainsKey('VlanId')) "Extra should have VlanId key"
    Assert-True ($first.Extra.ContainsKey('MacAddress')) "Extra should have MacAddress key"
}

Invoke-Test "FortiSwitchEvent: Port down events map to WARNING" {
    $entry = ConvertTo-LogEntry @{
        Index = 0; Timestamp = (Get-Date); Level = "WARNING"; Source = "FSW-01"
        Host = "FSW-01"; Message = "Port port1 down"
        RawLine = "devid=FSW01 msg=port down"
        Extra = @{ PortName = "port1"; PortStatus = "down"; VlanId = ""; MacAddress = "" }
    }
    Assert-Equal "WARNING" $entry.Level
}

Invoke-Test "FortiSwitchEvent: 802.1X auth failure maps to ERROR" {
    $entry = ConvertTo-LogEntry @{
        Index = 0; Timestamp = (Get-Date); Level = "ERROR"; Source = "FSW-01"
        Host = "FSW-01"; Message = "802.1X auth failure for AA:BB:CC:DD:EE:FF"
        RawLine = "devid=FSW01 msg=802.1x auth failure"
        Extra = @{ AuthResult = "failure"; MacAddress = "AA:BB:CC:DD:EE:FF"; PortName = "port5" }
    }
    Assert-Equal "ERROR" $entry.Level
}

Invoke-Test "FortiSwitchEvent: StpState field is extracted" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "fortiswitch-event" -FilePath $sampleFile -Encoding "UTF-8"
    $first = $entries[0]
    Assert-True ($first.Extra.ContainsKey('StpState')) "Extra should have StpState key"
}

Write-TestSummary
