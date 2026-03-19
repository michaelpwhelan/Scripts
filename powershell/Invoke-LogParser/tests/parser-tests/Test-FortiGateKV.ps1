# Test-FortiGateKV.ps1 — Tests for the Fortinet Key=Value parser

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"
. "$appRoot\lib\ParserEngine.ps1"
$Script:Parsers = [ordered]@{}
. "$appRoot\enrichment\FortiGateMappings.ps1"
. "$appRoot\parsers\FortiGateKV.ps1"

$sampleFile = Get-SampleFile "fortigate-kv.log"

Invoke-Test "FortiGateKV: Auto-detect identifies format" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $result = Invoke-AutoDetect $sampleFile
    Assert-Equal "fortigate-kv" $result
}

Invoke-Test "FortiGateKV: Parses sample without error" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "fortigate-kv" -FilePath $sampleFile -Encoding "UTF-8"
    Assert-NotNull $entries
    Assert-GreaterThan $entries.Count 0 "Should parse at least one entry"
}

Invoke-Test "FortiGateKV: Entries have required fields" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "fortigate-kv" -FilePath $sampleFile -Encoding "UTF-8"
    $first = $entries[0]
    Assert-NotNull $first.Message "Message should not be null"
    Assert-NotNull $first.Extra "Extra should not be null"
    Assert-True ($first.Level -in @("CRITICAL","ERROR","WARNING","INFO","DEBUG","TRACE","UNKNOWN")) "Level should be valid"
}

Invoke-Test "FortiGateKV: Parses key=value pairs into Extra" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "fortigate-kv" -FilePath $sampleFile -Encoding "UTF-8"
    $first = $entries[0]
    Assert-NotNull $first.Extra['type'] "Extra should contain 'type' field"
}

Invoke-Test "FortiGateKV: Skips malformed lines gracefully" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "fortigate-kv" -FilePath $sampleFile -Encoding "UTF-8"
    Assert-GreaterThan $entries.Count 5 "Should parse most lines"
}

Invoke-Test "FortiGateKV: ConvertTo-LogEntry produces valid structure" {
    $entry = ConvertTo-LogEntry @{
        Index = 0; Timestamp = (Get-Date); Level = "INFO"; Source = "FG-01"
        Host = "FG-01"; Message = "Test event"; RawLine = "test=value"
        Extra = @{ type = "traffic"; action = "accept" }
    }
    Assert-Equal "INFO" $entry.Level
    Assert-Equal "FG-01" $entry.Source
    Assert-NotNull $entry.Timestamp
}

Write-TestSummary
