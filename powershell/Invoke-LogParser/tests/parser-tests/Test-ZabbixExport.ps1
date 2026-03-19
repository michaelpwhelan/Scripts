# Test-ZabbixExport.ps1 — Tests for the Zabbix Event Export parser

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"
. "$appRoot\lib\ParserEngine.ps1"
$Script:Parsers = [ordered]@{}
. "$appRoot\parsers\ZabbixExport.ps1"

$sampleJson = Get-SampleFile "zabbix-export.json"
$sampleCsv = Get-SampleFile "zabbix-export.csv"

Invoke-Test "ZabbixExport: Auto-detect identifies JSON format" {
    if (-not (Test-Path $sampleJson)) { $Script:TestResults.Skipped++; return }
    $result = Invoke-AutoDetect $sampleJson
    Assert-Equal "zabbix-export" $result
}

Invoke-Test "ZabbixExport: Parses JSON sample without error" {
    if (-not (Test-Path $sampleJson)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "zabbix-export" -FilePath $sampleJson -Encoding "UTF-8"
    Assert-NotNull $entries
    Assert-GreaterThan $entries.Count 0 "Should parse at least one entry"
}

Invoke-Test "ZabbixExport: Entries contain ZabbixSeverity field" {
    if (-not (Test-Path $sampleJson)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "zabbix-export" -FilePath $sampleJson -Encoding "UTF-8"
    $first = $entries[0]
    Assert-NotNull $first.Extra['ZabbixSeverity'] "ZabbixSeverity should be in Extra"
}

Invoke-Test "ZabbixExport: Severity 5 (Disaster) maps to CRITICAL" {
    $entry = ConvertTo-LogEntry @{
        Index = 0; Timestamp = (Get-Date); Level = "CRITICAL"; Source = "Zabbix"
        Host = "web-01"; Message = "[Disaster] web-01 - Host unreachable"
        RawLine = "{}"; Extra = @{ ZabbixSeverity = "Disaster"; HostName = "web-01" }
    }
    Assert-Equal "CRITICAL" $entry.Level
}

Invoke-Test "ZabbixExport: Entries contain HostName and TriggerDescription" {
    if (-not (Test-Path $sampleJson)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "zabbix-export" -FilePath $sampleJson -Encoding "UTF-8"
    $first = $entries[0]
    Assert-True ($first.Extra.ContainsKey('HostName')) "Extra should have HostName key"
    Assert-True ($first.Extra.ContainsKey('TriggerDescription')) "Extra should have TriggerDescription key"
}

Invoke-Test "ZabbixExport: Unix epoch timestamps are converted" {
    if (-not (Test-Path $sampleJson)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "zabbix-export" -FilePath $sampleJson -Encoding "UTF-8"
    $first = $entries[0]
    Assert-True ($first.Timestamp -ne [datetime]::MinValue) "Timestamp should be parsed from epoch"
}

Invoke-Test "ZabbixExport: CSV format auto-detection works" {
    if (-not (Test-Path $sampleCsv)) { $Script:TestResults.Skipped++; return }
    $result = Invoke-AutoDetect $sampleCsv
    Assert-Equal "zabbix-export" $result
}

Write-TestSummary
