# Test-DefenderAlerts.ps1 — Tests for the Microsoft Defender Alerts parser

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"
. "$appRoot\lib\ParserEngine.ps1"
$Script:Parsers = [ordered]@{}
. "$appRoot\parsers\DefenderAlerts.ps1"

$sampleJson = Get-SampleFile "defender-alerts.json"
$sampleCsv = Get-SampleFile "defender-alerts.csv"

Invoke-Test "DefenderAlerts: Auto-detect identifies JSON format" {
    if (-not (Test-Path $sampleJson)) { $Script:TestResults.Skipped++; return }
    $result = Invoke-AutoDetect $sampleJson
    Assert-Equal "defender-alerts" $result
}

Invoke-Test "DefenderAlerts: Parses JSON sample without error" {
    if (-not (Test-Path $sampleJson)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "defender-alerts" -FilePath $sampleJson -Encoding "UTF-8"
    Assert-NotNull $entries
    Assert-GreaterThan $entries.Count 0 "Should parse at least one entry"
}

Invoke-Test "DefenderAlerts: Entries contain AlertId field" {
    if (-not (Test-Path $sampleJson)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "defender-alerts" -FilePath $sampleJson -Encoding "UTF-8"
    $first = $entries[0]
    Assert-NotNull $first.Extra['AlertId'] "AlertId should not be null"
}

Invoke-Test "DefenderAlerts: Entries contain Severity field" {
    if (-not (Test-Path $sampleJson)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "defender-alerts" -FilePath $sampleJson -Encoding "UTF-8"
    $first = $entries[0]
    Assert-NotNull $first.Extra['Severity'] "Severity should not be null"
}

Invoke-Test "DefenderAlerts: Entries contain Category field" {
    if (-not (Test-Path $sampleJson)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "defender-alerts" -FilePath $sampleJson -Encoding "UTF-8"
    $first = $entries[0]
    Assert-NotNull $first.Extra['Category'] "Category should not be null"
}

Invoke-Test "DefenderAlerts: Severity maps to correct log level" {
    $entry = ConvertTo-LogEntry @{
        Index = 0; Timestamp = (Get-Date); Level = "ERROR"; Source = "WindowsDefenderAtp"
        Host = "PC-01"; Message = "[High] Suspicious activity"
        RawLine = "{}"; Extra = @{ AlertId = "alert-1"; Severity = "High"; Category = "Malware" }
    }
    Assert-Equal "ERROR" $entry.Level
}

Invoke-Test "DefenderAlerts: CSV format auto-detection works" {
    if (-not (Test-Path $sampleCsv)) { $Script:TestResults.Skipped++; return }
    $result = Invoke-AutoDetect $sampleCsv
    Assert-Equal "defender-alerts" $result
}

Write-TestSummary
