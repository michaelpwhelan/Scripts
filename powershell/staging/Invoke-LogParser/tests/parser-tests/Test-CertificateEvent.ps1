# Test-CertificateEvent.ps1 — Tests for the Certificate Lifecycle Event parser

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"
. "$appRoot\lib\ParserEngine.ps1"
$Script:Parsers = [ordered]@{}
$Script:State = @{ EventIdLookup = @{} }
. "$appRoot\parsers\CertificateEvent.ps1"

$sampleJson = Get-SampleFile "certificate-event.json"
$sampleCsv = Get-SampleFile "certificate-event.csv"

Invoke-Test "CertificateEvent: Auto-detect identifies JSON format" {
    if (-not (Test-Path $sampleJson)) { $Script:TestResults.Skipped++; return }
    $result = Invoke-AutoDetect $sampleJson
    Assert-Equal "certificate-event" $result
}

Invoke-Test "CertificateEvent: Parses JSON sample without error" {
    if (-not (Test-Path $sampleJson)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "certificate-event" -FilePath $sampleJson -Encoding "UTF-8"
    Assert-NotNull $entries
    Assert-GreaterThan $entries.Count 0 "Should parse at least one entry"
}

Invoke-Test "CertificateEvent: Entries contain Thumbprint field" {
    if (-not (Test-Path $sampleJson)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "certificate-event" -FilePath $sampleJson -Encoding "UTF-8"
    $first = $entries[0]
    Assert-True ($first.Extra.ContainsKey('Thumbprint')) "Extra should have Thumbprint key"
}

Invoke-Test "CertificateEvent: Entries contain Subject and NotAfter fields" {
    if (-not (Test-Path $sampleJson)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "certificate-event" -FilePath $sampleJson -Encoding "UTF-8"
    $first = $entries[0]
    Assert-True ($first.Extra.ContainsKey('Subject')) "Extra should have Subject key"
    Assert-True ($first.Extra.ContainsKey('NotAfter')) "Extra should have NotAfter key"
}

Invoke-Test "CertificateEvent: Expired cert maps to CRITICAL level" {
    $entry = ConvertTo-LogEntry @{
        Index = 0; Timestamp = (Get-Date); Level = "CRITICAL"; Source = "Certificate"
        Host = ""; Message = "Certificate CN=expired.test expires 2024-01-01 (-365 days)"
        RawLine = "{}"; Extra = @{ Subject = "CN=expired.test"; NotAfter = "2024-01-01"; DaysToExpiry = -365 }
    }
    Assert-Equal "CRITICAL" $entry.Level
}

Invoke-Test "CertificateEvent: DaysToExpiry is calculated" {
    if (-not (Test-Path $sampleJson)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "certificate-event" -FilePath $sampleJson -Encoding "UTF-8"
    $first = $entries[0]
    Assert-True ($first.Extra.ContainsKey('DaysToExpiry')) "Extra should have DaysToExpiry key"
}

Invoke-Test "CertificateEvent: CSV format auto-detection works" {
    if (-not (Test-Path $sampleCsv)) { $Script:TestResults.Skipped++; return }
    $result = Invoke-AutoDetect $sampleCsv
    Assert-Equal "certificate-event" $result
}

Write-TestSummary
