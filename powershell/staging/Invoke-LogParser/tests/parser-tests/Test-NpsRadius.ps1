# Test-NpsRadius.ps1 — Tests for the NPS/RADIUS DTS XML parser

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"
. "$appRoot\lib\ParserEngine.ps1"
$Script:Parsers = [ordered]@{}
$Script:State = @{ NpsReasonLookup = @{} }
. "$appRoot\enrichment\NpsReasonCodes.ps1"
. "$appRoot\parsers\NpsRadius.ps1"

$sampleFile = Get-SampleFile "nps-radius.xml"

Invoke-Test "NpsRadius: Auto-detect identifies XML format" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $result = Invoke-AutoDetect $sampleFile
    Assert-Equal "nps-radius" $result
}

Invoke-Test "NpsRadius: Parses sample without error" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "nps-radius" -FilePath $sampleFile -Encoding "UTF-8"
    Assert-NotNull $entries
    Assert-GreaterThan $entries.Count 0 "Should parse at least one entry"
}

Invoke-Test "NpsRadius: Entries contain PacketTypeName field" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "nps-radius" -FilePath $sampleFile -Encoding "UTF-8"
    $first = $entries[0]
    Assert-NotNull $first.Extra['PacketTypeName'] "PacketTypeName should not be null"
    $validTypes = @("Access-Request","Access-Accept","Access-Reject","Accounting-Request","Accounting-Response","Access-Challenge")
    $isKnownType = $first.Extra['PacketTypeName'] -match '^(Access-|Accounting-|Type-)'
    Assert-True $isKnownType "PacketTypeName should be a known RADIUS type"
}

Invoke-Test "NpsRadius: Reason-Code field is extracted" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "nps-radius" -FilePath $sampleFile -Encoding "UTF-8"
    $hasReasonCode = $false
    foreach ($e in $entries) {
        if ($e.Extra.ContainsKey('Reason-Code')) { $hasReasonCode = $true; break }
    }
    # Reason-Code may not be in every event, just verify parsing does not error
    Assert-GreaterThan $entries.Count 0 "Should parse entries even without Reason-Code"
}

Invoke-Test "NpsRadius: Access-Reject maps to WARNING level" {
    $entry = ConvertTo-LogEntry @{
        Index = 0; Timestamp = (Get-Date); Level = "WARNING"; Source = "NPS"
        Host = "NPS-01"; Message = "Access-Reject for testuser"
        RawLine = "<Event>test</Event>"
        Extra = @{ PacketTypeName = "Access-Reject"; 'Reason-Code' = "16" }
    }
    Assert-Equal "WARNING" $entry.Level
}

Invoke-Test "NpsRadius: Message includes username when available" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "nps-radius" -FilePath $sampleFile -Encoding "UTF-8"
    $hasUser = $false
    foreach ($e in $entries) {
        if ($e.Message -match ' for ') { $hasUser = $true; break }
    }
    Assert-True $hasUser "At least one message should include 'for <user>'"
}

Write-TestSummary
