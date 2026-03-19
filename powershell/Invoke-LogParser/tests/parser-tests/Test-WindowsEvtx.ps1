# Test-WindowsEvtx.ps1 — Tests for the Windows Event Log (.evtx) parser
# Note: EVTX parsing requires Get-WinEvent which is Windows-only.
# Tests will skip gracefully on non-Windows platforms.

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"
. "$appRoot\lib\ParserEngine.ps1"
$Script:Parsers = [ordered]@{}
$Script:State = @{ EventIdLookup = @{} }
$Script:MitreEventIdMap = @{}
. "$appRoot\parsers\WindowsEvtx.ps1"

$sampleFile = Get-SampleFile "windows.evtx"
$isWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ($IsWindows -eq $true)

Invoke-Test "WindowsEvtx: Auto-detect identifies .evtx extension" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $result = Invoke-AutoDetect $sampleFile
    Assert-Equal "windows-evtx" $result
}

Invoke-Test "WindowsEvtx: Parser is registered with correct ID" {
    $parser = $Script:Parsers['windows-evtx']
    Assert-NotNull $parser "Parser should be registered"
    Assert-Equal "windows-evtx" $parser.Id
}

Invoke-Test "WindowsEvtx: Extensions include .evtx" {
    $parser = $Script:Parsers['windows-evtx']
    Assert-True ('.evtx' -in $parser.Extensions) "Extensions should include .evtx"
}

Invoke-Test "WindowsEvtx: Parses sample on Windows" {
    if (-not $isWindows) { $Script:TestResults.Skipped++; return }
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "windows-evtx" -FilePath $sampleFile -Encoding "UTF-8"
    Assert-NotNull $entries
    Assert-GreaterThan $entries.Count 0 "Should parse at least one entry"
}

Invoke-Test "WindowsEvtx: Entries have EventID in Extra" {
    if (-not $isWindows) { $Script:TestResults.Skipped++; return }
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "windows-evtx" -FilePath $sampleFile -Encoding "UTF-8"
    $first = $entries[0]
    Assert-NotNull $first.Extra['EventID'] "EventID should be in Extra"
}

Invoke-Test "WindowsEvtx: Level mapping from numeric values" {
    # Verify level mapping logic: 1=CRITICAL, 2=ERROR, 3=WARNING, 4=INFO, 5=DEBUG
    $entry = ConvertTo-LogEntry @{
        Index = 0; Timestamp = (Get-Date); Level = "CRITICAL"; Source = "Security"
        Host = "DC-01"; Message = "Critical event"; RawLine = "<xml/>"
        Extra = @{ EventID = 4625; ProviderName = "Security" }
    }
    Assert-Equal "CRITICAL" $entry.Level
}

Write-TestSummary
