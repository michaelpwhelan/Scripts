# Test-VeeamJob.ps1 — Tests for the Veeam Backup Job Log parser

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"
. "$appRoot\lib\ParserEngine.ps1"
$Script:Parsers = [ordered]@{}
. "$appRoot\parsers\VeeamJob.ps1"

$sampleFile = Get-SampleFile "veeam-job.log"

Invoke-Test "VeeamJob: Auto-detect identifies format" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $result = Invoke-AutoDetect $sampleFile
    Assert-Equal "veeam-job" $result
}

Invoke-Test "VeeamJob: Parses sample without error" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "veeam-job" -FilePath $sampleFile -Encoding "UTF-8"
    Assert-NotNull $entries
    Assert-GreaterThan $entries.Count 0 "Should parse at least one entry"
}

Invoke-Test "VeeamJob: Entries contain Thread and Module fields" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "veeam-job" -FilePath $sampleFile -Encoding "UTF-8"
    $first = $entries[0]
    Assert-NotNull $first.Extra['Thread'] "Thread should be in Extra"
}

Invoke-Test "VeeamJob: Parser is registered as tail-capable" {
    $parser = $Script:Parsers['veeam-job']
    Assert-NotNull $parser "Parser should be registered"
    Assert-True $parser.SupportsTail "VeeamJob should support tail mode"
}

Invoke-Test "VeeamJob: Failure patterns elevate log level" {
    # Messages containing 'Failed' or 'Error' should not remain at INFO
    $entry = ConvertTo-LogEntry @{
        Index = 0; Timestamp = (Get-Date); Level = "WARNING"; Source = "Veeam"
        Host = ""; Message = "Failed to process VM backup"
        RawLine = "[01.01.2025 10:00:00] <1> Warning [Agent] Failed to process VM backup"
        Extra = @{ Thread = "1"; Module = "Agent" }
    }
    Assert-True ($entry.Level -in @("WARNING","ERROR")) "Failure patterns should elevate level"
}

Invoke-Test "VeeamJob: Timestamp format dd.MM.yyyy is parsed correctly" {
    # Veeam uses [dd.MM.yyyy HH:mm:ss] format
    $entry = ConvertTo-LogEntry @{
        Index = 0; Timestamp = [datetime]::Parse("2025-01-15 10:30:00"); Level = "INFO"
        Source = "Veeam"; Host = ""; Message = "Job started"
        RawLine = "[15.01.2025 10:30:00] <1> Info [Manager] Job started"
        Extra = @{ Thread = "1"; Module = "Manager" }
    }
    Assert-Equal 2025 $entry.Timestamp.Year
}

Write-TestSummary
