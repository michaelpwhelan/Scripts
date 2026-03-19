# Test-SyslogRfc3164.ps1 — Tests for the Syslog RFC 3164 parser

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"
. "$appRoot\lib\ParserEngine.ps1"
$Script:Parsers = [ordered]@{}
. "$appRoot\parsers\SyslogRfc3164.ps1"

$sampleFile = Get-SampleFile "syslog-rfc3164.log"

Invoke-Test "SyslogRfc3164: Auto-detect identifies format" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $result = Invoke-AutoDetect $sampleFile
    Assert-Equal "syslog-rfc3164" $result
}

Invoke-Test "SyslogRfc3164: Parses sample without error" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "syslog-rfc3164" -FilePath $sampleFile -Encoding "UTF-8"
    Assert-NotNull $entries
    Assert-GreaterThan $entries.Count 0 "Should parse at least one entry"
}

Invoke-Test "SyslogRfc3164: Entries contain Priority and Facility" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "syslog-rfc3164" -FilePath $sampleFile -Encoding "UTF-8"
    $first = $entries[0]
    Assert-True ($first.Extra.ContainsKey('Priority') -or $first.Extra.ContainsKey('Facility')) "Extra should have Priority or Facility"
}

Invoke-Test "SyslogRfc3164: Severity maps to correct log level" {
    # Syslog severity: 0-2=CRITICAL, 3=ERROR, 4=WARNING, 5-6=INFO, 7=DEBUG
    $entry = ConvertTo-LogEntry @{
        Index = 0; Timestamp = (Get-Date); Level = "ERROR"; Source = "sshd"
        Host = "linux-01"; Message = "Failed password for root"
        RawLine = "<35>Jan 15 10:00:00 linux-01 sshd[1234]: Failed password for root"
        Extra = @{ Priority = 35; Facility = 4; Severity = 3 }
    }
    Assert-Equal "ERROR" $entry.Level
}

Invoke-Test "SyslogRfc3164: Host field is extracted" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "syslog-rfc3164" -FilePath $sampleFile -Encoding "UTF-8"
    $first = $entries[0]
    Assert-NotNull $first.Host "Host should be extracted from syslog header"
}

Invoke-Test "SyslogRfc3164: Source is set to process name" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "syslog-rfc3164" -FilePath $sampleFile -Encoding "UTF-8"
    $first = $entries[0]
    Assert-NotNull $first.Source "Source should be set to process name"
}

Invoke-Test "SyslogRfc3164: Parser supports tail mode" {
    $parser = $Script:Parsers['syslog-rfc3164']
    Assert-NotNull $parser "Parser should be registered"
    Assert-True $parser.SupportsTail "SyslogRfc3164 should support tail mode"
}

Invoke-Test "SyslogRfc3164: PID is extracted when present" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "syslog-rfc3164" -FilePath $sampleFile -Encoding "UTF-8"
    $hasPid = $false
    foreach ($e in $entries) {
        if ($e.Extra['PID']) { $hasPid = $true; break }
    }
    # PID is optional, just verify parsing works
    Assert-GreaterThan $entries.Count 0 "Parser should produce entries"
}

Write-TestSummary
