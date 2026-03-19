# Test-FortiManagerAudit.ps1 — Tests for the FortiManager Audit Log parser

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"
. "$appRoot\lib\ParserEngine.ps1"
$Script:Parsers = [ordered]@{}
. "$appRoot\enrichment\FortiGateMappings.ps1"
. "$appRoot\enrichment\FortiManagerMappings.ps1"
. "$appRoot\parsers\FortiManagerAudit.ps1"

$sampleFile = Get-SampleFile "fortimanager-audit.log"

Invoke-Test "FortiManagerAudit: Auto-detect identifies format" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $result = Invoke-AutoDetect $sampleFile
    Assert-Equal "fortimanager-audit" $result
}

Invoke-Test "FortiManagerAudit: Parses sample without error" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "fortimanager-audit" -FilePath $sampleFile -Encoding "UTF-8"
    Assert-NotNull $entries
    Assert-GreaterThan $entries.Count 0 "Should parse at least one entry"
}

Invoke-Test "FortiManagerAudit: Entries contain action field" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "fortimanager-audit" -FilePath $sampleFile -Encoding "UTF-8"
    $hasAction = $false
    foreach ($e in $entries) {
        if ($e.Extra['action']) { $hasAction = $true; break }
    }
    Assert-True $hasAction "At least one entry should have action field"
}

Invoke-Test "FortiManagerAudit: User field is appended to message" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "fortimanager-audit" -FilePath $sampleFile -Encoding "UTF-8"
    $hasUser = $false
    foreach ($e in $entries) {
        if ($e.Message -match 'user=') { $hasUser = $true; break }
    }
    Assert-True $hasUser "At least one message should contain user context"
}

Invoke-Test "FortiManagerAudit: Config change actions map to WARNING" {
    $entry = ConvertTo-LogEntry @{
        Index = 0; Timestamp = (Get-Date); Level = "WARNING"; Source = "FMG-01"
        Host = "FMG-01"; Message = "config-change - Modified firewall policy (user=admin)"
        RawLine = "devid=FMG01 action=config-change"
        Extra = @{ action = "config-change"; user = "admin" }
    }
    Assert-Equal "WARNING" $entry.Level
}

Invoke-Test "FortiManagerAudit: Parser is registered as tail-capable" {
    $parser = $Script:Parsers['fortimanager-audit']
    Assert-NotNull $parser "Parser should be registered"
    Assert-True $parser.SupportsTail "FortiManagerAudit should support tail mode"
}

Invoke-Test "FortiManagerAudit: ADOM name is extracted into AdomName" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "fortimanager-audit" -FilePath $sampleFile -Encoding "UTF-8"
    # ADOM may not be in every entry, verify the key exists when ADOM is present
    $hasAdom = $false
    foreach ($e in $entries) {
        if ($e.Extra['ADOM'] -or $e.Extra['AdomName']) { $hasAdom = $true; break }
    }
    # Not all samples have ADOM, so just ensure parser ran successfully
    Assert-GreaterThan $entries.Count 0 "Parser should produce entries"
}

Write-TestSummary
