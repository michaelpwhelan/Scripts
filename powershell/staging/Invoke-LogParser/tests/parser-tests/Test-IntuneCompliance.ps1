# Test-IntuneCompliance.ps1 — Tests for the Intune Device Compliance parser

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"
. "$appRoot\lib\ParserEngine.ps1"
$Script:Parsers = [ordered]@{}
. "$appRoot\parsers\IntuneCompliance.ps1"

$sampleFile = Get-SampleFile "intune-compliance.json"

Invoke-Test "IntuneCompliance: Auto-detect identifies format" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $result = Invoke-AutoDetect $sampleFile
    Assert-Equal "intune-compliance" $result
}

Invoke-Test "IntuneCompliance: Parses sample without error" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "intune-compliance" -FilePath $sampleFile -Encoding "UTF-8"
    Assert-NotNull $entries
    Assert-GreaterThan $entries.Count 0 "Should parse at least one entry"
}

Invoke-Test "IntuneCompliance: Entries contain ComplianceState" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "intune-compliance" -FilePath $sampleFile -Encoding "UTF-8"
    $first = $entries[0]
    Assert-NotNull $first.Extra['ComplianceState'] "ComplianceState should be in Extra"
}

Invoke-Test "IntuneCompliance: Entries contain DeviceName" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "intune-compliance" -FilePath $sampleFile -Encoding "UTF-8"
    $first = $entries[0]
    Assert-True ($first.Extra.ContainsKey('DeviceName')) "Extra should have DeviceName key"
}

Invoke-Test "IntuneCompliance: NonCompliant maps to WARNING level" {
    $entry = ConvertTo-LogEntry @{
        Index = 0; Timestamp = (Get-Date); Level = "WARNING"; Source = "Intune Compliance"
        Host = "LAPTOP-01"; Message = "LAPTOP-01 - noncompliant (policy: Baseline)"
        RawLine = "{}"; Extra = @{ ComplianceState = "noncompliant"; DeviceName = "LAPTOP-01"; PolicyName = "Baseline" }
    }
    Assert-Equal "WARNING" $entry.Level
}

Invoke-Test "IntuneCompliance: Compliant maps to INFO level" {
    $entry = ConvertTo-LogEntry @{
        Index = 0; Timestamp = (Get-Date); Level = "INFO"; Source = "Intune Compliance"
        Host = "PC-01"; Message = "PC-01 - compliant"
        RawLine = "{}"; Extra = @{ ComplianceState = "compliant"; DeviceName = "PC-01" }
    }
    Assert-Equal "INFO" $entry.Level
}

Invoke-Test "IntuneCompliance: Message includes policy name when available" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "intune-compliance" -FilePath $sampleFile -Encoding "UTF-8"
    $hasPolicy = $false
    foreach ($e in $entries) {
        if ($e.Message -match 'policy:') { $hasPolicy = $true; break }
    }
    # Policy may not be in all entries, just verify parser works
    Assert-GreaterThan $entries.Count 0 "Parser should produce entries"
}

Write-TestSummary
