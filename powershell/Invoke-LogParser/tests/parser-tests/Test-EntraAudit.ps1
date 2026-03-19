# Test-EntraAudit.ps1 — Tests for the Entra ID Audit Logs parser

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"
. "$appRoot\lib\ParserEngine.ps1"
$Script:Parsers = [ordered]@{}
. "$appRoot\parsers\EntraAudit.ps1"

$sampleFile = Get-SampleFile "entra-audit.json"

Invoke-Test "EntraAudit: Auto-detect identifies format" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $result = Invoke-AutoDetect $sampleFile
    Assert-Equal "entra-audit" $result
}

Invoke-Test "EntraAudit: Parses sample without error" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "entra-audit" -FilePath $sampleFile -Encoding "UTF-8"
    Assert-NotNull $entries
    Assert-GreaterThan $entries.Count 0 "Should parse at least one entry"
}

Invoke-Test "EntraAudit: Entries contain ActivityDisplayName" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "entra-audit" -FilePath $sampleFile -Encoding "UTF-8"
    $first = $entries[0]
    Assert-NotNull $first.Extra['ActivityDisplayName'] "ActivityDisplayName should be in Extra"
}

Invoke-Test "EntraAudit: Entries contain Result field" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "entra-audit" -FilePath $sampleFile -Encoding "UTF-8"
    $first = $entries[0]
    Assert-True ($first.Extra.ContainsKey('Result')) "Extra should have Result key"
}

Invoke-Test "EntraAudit: Failure result maps to ERROR level" {
    $entry = ConvertTo-LogEntry @{
        Index = 0; Timestamp = (Get-Date); Level = "ERROR"; Source = "UserManagement"
        Host = ""; Message = "Add user failed (failure)"
        RawLine = "{}"; Extra = @{ ActivityDisplayName = "Add user"; Result = "failure"; Category = "UserManagement" }
    }
    Assert-Equal "ERROR" $entry.Level
}

Invoke-Test "EntraAudit: InitiatedBy user is extracted" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "entra-audit" -FilePath $sampleFile -Encoding "UTF-8"
    $hasInitiator = $false
    foreach ($e in $entries) {
        if ($e.Extra['InitiatedByUser'] -or $e.Extra['InitiatedByApp']) {
            $hasInitiator = $true; break
        }
    }
    Assert-True $hasInitiator "At least one entry should have an initiator"
}

Invoke-Test "EntraAudit: Message includes activity and target resource" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "entra-audit" -FilePath $sampleFile -Encoding "UTF-8"
    $first = $entries[0]
    Assert-NotNull $first.Message "Message should not be null"
}

Write-TestSummary
