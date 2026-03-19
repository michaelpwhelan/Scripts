# Test-AnomalyDetector.ps1 — Tests for the Anomaly Detector

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"

$Config = @{ ScriptRoot = $appRoot }
. "$appRoot\lib\BaselineEngine.ps1"
. "$appRoot\analysis\AnomalyDetector.ps1"

Invoke-Test "AnomalyDetector: Returns empty result when no entries provided" {
    $result = Get-AnomalyDetection -Entries $null
    Assert-NotNull $result "Should return a result object"
    Assert-Equal 0 $result.Summary.Total "Should have zero anomalies"
}

Invoke-Test "AnomalyDetector: Returns empty result with empty entry list" {
    $entries = [System.Collections.Generic.List[object]]::new()
    $result = Get-AnomalyDetection -Entries $entries
    Assert-Equal 0 $result.Summary.Total "Empty entries should yield zero anomalies"
}

Invoke-Test "AnomalyDetector: Returns message when no baseline exists" {
    $entries = New-TestDataset -Count 50
    $result = Get-AnomalyDetection -Entries $entries -BaselineName "nonexistent-baseline-xyz"
    Assert-NotNull $result "Should return result even without baseline"
    Assert-Equal 0 $result.Summary.Total "Should have zero anomalies without baseline"
}

Invoke-Test "AnomalyDetector: Result structure has expected keys" {
    $result = Get-AnomalyDetection -Entries $null
    Assert-True ($result.ContainsKey('Anomalies')) "Result should have Anomalies key"
    Assert-True ($result.ContainsKey('Summary')) "Result should have Summary key"
    Assert-True ($result.ContainsKey('BaselineName')) "Result should have BaselineName key"
}

Invoke-Test "AnomalyDetector: Summary has severity counts" {
    $result = Get-AnomalyDetection -Entries $null
    $summary = $result.Summary
    Assert-True ($summary.ContainsKey('Total')) "Summary should have Total"
    Assert-True ($summary.ContainsKey('Critical')) "Summary should have Critical"
    Assert-True ($summary.ContainsKey('High')) "Summary should have High"
    Assert-True ($summary.ContainsKey('Medium')) "Summary should have Medium"
    Assert-True ($summary.ContainsKey('Low')) "Summary should have Low"
}

Invoke-Test "AnomalyDetector: Get-ZScore calculates standard deviation correctly" {
    # Z-score of mean should be 0, values at 1 stddev should be ~1
    $zs = Get-ZScore -Value 10 -Mean 10 -StdDev 2
    Assert-Equal 0 $zs "Z-score of mean should be 0"

    $zs2 = Get-ZScore -Value 12 -Mean 10 -StdDev 2
    Assert-Equal 1 $zs2 "Z-score one stddev above should be 1"
}

Invoke-Test "AnomalyDetector: Get-ZScore handles zero stddev gracefully" {
    $zs = Get-ZScore -Value 15 -Mean 10 -StdDev 0
    Assert-True ($zs -eq 0 -or $zs -gt 0) "Should handle zero stddev without error"
}

Write-TestSummary
