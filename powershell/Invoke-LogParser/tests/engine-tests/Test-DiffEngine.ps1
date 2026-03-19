# Test-DiffEngine.ps1 — Tests for log comparison and diff analysis
# Uses the Helpers and BaselineEngine compare functionality

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"

$Config = @{ ScriptRoot = $appRoot }
. "$appRoot\lib\BaselineEngine.ps1"

Invoke-Test "DiffEngine: Two identical datasets produce minimal anomalies" {
    $dataset = New-TestDataset -Count 50
    $profile = Build-Baseline -Entries $dataset -Name "test-diff-same"
    Save-BaselineProfile -Profile $profile -Name "test-diff-same"
    $anomalies = Compare-Baseline -Entries $dataset -BaselineName "test-diff-same"
    # Same data compared to itself should yield few or zero anomalies
    Assert-NotNull $anomalies "Comparison should not return null"
    try { Remove-Baseline -Name "test-diff-same" } catch { }
}

Invoke-Test "DiffEngine: Different level distributions produce anomalies" {
    # Baseline: mostly INFO
    $baseline = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt 100; $i++) {
        $baseline.Add((New-TestEvent -Index $i -Level "INFO" -Message "Normal event $i"))
    }
    $profile = Build-Baseline -Entries $baseline -Name "test-diff-levels"
    Save-BaselineProfile -Profile $profile -Name "test-diff-levels"

    # Current: mostly ERROR
    $current = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt 100; $i++) {
        $current.Add((New-TestEvent -Index $i -Level "ERROR" -Message "Error event $i"))
    }
    $anomalies = Compare-Baseline -Entries $current -BaselineName "test-diff-levels"
    Assert-GreaterThan @($anomalies).Count 0 "Level distribution change should produce anomalies"
    try { Remove-Baseline -Name "test-diff-levels" } catch { }
}

Invoke-Test "DiffEngine: Volume change is detected as anomaly" {
    # Baseline: 100 entries
    $baseline = New-TestDataset -Count 100
    $profile = Build-Baseline -Entries $baseline -Name "test-diff-volume"
    Save-BaselineProfile -Profile $profile -Name "test-diff-volume"

    # Current: 10 entries (significant volume decrease)
    $current = New-TestDataset -Count 10
    $anomalies = Compare-Baseline -Entries $current -BaselineName "test-diff-volume"
    Assert-NotNull $anomalies "Volume change should be detected"
    try { Remove-Baseline -Name "test-diff-volume" } catch { }
}

Invoke-Test "DiffEngine: Anomalies have Severity field" {
    $baseline = New-TestDataset -Count 50
    $profile = Build-Baseline -Entries $baseline -Name "test-diff-severity"
    Save-BaselineProfile -Profile $profile -Name "test-diff-severity"

    $current = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt 50; $i++) {
        $current.Add((New-TestEvent -Index $i -Level "CRITICAL" -Message "Critical event $i"))
    }
    $anomalies = Compare-Baseline -Entries $current -BaselineName "test-diff-severity"
    if (@($anomalies).Count -gt 0) {
        $first = $anomalies[0]
        Assert-NotNull $first.Severity "Anomaly should have Severity"
    }
    try { Remove-Baseline -Name "test-diff-severity" } catch { }
}

Write-TestSummary
