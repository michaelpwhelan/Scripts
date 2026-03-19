# Test-BaselineEngine.ps1 — Tests for the Baseline Engine

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"

$Config = @{ ScriptRoot = $appRoot }
. "$appRoot\lib\BaselineEngine.ps1"

Invoke-Test "BaselineEngine: Get-BaselinePath returns valid directory" {
    $path = Get-BaselinePath
    Assert-NotNull $path "Baseline path should not be null"
    Assert-True (Test-Path $path) "Baseline directory should exist after call"
}

Invoke-Test "BaselineEngine: Build-Baseline creates profile from entries" {
    $entries = New-TestDataset -Count 100
    $profile = Build-Baseline -Entries $entries -Name "test-unit-baseline"
    Assert-NotNull $profile "Profile should not be null"
    Assert-Equal "test-unit-baseline" $profile.Name
    Assert-Equal 100 $profile.EntryCount
}

Invoke-Test "BaselineEngine: Save and Load round-trip works" {
    $entries = New-TestDataset -Count 50
    $profile = Build-Baseline -Entries $entries -Name "test-roundtrip"
    Save-BaselineProfile -Profile $profile -Name "test-roundtrip"
    $loaded = Load-BaselineProfile -Name "test-roundtrip"
    Assert-NotNull $loaded "Loaded profile should not be null"
    Assert-Equal "test-roundtrip" $loaded.Name
    Assert-Equal 50 $loaded.EntryCount
}

Invoke-Test "BaselineEngine: Load-BaselineProfile returns null for missing profile" {
    $result = Load-BaselineProfile -Name "nonexistent-profile-xyz"
    Assert-Null $result "Missing profile should return null"
}

Invoke-Test "BaselineEngine: Get-BaselineList returns available baselines" {
    # Ensure at least one baseline exists from previous test
    $entries = New-TestDataset -Count 20
    $profile = Build-Baseline -Entries $entries -Name "test-list-check"
    Save-BaselineProfile -Profile $profile -Name "test-list-check"
    $list = Get-BaselineList
    Assert-GreaterThan @($list).Count 0 "Should list at least one baseline"
}

Invoke-Test "BaselineEngine: Compare-Baseline returns anomaly list" {
    $entries = New-TestDataset -Count 100
    $profile = Build-Baseline -Entries $entries -Name "test-compare"
    Save-BaselineProfile -Profile $profile -Name "test-compare"
    $anomalies = Compare-Baseline -Entries $entries -BaselineName "test-compare"
    Assert-NotNull $anomalies "Anomaly list should not be null"
    # Same data should have few/no anomalies
}

Invoke-Test "BaselineEngine: Get-ZScore handles normal values" {
    $z = Get-ZScore -Value 50 -Mean 50 -StdDev 10
    Assert-Equal 0 $z "Z-score at mean should be 0"
}

Invoke-Test "BaselineEngine: Remove-Baseline deletes profile" {
    $entries = New-TestDataset -Count 10
    $profile = Build-Baseline -Entries $entries -Name "test-remove"
    Save-BaselineProfile -Profile $profile -Name "test-remove"
    Remove-Baseline -Name "test-remove"
    $loaded = Load-BaselineProfile -Name "test-remove"
    Assert-Null $loaded "Removed profile should not be loadable"
}

# Cleanup test baselines
$cleanupNames = @("test-unit-baseline", "test-roundtrip", "test-list-check", "test-compare")
foreach ($name in $cleanupNames) {
    try { Remove-Baseline -Name $name } catch { }
}

Write-TestSummary
