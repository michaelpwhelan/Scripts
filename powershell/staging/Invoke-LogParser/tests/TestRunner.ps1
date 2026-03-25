# Test Runner — Discovers and executes test files
param(
    [ValidateSet("all", "parsers", "analysis", "queries", "engines", "integration")]
    [string]$Category = "all",
    [string]$Filter = ""  # run only tests matching this pattern
)

$ErrorActionPreference = "Continue"
$testRoot = $PSScriptRoot

# Load the application
$appRoot = Split-Path $testRoot -Parent
. "$appRoot\lib\Helpers.ps1"

# Load test helpers
. "$testRoot\TestHelpers.ps1"

Write-Host "Universal Log Parser — Test Runner" -ForegroundColor Cyan
Write-Host "Category: $Category" -ForegroundColor Gray
Write-Host ""

$testDirs = @{
    parsers     = "parser-tests"
    analysis    = "analysis-tests"
    queries     = "query-tests"
    engines     = "engine-tests"
    integration = "integration-tests"
}

$dirsToRun = if ($Category -eq "all") { $testDirs.Values } else { @($testDirs[$Category]) }

$totalFailed = 0
foreach ($dir in $dirsToRun) {
    $dirPath = Join-Path $testRoot $dir
    if (-not (Test-Path $dirPath)) { continue }
    $testFiles = Get-ChildItem "$dirPath\Test-*.ps1" -ErrorAction SilentlyContinue
    if ($Filter) { $testFiles = $testFiles | Where-Object { $_.Name -match $Filter } }
    foreach ($tf in $testFiles) {
        Write-Host ""
        Write-Host "Running: $($tf.Name)" -ForegroundColor Cyan
        $Script:TestResults = @{ Passed = 0; Failed = 0; Skipped = 0; Errors = @() }
        try {
            . $tf.FullName
        } catch {
            Write-Host "  ERROR: Test file crashed: $_" -ForegroundColor Red
            $Script:TestResults.Failed++
        }
        $totalFailed += $Script:TestResults.Failed
    }
}

Write-Host ""
Write-Host "Overall: $(if ($totalFailed -eq 0) { 'ALL TESTS PASSED' } else { "$totalFailed FAILURES" })" -ForegroundColor $(if ($totalFailed -eq 0) { "Green" } else { "Red" })
exit $totalFailed
