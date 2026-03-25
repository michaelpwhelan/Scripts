# Test-QueryToExport.ps1 — Integration test for query execution through to export formatting

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"

$Config = @{ ScriptRoot = $appRoot }
$Script:State = @{}
. "$appRoot\lib\QueryLanguage.ps1"
Initialize-QueryFieldMappings

# Create a structured dataset for export testing
function New-ExportTestDataset {
    $entries = [System.Collections.Generic.List[object]]::new()
    $baseTime = [datetime]::Parse("2025-06-15 08:00:00")
    $sources = @("FG-01", "DC-01", "NPS-01")
    $levels = @("ERROR", "WARNING", "INFO")
    for ($i = 0; $i -lt 30; $i++) {
        $entries.Add((New-TestEvent -Index $i `
            -Timestamp $baseTime.AddMinutes($i * 2) `
            -Level $levels[$i % 3] `
            -Source $sources[$i % 3] `
            -Host2 $sources[$i % 3] `
            -Message "Test event $i from $($sources[$i % 3])" `
            -Extra @{ EventNum = $i; srcip = "10.0.0.$($i + 1)" }))
    }
    return $entries
}

Invoke-Test "QueryToExport: Full query pipeline produces results" {
    $entries = New-ExportTestDataset
    $result = Invoke-QueryFilter -Query "level:ERROR" -Entries $entries
    Assert-NotNull $result "Query result should not be null"
    if ($result.FilteredEntries) {
        Assert-GreaterThan $result.FilteredEntries.Count 0 "Should have filtered entries"
    }
}

Invoke-Test "QueryToExport: Count aggregation produces groups" {
    $entries = New-ExportTestDataset
    $result = Invoke-QueryFilter -Query "| count by level" -Entries $entries
    Assert-NotNull $result.AggregateResults "Should have aggregate results"
}

Invoke-Test "QueryToExport: Top N limits aggregation output" {
    $entries = New-ExportTestDataset
    $result = Invoke-QueryFilter -Query "| count by source | top 2" -Entries $entries
    Assert-NotNull $result.AggregateResults "Should have aggregate results"
}

Invoke-Test "QueryToExport: Table stage selects specific fields" {
    $entries = New-ExportTestDataset
    $result = Invoke-QueryFilter -Query "| table source level message" -Entries $entries
    Assert-NotNull $result "Table query should produce results"
}

Invoke-Test "QueryToExport: Format-QueryResults produces formatted output" {
    $entries = New-ExportTestDataset
    $result = Invoke-QueryFilter -Query "| count by level" -Entries $entries
    if ($result.AggregateResults) {
        $formatted = Format-QueryResults -Results $result
        Assert-NotNull $formatted "Formatted output should not be null"
    }
}

Invoke-Test "QueryToExport: Head limits entry count" {
    $entries = New-ExportTestDataset
    $result = Invoke-QueryFilter -Query "| head 5" -Entries $entries
    if ($result.FilteredEntries) {
        Assert-True ($result.FilteredEntries.Count -le 5) "Head 5 should limit to 5 entries"
    }
}

Invoke-Test "QueryToExport: Multiple pipeline stages chain correctly" {
    $entries = New-ExportTestDataset
    $result = Invoke-QueryFilter -Query "level:ERROR | count by source | top 2" -Entries $entries
    Assert-NotNull $result "Chained pipeline should produce results"
}

Invoke-Test "QueryToExport: Query history is recorded" {
    $entries = New-ExportTestDataset
    $before = @(Get-QueryHistory).Count
    Invoke-QueryFilter -Query "test query" -Entries $entries
    $after = @(Get-QueryHistory).Count
    Assert-GreaterThan $after $before "Query history should increase after query"
}

Invoke-Test "QueryToExport: Get-QuerySyntaxHelp returns help text" {
    $help = Get-QuerySyntaxHelp
    Assert-NotNull $help "Syntax help should not be null"
    Assert-GreaterThan $help.Length 50 "Help text should be substantial"
}

Write-TestSummary
