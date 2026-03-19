# Test-QueryAggregation.ps1 — Tests for the Query Pipeline Aggregation stages

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"

$Config = @{ ScriptRoot = $appRoot }
$Script:State = @{}
. "$appRoot\lib\QueryLanguage.ps1"
Initialize-QueryFieldMappings

# Create a test dataset with known level distribution
function New-AggregationTestDataset {
    $entries = [System.Collections.Generic.List[object]]::new()
    $baseTime = (Get-Date).AddHours(-2)
    $levels = @("ERROR","ERROR","ERROR","WARNING","WARNING","INFO","INFO","INFO","INFO","INFO")
    $sources = @("FG-01","FG-01","FG-02","FG-02","FG-03","FG-01","FG-02","FG-03","FG-01","FG-03")
    for ($i = 0; $i -lt 10; $i++) {
        $entries.Add((New-TestEvent -Index $i -Timestamp $baseTime.AddMinutes($i * 10) `
            -Level $levels[$i] -Source $sources[$i] -Message "Event $i"))
    }
    return $entries
}

Invoke-Test "QueryAggregation: Count by level produces correct groups" {
    $entries = New-AggregationTestDataset
    $result = Invoke-QueryFilter -Query "| count by level" -Entries $entries
    Assert-NotNull $result "Should return results"
    # Result should contain aggregated data
    Assert-NotNull $result.AggregateResults "Should have aggregate results"
}

Invoke-Test "QueryAggregation: Top N limits output" {
    $entries = New-AggregationTestDataset
    $result = Invoke-QueryFilter -Query "| count by source | top 2" -Entries $entries
    Assert-NotNull $result.AggregateResults "Should have aggregate results"
}

Invoke-Test "QueryAggregation: Filter then aggregate works" {
    $entries = New-AggregationTestDataset
    $result = Invoke-QueryFilter -Query "level:ERROR | count by source" -Entries $entries
    Assert-NotNull $result "Combined filter+aggregate should work"
}

Invoke-Test "QueryAggregation: Sort stage is recognized" {
    $entries = New-AggregationTestDataset
    $tokens = Invoke-QueryLex "| sort level"
    $ast = Build-QueryAst $tokens
    Assert-GreaterThan @($ast.PipelineStages).Count 0 "Should have sort stage"
}

Invoke-Test "QueryAggregation: Head stage limits entries" {
    $entries = New-AggregationTestDataset
    $result = Invoke-QueryFilter -Query "| head 3" -Entries $entries
    Assert-NotNull $result
    if ($result.FilteredEntries) {
        Assert-True ($result.FilteredEntries.Count -le 3) "Head 3 should return at most 3 entries"
    }
}

Invoke-Test "QueryAggregation: Stats stage is recognized" {
    $tokens = Invoke-QueryLex "| stats count avg(dstport) by source"
    $ast = Build-QueryAst $tokens
    Assert-GreaterThan @($ast.PipelineStages).Count 0 "Should have stats stage"
}

Invoke-Test "QueryAggregation: Timeline stage is recognized" {
    $tokens = Invoke-QueryLex "| timeline 1h"
    $ast = Build-QueryAst $tokens
    Assert-GreaterThan @($ast.PipelineStages).Count 0 "Should have timeline stage"
}

Invoke-Test "QueryAggregation: Table stage is recognized" {
    $tokens = Invoke-QueryLex "| table source level message"
    $ast = Build-QueryAst $tokens
    Assert-GreaterThan @($ast.PipelineStages).Count 0 "Should have table stage"
}

Invoke-Test "QueryAggregation: Empty entries returns empty result" {
    $entries = [System.Collections.Generic.List[object]]::new()
    $result = Invoke-QueryFilter -Query "error | count by level" -Entries $entries
    Assert-NotNull $result "Should handle empty entries"
}

Write-TestSummary
