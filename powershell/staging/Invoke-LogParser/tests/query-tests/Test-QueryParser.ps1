# Test-QueryParser.ps1 — Tests for the Query Language Parser (Build-QueryAst)

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"

$Config = @{ ScriptRoot = $appRoot }
$Script:State = @{}
. "$appRoot\lib\QueryLanguage.ps1"
Initialize-QueryFieldMappings

Invoke-Test "QueryParser: Builds AST from bare word" {
    $tokens = Invoke-QueryLex "error"
    $ast = Build-QueryAst $tokens
    Assert-NotNull $ast "AST should not be null"
    Assert-NotNull $ast.FilterNode "FilterNode should exist"
}

Invoke-Test "QueryParser: Builds AST for AND expression" {
    $tokens = Invoke-QueryLex "error AND timeout"
    $ast = Build-QueryAst $tokens
    Assert-NotNull $ast.FilterNode
    Assert-Equal "AND" $ast.FilterNode.Type "Root node should be AND"
    Assert-NotNull $ast.FilterNode.Left "Left child should exist"
    Assert-NotNull $ast.FilterNode.Right "Right child should exist"
}

Invoke-Test "QueryParser: Builds AST for OR expression" {
    $tokens = Invoke-QueryLex "error OR warning"
    $ast = Build-QueryAst $tokens
    Assert-NotNull $ast.FilterNode
    Assert-Equal "OR" $ast.FilterNode.Type "Root node should be OR"
}

Invoke-Test "QueryParser: Builds AST for NOT expression" {
    $tokens = Invoke-QueryLex "NOT debug"
    $ast = Build-QueryAst $tokens
    Assert-NotNull $ast.FilterNode
    Assert-Equal "NOT" $ast.FilterNode.Type "Root node should be NOT"
    Assert-NotNull $ast.FilterNode.Child "Child should exist"
}

Invoke-Test "QueryParser: Builds AST for field:value match" {
    $tokens = Invoke-QueryLex "srcip:10.0.0.1"
    $ast = Build-QueryAst $tokens
    Assert-NotNull $ast.FilterNode
    Assert-Equal "MATCH" $ast.FilterNode.Type "Node should be MATCH"
    Assert-Equal "srcip" $ast.FilterNode.Field
    Assert-Equal "10.0.0.1" $ast.FilterNode.Value
}

Invoke-Test "QueryParser: Handles grouped expressions with parentheses" {
    $tokens = Invoke-QueryLex "(error OR warning) AND source:FG-01"
    $ast = Build-QueryAst $tokens
    Assert-NotNull $ast.FilterNode
    Assert-Equal "AND" $ast.FilterNode.Type "Root should be AND"
}

Invoke-Test "QueryParser: Separates filter from pipeline stages" {
    $tokens = Invoke-QueryLex "error | count by level"
    $ast = Build-QueryAst $tokens
    Assert-NotNull $ast.FilterNode "Should have filter expression"
    Assert-NotNull $ast.PipelineStages "Should have pipeline stages"
    Assert-GreaterThan @($ast.PipelineStages).Count 0 "Should have at least one pipeline stage"
}

Invoke-Test "QueryParser: Handles empty filter with pipeline only" {
    $tokens = Invoke-QueryLex "| count by source"
    $ast = Build-QueryAst $tokens
    # Filter may be null for pipeline-only queries
    Assert-NotNull $ast.PipelineStages "Should have pipeline stages"
}

Invoke-Test "QueryParser: Builds AST for complex nested query" {
    $tokens = Invoke-QueryLex "(srcip:10.0.0.1 OR srcip:10.0.0.2) AND NOT level:debug"
    $ast = Build-QueryAst $tokens
    Assert-NotNull $ast.FilterNode "Should handle complex nested queries"
}

Write-TestSummary
