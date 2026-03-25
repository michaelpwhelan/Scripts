# Test-QueryLexer.ps1 — Tests for the Query Language Lexer (Invoke-QueryLex)

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"

$Config = @{ ScriptRoot = $appRoot }
$Script:State = @{}
. "$appRoot\lib\QueryLanguage.ps1"
Initialize-QueryFieldMappings

Invoke-Test "QueryLexer: Tokenizes bare word" {
    $tokens = Invoke-QueryLex "error"
    Assert-NotNull $tokens
    Assert-Equal 1 $tokens.Count
    Assert-Equal "BARE_WORD" $tokens[0].Type
    Assert-Equal "error" $tokens[0].Value
}

Invoke-Test "QueryLexer: Tokenizes quoted string" {
    $tokens = Invoke-QueryLex '"failed login"'
    Assert-NotNull $tokens
    Assert-Equal 1 $tokens.Count
    Assert-Equal "QUOTED_STRING" $tokens[0].Type
    Assert-Equal "failed login" $tokens[0].Value
}

Invoke-Test "QueryLexer: Tokenizes field:value pair" {
    $tokens = Invoke-QueryLex "srcip:10.0.0.1"
    Assert-NotNull $tokens
    Assert-Equal 1 $tokens.Count
    Assert-Equal "FIELD_MATCH" $tokens[0].Type
    Assert-Equal "srcip" $tokens[0].Field
    Assert-Equal "10.0.0.1" $tokens[0].Value
}

Invoke-Test "QueryLexer: Tokenizes AND operator" {
    $tokens = Invoke-QueryLex "error AND timeout"
    Assert-Equal 3 $tokens.Count
    Assert-Equal "AND" $tokens[1].Type
}

Invoke-Test "QueryLexer: Tokenizes OR operator" {
    $tokens = Invoke-QueryLex "error OR warning"
    Assert-Equal 3 $tokens.Count
    Assert-Equal "OR" $tokens[1].Type
}

Invoke-Test "QueryLexer: Tokenizes NOT operator" {
    $tokens = Invoke-QueryLex "NOT debug"
    Assert-Equal 2 $tokens.Count
    Assert-Equal "NOT" $tokens[0].Type
}

Invoke-Test "QueryLexer: Tokenizes pipe operator" {
    $tokens = Invoke-QueryLex "error | count by source"
    $pipes = $tokens | Where-Object { $_.Type -eq 'PIPE' }
    Assert-Equal 1 @($pipes).Count "Should have one PIPE token"
}

Invoke-Test "QueryLexer: Tokenizes comparison operators in field match" {
    $tokens = Invoke-QueryLex "dstport:>1024"
    Assert-Equal 1 $tokens.Count
    Assert-Equal "FIELD_MATCH" $tokens[0].Type
    Assert-Equal "gt" $tokens[0].Operator
}

Invoke-Test "QueryLexer: Tokenizes wildcard in field match" {
    $tokens = Invoke-QueryLex "source:FG-*"
    Assert-Equal 1 $tokens.Count
    Assert-Equal "wildcard" $tokens[0].Operator
}

Invoke-Test "QueryLexer: Tokenizes parentheses" {
    $tokens = Invoke-QueryLex "(error OR warning) AND srcip:10.0.0.1"
    $lparens = $tokens | Where-Object { $_.Type -eq 'LPAREN' }
    $rparens = $tokens | Where-Object { $_.Type -eq 'RPAREN' }
    Assert-Equal 1 @($lparens).Count
    Assert-Equal 1 @($rparens).Count
}

Invoke-Test "QueryLexer: Handles empty query" {
    $tokens = Invoke-QueryLex ""
    Assert-NotNull $tokens
    Assert-Equal 0 $tokens.Count
}

Invoke-Test "QueryLexer: Recognizes pipeline keywords" {
    $tokens = Invoke-QueryLex "error | count by level | top 10"
    $keywords = $tokens | Where-Object { $_.Type -eq 'KEYWORD' }
    Assert-GreaterThan @($keywords).Count 0 "Should have pipeline keywords"
}

Write-TestSummary
