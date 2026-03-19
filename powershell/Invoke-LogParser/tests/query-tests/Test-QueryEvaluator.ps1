# Test-QueryEvaluator.ps1 — Tests for the Query Evaluator (Test-QueryMatch)

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"

$Config = @{ ScriptRoot = $appRoot }
$Script:State = @{}
. "$appRoot\lib\QueryLanguage.ps1"
Initialize-QueryFieldMappings

# Helper: parse query and return filter node
function Get-FilterNode {
    param([string]$Query)
    $tokens = Invoke-QueryLex $Query
    $ast = Build-QueryAst $tokens
    return $ast.FilterNode
}

Invoke-Test "QueryEvaluator: Bare word matches message content" {
    $node = Get-FilterNode "timeout"
    $entry = New-TestEvent -Message "Connection timeout occurred"
    $result = Test-QueryMatch -Node $node -Entry $entry
    Assert-True $result "Should match 'timeout' in message"
}

Invoke-Test "QueryEvaluator: Bare word does not match unrelated message" {
    $node = Get-FilterNode "timeout"
    $entry = New-TestEvent -Message "Login successful"
    $result = Test-QueryMatch -Node $node -Entry $entry
    Assert-False $result "Should not match 'timeout' in unrelated message"
}

Invoke-Test "QueryEvaluator: Field:value matches Extra field" {
    $node = Get-FilterNode "srcip:10.0.0.1"
    $entry = New-TestEvent -Extra @{ srcip = "10.0.0.1" }
    $result = Test-QueryMatch -Node $node -Entry $entry
    Assert-True $result "Should match srcip field"
}

Invoke-Test "QueryEvaluator: Field:value does not match wrong value" {
    $node = Get-FilterNode "srcip:10.0.0.2"
    $entry = New-TestEvent -Extra @{ srcip = "10.0.0.1" }
    $result = Test-QueryMatch -Node $node -Entry $entry
    Assert-False $result "Should not match wrong srcip"
}

Invoke-Test "QueryEvaluator: AND requires both sides to match" {
    $node = Get-FilterNode "error AND timeout"
    $entry1 = New-TestEvent -Message "error timeout occurred"
    $entry2 = New-TestEvent -Message "error happened"
    Assert-True (Test-QueryMatch -Node $node -Entry $entry1) "Both terms present should match"
    Assert-False (Test-QueryMatch -Node $node -Entry $entry2) "Missing one term should not match"
}

Invoke-Test "QueryEvaluator: OR matches when either side matches" {
    $node = Get-FilterNode "error OR warning"
    $entry = New-TestEvent -Message "warning message"
    $result = Test-QueryMatch -Node $node -Entry $entry
    Assert-True $result "OR should match when one side matches"
}

Invoke-Test "QueryEvaluator: NOT inverts match" {
    $node = Get-FilterNode "NOT debug"
    $entry1 = New-TestEvent -Message "Info message"
    $entry2 = New-TestEvent -Message "debug trace"
    Assert-True (Test-QueryMatch -Node $node -Entry $entry1) "NOT debug should match non-debug"
    Assert-False (Test-QueryMatch -Node $node -Entry $entry2) "NOT debug should not match debug"
}

Invoke-Test "QueryEvaluator: Wildcard matching works" {
    $node = Get-FilterNode "source:FG-*"
    $entry = New-TestEvent -Source "FG-01"
    $result = Test-QueryMatch -Node $node -Entry $entry
    Assert-True $result "Wildcard should match FG-01"
}

Invoke-Test "QueryEvaluator: Severity alias matching works" {
    $node = Get-FilterNode "severity:high"
    $entryCrit = New-TestEvent -Level "CRITICAL"
    $entryErr = New-TestEvent -Level "ERROR"
    $entryInfo = New-TestEvent -Level "INFO"
    Assert-True (Test-QueryMatch -Node $node -Entry $entryCrit) "high should match CRITICAL"
    Assert-True (Test-QueryMatch -Node $node -Entry $entryErr) "high should match ERROR"
    Assert-False (Test-QueryMatch -Node $node -Entry $entryInfo) "high should not match INFO"
}

Invoke-Test "QueryEvaluator: Null node matches everything" {
    $entry = New-TestEvent -Message "any message"
    $result = Test-QueryMatch -Node $null -Entry $entry
    Assert-True $result "Null node should match all entries"
}

Invoke-Test "QueryEvaluator: Comparison operators work for numeric fields" {
    $node = Get-FilterNode "dstport:>1024"
    $entry = New-TestEvent -Extra @{ dstport = "8080" }
    $result = Test-QueryMatch -Node $node -Entry $entry
    Assert-True $result "dstport > 1024 should match 8080"
}

Write-TestSummary
