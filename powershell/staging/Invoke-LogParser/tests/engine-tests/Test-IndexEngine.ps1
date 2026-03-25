# Test-IndexEngine.ps1 — Tests for query field resolution and indexing

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"

$Config = @{ ScriptRoot = $appRoot }
$Script:State = @{}
. "$appRoot\lib\QueryLanguage.ps1"
Initialize-QueryFieldMappings

Invoke-Test "IndexEngine: Virtual field mappings are initialized" {
    Assert-NotNull $Script:QueryFieldMappings "Field mappings should be initialized"
    Assert-GreaterThan $Script:QueryFieldMappings.Count 0 "Should have at least one virtual field"
}

Invoke-Test "IndexEngine: User virtual field resolves across providers" {
    $mapping = $Script:QueryFieldMappings['user']
    Assert-NotNull $mapping "User virtual field should exist"
    Assert-GreaterThan $mapping.ExtraFields.Count 0 "User should map to multiple Extra fields"
}

Invoke-Test "IndexEngine: Resolve-FieldValue finds entry-level fields" {
    $entry = New-TestEvent -Source "FG-01" -Level "ERROR"
    $value = Resolve-FieldValue -FieldName "source" -Entry $entry
    Assert-Equal "FG-01" $value "Should resolve Source entry field"
}

Invoke-Test "IndexEngine: Resolve-FieldValue finds Extra fields" {
    $entry = New-TestEvent -Extra @{ srcip = "10.0.0.5" }
    $value = Resolve-FieldValue -FieldName "srcip" -Entry $entry
    Assert-Equal "10.0.0.5" $value "Should resolve srcip from Extra"
}

Invoke-Test "IndexEngine: Resolve-FieldValue uses virtual field mappings" {
    # The 'user' virtual field should find 'User-Name' in Extra
    $entry = New-TestEvent -Extra @{ 'User-Name' = "jsmith" }
    $value = Resolve-FieldValue -FieldName "user" -Entry $entry
    Assert-Equal "jsmith" $value "Should resolve 'user' via virtual mapping"
}

Invoke-Test "IndexEngine: Resolve-FieldValue returns null for unknown fields" {
    $entry = New-TestEvent -Extra @{}
    $value = Resolve-FieldValue -FieldName "nonexistent_field_xyz" -Entry $entry
    Assert-Null $value "Unknown field should return null"
}

Invoke-Test "IndexEngine: Severity aliases are initialized" {
    Assert-NotNull $Script:SeverityAliases "Severity aliases should be initialized"
    Assert-True ($Script:SeverityAliases.ContainsKey('high')) "Should have 'high' alias"
    Assert-True ($Script:SeverityAliases.ContainsKey('critical')) "Should have 'critical' alias"
}

Invoke-Test "IndexEngine: Get-FieldValueFromEntry resolves direct properties" {
    $entry = New-TestEvent -Level "WARNING" -Source "NPS-01" -Host2 "DC-01"
    Assert-Equal "WARNING" (Get-FieldValueFromEntry -FieldName "level" -Entry $entry)
    Assert-Equal "NPS-01" (Get-FieldValueFromEntry -FieldName "source" -Entry $entry)
    Assert-Equal "DC-01" (Get-FieldValueFromEntry -FieldName "host" -Entry $entry)
}

Invoke-Test "IndexEngine: ConvertTo-TimelineBucket produces consistent keys" {
    $time1 = [datetime]::Parse("2025-01-15 10:00:00")
    $time2 = [datetime]::Parse("2025-01-15 10:30:00")
    $bucket1 = ConvertTo-TimelineBucket -Time $time1 -Interval "1h"
    $bucket2 = ConvertTo-TimelineBucket -Time $time2 -Interval "1h"
    Assert-Equal $bucket1 $bucket2 "Same hour should be same bucket"
}

Write-TestSummary
