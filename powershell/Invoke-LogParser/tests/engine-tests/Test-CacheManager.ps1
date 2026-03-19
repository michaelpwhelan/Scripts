# Test-CacheManager.ps1 — Tests for caching, persistence, and state management

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"

$Config = @{ ScriptRoot = $appRoot }

Invoke-Test "CacheManager: ConvertTo-LogEntry produces valid structure" {
    $entry = ConvertTo-LogEntry @{
        Index = 0; Timestamp = (Get-Date); Level = "INFO"; Source = "Test"
        Host = "PC-01"; Message = "Hello"; RawLine = "raw"; Extra = @{ key = "val" }
    }
    Assert-Equal 0 $entry.Index
    Assert-Equal "INFO" $entry.Level
    Assert-Equal "Test" $entry.Source
    Assert-Equal "PC-01" $entry.Host
    Assert-Equal "Hello" $entry.Message
    Assert-Equal "raw" $entry.RawLine
    Assert-Equal "val" $entry.Extra['key']
    Assert-False $entry.Bookmarked "Default bookmark should be false"
}

Invoke-Test "CacheManager: ConvertTo-LogEntry normalizes level to uppercase" {
    $entry = ConvertTo-LogEntry @{ Index = 0; Level = "warning"; Message = "test" }
    Assert-Equal "WARNING" $entry.Level
}

Invoke-Test "CacheManager: ConvertTo-LogEntry defaults missing fields" {
    $entry = ConvertTo-LogEntry @{ Index = 0; Message = "only message" }
    Assert-Equal "" $entry.Source "Missing Source should default to empty"
    Assert-Equal "" $entry.Host "Missing Host should default to empty"
    Assert-Equal "UNKNOWN" $entry.Level "Missing Level should default to UNKNOWN"
}

Invoke-Test "CacheManager: Get-LevelFromText detects ERROR" {
    $level = Get-LevelFromText "Something FAILED in the process"
    Assert-Equal "ERROR" $level
}

Invoke-Test "CacheManager: Get-LevelFromText detects WARNING" {
    $level = Get-LevelFromText "Warning: disk space low"
    Assert-Equal "WARNING" $level
}

Invoke-Test "CacheManager: Get-LevelFromText detects CRITICAL" {
    $level = Get-LevelFromText "EMERGENCY: system shutdown"
    Assert-Equal "CRITICAL" $level
}

Invoke-Test "CacheManager: Get-LevelFromText returns UNKNOWN for plain text" {
    $level = Get-LevelFromText "Just a normal log line"
    Assert-Equal "UNKNOWN" $level
}

Invoke-Test "CacheManager: Invoke-HtmlEncode escapes special characters" {
    $result = Invoke-HtmlEncode '<script>alert("xss")</script>'
    Assert-Contains $result "&lt;" "Should escape <"
    Assert-Contains $result "&gt;" "Should escape >"
    Assert-Contains $result "&quot;" "Should escape quotes"
}

Invoke-Test "CacheManager: Invoke-HtmlEncode handles null input" {
    $result = Invoke-HtmlEncode $null
    Assert-Equal "" $result "Null input should return empty string"
}

Invoke-Test "CacheManager: New-TestEvent creates valid event" {
    $event = New-TestEvent -Index 5 -Level "ERROR" -Message "Test error" -Extra @{ key = "value" }
    Assert-Equal 5 $event.Index
    Assert-Equal "ERROR" $event.Level
    Assert-Equal "Test error" $event.Message
    Assert-Equal "value" $event.Extra['key']
}

Invoke-Test "CacheManager: New-TestDataset creates correct count" {
    $dataset = New-TestDataset -Count 25
    Assert-Count $dataset 25 "Should create exactly 25 events"
}

Write-TestSummary
