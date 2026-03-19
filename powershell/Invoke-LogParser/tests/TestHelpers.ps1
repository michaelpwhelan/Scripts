# ═══════════════════════════════════════════════════════════════════════════════
# TEST HELPERS — Shared test utilities and assertion functions
# ═══════════════════════════════════════════════════════════════════════════════

$Script:TestResults = @{ Passed = 0; Failed = 0; Skipped = 0; Errors = @() }

function Assert-Equal {
    param($Expected, $Actual, [string]$Message = "")
    if ($Expected -ne $Actual) {
        $msg = "ASSERT FAILED: Expected '$Expected' but got '$Actual'"
        if ($Message) { $msg += " — $Message" }
        throw $msg
    }
}

function Assert-NotNull {
    param($Value, [string]$Message = "")
    if ($null -eq $Value) {
        throw "ASSERT FAILED: Value is null$(if ($Message) { " — $Message" })"
    }
}

function Assert-Null {
    param($Value, [string]$Message = "")
    if ($null -ne $Value) {
        throw "ASSERT FAILED: Expected null but got '$Value'$(if ($Message) { " — $Message" })"
    }
}

function Assert-Contains {
    param([string]$Haystack, [string]$Needle, [string]$Message = "")
    if (-not $Haystack.Contains($Needle)) {
        throw "ASSERT FAILED: '$Haystack' does not contain '$Needle'$(if ($Message) { " — $Message" })"
    }
}

function Assert-GreaterThan {
    param($Value, $Threshold, [string]$Message = "")
    if ($Value -le $Threshold) {
        throw "ASSERT FAILED: $Value is not greater than $Threshold$(if ($Message) { " — $Message" })"
    }
}

function Assert-LessThan {
    param($Value, $Threshold, [string]$Message = "")
    if ($Value -ge $Threshold) {
        throw "ASSERT FAILED: $Value is not less than $Threshold$(if ($Message) { " — $Message" })"
    }
}

function Assert-Match {
    param([string]$Value, [string]$Pattern, [string]$Message = "")
    if ($Value -notmatch $Pattern) {
        throw "ASSERT FAILED: '$Value' does not match pattern '$Pattern'$(if ($Message) { " — $Message" })"
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Message = "")
    if (-not $Condition) {
        throw "ASSERT FAILED: Condition is false$(if ($Message) { " — $Message" })"
    }
}

function Assert-False {
    param([bool]$Condition, [string]$Message = "")
    if ($Condition) {
        throw "ASSERT FAILED: Condition is true$(if ($Message) { " — $Message" })"
    }
}

function Assert-Throws {
    param([scriptblock]$ScriptBlock, [string]$Message = "")
    $threw = $false
    try { & $ScriptBlock } catch { $threw = $true }
    if (-not $threw) {
        throw "ASSERT FAILED: Expected exception was not thrown$(if ($Message) { " — $Message" })"
    }
}

function Assert-Count {
    param($Collection, [int]$ExpectedCount, [string]$Message = "")
    $actual = @($Collection).Count
    if ($actual -ne $ExpectedCount) {
        throw "ASSERT FAILED: Expected count $ExpectedCount but got $actual$(if ($Message) { " — $Message" })"
    }
}

function New-TestEvent {
    param(
        [int]$Index = 0,
        [datetime]$Timestamp = (Get-Date),
        [string]$Level = "INFO",
        [string]$Source = "TestSource",
        [string]$Host2 = "TestHost",
        [string]$Message = "Test message",
        [string]$RawLine = "",
        [hashtable]$Extra = @{}
    )
    if (-not $RawLine) { $RawLine = $Message }
    return [PSCustomObject]@{
        Index = $Index; Timestamp = $Timestamp; Level = $Level
        Source = $Source; Host = $Host2; Message = $Message
        RawLine = $RawLine; Extra = $Extra; Bookmarked = $false
    }
}

function New-TestDataset {
    param([int]$Count = 100, [string]$Source = "TestSource")
    $entries = [System.Collections.Generic.List[object]]::new()
    $levels = @("CRITICAL", "ERROR", "WARNING", "INFO", "INFO", "INFO", "DEBUG")
    $baseTime = (Get-Date).AddHours(-24)
    for ($i = 0; $i -lt $Count; $i++) {
        $ts = $baseTime.AddMinutes($i * (1440 / $Count))
        $level = $levels[$i % $levels.Count]
        $entries.Add((New-TestEvent -Index $i -Timestamp $ts -Level $level -Source $Source -Message "Event $i" -Extra @{ EventNum = $i }))
    }
    return $entries
}

function Get-SampleFile {
    param([string]$FileName)
    $samplesDir = Join-Path $PSScriptRoot "samples"
    return Join-Path $samplesDir $FileName
}

function Invoke-Test {
    param([string]$Name, [scriptblock]$Test)
    try {
        & $Test
        $Script:TestResults.Passed++
        Write-Host "  PASS: $Name" -ForegroundColor Green
    } catch {
        $Script:TestResults.Failed++
        $Script:TestResults.Errors += @{ Name = $Name; Error = $_.ToString() }
        Write-Host "  FAIL: $Name — $_" -ForegroundColor Red
    }
}

function Write-TestSummary {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    $total = $Script:TestResults.Passed + $Script:TestResults.Failed + $Script:TestResults.Skipped
    Write-Host "Tests: $total total, $($Script:TestResults.Passed) passed, $($Script:TestResults.Failed) failed, $($Script:TestResults.Skipped) skipped" -ForegroundColor $(if ($Script:TestResults.Failed -gt 0) { "Red" } else { "Green" })
    if ($Script:TestResults.Errors.Count -gt 0) {
        Write-Host ""
        Write-Host "Failures:" -ForegroundColor Red
        foreach ($err in $Script:TestResults.Errors) {
            Write-Host "  $($err.Name): $($err.Error)" -ForegroundColor Yellow
        }
    }
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    return $Script:TestResults.Failed
}
