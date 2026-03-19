# Test-CorrelationEngine.ps1 — Tests for the Cross-Source Correlation Engine

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"

$Config = @{ ScriptRoot = $appRoot }
. "$appRoot\analysis\CorrelationEngine.ps1"

# Build a synthetic multi-source dataset with known correlation patterns
function New-CorrelationTestDataset {
    $entries = [System.Collections.Generic.List[object]]::new()
    $baseTime = (Get-Date).AddHours(-1)

    # User "jsmith" appears in both FortiGate and EVTX within a 10-minute window
    $entries.Add((New-TestEvent -Index 0 -Timestamp $baseTime -Level "WARNING" -Source "FG-01" `
        -Message "deny user=jsmith" -Extra @{ SourceFormat = "fortigate-traffic"; user = "jsmith"; srcip = "10.0.0.5" }))
    $entries.Add((New-TestEvent -Index 1 -Timestamp $baseTime.AddMinutes(5) -Level "ERROR" -Source "DC-01" `
        -Message "Login failed for jsmith" -Extra @{ SourceFormat = "evtx"; TargetUserName = "jsmith"; EventID = 4625 }))

    # IP 192.168.1.50 appears across FortiGate and NPS
    $entries.Add((New-TestEvent -Index 2 -Timestamp $baseTime.AddMinutes(2) -Level "INFO" -Source "FG-01" `
        -Message "accept srcip=192.168.1.50" -Extra @{ SourceFormat = "fortigate-traffic"; srcip = "192.168.1.50" }))
    $entries.Add((New-TestEvent -Index 3 -Timestamp $baseTime.AddMinutes(8) -Level "INFO" -Source "NPS-01" `
        -Message "Access-Accept" -Extra @{ SourceFormat = "nps-radius"; 'Calling-Station-Id' = "192.168.1.50" }))

    # Uncorrelated entry (different source, no matching fields)
    $entries.Add((New-TestEvent -Index 4 -Timestamp $baseTime.AddMinutes(30) -Level "INFO" -Source "Zabbix" `
        -Message "Trigger resolved" -Extra @{ SourceFormat = "zabbix-export" }))

    return $entries
}

Invoke-Test "CorrelationEngine: Returns results for correlated dataset" {
    $entries = New-CorrelationTestDataset
    $results = Invoke-CrossSourceCorrelation -Entries $entries
    Assert-NotNull $results "Results should not be null"
}

Invoke-Test "CorrelationEngine: Finds username correlation across sources" {
    $entries = New-CorrelationTestDataset
    $results = Invoke-CrossSourceCorrelation -Entries $entries
    $usernameCorrelation = $results | Where-Object { $_.CorrelationKey -eq 'username' -and $_.KeyValue -eq 'jsmith' }
    Assert-GreaterThan @($usernameCorrelation).Count 0 "Should find username correlation for jsmith"
}

Invoke-Test "CorrelationEngine: Finds IP correlation across sources" {
    $entries = New-CorrelationTestDataset
    $results = Invoke-CrossSourceCorrelation -Entries $entries
    $ipCorrelation = $results | Where-Object { $_.CorrelationKey -eq 'ip' -and $_.KeyValue -eq '192.168.1.50' }
    Assert-GreaterThan @($ipCorrelation).Count 0 "Should find IP correlation for 192.168.1.50"
}

Invoke-Test "CorrelationEngine: Returns empty for uncorrelated data" {
    $entries = [System.Collections.Generic.List[object]]::new()
    $entries.Add((New-TestEvent -Index 0 -Level "INFO" -Extra @{ SourceFormat = "zabbix-export" }))
    $entries.Add((New-TestEvent -Index 1 -Level "INFO" -Extra @{ SourceFormat = "zabbix-export" }))
    $results = Invoke-CrossSourceCorrelation -Entries $entries
    Assert-Equal 0 @($results).Count "Single-source data should yield no correlations"
}

Invoke-Test "CorrelationEngine: Results include severity and event count" {
    $entries = New-CorrelationTestDataset
    $results = Invoke-CrossSourceCorrelation -Entries $entries
    if (@($results).Count -gt 0) {
        $first = $results[0]
        Assert-NotNull $first.Severity "Result should have Severity"
        Assert-GreaterThan $first.EventCount 0 "Result should have positive EventCount"
    }
}

Invoke-Test "CorrelationEngine: Results are sorted by severity" {
    $entries = New-CorrelationTestDataset
    $results = Invoke-CrossSourceCorrelation -Entries $entries
    if (@($results).Count -ge 2) {
        $severityOrder = @{ 'CRITICAL' = 0; 'HIGH' = 1; 'MEDIUM' = 2; 'LOW' = 3 }
        $prev = $severityOrder[$results[0].Severity]
        $curr = $severityOrder[$results[1].Severity]
        Assert-True ($prev -le $curr) "Results should be sorted by severity"
    }
}

Write-TestSummary
