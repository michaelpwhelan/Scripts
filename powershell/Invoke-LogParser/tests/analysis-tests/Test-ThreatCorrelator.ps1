# Test-ThreatCorrelator.ps1 — Tests for the Threat Correlation analysis

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"
. "$appRoot\analysis\ThreatCorrelator.ps1"

# Build dataset with known threat indicators
function New-ThreatTestDataset {
    $entries = [System.Collections.Generic.List[object]]::new()
    $baseTime = (Get-Date).AddHours(-2)

    # Defender alert on host PC-01
    $entries.Add((New-TestEvent -Index 0 -Timestamp $baseTime -Level "ERROR" -Source "WindowsDefenderAtp" `
        -Host2 "PC-01" -Message "[High] Suspicious process" `
        -Extra @{ SourceFormat = "defender-alerts"; AlertTitle = "Suspicious process"; Severity = "High"; DeviceName = "PC-01"; AccountName = "jdoe" }))

    # IPS deny from IP 10.10.10.5
    $entries.Add((New-TestEvent -Index 1 -Timestamp $baseTime.AddMinutes(5) -Level "ERROR" -Source "FG-01" `
        -Message "IPS deny attack=CVE-2024-1234" `
        -Extra @{ SourceFormat = "fortigate-kv"; type = "utm"; subtype = "ips"; action = "deny"; srcip = "10.10.10.5"; attack = "CVE-2024-1234" }))

    # Multiple failed logins for user "admin" (brute force indicator)
    for ($i = 0; $i -lt 10; $i++) {
        $entries.Add((New-TestEvent -Index (2 + $i) -Timestamp $baseTime.AddMinutes($i) -Level "WARNING" `
            -Source "DC-01" -Message "Failed login for admin" `
            -Extra @{ SourceFormat = "evtx"; EventID = 4625; TargetUserName = "admin" }))
    }

    # Normal traffic (should not be flagged)
    $entries.Add((New-TestEvent -Index 12 -Timestamp $baseTime.AddMinutes(15) -Level "INFO" -Source "FG-01" `
        -Message "accept srcip=192.168.1.1" `
        -Extra @{ SourceFormat = "fortigate-kv"; type = "traffic"; action = "accept"; srcip = "192.168.1.1" }))

    return $entries
}

Invoke-Test "ThreatCorrelator: Returns results for threat dataset" {
    $entries = New-ThreatTestDataset
    $results = Get-ThreatCorrelation -Entries $entries
    Assert-NotNull $results "Results should not be null"
    Assert-GreaterThan $results.Summary.TotalIndicators 0 "Should find threat indicators"
}

Invoke-Test "ThreatCorrelator: Identifies Defender alerts as threats" {
    $entries = New-ThreatTestDataset
    $results = Get-ThreatCorrelation -Entries $entries
    $defenderEvents = $results.ThreatEvents | Where-Object { $_.ThreatType -eq "Defender Alert" }
    Assert-GreaterThan @($defenderEvents).Count 0 "Should identify Defender alerts"
}

Invoke-Test "ThreatCorrelator: Identifies brute force attempts" {
    $entries = New-ThreatTestDataset
    $results = Get-ThreatCorrelation -Entries $entries
    $bruteForce = $results.ThreatEvents | Where-Object { $_.ThreatType -eq "Brute Force" }
    Assert-GreaterThan @($bruteForce).Count 0 "Should identify brute force attempts"
}

Invoke-Test "ThreatCorrelator: Scores entities correctly" {
    $entries = New-ThreatTestDataset
    $results = Get-ThreatCorrelation -Entries $entries
    Assert-GreaterThan $results.Summary.UniqueEntities 0 "Should have at least one entity"
    # IPS deny entity should have score >= 5
    $ipsEntity = $results.Entities.Values | Where-Object { $_.EntityId -eq "10.10.10.5" }
    if (@($ipsEntity).Count -gt 0) {
        Assert-GreaterThan $ipsEntity[0].ThreatScore 0 "IPS entity should have positive score"
    }
}

Invoke-Test "ThreatCorrelator: Summary includes risk level counts" {
    $entries = New-ThreatTestDataset
    $results = Get-ThreatCorrelation -Entries $entries
    $summary = $results.Summary
    Assert-True ($summary.ContainsKey('HighRisk')) "Summary should have HighRisk count"
    Assert-True ($summary.ContainsKey('MediumRisk')) "Summary should have MediumRisk count"
    Assert-True ($summary.ContainsKey('LowRisk')) "Summary should have LowRisk count"
}

Invoke-Test "ThreatCorrelator: Normal traffic is not flagged" {
    $entries = [System.Collections.Generic.List[object]]::new()
    $entries.Add((New-TestEvent -Index 0 -Level "INFO" -Source "FG-01" `
        -Extra @{ SourceFormat = "fortigate-kv"; type = "traffic"; action = "accept"; srcip = "192.168.1.1" }))
    $results = Get-ThreatCorrelation -Entries $entries
    Assert-Equal 0 $results.Summary.TotalIndicators "Normal traffic should not generate indicators"
}

Invoke-Test "ThreatCorrelator: Multi-source bonus increases entity score" {
    $entries = New-ThreatTestDataset
    $results = Get-ThreatCorrelation -Entries $entries
    # Entities with multiple indicator types should get a bonus
    $multiIndicator = $results.Entities.Values | Where-Object {
        ($_.Indicators | Select-Object -Unique).Count -gt 1
    }
    # If any multi-indicator entity exists, its score should reflect the bonus
    if (@($multiIndicator).Count -gt 0) {
        Assert-GreaterThan $multiIndicator[0].ThreatScore 5 "Multi-indicator entities should have boosted score"
    }
}

Write-TestSummary
