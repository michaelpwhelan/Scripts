# Test-TriageWorkflow.ps1 — Integration test for the triage investigation workflow

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"

$Config = @{ ScriptRoot = $appRoot }
$Script:State = @{}
. "$appRoot\lib\QueryLanguage.ps1"
Initialize-QueryFieldMappings

. "$appRoot\analysis\ThreatCorrelator.ps1"

# Simulate a triage workflow: filter -> query -> threat correlation
function New-TriageDataset {
    $entries = [System.Collections.Generic.List[object]]::new()
    $baseTime = (Get-Date).AddHours(-4)

    # Normal traffic (background noise)
    for ($i = 0; $i -lt 20; $i++) {
        $entries.Add((New-TestEvent -Index $i -Timestamp $baseTime.AddMinutes($i * 5) `
            -Level "INFO" -Source "FG-01" -Host2 "FG-01" `
            -Message "accept srcip=192.168.1.$($i + 10) dstip=10.0.0.1" `
            -Extra @{ SourceFormat = "fortigate-kv"; type = "traffic"; action = "accept"; srcip = "192.168.1.$($i + 10)" }))
    }

    # Suspicious activity: UTM IPS deny events from a single IP
    for ($i = 0; $i -lt 5; $i++) {
        $entries.Add((New-TestEvent -Index (20 + $i) -Timestamp $baseTime.AddMinutes(60 + $i) `
            -Level "ERROR" -Source "FG-01" -Host2 "FG-01" `
            -Message "IPS deny attack=SQL.Injection srcip=10.99.99.99" `
            -Extra @{ SourceFormat = "fortigate-kv"; type = "utm"; subtype = "ips"; action = "deny"; srcip = "10.99.99.99"; attack = "SQL.Injection" }))
    }

    # Defender alert on a host
    $entries.Add((New-TestEvent -Index 25 -Timestamp $baseTime.AddMinutes(65) `
        -Level "ERROR" -Source "WindowsDefenderAtp" -Host2 "SRV-DB-01" `
        -Message "[High] Suspicious SQL activity on SRV-DB-01" `
        -Extra @{ SourceFormat = "defender-alerts"; AlertTitle = "Suspicious SQL activity"; Severity = "High"; DeviceName = "SRV-DB-01" }))

    return $entries
}

Invoke-Test "TriageWorkflow: Query filters narrow results correctly" {
    $entries = New-TriageDataset
    $result = Invoke-QueryFilter -Query "level:ERROR" -Entries $entries
    Assert-NotNull $result "Query should return results"
    if ($result.FilteredEntries) {
        Assert-GreaterThan $result.FilteredEntries.Count 0 "Should find ERROR entries"
        foreach ($e in $result.FilteredEntries) {
            Assert-Equal "ERROR" $e.Level "All filtered entries should be ERROR"
        }
    }
}

Invoke-Test "TriageWorkflow: Field query finds specific IPs" {
    $entries = New-TriageDataset
    $result = Invoke-QueryFilter -Query "srcip:10.99.99.99" -Entries $entries
    if ($result.FilteredEntries) {
        Assert-GreaterThan $result.FilteredEntries.Count 0 "Should find entries from attacker IP"
    }
}

Invoke-Test "TriageWorkflow: Threat correlation identifies attacker IP" {
    $entries = New-TriageDataset
    $threatResults = Get-ThreatCorrelation -Entries $entries
    Assert-GreaterThan $threatResults.Summary.TotalIndicators 0 "Should find threat indicators"
    $attackerEntity = $threatResults.Entities.Values | Where-Object { $_.EntityId -eq "10.99.99.99" }
    Assert-GreaterThan @($attackerEntity).Count 0 "Should identify attacker IP as entity"
}

Invoke-Test "TriageWorkflow: Aggregation summarizes by source" {
    $entries = New-TriageDataset
    $result = Invoke-QueryFilter -Query "| count by source" -Entries $entries
    Assert-NotNull $result.AggregateResults "Should produce aggregation results"
}

Invoke-Test "TriageWorkflow: Combined filter and aggregation works" {
    $entries = New-TriageDataset
    $result = Invoke-QueryFilter -Query "level:ERROR | count by source" -Entries $entries
    Assert-NotNull $result "Combined query should work"
}

Invoke-Test "TriageWorkflow: NOT query excludes entries" {
    $entries = New-TriageDataset
    $result = Invoke-QueryFilter -Query "NOT level:INFO" -Entries $entries
    if ($result.FilteredEntries) {
        foreach ($e in $result.FilteredEntries) {
            Assert-True ($e.Level -ne "INFO") "NOT level:INFO should exclude INFO entries"
        }
    }
}

Write-TestSummary
