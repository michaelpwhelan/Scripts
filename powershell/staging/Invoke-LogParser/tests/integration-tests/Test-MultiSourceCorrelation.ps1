# Test-MultiSourceCorrelation.ps1 — Integration test for multi-source loading and correlation

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"
. "$appRoot\lib\ParserEngine.ps1"
$Script:Parsers = [ordered]@{}
$Script:State = @{ EventIdLookup = @{}; NpsReasonLookup = @{} }
$Script:MitreEventIdMap = @{}

$Config = @{ ScriptRoot = $appRoot }

# Load enrichment and parsers
$enrichDir = Join-Path $appRoot "enrichment"
foreach ($f in (Get-ChildItem -Path $enrichDir -Filter "*.ps1" -ErrorAction SilentlyContinue)) { . $f.FullName }
$parserDir = Join-Path $appRoot "parsers"
foreach ($f in (Get-ChildItem -Path $parserDir -Filter "*.ps1" -ErrorAction SilentlyContinue)) { . $f.FullName }

. "$appRoot\analysis\CorrelationEngine.ps1"
. "$appRoot\analysis\ThreatCorrelator.ps1"

# Build synthetic multi-source dataset simulating real-world scenario
function New-MultiSourceScenario {
    $entries = [System.Collections.Generic.List[object]]::new()
    $baseTime = (Get-Date).AddHours(-1)

    # FortiGate traffic: user "jsmith" denied
    $entries.Add((ConvertTo-LogEntry @{
        Index = 0; Timestamp = $baseTime; Level = "WARNING"; Source = "FG-HUB-01"
        Host = "FG-HUB-01"; Message = "deny srcip=10.0.1.50 dstip=8.8.8.8"
        RawLine = "deny user=jsmith"; Extra = @{ SourceFormat = "fortigate-traffic"; user = "jsmith"; srcip = "10.0.1.50"; action = "deny" }
    }))

    # NPS RADIUS: same user "jsmith" rejected
    $entries.Add((ConvertTo-LogEntry @{
        Index = 1; Timestamp = $baseTime.AddMinutes(3); Level = "WARNING"; Source = "NPS-01"
        Host = "NPS-01"; Message = "Access-Reject for jsmith"
        RawLine = "<Event>reject</Event>"; Extra = @{ SourceFormat = "nps-radius"; 'User-Name' = "jsmith"; PacketTypeName = "Access-Reject" }
    }))

    # Windows EVTX: same user "jsmith" failed login (EventID 4625)
    $entries.Add((ConvertTo-LogEntry @{
        Index = 2; Timestamp = $baseTime.AddMinutes(5); Level = "ERROR"; Source = "Security"
        Host = "DC-01"; Message = "Logon failed for jsmith"
        RawLine = "<xml/>"; Extra = @{ SourceFormat = "evtx"; EventID = 4625; TargetUserName = "jsmith"; IpAddress = "10.0.1.50" }
    }))

    # Unrelated Zabbix event
    $entries.Add((ConvertTo-LogEntry @{
        Index = 3; Timestamp = $baseTime.AddMinutes(10); Level = "INFO"; Source = "Zabbix"
        Host = "web-01"; Message = "[Information] CPU OK"
        RawLine = "{}"; Extra = @{ SourceFormat = "zabbix-export" }
    }))

    return $entries
}

Invoke-Test "MultiSource: Correlation engine finds cross-source activity" {
    $entries = New-MultiSourceScenario
    $results = Invoke-CrossSourceCorrelation -Entries $entries
    Assert-NotNull $results "Correlation results should not be null"
    $jsmithCorrelation = $results | Where-Object { $_.KeyValue -eq 'jsmith' }
    Assert-GreaterThan @($jsmithCorrelation).Count 0 "Should find jsmith across sources"
}

Invoke-Test "MultiSource: Threat correlator identifies failed logins" {
    $entries = New-MultiSourceScenario
    # Add more failed logins to exceed brute force threshold
    $baseTime = (Get-Date).AddHours(-1)
    for ($i = 0; $i -lt 10; $i++) {
        $entries.Add((ConvertTo-LogEntry @{
            Index = (4 + $i); Timestamp = $baseTime.AddMinutes($i); Level = "ERROR"; Source = "DC-01"
            Host = "DC-01"; Message = "Logon failed for admin"
            RawLine = "<xml/>"; Extra = @{ SourceFormat = "evtx"; EventID = 4625; TargetUserName = "admin" }
        }))
    }
    $threatResults = Get-ThreatCorrelation -Entries $entries
    Assert-GreaterThan $threatResults.Summary.TotalIndicators 0 "Should find threat indicators"
}

Invoke-Test "MultiSource: Correlation results include source information" {
    $entries = New-MultiSourceScenario
    $results = Invoke-CrossSourceCorrelation -Entries $entries
    if (@($results).Count -gt 0) {
        Assert-NotNull $results[0].Sources "Correlation should list source formats"
    }
}

Invoke-Test "MultiSource: Empty dataset produces no correlations" {
    $entries = [System.Collections.Generic.List[object]]::new()
    $results = Invoke-CrossSourceCorrelation -Entries $entries
    Assert-Equal 0 @($results).Count "Empty dataset should have zero correlations"
}

Invoke-Test "MultiSource: Single-source dataset produces no correlations" {
    $entries = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt 5; $i++) {
        $entries.Add((ConvertTo-LogEntry @{
            Index = $i; Timestamp = (Get-Date); Level = "INFO"; Source = "FG-01"
            Host = "FG-01"; Message = "event $i"; RawLine = "test"
            Extra = @{ SourceFormat = "fortigate-traffic"; user = "same-user" }
        }))
    }
    $results = Invoke-CrossSourceCorrelation -Entries $entries
    Assert-Equal 0 @($results).Count "Single source should have zero cross-source correlations"
}

Write-TestSummary
