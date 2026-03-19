# Test-AutoDetection.ps1 — Cross-parser auto-detection tests
# Verifies that Invoke-AutoDetect correctly identifies each sample file format

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"
. "$appRoot\lib\ParserEngine.ps1"
$Script:Parsers = [ordered]@{}
$Script:State = @{ EventIdLookup = @{}; NpsReasonLookup = @{} }
$Script:MitreEventIdMap = @{}

# Load all enrichment mappings
$enrichDir = Join-Path $appRoot "enrichment"
foreach ($enrichFile in (Get-ChildItem -Path $enrichDir -Filter "*.ps1" -ErrorAction SilentlyContinue)) {
    . $enrichFile.FullName
}

# Load all parsers
$parserDir = Join-Path $appRoot "parsers"
foreach ($parserFile in (Get-ChildItem -Path $parserDir -Filter "*.ps1" -ErrorAction SilentlyContinue)) {
    . $parserFile.FullName
}

# Map of sample files to expected parser IDs
$detectionTests = @(
    @{ File = "fortigate-kv.log";         Expected = "fortigate-kv" }
    @{ File = "fortigate-ipsec.log";      Expected = "fortigate-ipsec" }
    @{ File = "fortigate-bgp.log";        Expected = "fortigate-bgp" }
    @{ File = "nps-radius.xml";           Expected = "nps-radius" }
    @{ File = "defender-alerts.json";     Expected = "defender-alerts" }
    @{ File = "dhcp-server.log";          Expected = "dhcp-server" }
    @{ File = "veeam-job.log";            Expected = "veeam-job" }
    @{ File = "zabbix-export.json";       Expected = "zabbix-export" }
    @{ File = "entra-audit.json";         Expected = "entra-audit" }
    @{ File = "fortiswitch-event.log";    Expected = "fortiswitch-event" }
    @{ File = "certificate-event.json";   Expected = "certificate-event" }
    @{ File = "intune-compliance.json";   Expected = "intune-compliance" }
    @{ File = "fortimanager-audit.log";   Expected = "fortimanager-audit" }
    @{ File = "syslog-rfc3164.log";       Expected = "syslog-rfc3164" }
)

foreach ($test in $detectionTests) {
    Invoke-Test "AutoDetect: Identifies $($test.File) as $($test.Expected)" {
        $samplePath = Get-SampleFile $test.File
        if (-not (Test-Path $samplePath)) { $Script:TestResults.Skipped++; return }
        $result = Invoke-AutoDetect $samplePath
        Assert-Equal $test.Expected $result
    }
}

Invoke-Test "AutoDetect: Returns plaintext for unknown format" {
    $tempFile = [System.IO.Path]::GetTempFileName()
    try {
        "This is just some plain text that does not match any parser." | Set-Content -Path $tempFile
        "Another line of ordinary content." | Add-Content -Path $tempFile
        $result = Invoke-AutoDetect $tempFile
        Assert-Equal "plaintext" $result
    } finally {
        Remove-Item $tempFile -ErrorAction SilentlyContinue
    }
}

Invoke-Test "AutoDetect: All parsers are registered" {
    $registeredCount = $Script:Parsers.Count
    Assert-GreaterThan $registeredCount 10 "Should have at least 10 parsers registered"
}

Write-TestSummary
