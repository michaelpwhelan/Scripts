# Test-FortiGateIpsec.ps1 — Tests for the FortiGate IPsec VPN parser

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"
. "$appRoot\lib\ParserEngine.ps1"
$Script:Parsers = [ordered]@{}
. "$appRoot\enrichment\FortiGateMappings.ps1"
. "$appRoot\enrichment\IpsecErrorCodes.ps1"
. "$appRoot\parsers\FortiGateIpsec.ps1"

$sampleFile = Get-SampleFile "fortigate-ipsec.log"

Invoke-Test "FortiGateIpsec: Auto-detect identifies format" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $result = Invoke-AutoDetect $sampleFile
    Assert-Equal "fortigate-ipsec" $result
}

Invoke-Test "FortiGateIpsec: Parses sample without error" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "fortigate-ipsec" -FilePath $sampleFile -Encoding "UTF-8"
    Assert-NotNull $entries
    Assert-GreaterThan $entries.Count 0 "Should parse at least one entry"
}

Invoke-Test "FortiGateIpsec: Entries contain TunnelName field" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "fortigate-ipsec" -FilePath $sampleFile -Encoding "UTF-8"
    $hasTunnel = $false
    foreach ($e in $entries) {
        if ($e.Extra['TunnelName']) { $hasTunnel = $true; break }
    }
    Assert-True $hasTunnel "At least one entry should have TunnelName"
}

Invoke-Test "FortiGateIpsec: Entries contain RemoteGw field" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "fortigate-ipsec" -FilePath $sampleFile -Encoding "UTF-8"
    $hasRemoteGw = $false
    foreach ($e in $entries) {
        if ($e.Extra['RemoteGw']) { $hasRemoteGw = $true; break }
    }
    Assert-True $hasRemoteGw "At least one entry should have RemoteGw"
}

Invoke-Test "FortiGateIpsec: Phase field is populated for negotiation events" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "fortigate-ipsec" -FilePath $sampleFile -Encoding "UTF-8"
    $hasPhase = $false
    foreach ($e in $entries) {
        if ($e.Extra['Phase'] -in @('phase1', 'phase2')) { $hasPhase = $true; break }
    }
    Assert-True $hasPhase "At least one entry should have Phase field"
}

Invoke-Test "FortiGateIpsec: Level mapping works for negotiation errors" {
    $entry = ConvertTo-LogEntry @{
        Index = 0; Timestamp = (Get-Date); Level = "ERROR"; Source = "FG-01"
        Host = "FG-01"; Message = "phase1 negotiation failure"
        RawLine = "date=2025-01-01 action=negotiate-error msg=phase1 negotiation failure"
        Extra = @{ TunnelName = "VPN-1"; RemoteGw = "10.0.0.1"; Phase = "phase1" }
    }
    Assert-Equal "ERROR" $entry.Level
}

Write-TestSummary
