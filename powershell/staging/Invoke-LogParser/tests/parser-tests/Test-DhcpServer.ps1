# Test-DhcpServer.ps1 — Tests for the Windows DHCP Server Log parser

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"
. "$appRoot\lib\ParserEngine.ps1"
$Script:Parsers = [ordered]@{}
$Script:State = @{ EventIdLookup = @{} }
. "$appRoot\parsers\DhcpServer.ps1"

$sampleFile = Get-SampleFile "dhcp-server.log"

Invoke-Test "DhcpServer: Auto-detect identifies format" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $result = Invoke-AutoDetect $sampleFile
    Assert-Equal "dhcp-server" $result
}

Invoke-Test "DhcpServer: Parses sample without error" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "dhcp-server" -FilePath $sampleFile -Encoding "UTF-8"
    Assert-NotNull $entries
    Assert-GreaterThan $entries.Count 0 "Should parse at least one entry"
}

Invoke-Test "DhcpServer: Entries contain EventID field" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "dhcp-server" -FilePath $sampleFile -Encoding "UTF-8"
    $first = $entries[0]
    Assert-NotNull $first.Extra['EventID'] "EventID should be in Extra"
}

Invoke-Test "DhcpServer: Entries contain IPAddress field" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "dhcp-server" -FilePath $sampleFile -Encoding "UTF-8"
    $hasIp = $false
    foreach ($e in $entries) {
        if ($e.Extra['IPAddress']) { $hasIp = $true; break }
    }
    Assert-True $hasIp "At least one entry should have IPAddress"
}

Invoke-Test "DhcpServer: EventID severity mapping works" {
    # EventID 10=New lease=INFO, 14=Duplicate address=ERROR
    $entry = ConvertTo-LogEntry @{
        Index = 0; Timestamp = (Get-Date); Level = "INFO"; Source = "DHCP"
        Host = "DHCP-01"; Message = "[10] New lease IP=192.168.1.100"
        RawLine = "10,01/01/2025,10:00:00,New,192.168.1.100,PC-01,AA:BB:CC:DD:EE:FF"
        Extra = @{ EventID = 10; IPAddress = "192.168.1.100"; MACAddress = "AA:BB:CC:DD:EE:FF" }
    }
    Assert-Equal "INFO" $entry.Level
}

Invoke-Test "DhcpServer: Message includes IP and host info" {
    if (-not (Test-Path $sampleFile)) { $Script:TestResults.Skipped++; return }
    $entries = Invoke-ParserForFile -ParserId "dhcp-server" -FilePath $sampleFile -Encoding "UTF-8"
    $first = $entries[0]
    Assert-NotNull $first.Message "Message should not be null"
    Assert-Contains $first.Message "IP=" "Message should contain IP address"
}

Write-TestSummary
