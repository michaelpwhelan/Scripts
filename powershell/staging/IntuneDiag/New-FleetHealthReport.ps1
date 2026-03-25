<#
.SYNOPSIS
    Generates a printable HTML report from Invoke-FleetScan.ps1 JSON output.

.DESCRIPTION
    Consumes the full JSON file produced by Invoke-FleetScan.ps1 and generates a
    self-contained black-and-white HTML report suitable for printing, triage, and
    NCUA/FFIEC exam documentation.

    Report sections:
      1. Executive Summary  — fleet-wide health overview and top findings
      2. Finding Distribution — count of devices affected by each finding
      3. Device Detail      — unhealthy devices with findings and next steps
      4. Recommended Actions — prioritized fleet-wide remediation checklist

.PARAMETER JsonPath
    Path to the FleetHealth JSON file from Invoke-FleetScan.ps1.

.PARAMETER OutputPath
    Output HTML file path. Default: same directory as JsonPath with .html extension.

.EXAMPLE
    .\New-FleetHealthReport.ps1 -JsonPath .\FleetHealth_20240815_143022.json
    Generate report alongside the JSON file.

.EXAMPLE
    .\New-FleetHealthReport.ps1 -JsonPath .\FleetHealth.json -OutputPath C:\Reports\fleet.html
    Generate report at a specific path.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory, HelpMessage = 'Path to FleetHealth JSON from Invoke-FleetScan.')]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$JsonPath,

    [Parameter(HelpMessage = 'Output HTML file path.')]
    [string]$OutputPath
)

# =============================================================================
# Configuration
# =============================================================================
if (-not $OutputPath) {
    $OutputPath = [System.IO.Path]::ChangeExtension($JsonPath, '.html')
}

# Severity rank for sorting (lower = more severe)
$SeverityRank = @{ 'CRITICAL' = 1; 'HIGH' = 2; 'MEDIUM' = 3; 'LOW' = 4 }

# Action map: finding pattern -> remediation guidance
# Each entry maps a substring found in finding text to a recommended action.
$ActionMap = @(
    [ordered]@{
        Pattern  = 'AzureAdPrt'
        Severity = 'CRITICAL'
        Title    = 'Fix Azure AD Primary Refresh Token (PRT)'
        Detail   = 'Run dsregcmd /refreshprt or lock/unlock the device to force PRT renewal. If PRT remains NO, check Entra Connect sync health, TPM status (tpm.msc), and verify the device can reach login.microsoftonline.com in SYSTEM context.'
    }
    [ordered]@{
        Pattern  = 'MdmUrl.*MISSING'
        Severity = 'CRITICAL'
        Title    = 'Configure MDM auto-enrollment URLs'
        Detail   = 'Verify the "Enable automatic MDM enrollment using default Azure AD credentials" GPO is applied and linked. Check HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\{TenantID} for MdmEnrollmentUrl, MdmTermsOfUseUrl, and MdmComplianceUrl values.'
    }
    [ordered]@{
        Pattern  = 'MmpcEnrollmentFlag'
        Severity = 'CRITICAL'
        Title    = 'Clear MDE enrollment flag'
        Detail   = 'Set HKLM:\SOFTWARE\Microsoft\Enrollments\MmpcEnrollmentFlag to 0 (DWORD). If ExternallyManaged is also set, clear it too. Then trigger MDM re-enrollment via: deviceenroller.exe /c /AutoEnrollMDMUsingAADDeviceCredential'
    }
    [ordered]@{
        Pattern  = 'ExternallyManaged'
        Severity = 'CRITICAL'
        Title    = 'Clear ExternallyManaged block'
        Detail   = 'Set HKLM:\SOFTWARE\Microsoft\Enrollments\ExternallyManaged to 0 (DWORD). Then trigger MDM re-enrollment. If the device was previously managed by MDE Security Settings Management, also clear MmpcEnrollmentFlag.'
    }
    [ordered]@{
        Pattern  = 'No valid Intune MDM enrollment'
        Severity = 'HIGH'
        Title    = 'Trigger Intune MDM enrollment'
        Detail   = 'Verify GPO auto-enrollment is configured (AutoEnrollMDM = 1). For hybrid joined devices, run: deviceenroller.exe /c /AutoEnrollMDMUsingAADDeviceCredential. Check for blocking conditions (MmpcEnrollmentFlag, ExternallyManaged) first.'
    }
    [ordered]@{
        Pattern  = 'IME service'
        Severity = 'HIGH'
        Title    = 'Trigger IME installation'
        Detail   = 'Assign at least one Win32 app, PowerShell platform script, or Proactive Remediation to the device/user in Intune. IME auto-installs when any of these workloads are targeted. Verify enrollment is healthy first.'
    }
    [ordered]@{
        Pattern  = 'MDM.*certificate'
        Severity = 'HIGH'
        Title    = 'Fix MDM certificate'
        Detail   = 'Delete stale enrollment GUIDs from HKLM:\SOFTWARE\Microsoft\Enrollments\ and orphaned task folders from C:\windows\system32\tasks\Microsoft\Windows\EnterpriseMgmt\. Then re-trigger enrollment to get a fresh MDM Device CA certificate.'
    }
    [ordered]@{
        Pattern  = 'dmwappush'
        Severity = 'HIGH'
        Title    = 'Restore dmwappushservice'
        Detail   = 'Set dmwappushservice startup type to Automatic (Delayed Start) and start the service. If the service registry key is missing entirely, export HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice from a healthy device and import.'
    }
    [ordered]@{
        Pattern  = 'Domain time hierarchy broken'
        Severity = 'HIGH'
        Title    = 'Fix Windows Time hierarchy'
        Detail   = 'The device clock is not syncing from a domain controller. Run: w32tm /resync /force. If the source remains "Local CMOS Clock", check that the W32Time service is running and the device can reach a domain controller on UDP 123.'
    }
    [ordered]@{
        Pattern  = 'NoCloudApplicationNotification'
        Severity = 'MEDIUM'
        Title    = 'Exempt WNS from CIS L2 notification GPO'
        Detail   = 'The "Turn off notifications network usage" GPO (CIS L2 18.7.1.1) is blocking Intune push notifications. Create a GPO exemption that sets HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\NoCloudApplicationNotification to 0 for Intune-managed devices.'
    }
    [ordered]@{
        Pattern  = 'WpnService disabled'
        Severity = 'MEDIUM'
        Title    = 'Re-enable WpnService'
        Detail   = 'WpnService (Windows Push Notifications System Service) is disabled, likely by CIS L2 benchmark hardening. Set HKLM:\SYSTEM\CurrentControlSet\Services\WpnService\Start to 2 (Automatic) and start the service. Create a GPO exemption for CIS recommendation 5.34/5.37/5.38.'
    }
    [ordered]@{
        Pattern  = 'SCCM remnants'
        Severity = 'MEDIUM'
        Title    = 'Clean SCCM/ConfigMgr remnants'
        Detail   = 'Remove all SCCM artifacts: stop/delete CcmExec service, remove HKLM:\SOFTWARE\Microsoft\CCM registry key, delete root\ccm WMI namespace (Get-CimInstance -Query "SELECT * FROM __Namespace WHERE Name=''ccm''" -Namespace root | Remove-CimInstance), delete C:\Windows\CCM\ and C:\Windows\smscfg.ini.'
    }
    [ordered]@{
        Pattern  = 'SSL interception'
        Severity = 'MEDIUM'
        Title    = 'Add Microsoft endpoints to SSL inspection exemption'
        Detail   = 'Add the following to FortiGate SSL deep inspection exemption list: *.manage.microsoft.com, *.dm.microsoft.com, login.microsoftonline.com, enterpriseregistration.windows.net, graph.microsoft.com, *.notify.windows.com, *.wns.windows.com, and CRL/OCSP endpoints.'
    }
    [ordered]@{
        Pattern  = 'AutoEnrollMDM.*not configured'
        Severity = 'MEDIUM'
        Title    = 'Enable MDM auto-enrollment GPO'
        Detail   = 'Configure the "Enable automatic MDM enrollment using default Azure AD credentials" GPO: Computer Configuration > Administrative Templates > Windows Components > MDM. Set AutoEnrollMDM = 1 and UseAADCredentialType = 1 (User Credential) for hybrid joined devices.'
    }
    [ordered]@{
        Pattern  = 'Clock skew'
        Severity = 'MEDIUM'
        Title    = 'Correct clock skew'
        Detail   = 'Run w32tm /resync /force on affected devices. Verify NTP source with w32tm /query /source. If skew persists, check that the PDC emulator is syncing to an external NTP source and that UDP 123 is not blocked between the device and its domain controller.'
    }
    [ordered]@{
        Pattern  = 'Connectivity failed'
        Severity = 'MEDIUM'
        Title    = 'Verify firewall rules for Intune endpoints'
        Detail   = 'Ensure TCP 443 is permitted outbound to: manage.microsoft.com, login.microsoftonline.com, client.wns.windows.com, enterpriseregistration.windows.net. Check FortiGate firewall policies and any web filtering rules that may block these endpoints.'
    }
    [ordered]@{
        Pattern  = 'Orphaned EnterpriseMgmt'
        Severity = 'MEDIUM'
        Title    = 'Clean orphaned scheduled tasks'
        Detail   = 'Delete orphaned task folders from C:\windows\system32\tasks\Microsoft\Windows\EnterpriseMgmt\ where the GUID no longer has a matching enrollment registry entry. These fire uselessly and can interfere with new enrollment.'
    }
    [ordered]@{
        Pattern  = 'Professional'
        Severity = 'LOW'
        Title    = 'Fix Windows subscription activation'
        Detail   = 'Apply KB5041585 (UBR >= 4037) to fix the subscription activation bug. Verify user has M365 E3/E5 license, AzureAdPrt = YES, and the Microsoft Account Sign-in Assistant (wlidsvc) is running. Check LicenseAcquisition task for errors.'
    }
    [ordered]@{
        Pattern  = 'KB5041585 not applied'
        Severity = 'LOW'
        Title    = 'Apply KB5041585 subscription activation fix'
        Detail   = 'Deploy KB5041585 (August 2024) via WSUS or Windows Update. This fixes the ClipRenew.exe access denied bug (KB5036980) that prevents Enterprise subscription activation renewal.'
    }
)

# =============================================================================
# HTML encoding helper (System.Web may not be loaded in PS 5.1)
# =============================================================================
Add-Type -AssemblyName System.Web -EA SilentlyContinue
function Encode-Html {
    param([string]$Text)
    if (-not $Text) { return '' }
    if ([System.Web.HttpUtility]) {
        return Encode-Html($Text)
    }
    # Fallback: manual encoding for the critical characters
    $Text -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' -replace "'",'&#39;'
}

# =============================================================================
# Load and parse data
# =============================================================================
Write-Host "Loading fleet health data from $JsonPath..." -ForegroundColor Cyan
$rawJson = Get-Content -Path $JsonPath -Raw -Encoding UTF8
$data = $rawJson | ConvertFrom-Json

if (-not $data -or $data.Count -eq 0) {
    throw "No data found in $JsonPath"
}

Write-Host "Loaded $($data.Count) device records" -ForegroundColor Cyan

# =============================================================================
# Compute aggregations
# =============================================================================
$totalCount       = $data.Count
$healthyDevices   = @($data | Where-Object { $_.HealthScore -and $_.HealthScore.Healthy -eq $true })
$unhealthyDevices = @($data | Where-Object { $_.HealthScore -and $_.HealthScore.Healthy -eq $false -and $_.Status -notin @('UNREACHABLE','PARSE_ERROR') })
$unreachable      = @($data | Where-Object { $_.Status -in @('UNREACHABLE','PARSE_ERROR') })

$healthyCount     = $healthyDevices.Count
$unhealthyCount   = $unhealthyDevices.Count
$unreachableCount = $unreachable.Count

# Flatten all findings into a frequency table
$findingFrequency = @{}
foreach ($device in $data) {
    if ($device.HealthScore -and $device.HealthScore.Findings) {
        foreach ($finding in $device.HealthScore.Findings) {
            if ($findingFrequency.ContainsKey($finding)) {
                $findingFrequency[$finding]++
            } else {
                $findingFrequency[$finding] = 1
            }
        }
    }
}

# Sort findings by severity rank then count
$sortedFindings = $findingFrequency.GetEnumerator() | ForEach-Object {
    $severity = 'UNKNOWN'
    if ($_.Key -match '^(CRITICAL|HIGH|MEDIUM|LOW):') { $severity = $Matches[1] }
    [PSCustomObject]@{
        Finding  = $_.Key
        Severity = $severity
        Rank     = if ($SeverityRank.ContainsKey($severity)) { $SeverityRank[$severity] } else { 99 }
        Count    = $_.Value
        Pct      = [Math]::Round(($_.Value / $totalCount) * 100, 1)
    }
} | Sort-Object Rank, @{Expression={$_.Count}; Descending=$true}

# Compute recommended actions with device counts
$actionResults = [System.Collections.Generic.List[PSObject]]::new()
foreach ($action in $ActionMap) {
    $matchCount = 0
    foreach ($device in $data) {
        if ($device.HealthScore -and $device.HealthScore.Findings) {
            $hasMatch = $false
            foreach ($finding in $device.HealthScore.Findings) {
                if ($finding -match $action.Pattern) { $hasMatch = $true; break }
            }
            if ($hasMatch) { $matchCount++ }
        }
    }
    if ($matchCount -gt 0) {
        $actionResults.Add([PSCustomObject]@{
            Severity = $action.Severity
            Rank     = if ($SeverityRank.ContainsKey($action.Severity)) { $SeverityRank[$action.Severity] } else { 99 }
            Title    = $action.Title
            Detail   = $action.Detail
            Count    = $matchCount
        })
    }
}
$actionResults = $actionResults | Sort-Object Rank, @{Expression={$_.Count}; Descending=$true}

# Get next step for each unhealthy device (based on highest-severity finding)
function Get-NextStep {
    param([string[]]$Findings)
    if (-not $Findings -or $Findings.Count -eq 0) { return 'Review device manually' }

    # Sort findings by severity to get the most critical one
    $sorted = $Findings | ForEach-Object {
        $sev = 'UNKNOWN'
        if ($_ -match '^(CRITICAL|HIGH|MEDIUM|LOW):') { $sev = $Matches[1] }
        [PSCustomObject]@{ Text = $_; Rank = if ($SeverityRank.ContainsKey($sev)) { $SeverityRank[$sev] } else { 99 } }
    } | Sort-Object Rank | Select-Object -First 1

    $topFinding = $sorted.Text

    # Match against action map
    foreach ($action in $ActionMap) {
        if ($topFinding -match $action.Pattern) {
            return $action.Title
        }
    }
    return 'Review device manually'
}

# =============================================================================
# Build HTML
# =============================================================================
$html = [System.Text.StringBuilder]::new(32768)

# HTML head with inline CSS
[void]$html.AppendLine('<!DOCTYPE html>')
[void]$html.AppendLine('<html lang="en">')
[void]$html.AppendLine('<head>')
[void]$html.AppendLine('<meta charset="UTF-8">')
[void]$html.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
[void]$html.AppendLine('<title>Intune Fleet Health Assessment</title>')
[void]$html.AppendLine('<style>')
[void]$html.AppendLine(@'
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: 'Courier New', Courier, monospace;
    font-size: 11pt;
    line-height: 1.4;
    padding: 1cm;
    color: #000;
    background: #fff;
}
h1 {
    font-size: 16pt;
    border-bottom: 3px double #000;
    padding-bottom: 6pt;
    margin-bottom: 12pt;
    text-transform: uppercase;
    letter-spacing: 1px;
}
h2 {
    font-size: 13pt;
    border-bottom: 1px solid #000;
    padding-bottom: 3pt;
    margin: 20pt 0 8pt 0;
    text-transform: uppercase;
}
table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 16pt;
}
th, td {
    border: 1px solid #000;
    padding: 3pt 6pt;
    text-align: left;
    vertical-align: top;
    font-size: 10pt;
    font-family: 'Courier New', Courier, monospace;
}
th {
    background: #e8e8e8;
    font-weight: bold;
}
.section {
    border: 1px solid #000;
    padding: 10pt;
    margin-bottom: 16pt;
}
.stats-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 8pt;
    margin-bottom: 12pt;
}
.stat-box {
    border: 1px solid #000;
    padding: 8pt;
    text-align: center;
}
.stat-label {
    font-size: 9pt;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.stat-value {
    font-size: 18pt;
    font-weight: bold;
}
.action-item {
    border: 1px solid #000;
    padding: 8pt;
    margin-bottom: 8pt;
}
.action-header {
    font-weight: bold;
    margin-bottom: 4pt;
}
.action-detail {
    font-size: 9pt;
    margin-left: 24pt;
}
.action-impact {
    font-size: 9pt;
    font-weight: bold;
    margin-left: 24pt;
    margin-top: 2pt;
}
.severity-critical { font-weight: bold; text-decoration: underline; }
.severity-high { font-weight: bold; }
.timestamp {
    font-size: 9pt;
    margin-bottom: 8pt;
}
.footer {
    border-top: 1px solid #000;
    padding-top: 6pt;
    margin-top: 20pt;
    font-size: 9pt;
}
@media print {
    body { padding: 0; }
    .page-break { page-break-before: always; }
    .no-break { page-break-inside: avoid; }
}
'@)
[void]$html.AppendLine('</style>')
[void]$html.AppendLine('</head>')
[void]$html.AppendLine('<body>')

# --- Title ---
[void]$html.AppendLine('<h1>Intune Fleet Health Assessment</h1>')
[void]$html.AppendLine("<p class='timestamp'>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC</p>")

# --- Section 1: Executive Summary ---
[void]$html.AppendLine('<h2>1. Executive Summary</h2>')
[void]$html.AppendLine('<div class="section">')

[void]$html.AppendLine('<div class="stats-grid">')
[void]$html.AppendLine("<div class='stat-box'><div class='stat-value'>$totalCount</div><div class='stat-label'>Total Scanned</div></div>")
[void]$html.AppendLine("<div class='stat-box'><div class='stat-value'>$healthyCount</div><div class='stat-label'>Healthy</div></div>")
[void]$html.AppendLine("<div class='stat-box'><div class='stat-value'>$unhealthyCount</div><div class='stat-label'>Unhealthy</div></div>")
[void]$html.AppendLine("<div class='stat-box'><div class='stat-value'>$unreachableCount</div><div class='stat-label'>Unreachable</div></div>")
[void]$html.AppendLine('</div>')

# Health percentage
if ($totalCount -gt 0) {
    $healthPct = [Math]::Round(($healthyCount / $totalCount) * 100, 1)
    [void]$html.AppendLine("<p><strong>Fleet Health Rate: ${healthPct}%</strong></p>")
}

# Top 3 findings
$topThree = $sortedFindings | Where-Object { $_.Severity -ne 'LOW' } | Select-Object -First 3
if ($topThree.Count -gt 0) {
    [void]$html.AppendLine('<p><strong>Top Findings:</strong></p>')
    [void]$html.AppendLine('<table>')
    [void]$html.AppendLine('<tr><th>#</th><th>Finding</th><th>Devices</th></tr>')
    $i = 1
    foreach ($f in $topThree) {
        $escapedFinding = Encode-Html($f.Finding)
        [void]$html.AppendLine("<tr><td>$i</td><td>$escapedFinding</td><td>$($f.Count)</td></tr>")
        $i++
    }
    [void]$html.AppendLine('</table>')
}

[void]$html.AppendLine('</div>')

# --- Section 2: Finding Distribution ---
[void]$html.AppendLine('<h2>2. Finding Distribution</h2>')

if ($sortedFindings.Count -gt 0) {
    [void]$html.AppendLine('<table>')
    [void]$html.AppendLine('<tr><th>Severity</th><th>Finding</th><th>Devices</th><th>%</th></tr>')
    foreach ($f in $sortedFindings) {
        $sevClass = "severity-$($f.Severity.ToLower())"
        $escapedFinding = Encode-Html($f.Finding)
        [void]$html.AppendLine("<tr class='no-break'><td class='$sevClass'>$($f.Severity)</td><td>$escapedFinding</td><td>$($f.Count)</td><td>$($f.Pct)%</td></tr>")
    }
    [void]$html.AppendLine('</table>')
} else {
    [void]$html.AppendLine('<p>No findings detected across the fleet.</p>')
}

# --- Section 3: Device Detail ---
[void]$html.AppendLine('<div class="page-break"></div>')
[void]$html.AppendLine('<h2>3. Device Detail</h2>')

$problemDevices = @($data | Where-Object { $_.HealthScore -and $_.HealthScore.Healthy -eq $false })
if ($problemDevices.Count -gt 0) {
    [void]$html.AppendLine('<table>')
    [void]$html.AppendLine('<tr><th>Computer</th><th>Findings</th><th>Next Step</th></tr>')
    foreach ($device in ($problemDevices | Sort-Object ComputerName)) {
        $name = Encode-Html($device.ComputerName)

        if ($device.Status -in @('UNREACHABLE','PARSE_ERROR')) {
            $findingsHtml = Encode-Html($device.Error)
            $nextStep = 'Verify WinRM / network access'
        } else {
            $deviceFindings = @()
            if ($device.HealthScore.Findings) {
                $deviceFindings = @($device.HealthScore.Findings)
            }
            $findingsHtml = ($deviceFindings | ForEach-Object { Encode-Html($_) }) -join '<br>'
            $nextStep = Get-NextStep -Findings $deviceFindings
        }

        [void]$html.AppendLine("<tr class='no-break'><td>$name</td><td>$findingsHtml</td><td>$(Encode-Html($nextStep))</td></tr>")
    }
    [void]$html.AppendLine('</table>')
} else {
    [void]$html.AppendLine('<p>All scanned devices are healthy.</p>')
}

# --- Section 4: Recommended Actions ---
[void]$html.AppendLine('<div class="page-break"></div>')
[void]$html.AppendLine('<h2>4. Recommended Actions</h2>')

if ($actionResults.Count -gt 0) {
    $priority = 1
    foreach ($action in $actionResults) {
        [void]$html.AppendLine('<div class="action-item no-break">')
        $sevClass = "severity-$($action.Severity.ToLower())"
        [void]$html.AppendLine("<div class='action-header'>&#9744; $priority. [$($action.Severity)] $(Encode-Html($action.Title))</div>")
        [void]$html.AppendLine("<div class='action-detail'>$(Encode-Html($action.Detail))</div>")
        [void]$html.AppendLine("<div class='action-impact'>Impact: Fixes $($action.Count) device(s)</div>")
        [void]$html.AppendLine('</div>')
        $priority++
    }
} else {
    [void]$html.AppendLine('<p>No recommended actions - all devices are healthy.</p>')
}

# --- Footer ---
[void]$html.AppendLine('<div class="footer">')
[void]$html.AppendLine("<p>Source: $(Encode-Html((Split-Path $JsonPath -Leaf)))</p>")
[void]$html.AppendLine("<p>Generated by IntuneDiag Fleet Health Report</p>")
[void]$html.AppendLine('</div>')

[void]$html.AppendLine('</body>')
[void]$html.AppendLine('</html>')

# =============================================================================
# Write output
# =============================================================================
[System.IO.File]::WriteAllText($OutputPath, $html.ToString(), [System.Text.Encoding]::UTF8)

Write-Host ''
Write-Host '================================================================' -ForegroundColor White
Write-Host '  FLEET HEALTH REPORT GENERATED' -ForegroundColor White
Write-Host '================================================================' -ForegroundColor White
Write-Host "  Total Devices:  $totalCount"
Write-Host "  Healthy:        $healthyCount" -ForegroundColor Green
Write-Host "  Unhealthy:      $unhealthyCount" -ForegroundColor Yellow
Write-Host "  Unreachable:    $unreachableCount" -ForegroundColor Red
Write-Host "  Actions:        $($actionResults.Count) recommended" -ForegroundColor White
Write-Host '----------------------------------------------------------------' -ForegroundColor White
Write-Host "  Report: $OutputPath" -ForegroundColor Cyan
Write-Host ''
