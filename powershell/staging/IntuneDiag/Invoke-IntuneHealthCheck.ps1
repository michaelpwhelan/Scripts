<#
.SYNOPSIS
    Intune MDM Enrollment Health Diagnostic — single-device assessment.

.DESCRIPTION
    Read-only diagnostic script that checks all known Intune MDM enrollment failure
    patterns on a Windows 11 endpoint. Designed to run via Invoke-Command -FilePath
    over PSRemoting, or locally as admin/SYSTEM.

    Checks 13 diagnostic areas:
      1.  Device identity and hybrid join health (dsregcmd)
      2.  MDM enrollment registry analysis
      3.  Intune Management Extension (IME) status
      4.  EnterpriseMgmt scheduled tasks
      5.  Push notification / WNS health
      6.  Windows edition and subscription activation
      7.  SCCM remnants
      8.  MDM certificate health
      9.  SSL deep inspection spot check
      10. Network connectivity
      11. GPO auto-enrollment configuration
      12. Clock skew
      13. Recent enrollment events

    Outputs a single JSON object to stdout. Exit code 0 = healthy, 1 = issues.

    This script is DIAGNOSTIC ONLY — it makes no changes to the system.

.NOTES
    Designed for: Windows 11 endpoints, hybrid Entra ID joined, M365 E5
    Run context:  SYSTEM (PSRemoting / Proactive Remediation) or local admin
    Output:       JSON to stdout
    Exit code:    0 = healthy, 1 = issues detected
#>
#Requires -Version 5.1

$diag = [ordered]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = (Get-Date).ToUniversalTime().ToString('o')
}

#region 1. Device Identity & Hybrid Join Health
# Parse dsregcmd /status for join state, PRT, and MDM URL.
# AzureAdPrt = NO is the highest-severity finding — blocks all Entra auth.
# MdmUrl blank means auto-enrollment will never fire.
$dsreg = dsregcmd /status 2>&1

# Helper: extract a value from dsregcmd output by key name
function Get-DsregValue {
    param([string[]]$Lines, [string]$Key)
    $match = $Lines | Select-String "$Key\s*:\s*(.+)"
    if ($match) { $match.Matches.Groups[1].Value.Trim() } else { $null }
}

$azureAdJoined = Get-DsregValue $dsreg 'AzureAdJoined'
$domainJoined  = Get-DsregValue $dsreg 'DomainJoined'
$azureAdPrt    = Get-DsregValue $dsreg 'AzureAdPrt'
$mdmUrl        = Get-DsregValue $dsreg 'MdmUrl'
$tenantId      = Get-DsregValue $dsreg 'TenantId'

$diag.Identity = [ordered]@{
    AzureAdJoined = if ($azureAdJoined) { $azureAdJoined } else { 'UNKNOWN' }
    DomainJoined  = if ($domainJoined)  { $domainJoined }  else { 'UNKNOWN' }
    AzureAdPrt    = if ($azureAdPrt)    { $azureAdPrt }    else { 'UNKNOWN' }
    MdmUrl        = if ($mdmUrl)        { $mdmUrl }        else { 'MISSING' }
    TenantId      = if ($tenantId)      { $tenantId }      else { 'MISSING' }
}
#endregion

#region 2. MDM Enrollment Registry Analysis
# Enumerate all enrollment GUIDs under HKLM:\SOFTWARE\Microsoft\Enrollments.
# Classify each as IntuneMDM, MDEOnly, SCCM, AzureADJoin, DeviceCredential, or Unknown.
# Check MmpcEnrollmentFlag (0x2 = MDE blocking real enrollment).
# Check ExternallyManaged (1 = hard block on enrollment).
$mmpcFlag  = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Enrollments' -Name MmpcEnrollmentFlag -EA SilentlyContinue).MmpcEnrollmentFlag
$extManaged = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Enrollments' -Name ExternallyManaged -EA SilentlyContinue).ExternallyManaged

# SenseCM: MDE attachment status (only exists on MDE-onboarded devices)
$senseCM = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\SenseCM' -EA SilentlyContinue).EnrollmentStatus

# Enumerate enrollment entries
$entries = [System.Collections.Generic.List[hashtable]]::new()
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -EA SilentlyContinue |
    Where-Object { $_.PSChildName -match '^[{(]?[0-9a-fA-F]{8}' } | ForEach-Object {
    $props = Get-ItemProperty $_.PSPath -EA SilentlyContinue
    $provId   = $props.ProviderID
    $enrollType = $props.EnrollmentType
    $discUrl  = $props.DiscoveryServiceFullURL
    $upn      = $props.UPN

    # Classification cascade (order matters — ProviderID check takes precedence)
    $classification = if ($provId -eq 'MS DM Server') {
        'IntuneMDM'
    } elseif ($enrollType -eq 14 -or ($discUrl -and $discUrl -match 'dm\.microsoft\.com')) {
        'MDEOnly'
    } elseif ($provId -and $provId -match 'SMS|WMI_Bridge') {
        'SCCM'
    } elseif ($enrollType -eq 18) {
        'AzureADJoin'
    } elseif ($enrollType -in @(2, 32)) {
        'DeviceCredential'
    } else {
        'Unknown'
    }

    $entries.Add([ordered]@{
        GUID           = $_.PSChildName
        ProviderID     = $provId
        EnrollmentType = $enrollType
        Classification = $classification
        UPN            = $upn
        DiscoveryURL   = $discUrl
    })
}

$diag.Enrollment = [ordered]@{
    MmpcEnrollmentFlag = $mmpcFlag
    ExternallyManaged  = $extManaged
    SenseCMStatus      = $senseCM
    Entries            = @($entries)
    HasValidIntuneMDM  = ($entries | Where-Object { $_.Classification -eq 'IntuneMDM' }).Count -gt 0
}
#endregion

#region 3. Intune Management Extension Status
# IME installs only when triggered by Win32 apps, PS scripts, Proactive Remediations, etc.
# If the service doesn't exist, no Win32 app deployment is possible.
$imeSvc = Get-Service -Name IntuneManagementExtension -EA SilentlyContinue

# Check for downloaded-but-not-installed MSI (indicates IME delivery was attempted)
$msiDownloaded = $false
$msiPath = 'C:\Windows\System32\config\systemprofile\AppData\Local\mdm'
if (Test-Path $msiPath) {
    $msiDownloaded = (Get-ChildItem $msiPath -Filter '*.msi' -EA SilentlyContinue).Count -gt 0
}

$diag.IME = [ordered]@{
    ServiceExists  = $null -ne $imeSvc
    ServiceStatus  = if ($imeSvc) { $imeSvc.Status.ToString() } else { $null }
    InstallDirExists = Test-Path 'C:\Program Files (x86)\Microsoft Intune Management Extension\'
    MSIDownloaded  = $msiDownloaded
}
#endregion

#region 4. EnterpriseMgmt Scheduled Tasks
# After enrollment, Windows creates tasks under EnterpriseMgmt\{GUID}\.
# Some tasks are HIDDEN from Get-ScheduledTask — must check the filesystem directly.
# Orphaned tasks (task folder exists, no matching enrollment) indicate failed cleanup.
# Missing tasks (Intune enrollment exists, no task folder) indicate broken enrollment.
$taskBasePath = 'C:\windows\system32\tasks\Microsoft\Windows\EnterpriseMgmt'
$taskGUIDs = @()
if (Test-Path $taskBasePath) {
    $taskGUIDs = @(Get-ChildItem $taskBasePath -EA SilentlyContinue |
        Where-Object { $_.PSIsContainer -and $_.Name -match '^[0-9a-fA-F]{8}-' } |
        Select-Object -ExpandProperty Name)
}

# Enrollment registry GUIDs (from region 2)
$regGUIDs = @($entries | ForEach-Object { $_.GUID })

# Intune-specific enrollment GUIDs (only these should have task folders)
$intuneGUIDs = @($entries | Where-Object { $_.Classification -eq 'IntuneMDM' } | ForEach-Object { $_.GUID })

$diag.ScheduledTasks = [ordered]@{
    EnterpriseMgmtGUIDs = $taskGUIDs
    OrphanedGUIDs       = @($taskGUIDs | Where-Object { $_ -notin $regGUIDs })
    MissingTaskGUIDs    = @($intuneGUIDs | Where-Object { $_ -notin $taskGUIDs })
    PushLaunchExists    = $null -ne (Get-ScheduledTask -TaskPath '\Microsoft\Windows\EnterpriseMgmt\*' -TaskName 'PushLaunch' -EA SilentlyContinue)
}
#endregion

#region 5. Push Notification / WNS Health
# Intune uses WNS for real-time sync. Without it, devices fall back to 8-hour polling.
# CIS Level 2 benchmarks commonly disable these services in financial institutions.
$dmwapSvc = Get-Service -Name dmwappushservice -EA SilentlyContinue
$wpnSvc   = Get-Service -Name WpnService -EA SilentlyContinue

# GPO that kills cloud notifications (CIS L2 recommendation 18.7.1.1)
$noCloud = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -Name NoCloudApplicationNotification -EA SilentlyContinue).NoCloudApplicationNotification

# WpnService start type from registry (Get-Service.StartType can be unreliable for delayed start)
$wpnStart = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WpnService' -Name Start -EA SilentlyContinue).Start

$diag.PushNotifications = [ordered]@{
    DmwappushStatus     = if ($dmwapSvc) { $dmwapSvc.Status.ToString() } else { 'NotInstalled' }
    WpnServiceStatus    = if ($wpnSvc) { $wpnSvc.Status.ToString() } else { 'NotInstalled' }
    NoCloudNotification = $noCloud
    WpnStartType        = $wpnStart
}
#endregion

#region 6. Windows Edition & Subscription Activation
# KB5036980 (April 2024) broke subscription activation — ClipRenew.exe fails with 0x80070005.
# KB5041585 (August 2024, UBR >= 4037) is the production fix.
# Devices stuck on Pro instead of Enterprise can't receive Enterprise-only policies.
$ntVer = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'

# LicenseAcquisition task: LastTaskResult 0x80070005 = the KB5036980 bug is active
$licTask = $null
try {
    $licTask = Get-ScheduledTaskInfo -TaskName 'LicenseAcquisition' -EA SilentlyContinue
} catch {
    # Task info can throw on corrupted task state
}

# Subscription license status via WMI (can be slow ~5-10s on some machines)
$licStatus = $null
try {
    $licProduct = Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" -EA SilentlyContinue |
        Where-Object { $_.PartialProductKey } | Select-Object -First 1
    if ($licProduct) { $licStatus = $licProduct.LicenseStatus }
} catch {
    # CIM query failure — leave as null
}

$diag.WindowsEdition = [ordered]@{
    EditionID            = $ntVer.EditionID
    Build                = $ntVer.CurrentBuild
    UBR                  = [int]$ntVer.UBR
    KB5041585Applied     = ([int]$ntVer.UBR -ge 4037)
    MfaRegKeyExists      = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MfaRequiredInClipRenew'
    LicenseTaskLastResult = if ($licTask) { '0x{0:X}' -f $licTask.LastTaskResult } else { 'TASK_MISSING' }
    LicenseTaskLastRun   = if ($licTask -and $licTask.LastRunTime) { $licTask.LastRunTime.ToString('o') } else { $null }
    LicenseStatus        = $licStatus
}
#endregion

#region 7. SCCM Remnants
# After SCCM/ConfigMgr removal, persistent artifacts cause Intune to report devices
# as "co-managed" when no management authority exists. All remnants should be cleaned.
$hasSccmEnrollment = ($entries | Where-Object { $_.Classification -eq 'SCCM' }).Count -gt 0

$diag.SCCMRemnants = [ordered]@{
    CcmExecService   = $null -ne (Get-Service -Name CcmExec -EA SilentlyContinue)
    CCMRegistryKey   = Test-Path 'HKLM:\SOFTWARE\Microsoft\CCM'
    CCMWmiNamespace  = $null -ne (Get-CimInstance -Query "SELECT * FROM __Namespace WHERE Name='ccm'" -Namespace root -EA SilentlyContinue)
    CCMDirectory     = Test-Path "$env:WinDir\CCM"
    SmsCfgIni        = Test-Path "$env:WinDir\smscfg.ini"
    HasSCCMEnrollment = $hasSccmEnrollment
}
#endregion

#region 8. MDM Certificate Health
# A valid MDM Device CA certificate is required for enrollment to function.
# Missing cert with existing enrollment = broken enrollment.
# Expired cert = enrollment will fail to renew.
$mdmCert = Get-ChildItem 'Cert:\LocalMachine\My' -EA SilentlyContinue |
    Where-Object { $_.Issuer -match 'Microsoft Intune MDM Device CA' } |
    Sort-Object NotAfter -Descending | Select-Object -First 1

$diag.MDMCertificate = [ordered]@{
    Present = $null -ne $mdmCert
    Expiry  = if ($mdmCert) { $mdmCert.NotAfter.ToString('o') } else { $null }
    Valid   = if ($mdmCert) { $mdmCert.NotAfter -gt (Get-Date) } else { $false }
}
#endregion

#region 9. SSL Deep Inspection Spot Check
# Microsoft endpoints use certificate pinning. SSL interception causes errors like
# 0x80072f8f and SecureChannelFailure. Legitimate certs come from Microsoft/DigiCert/
# Baltimore/GlobalSign. Any other issuer (Fortinet, Zscaler, Palo Alto) = interception.
$sslResults = [System.Collections.Generic.List[hashtable]]::new()
foreach ($fqdn in @('manage.microsoft.com', 'login.microsoftonline.com')) {
    $tcp = $null
    $ssl = $null
    try {
        $tcp = New-Object Net.Sockets.TcpClient
        $tcp.SendTimeout = 10000
        $tcp.ReceiveTimeout = 10000
        $tcp.Connect($fqdn, 443)

        $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false)
        $ssl.AuthenticateAsClient($fqdn)
        $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)

        $sslResults.Add([ordered]@{
            Host        = $fqdn
            Issuer      = $cert.Issuer
            Intercepted = $cert.Issuer -notmatch 'Microsoft|DigiCert|Baltimore|GlobalSign'
        })
    } catch {
        $sslResults.Add([ordered]@{
            Host        = $fqdn
            Issuer      = $null
            Intercepted = 'UNKNOWN'
        })
    } finally {
        if ($ssl) { try { $ssl.Dispose() } catch {} }
        if ($tcp) { try { $tcp.Dispose() } catch {} }
    }
}
$diag.SSLInspection = @($sslResults)
#endregion

#region 10. Network Connectivity
# TCP 443 to Intune, Entra, WNS, and device registration endpoints.
# Do NOT test dm.microsoft.com or notify.windows.com — they return SOA only (by design).
$connectivity = [ordered]@{}
foreach ($endpoint in @('manage.microsoft.com', 'login.microsoftonline.com', 'client.wns.windows.com', 'enterpriseregistration.windows.net')) {
    $test = Test-NetConnection -ComputerName $endpoint -Port 443 -WarningAction SilentlyContinue -EA SilentlyContinue
    $connectivity[$endpoint] = if ($test) { $test.TcpTestSucceeded } else { $false }
}
$diag.Connectivity = $connectivity
#endregion

#region 11. GPO Auto-Enrollment Configuration
# AutoEnrollMDM = 1 enables the scheduled task that triggers deviceenroller.exe.
# UseAADCredentialType: 1 = User Credential, 2 = Device Credential.
# Hybrid Entra ID joined devices should use 1 (User Credential).
$mdmGPO = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM' -EA SilentlyContinue

$diag.GPOConfig = [ordered]@{
    AutoEnrollMDM       = if ($mdmGPO) { $mdmGPO.AutoEnrollMDM } else { $null }
    UseAADCredentialType = if ($mdmGPO) { $mdmGPO.UseAADCredentialType } else { $null }
}
#endregion

#region 12. Clock Skew
# Clock skew > 5 minutes breaks Kerberos token validation, causing silent enrollment failures.
# "Local CMOS Clock" or "Free-Running System Clock" = domain time hierarchy is broken.
# Flag skew > 2 minutes as a warning (Kerberos tolerance is 5, but 2+ is concerning).
$timeSource = $null
$skewSeconds = $null
$domainBroken = $false

try {
    $sourceOutput = w32tm /query /source 2>&1
    $timeSource = ($sourceOutput | Select-Object -First 1).ToString().Trim()

    # Check for broken time hierarchy
    if ($timeSource -match 'Local CMOS Clock|Free-Running System Clock') {
        $domainBroken = $true
    }

    # Parse phase offset from w32tm /query /status
    # Output line looks like: "Phase Offset : 0.0012345s"
    $statusOutput = w32tm /query /status 2>&1
    $phaseMatch = $statusOutput | Select-String 'Phase Offset\s*:\s*([-\d.]+)'
    if ($phaseMatch) {
        $skewSeconds = [Math]::Abs([double]$phaseMatch.Matches.Groups[1].Value)
    }
} catch {
    # W32Time service not running or w32tm command failed
    $domainBroken = $true
    if (-not $timeSource) { $timeSource = 'ERROR: W32Time query failed' }
}

$diag.ClockHealth = [ordered]@{
    TimeSource            = $timeSource
    SkewSeconds           = $skewSeconds
    DomainHierarchyBroken = $domainBroken
}
#endregion

#region 13. Recent Enrollment Events
# Event 75 = enrollment succeeded, Event 76 = enrollment failed.
# Use -FilterHashtable for performance (not -MaxEvents with Where-Object post-filter).
# Get-WinEvent THROWS when zero events match — must wrap in try/catch.
$recentEvents = [System.Collections.Generic.List[hashtable]]::new()
try {
    $rawEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
        Id      = 75, 76
    } -MaxEvents 10 -EA Stop
    foreach ($evt in $rawEvents) {
        $recentEvents.Add([ordered]@{
            Time    = $evt.TimeCreated.ToString('o')
            EventID = $evt.Id
            Message = $evt.Message.Substring(0, [Math]::Min(300, $evt.Message.Length))
        })
    }
} catch {
    # No matching events or log not found — this is normal on devices that never attempted enrollment
}
$diag.RecentEvents = @($recentEvents)
#endregion

#region HealthScore Computation
# Single pass through collected data. Each failing condition adds a severity-rated finding.
# Healthy = true only when zero findings of severity CRITICAL, HIGH, or MEDIUM.
# LOW findings are informational and do not affect the Healthy boolean.
$findings = [System.Collections.Generic.List[string]]::new()

# --- CRITICAL ---
if ($diag.Identity.AzureAdPrt -eq 'NO') {
    $findings.Add('CRITICAL: AzureAdPrt is NO - device cannot authenticate to Entra ID')
}
if ($diag.Identity.MdmUrl -eq 'MISSING') {
    $findings.Add('CRITICAL: MdmUrl is MISSING - MDM auto-enrollment will never fire')
}
if ($diag.Enrollment.MmpcEnrollmentFlag -eq 2) {
    $findings.Add('CRITICAL: MmpcEnrollmentFlag is 0x2 - MDE blocking MDM enrollment')
}
if ($diag.Enrollment.ExternallyManaged -eq 1) {
    $findings.Add('CRITICAL: ExternallyManaged is 1 - enrollment engine refuses to enroll')
}

# --- HIGH ---
if (-not $diag.Enrollment.HasValidIntuneMDM) {
    $findings.Add('HIGH: No valid Intune MDM enrollment found')
}
if (-not $diag.IME.ServiceExists) {
    $findings.Add('HIGH: IME service not installed - no Win32 app deployment capability')
}
if (-not $diag.MDMCertificate.Present) {
    $findings.Add('HIGH: MDM Device CA certificate missing - enrollment is broken')
} elseif (-not $diag.MDMCertificate.Valid) {
    $findings.Add('HIGH: MDM Device CA certificate expired - enrollment will fail to renew')
}
if ($diag.PushNotifications.DmwappushStatus -ne 'Running') {
    $findings.Add('HIGH: dmwappushservice not running - device cannot sync with Intune')
}
if ($diag.ClockHealth.DomainHierarchyBroken) {
    $findings.Add('HIGH: Domain time hierarchy broken - clock source is ' + $diag.ClockHealth.TimeSource)
}
$failedEndpoints = @($diag.Connectivity.Keys | Where-Object { -not $diag.Connectivity[$_] })
if ($failedEndpoints.Count -eq $diag.Connectivity.Count -and $diag.Connectivity.Count -gt 0) {
    $findings.Add('HIGH: All connectivity checks failed - device cannot reach any Intune endpoint')
}

# --- MEDIUM ---
if ($diag.Identity.AzureAdJoined -ne 'YES') {
    $findings.Add('MEDIUM: AzureAdJoined is not YES - device may not be hybrid joined')
}
if ($diag.Identity.DomainJoined -ne 'YES') {
    $findings.Add('MEDIUM: DomainJoined is not YES - device may not be domain joined')
}

# SCCM remnants — list which artifacts were found
$sccmArtifacts = @()
if ($diag.SCCMRemnants.CcmExecService)    { $sccmArtifacts += 'CcmExec service' }
if ($diag.SCCMRemnants.CCMRegistryKey)     { $sccmArtifacts += 'CCM registry' }
if ($diag.SCCMRemnants.CCMWmiNamespace)    { $sccmArtifacts += 'CCM WMI namespace' }
if ($diag.SCCMRemnants.CCMDirectory)       { $sccmArtifacts += 'CCM directory' }
if ($diag.SCCMRemnants.SmsCfgIni)          { $sccmArtifacts += 'smscfg.ini' }
if ($diag.SCCMRemnants.HasSCCMEnrollment)  { $sccmArtifacts += 'SCCM enrollment entry' }
if ($sccmArtifacts.Count -gt 0) {
    $findings.Add('MEDIUM: SCCM remnants detected (' + ($sccmArtifacts -join ', ') + ')')
}

if ($diag.PushNotifications.NoCloudNotification -eq 1) {
    $findings.Add('MEDIUM: NoCloudApplicationNotification is 1 - WNS push notifications disabled by GPO')
}
if ($diag.PushNotifications.WpnStartType -eq 4) {
    $findings.Add('MEDIUM: WpnService disabled (StartType 4) - push notifications cannot function')
}
if ($diag.ScheduledTasks.OrphanedGUIDs.Count -gt 0) {
    $findings.Add('MEDIUM: Orphaned EnterpriseMgmt tasks found (' + ($diag.ScheduledTasks.OrphanedGUIDs -join ', ') + ')')
}
if ($diag.ScheduledTasks.MissingTaskGUIDs.Count -gt 0) {
    $findings.Add('MEDIUM: Missing EnterpriseMgmt tasks for enrolled GUIDs (' + ($diag.ScheduledTasks.MissingTaskGUIDs -join ', ') + ')')
}
if (-not $diag.ScheduledTasks.PushLaunchExists -and $diag.Enrollment.HasValidIntuneMDM) {
    $findings.Add('MEDIUM: PushLaunch scheduled task missing - WNS push sync not configured')
}

# SSL interception (only flag if we confirmed interception, not UNKNOWN)
$interceptedHosts = @($diag.SSLInspection | Where-Object { $_.Intercepted -eq $true })
if ($interceptedHosts.Count -gt 0) {
    $hostList = ($interceptedHosts | ForEach-Object { $_.Host }) -join ', '
    $findings.Add("MEDIUM: SSL interception detected on $hostList - may cause enrollment failures")
}

# Individual connectivity failures (only if not already flagged as all-failed)
if ($failedEndpoints.Count -gt 0 -and $failedEndpoints.Count -lt $diag.Connectivity.Count) {
    $findings.Add('MEDIUM: Connectivity failed to ' + ($failedEndpoints -join ', '))
}

if ($diag.GPOConfig.AutoEnrollMDM -ne 1) {
    $findings.Add('MEDIUM: AutoEnrollMDM GPO not configured - automatic MDM enrollment is disabled')
}
if ($diag.ClockHealth.SkewSeconds -ne $null -and $diag.ClockHealth.SkewSeconds -gt 120) {
    $findings.Add('MEDIUM: Clock skew is ' + [Math]::Round($diag.ClockHealth.SkewSeconds, 1) + ' seconds - Kerberos tolerance is 300s')
}

# --- LOW ---
if ($diag.WindowsEdition.EditionID -eq 'Professional') {
    $findings.Add('LOW: Windows Edition is Professional - subscription activation not working')
}
if (-not $diag.WindowsEdition.KB5041585Applied) {
    $findings.Add('LOW: KB5041585 not applied (UBR ' + $diag.WindowsEdition.UBR + ' < 4037) - subscription activation bug may be present')
}
if ($diag.WindowsEdition.MfaRegKeyExists) {
    $findings.Add('LOW: MfaRequiredInClipRenew registry key exists - indicates KB5036980 bug was encountered')
}
if ($diag.WindowsEdition.LicenseTaskLastResult -eq '0x80070005') {
    $findings.Add('LOW: LicenseAcquisition task failed with 0x80070005 (Access Denied) - KB5036980 subscription bug active')
}

# Check for recent enrollment failures (Event ID 76)
$recentFailures = @($diag.RecentEvents | Where-Object { $_.EventID -eq 76 })
if ($recentFailures.Count -gt 0) {
    $findings.Add('LOW: ' + $recentFailures.Count + ' recent enrollment failure event(s) in diagnostic log')
}

# Healthy = no findings of CRITICAL, HIGH, or MEDIUM severity
$nonLowFindings = @($findings | Where-Object { $_ -notmatch '^LOW:' })

$diag.HealthScore = [ordered]@{
    Healthy  = $nonLowFindings.Count -eq 0
    Findings = @($findings)
}
#endregion

#region Output
# Single compressed JSON string to stdout for PSRemoting capture
$json = [PSCustomObject]$diag | ConvertTo-Json -Depth 5 -Compress
Write-Output $json

# Exit code: 0 = healthy, 1 = issues (Proactive Remediation compatible)
exit ([int](-not $diag.HealthScore.Healthy))
#endregion
