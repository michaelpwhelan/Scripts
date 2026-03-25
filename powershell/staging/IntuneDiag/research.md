# Intune MDM enrollment failure diagnostics for hybrid Azure AD joined Windows 11

**Hybrid Azure AD joined devices fail Intune MDM enrollment for at least ten distinct, interlocking reasons** — from phantom MDE device records and orphaned SCCM remnants to CIS benchmark hardening that silently kills push notifications. This report documents every failure pattern with the exact registry paths, error codes, service names, event IDs, and PowerShell commands needed to build a fleet-wide diagnostic script. The information draws from Microsoft Learn documentation, Call4Cloud (Rudy Ooms), scloud.work, oofhours.com, and community-verified troubleshooting patterns confirmed through production deployments.

---

## 1. MDE security settings management creates phantom enrollment records

Microsoft Defender for Endpoint's Security Settings Management (MMP-C) creates **synthetic device identities** that block real Intune MDM enrollment. When a device is onboarded to MDE with Security Settings Management enabled, `SenseCM.exe` performs a synthetic Azure AD registration using a Leviathan token — not a standard AAD token — and creates an Intune device object marked **"Managed by: MDE"**. This enrollment uses `enrollment.dm.microsoft.com` for discovery and `checkin.dm.microsoft.com` for sync, operating entirely outside the normal MDM enrollment pipeline.

The critical blocking mechanism is the **MmpcEnrollmentFlag** registry value at `HKLM\SOFTWARE\Microsoft\Enrollments\MmpcEnrollmentFlag` (DWORD). A value of **0x2** indicates the device was enrolled via MMP-C/Declared Configuration. When this flag persists after the MDE-only record is deleted from the Intune admin center, subsequent auto-enrollment attempts fail with **error 0x80190190** (HTTP 400 Bad Request). The enrollment engine sees the flag and assumes an MMP-C enrollment already exists.

A second blocking mechanism is the **ExternallyManaged** value at `HKLM\SOFTWARE\Microsoft\Enrollments\ExternallyManaged` (DWORD). When set to **1**, the device enrollment engine returns **error 0x80180026**, refusing to enroll because it believes the device is already managed externally.

### Distinguishing real MDM enrollment from MDE stubs

Every enrollment creates a GUID subkey under `HKLM\SOFTWARE\Microsoft\Enrollments\{GUID}`. The key fields that differentiate a healthy Intune enrollment from a stale or MDE-only stub are:

| Registry value | Healthy Intune MDM | MDE-only/Stale |
|---|---|---|
| `ProviderID` | `MS DM Server` | Absent or different |
| `EnrollmentType` | `6` (hybrid AADJ GPO) or `0` (user enrolled) | `14` (local/linked) or missing |
| `DiscoveryServiceFullURL` | `https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc` | `discovery.dm.microsoft.com` or blank |
| `ForceAadToken` | `1` (device credential) | `0` or missing |
| `DMClient\MS DM Server` subkey | Present with `EntDMID` | Absent |

MDE-specific enrollment state lives at `HKLM\SOFTWARE\Microsoft\SenseCM` where `EnrollmentStatus` = **0x1** means MDE-enrolled and **0x4** means the device thinks it's managed by ConfigMgr.

### Remediation commands

```powershell
# Clear the MMP-C enrollment flag
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments" -Name "MmpcEnrollmentFlag" -Value 0 -Type DWord

# Clear ExternallyManaged block
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Enrollments" -Name "ExternallyManaged" -Value 0 -Type DWord

# For full MDE re-registration: offboard from MDE, then delete the SenseCM key
# Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\SenseCM" -Recurse -Force
```

After deleting an MDE-only record from the Intune admin center, the `MmpcEnrollmentFlag` and `SenseCM` registry keys persist on the device. The correct remediation sequence is: offboard from MDE → set `MmpcEnrollmentFlag` to 0 → delete the `SenseCM` registry key → re-onboard to MDE if needed → trigger MDM enrollment.

---

## 2. Intune Management Extension installs only when triggered — and fails silently when blocked

The IME (service name: **`IntuneManagementExtension`**) auto-installs when any of these workloads are assigned to the device or user: **Win32 apps**, **PowerShell platform scripts**, **Proactive Remediations**, **custom compliance scripts**, **Microsoft Store apps** (new winget-based), **Remote Help**, **Managed Installers** (WDAC), or **BIOS update policies**. Without at least one of these assigned, IME never installs — a common oversight when enrollment succeeds but app delivery never starts.

### Prerequisites for IME installation

The device must be enrolled in Intune MDM (verified by `ProviderID = "MS DM Server"` in the enrollment registry), running **Windows 10 1607+** (not Home or S mode), with **.NET Framework 4.7.2+** and **PowerShell 5.1+**. For co-managed devices, the Apps workload must be set to Pilot Intune or Intune. The IME MSI is delivered via the `EnterpriseDesktopAppManagement` CSP, with the download URL stored at `HKLM\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement\S-0-0-00-0000000000-0000000000-000000000-000\MSI\{GUID}\CurrentDownloadUrl`.

### Verifying IME state

| Check | Path/Command |
|---|---|
| Service status | `Get-Service -Name IntuneManagementExtension` |
| Install directory | `C:\Program Files (x86)\Microsoft Intune Management Extension\` |
| Primary log | `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log` |
| Agent executor log | `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AgentExecutor.log` |
| Win32 app log | `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AppWorkload.log` |
| Health check | `C:\Program Files (x86)\Microsoft Intune Management Extension\ClientHealthEval.exe` |
| Script tracking | `HKLM\SOFTWARE\Microsoft\IntuneManagementExtension\SideCarPolicies\Scripts` |
| Win32 app state | `HKLM\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps\<UserGUID>\<AppGUID>` |

### The Microsoft Intune Windows Agent enterprise app

The IME authenticates against a service principal in Entra ID called **"Microsoft Intune Windows Agent"**. When this enterprise application is disabled (Properties → "Enabled for users to sign-in?" = No), the IME cannot acquire tokens and all user-targeted payloads stop working. Apps show **"download pending"** indefinitely, and `IntuneManagementExtension.log` shows `TokenAquireException: Attempt to get token, but failed`. Look in Entra sign-in logs under **non-interactive sign-ins** for the app name with failure reason "Application is disabled." If the app is stuck in a disabled state, Microsoft recommends deleting the service principal via Graph API (`DELETE https://graph.microsoft.com/v1.0/servicePrincipals/{id}`) and allowing it to recreate.

---

## 3. deviceenroller.exe methods, error codes, and event monitoring

Two distinct enrollment methods exist, and using the wrong one is a frequent failure cause. **`deviceenroller.exe /c /AutoEnrollMDM`** uses **user credentials** and requires an active user session — this is the correct method for Azure AD joined devices. **`deviceenroller.exe /c /AutoEnrollMDMUsingAADDeviceCredential`** uses **device credentials** and can run as SYSTEM — this is the correct method for **hybrid Azure AD joined** devices and co-management scenarios. Using the device credential method on a non-hybrid device produces **error 0x80180001**.

The GPO "Enable automatic MDM enrollment using default Azure AD credentials" (`HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM\AutoEnrollMDM` = 1) creates a scheduled task that runs `deviceenroller.exe` every 5 minutes for one day.

### Error code reference

| Error | Meaning | Root cause and fix |
|---|---|---|
| **0x80180026** | ExternallyManaged | `HKLM\...\Enrollments\ExternallyManaged` = 1. Set to 0 |
| **0x8018002b** | Already enrolled / prerequisites unmet | Stale enrollment in registry, user not in MDM scope, or missing Intune license. Clean stale GUIDs under `Enrollments\` |
| **0xCAA9004D** | Token does not exist | Device cannot obtain AAD token. Check hybrid join status, DNS CNAME for `enterpriseregistration.windows.net`, user licensing |
| **0xcaa9001f** | IWA only supported in federation flow | Domain not federated and IWA attempted. Device may have moved out of Entra Connect sync OU. Run `dsregcmd /leave` then rejoin |
| **0x80190190** | HTTP 400 Bad Request | Expired MDM Device CA certificate, stale `MmpcEnrollmentFlag`, or duplicate certificates. Verify cert in `Cert:\LocalMachine\My` with issuer "Microsoft Intune MDM Device CA" |
| **0x8018002a** | Enrollment blocked by Conditional Access | CA policy requiring MFA on "All Cloud Apps" is blocking enrollment. Exclude **Microsoft Intune Enrollment** cloud app from MFA policies |
| **0x80180031** | MDM not configured | Missing MDM enrollment URLs in `HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\<TenantID>`. Write them manually (see remediation below) |
| **0x82aa0008** | Impersonation failure | System proxy not configured. Set proxy via `netsh winhttp set proxy` |

### Event log monitoring

The primary log is `Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin`. **Event ID 75** = enrollment succeeded, **Event ID 76** = enrollment failed (message includes the specific hex error code). Event IDs **90/91** track AAD token retrieval. Query with:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin" |
    Where-Object { $_.Id -in @(75, 76) } | Select-Object TimeCreated, Id, Message
```

**Clock skew** beyond Kerberos' default **5-minute tolerance** causes silent token validation failures that cascade into enrollment failures. Diagnose with `w32tm /stripchart /computer:dc01.domain.com /samples:5` and fix with `w32tm /resync /force`.

---

## 4. EnterpriseMgmt scheduled tasks reveal enrollment health at a glance

After successful enrollment, Windows creates tasks under `\Microsoft\Windows\EnterpriseMgmt\{EnrollmentGUID}\` where the GUID matches the enrollment registry key at `HKLM\SOFTWARE\Microsoft\Enrollments\{GUID}`. The complete task set includes:

- **Schedule #1** — syncs every **3 minutes for 15 minutes** (initial rapid sync)
- **Schedule #2** — syncs every **15 minutes for 2 hours** (settling period)
- **Schedule #3** — syncs every **8 hours** indefinitely (ongoing maintenance sync)
- **Login Schedule** — triggers sync at every user logon
- **PushLaunch** — fires on WNS push notification receipt (WNF state change trigger)
- **PushRenewal** — renews the WNS channel URI (valid 30 days, auto-renews at 15 days)
- **Schedule to run OMADMClient by client/server** — the actual sync executor

Schedules #1, #2, #3, and the Login task are **hidden** from `Get-ScheduledTask` but visible in the filesystem at `C:\windows\system32\tasks\Microsoft\Windows\EnterpriseMgmt\{GUID}\`. PushLaunch, PushRenewal, and PushUpgrade are visible to the cmdlet.

### Detecting orphaned tasks

Orphaned tasks — where the GUID folder exists in Task Scheduler but the corresponding registry entry under `HKLM\SOFTWARE\Microsoft\Enrollments\{GUID}` is missing — indicate a failed or partially cleaned enrollment. These tasks fire but accomplish nothing, creating the illusion of management.

```powershell
$TaskGUIDs = Get-ChildItem "C:\windows\system32\tasks\Microsoft\Windows\EnterpriseMgmt" |
    Where-Object { $_.Name -match "^[0-9a-fA-F]{8}-" } | Select-Object -ExpandProperty Name

$RegGUIDs = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments" |
    Where-Object { $_.PSChildName -match "^[0-9a-fA-F]{8}-" } | Select-Object -ExpandProperty PSChildName

$Orphaned = $TaskGUIDs | Where-Object { $_ -notin $RegGUIDs }
```

---

## 5. WNS and dmwappushservice — when push notifications die, so does real-time management

Intune uses the **Windows Push Notification Service (WNS)** to trigger device check-ins. When an admin clicks "Sync" or a policy changes, Intune sends a raw push notification via WNS, which triggers the **PushLaunch** scheduled task → `deviceenroller.exe` → `OMADMClient.exe` → full SyncML exchange. Without WNS, devices fall back to the **8-hour Schedule #3 sync only** and all real-time features (remote wipe, lock, device query, EPM) stop working.

Two GPO settings silently kill WNS. The **"Turn off notifications network usage"** GPO at `Computer Configuration > Administrative Templates > Start Menu and Taskbar > Notifications` sets `HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications\NoCloudApplicationNotification` to 1. The **WpnService** (Windows Push Notifications System Service) can also be disabled via GPO or directly at `HKLM\SYSTEM\CurrentControlSet\Services\WpnService\Start` = 4.

### CIS Benchmark Level 2 breaks Intune

**CIS Benchmark recommendation 5.34/5.37/5.38 (L2)** explicitly recommends disabling WpnService. **CIS recommendation 18.7.1.1 (L2)** recommends enabling "Turn off notifications network usage." Both break Intune push-initiated sync. Microsoft's own CSP documentation warns: *"This policy may cause some MDM processes to break."* Organizations applying CIS L2 hardening must create exemptions for these two settings.

### dmwappushservice is the MDM sync orchestrator

The **dmwappushservice** (Device Management WAP Push Message Routing Service, default startup: Automatic Delayed Start) orchestrates all MDM sync sessions. When disabled or missing, **the device stops syncing entirely** — both push-initiated and scheduled syncs fail. Error **0x800706D9** appears, and critically, **no errors are logged** in event logs, making diagnosis difficult. The IME, however, continues functioning independently on its own 60-minute polling timer.

Common causes of dmwappushservice being disabled: privacy/hardening scripts (O&O ShutUp10, Disassembler0/Win10-Initial-Setup-Script), CIS/STIG hardening scripts, and administrators who mistake it for a telemetry service. If the registry key is entirely deleted from `HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice`, export it from a healthy device and import.

```powershell
# Verify WNS health
Get-Service -Name WpnService | Select-Object Name, Status, StartType
Get-Service -Name dmwappushservice | Select-Object Name, Status, StartType
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name NoCloudApplicationNotification -EA SilentlyContinue
Get-ScheduledTask | Where-Object { $_.TaskName -eq "PushLaunch" }  # Absent = push is broken
Test-NetConnection -ComputerName client.wns.windows.com -Port 443
```

---

## 6. Azure AD PRT and hybrid join are the foundation — when they break, everything breaks

For a hybrid Azure AD joined device, `dsregcmd /status` must show **AzureAdJoined: YES**, **DomainJoined: YES**, and **AzureAdPrt: YES**. The **MDMUrl** field must contain `https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc` — if blank, auto-enrollment will never occur. MDM URLs are stored at `HKLM\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\<TenantID>` as `MdmEnrollmentUrl`, `MdmTermsOfUseUrl`, and `MdmComplianceUrl`.

**AzureAdPrt = NO** blocks enrollment because the device cannot authenticate silently to Entra ID. Common causes include: the user not having signed in interactively, clock skew exceeding 5 minutes, TPM failures (error **0x80090016** NTE_BAD_KEYSET), network inability to reach `login.microsoftonline.com` in SYSTEM context, and outbound proxy blocking system-context traffic. Fix PRT issues with `dsregcmd /refreshprt` or by locking and unlocking the device.

### Dual device objects cause targeting confusion

When Autopilot pre-registration creates one Entra device object and hybrid Azure AD join creates another, Intune policies may target the wrong object. Detection requires querying Microsoft Graph for duplicate display names:

```powershell
$devices = Get-MgDevice -All
$devices | Group-Object -Property DisplayName | Where-Object { $_.Count -gt 1 } |
    ForEach-Object { $_.Group | Select-Object DisplayName, DeviceId, TrustType, ApproximateLastSignInDateTime }
```

To prevent the "dual state" where domain-joined devices also register as Azure AD Registered, set `HKLM\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin\BlockAADWorkplaceJoin` = 1 (DWORD).

### Entra Connect sync delays

Hybrid join depends on Entra Connect syncing the device's **userCertificate** attribute from on-premises AD. Devices without this attribute are never synced to Entra and remain stuck in "Pending" state. The Service Connection Point (SCP) at `CN=62a0ff2e-97b9-4513-943f-0d221bd30080,CN=Device Registration Configuration,CN=Services` in AD Configuration must contain the correct `azureADId:<TenantID>` keyword. Verify with:

```powershell
Get-ADComputer -Identity "COMPUTERNAME" -Properties userCertificate |
    Select-Object Name, @{N='HasCert'; E={$_.userCertificate.Count -gt 0}}
```

---

## 7. SCCM remnants silently poison Intune enrollment

After SCCM/ConfigMgr client removal, persistent artifacts cause Intune to report devices as "co-managed" when no management authority exists. The **ccmexec** service (SMS Agent Host), `root\ccm` WMI namespace, and registry keys under `HKLM\SOFTWARE\Microsoft\CCM` survive incomplete uninstalls. The co-management handler scans `HKLM\SOFTWARE\Microsoft\Enrollments\` for `DMClient` subkeys and enters **co-existence mode** if it finds non-Intune enrollment entries, disabling workloads.

### Complete SCCM remnant checklist

- **Services**: `CcmExec`, `ccmsetup`, `smstsmgr`, `CmRcService`
- **Registry**: `HKLM\SOFTWARE\Microsoft\CCM`, `HKLM\SOFTWARE\Microsoft\CCMSetup`, `HKLM\SOFTWARE\Microsoft\SMS`, `HKLM\SOFTWARE\Microsoft\SystemCertificates\SMS`
- **WMI namespaces**: `root\ccm`, `root\cimv2\sms`
- **File system**: `C:\Windows\CCM\`, `C:\Windows\CCMSetup\`, `C:\Windows\CCMCache\`, `C:\Windows\smscfg.ini`
- **Certificates**: `Cert:\LocalMachine\SMS`
- **Co-management log**: `C:\Windows\CCM\Logs\CoManagementHandler.log` — look for "This device is enrolled to an unexpected vendor, it will be set in co-existence mode"

SCCM uninstall can also damage the **dmwappushservice** (required for MDM push), causing error **0x80180023**. If the service registry key is missing, export from a healthy device at `HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice` and import.

---

## 8. KB5036980 broke Windows Enterprise subscription activation for four months

The **April 2024 updates** (KB5036893 security and KB5036980 preview) activated a feature called **MFACheckInClipRenew** (feature ID 38124097) in `ClipRenew.exe` (`%SystemRoot%\system32\ClipRenew.exe`), the executable responsible for acquiring subscription activation licenses from `licensing.mp.microsoft.com`. The feature attempted to create a registry key at `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MfaRequiredInClipRenew` with a DWORD value "Verify Multifactor Authentication in ClipRenew" = 0. Because the **LicenseAcquisition** scheduled task at `\Microsoft\Windows\Subscription\LicenseAcquisition` runs as the **interactive user** (not SYSTEM), standard users lack permission to write to HKLM, and the operation fails with **0x80070005** (Access Denied). ClipRenew then aborts the entire license acquisition, causing devices to **revert from Enterprise to Pro** after their 30-day renewal cycle or 90-day grace period.

**KB5041585** (August 13, 2024, builds **22621.4037** / **22631.4037**) was the production fix. It enabled a `HandleAccessDenied` feature flag by default, allowing ClipRenew to bypass the access denied error and continue the license acquisition. The long-term fix in Insider builds moves the registry key from HKLM to HKCU.

### Detecting and verifying subscription activation

```powershell
# Check current edition
$edition = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'EditionID'
# "Professional" = Pro (not activated), "Enterprise" = activated

# Check if the fix KB is installed
$ubr = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'UBR'
$fixed = $ubr -ge 4037  # Build revision from KB5041585

# Check LicenseAcquisition task health
Get-ScheduledTaskInfo -TaskName 'LicenseAcquisition' | Select-Object LastRunTime, LastTaskResult
# LastTaskResult 0x80070005 = the bug is still present

# Check subscription licensing state
Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" |
    Where-Object { $_.PartialProductKey } |
    Select-Object Name, Description, LicenseStatus
# LicenseStatus 1 = Licensed/Activated

# Check if MfaRequiredInClipRenew key exists (the workaround)
Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MfaRequiredInClipRenew'
```

Subscription activation also requires: Windows Pro base edition, **AzureAdPrt = YES**, the user licensed with M365 E3/E5 or Windows Enterprise E3/E5, and the Microsoft Account Sign-in Assistant service (`Wlidsvc`) running. The Conditional Access exclusion for cloud app **45a330b1-b1ec-4cc1-9161-9f03992aa49f** (Universal Store Service APIs) may also be needed.

---

## 9. SSL deep inspection on Microsoft endpoints causes silent, cascading failures

Microsoft explicitly states that **SSL traffic inspection is not supported** on Intune service endpoints. Certificate pinning is used on `*.manage.microsoft.com` and `*.dm.microsoft.com`, and interception produces errors like **0x80072f8f** (WININET_E_DECODING_FAILED), `SecureChannelFailure` in IME logs, and silent MMP-C enrollment failures. The endpoints requiring SSL inspection exemption span seven categories:

- **Intune core**: `*.manage.microsoft.com`, `*.dm.microsoft.com`
- **Authentication**: `login.microsoftonline.com`, `enterpriseregistration.windows.net`, `graph.microsoft.com`
- **WNS**: `*.notify.windows.com`, `*.wns.windows.com`, `client.wns.windows.com`
- **Win32 app CDN**: `swda01-mscdn.manage.microsoft.com` through `swdd02-mscdn.manage.microsoft.com`
- **Device Health Attestation**: `has.spserv.microsoft.com`, `intunemaape*.attest.azure.net`
- **CRL/OCSP**: `crl.microsoft.com`, `crl3.digicert.com`, `ocsp.digicert.com`, `oneocsp.microsoft.com`
- **Store APIs**: `displaycatalog.mp.microsoft.com`, `licensing.mp.microsoft.com`

### Programmatic SSL inspection detection

```powershell
function Test-SSLInspection {
    param([string]$FQDN, [int]$Port = 443)
    try {
        $tcp = New-Object Net.Sockets.TcpClient($FQDN, $Port)
        $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false)
        $ssl.AuthenticateAsClient($FQDN)
        $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        [PSCustomObject]@{
            Host         = $FQDN
            Issuer       = $cert.Issuer
            SSLInspected = $cert.Issuer -notmatch "Microsoft|DigiCert|Baltimore|GlobalSign"
        }
        $ssl.Dispose(); $tcp.Dispose()
    } catch {
        [PSCustomObject]@{ Host = $FQDN; Error = $_.Exception.Message; SSLInspected = "CONNECTION_FAILED" }
    }
}

@("manage.microsoft.com","login.microsoftonline.com","dm.microsoft.com","client.wns.windows.com") |
    ForEach-Object { Test-SSLInspection -FQDN $_ } | Format-Table Host, Issuer, SSLInspected
```

Legitimate Microsoft certificate chains root to **DigiCert Global Root G2**, **Baltimore CyberTrust Root**, or **Microsoft RSA Root Certificate Authority 2017** with intermediates from **Microsoft Azure RSA TLS Issuing CA**. Any other issuer (Zscaler, Palo Alto, Fortinet) indicates SSL inspection is active.

---

## 10. Fleet-wide diagnostic script architecture

Three deployment patterns suit different scenarios: **Invoke-Command via PSRemoting** for immediate fleet scans, **Intune Proactive Remediations** for ongoing monitoring (detection script only, no remediation), and **Intune Custom Compliance Scripts** for compliance-gated diagnostics. All diagnostic scripts should be strictly read-only — using only `Get-*`, `Test-*`, `Get-ItemProperty`, `Get-CimInstance`, `Get-WinEvent`, and `Get-Service` cmdlets.

For PSRemoting deployment, WinRM must be enabled on targets (port 5985), and Kerberos authentication handles domain-joined environments without credential delegation. Use `-ThrottleLimit` to control parallel connections (default 32) and `-AsJob` for large fleets. Every result should include `$env:COMPUTERNAME` and a UTC timestamp for correlation.

### Comprehensive fleet diagnostic script

The following script covers all ten diagnostic areas and outputs structured JSON suitable for fleet aggregation:

```powershell
<#
.SYNOPSIS
    Intune MDM Enrollment Health Diagnostic — Fleet Assessment Script
.DESCRIPTION
    Read-only diagnostic covering all major enrollment failure patterns.
    Deploy via Invoke-Command, Intune Platform Script, or Proactive Remediation.
    Outputs structured JSON. Run as SYSTEM for full registry access.
#>

$diag = [ordered]@{ ComputerName = $env:COMPUTERNAME; Timestamp = (Get-Date -Format 'o') }

#region --- Device Identity & Hybrid Join ---
$dsreg = dsregcmd /status 2>&1
$diag.AzureAdJoined  = ($dsreg | Select-String "AzureAdJoined\s*:\s*(\w+)").Matches.Groups[1].Value
$diag.DomainJoined   = ($dsreg | Select-String "DomainJoined\s*:\s*(\w+)").Matches.Groups[1].Value
$diag.AzureAdPrt     = ($dsreg | Select-String "AzureAdPrt\s*:\s*(\w+)").Matches.Groups[1].Value
$mdmUrlMatch = $dsreg | Select-String "MdmUrl\s*:\s*(.+)"
$diag.MdmUrl = if ($mdmUrlMatch) { $mdmUrlMatch.Matches.Groups[1].Value.Trim() } else { "MISSING" }
#endregion

#region --- OS Edition & Subscription Activation ---
$ntVer = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$diag.EditionID     = $ntVer.EditionID
$diag.CurrentBuild  = $ntVer.CurrentBuild
$diag.UBR           = $ntVer.UBR
$diag.KB5041585Fix  = ($ntVer.UBR -ge 4037)
$diag.MfaRegKeyExists = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\MfaRequiredInClipRenew'

$licTask = Get-ScheduledTaskInfo -TaskName 'LicenseAcquisition' -EA SilentlyContinue
$diag.LicenseTaskLastResult = if ($licTask) { '0x{0:X}' -f $licTask.LastTaskResult } else { "TASK_MISSING" }
$diag.LicenseTaskLastRun    = if ($licTask) { $licTask.LastRunTime.ToString('o') } else { $null }
#endregion

#region --- MDM Enrollment Registry ---
$mmpcFlag = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Enrollments" -Name MmpcEnrollmentFlag -EA SilentlyContinue).MmpcEnrollmentFlag
$extManaged = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Enrollments" -Name ExternallyManaged -EA SilentlyContinue).ExternallyManaged
$diag.MmpcEnrollmentFlag = $mmpcFlag
$diag.ExternallyManaged  = $extManaged

$enrollments = @()
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments" -EA SilentlyContinue |
    Where-Object { $_.PSChildName -match '^[{(]?[0-9a-fA-F]{8}' } | ForEach-Object {
    $p = Get-ItemProperty $_.PSPath -EA SilentlyContinue
    $enrollments += [ordered]@{
        GUID           = $_.PSChildName
        ProviderID     = $p.ProviderID
        EnrollmentType = $p.EnrollmentType
        DiscoveryURL   = $p.DiscoveryServiceFullURL
        UPN            = $p.UPN
    }
}
$diag.Enrollments = $enrollments
$diag.HasIntuneEnrollment = ($enrollments | Where-Object { $_.ProviderID -eq 'MS DM Server' }).Count -gt 0
#endregion

#region --- EnterpriseMgmt Scheduled Tasks ---
$taskGUIDs = @(Get-ChildItem "C:\windows\system32\tasks\Microsoft\Windows\EnterpriseMgmt" -EA SilentlyContinue |
    Where-Object { $_.Name -match "^[0-9a-fA-F]{8}-" } | Select-Object -ExpandProperty Name)
$regGUIDs = @(Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments" -EA SilentlyContinue |
    Where-Object { $_.PSChildName -match "^[0-9a-fA-F]{8}-" } | Select-Object -ExpandProperty PSChildName)

$diag.EnterpriseMgmtTaskGUIDs = $taskGUIDs
$diag.OrphanedTaskGUIDs = @($taskGUIDs | Where-Object { $_ -notin $regGUIDs })
$diag.PushLaunchExists = $null -ne (Get-ScheduledTask -EA SilentlyContinue | Where-Object { $_.TaskName -eq 'PushLaunch' })
#endregion

#region --- Key Services ---
$services = @('IntuneManagementExtension','dmwappushservice','WpnService','CcmExec','Wlidsvc')
$svcResults = @{}
foreach ($svc in $services) {
    $s = Get-Service -Name $svc -EA SilentlyContinue
    $svcResults[$svc] = if ($s) { "$($s.Status)/$($s.StartType)" } else { "NotInstalled" }
}
$diag.Services = $svcResults
#endregion

#region --- WNS / Push Notification Health ---
$noCloud = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name NoCloudApplicationNotification -EA SilentlyContinue).NoCloudApplicationNotification
$diag.NoCloudApplicationNotification = $noCloud
$wpnStart = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WpnService" -Name Start -EA SilentlyContinue).Start
$diag.WpnServiceStartType = $wpnStart  # 2=Auto, 3=Manual, 4=Disabled
#endregion

#region --- SCCM Remnants ---
$diag.SCCMRemnants = [ordered]@{
    CcmExecService  = $null -ne (Get-Service -Name CcmExec -EA SilentlyContinue)
    CCMRegistryKey  = Test-Path "HKLM:\SOFTWARE\Microsoft\CCM"
    CCMWmiNamespace = $null -ne (Get-CimInstance -Query "SELECT * FROM __Namespace WHERE Name='ccm'" -Namespace root -EA SilentlyContinue)
    CCMDirectory    = Test-Path "$env:WinDir\CCM"
    SmsCfgIni       = Test-Path "$env:WinDir\smscfg.ini"
}
#endregion

#region --- MDM Certificate ---
$mdmCert = Get-ChildItem "Cert:\LocalMachine\My" -EA SilentlyContinue |
    Where-Object { $_.Issuer -match "Microsoft Intune MDM Device CA" } |
    Sort-Object NotAfter -Descending | Select-Object -First 1
$diag.MDMCertPresent = $null -ne $mdmCert
$diag.MDMCertExpiry  = if ($mdmCert) { $mdmCert.NotAfter.ToString('o') } else { $null }
$diag.MDMCertValid   = if ($mdmCert) { $mdmCert.NotAfter -gt (Get-Date) } else { $false }
#endregion

#region --- Recent Enrollment Events ---
$events = @()
Get-WinEvent -LogName "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin" -MaxEvents 10 -EA SilentlyContinue |
    Where-Object { $_.Id -in @(75, 76) } | ForEach-Object {
    $events += [ordered]@{
        Time    = $_.TimeCreated.ToString('o')
        EventID = $_.Id
        Message = $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length))
    }
}
$diag.RecentEnrollmentEvents = $events
#endregion

#region --- SSL Inspection Spot Check ---
$sslCheck = @()
foreach ($host_ in @("manage.microsoft.com","login.microsoftonline.com")) {
    try {
        $tcp = New-Object Net.Sockets.TcpClient($host_, 443)
        $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false)
        $ssl.AuthenticateAsClient($host_)
        $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
        $sslCheck += [ordered]@{
            Host = $host_; Issuer = $cert.Issuer
            Intercepted = $cert.Issuer -notmatch "Microsoft|DigiCert|Baltimore|GlobalSign"
        }
        $ssl.Dispose(); $tcp.Dispose()
    } catch {
        $sslCheck += [ordered]@{ Host = $host_; Error = $_.Exception.Message; Intercepted = "UNKNOWN" }
    }
}
$diag.SSLInspection = $sslCheck
#endregion

#region --- Connectivity ---
$connectivity = @{}
foreach ($ep in @("manage.microsoft.com","login.microsoftonline.com","client.wns.windows.com","enterpriseregistration.windows.net")) {
    $t = Test-NetConnection -ComputerName $ep -Port 443 -WarningAction SilentlyContinue -EA SilentlyContinue
    $connectivity[$ep] = $t.TcpTestSucceeded
}
$diag.Connectivity = $connectivity
#endregion

#region --- GPO MDM Auto-Enrollment Config ---
$mdmGPO = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM" -EA SilentlyContinue
$diag.AutoEnrollMDM = $mdmGPO.AutoEnrollMDM
$diag.UseAADCredentialType = $mdmGPO.UseAADCredentialType  # 1=User, 2=Device
#endregion

#region --- SenseCM (MDE Attach) ---
$senseCM = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\SenseCM" -EA SilentlyContinue
$diag.SenseCMEnrollmentStatus = $senseCM.EnrollmentStatus
#endregion

#region --- Output ---
$json = [PSCustomObject]$diag | ConvertTo-Json -Depth 5 -Compress
Write-Output $json

# Exit code for Proactive Remediation: 0=healthy, 1=issues
$healthy = ($diag.AzureAdJoined -eq 'YES') -and ($diag.AzureAdPrt -eq 'YES') -and
           $diag.HasIntuneEnrollment -and $diag.MDMCertValid -and
           ($diag.MmpcEnrollmentFlag -ne 2) -and ($diag.ExternallyManaged -ne 1) -and
           ($diag.OrphanedTaskGUIDs.Count -eq 0) -and $diag.PushLaunchExists -and
           ($svcResults['dmwappushservice'] -like 'Running*') -and
           ($noCloud -ne 1)
exit ([int](-not $healthy))
#endregion
```

### Fleet aggregation via PSRemoting

```powershell
$computers = (Get-ADComputer -Filter "Enabled -eq 'True'" -SearchBase "OU=Workstations,DC=contoso,DC=com").Name
$results = Invoke-Command -ComputerName $computers -FilePath ".\IntuneDiagnostic.ps1" -ThrottleLimit 50 -EA Continue

$parsed = $results | ForEach-Object { $_ | ConvertFrom-Json }
$parsed | ConvertTo-Json -Depth 6 | Out-File "FleetHealth_$(Get-Date -Format yyyyMMdd).json"
$parsed | Select-Object ComputerName, AzureAdJoined, AzureAdPrt, HasIntuneEnrollment, EditionID,
    MmpcEnrollmentFlag, ExternallyManaged, PushLaunchExists,
    @{N='IME'; E={$_.Services.IntuneManagementExtension}},
    @{N='dmwappush'; E={$_.Services.dmwappushservice}},
    MDMCertValid, KB5041585Fix |
    Export-Csv "FleetHealthSummary_$(Get-Date -Format yyyyMMdd).csv" -NoTypeInformation
```

For ongoing monitoring, deploy the diagnostic script as an **Intune Proactive Remediation** (detection script only, run every 24 hours). Results are visible per-device in the Intune portal, queryable via Graph API at `deviceManagement/deviceHealthScripts/{id}/deviceRunStates`, and can be forwarded to a **Log Analytics workspace** using the Azure Monitor HTTP Data Collector API for KQL querying across the fleet.

---

## Conclusion: a decision tree for enrollment failure triage

The diagnostic script above produces a JSON payload that enables automated triage. The highest-value checks, in order of diagnostic power, are: **AzureAdPrt = NO** (blocks everything downstream), **MdmUrl = MISSING** (enrollment never initiates), **MmpcEnrollmentFlag = 0x2** (blocks re-enrollment after MDE record deletion), **ExternallyManaged = 1** (hard block on enrollment), **dmwappushservice disabled** (kills all sync silently), **NoCloudApplicationNotification = 1** (kills push notifications), **SCCM remnants present** (causes false co-management state), **orphaned EnterpriseMgmt tasks** (creates the illusion of management without actual policy application), and **SSL inspection on Microsoft endpoints** (causes SecureChannelFailure errors in IME). The KB5041585 fix check and LicenseAcquisition task result catch the subscription activation regression that silently demotes Enterprise to Pro. Running this diagnostic across a fleet will surface the specific failure pattern affecting each device, enabling targeted remediation rather than the common but destructive approach of full re-enrollment.