# Intune Fleet Health Diagnostic — Claude Code Build Spec

## What This Is

A specification for building a PowerShell-based fleet diagnostic tool that assesses
Intune MDM enrollment health across all Windows endpoints at CFCU (a small credit
union). This was born from a single-device troubleshooting session that uncovered
at least six distinct, interlocking failure patterns — all of which are suspected
to affect multiple devices fleet-wide.

The goal is a **diagnostic and reporting tool**, not a remediation tool. It identifies
what's broken on each machine and produces structured output for triage. Remediation
comes later, after we know the scope.

---

## Who This Is For

Michael — sysadmin/network engineer, small IT team (<10 people). He's technically
sharp but Intune is inherited infrastructure he didn't build. His techs are the ones
feeling the pain daily. He needs to understand the state of his fleet before he can
fix it.

**Communication style:** Casual, direct, no fluff. Code should be well-commented.
He works under DLP constraints — the script must never collect or output hostnames,
IPs, credentials, or member data beyond what's needed for diagnostics.

---

## Environment Context

- **Endpoints:** Windows 11, mix of Dell and HP hardware
- **Licensing:** Microsoft 365 E5 (Entra ID P2, Defender for Endpoint P2, Intune P1)
- **Identity:** Hybrid Azure AD joined via Entra Connect. On-prem AD with GPO + RODCs
- **Management:** Co-managed GPO + Intune (no SCCM/ConfigMgr, but SCCM remnants exist
  on some machines from a previous deployment)
- **Patching:** WSUS (decommission to WUfB planned but not started)
- **Firewall:** FortiGate with SSL deep inspection (Microsoft endpoints exempted)
- **Endpoint security:** FortiClient EMS 7.2 + Microsoft Defender for Endpoint P2
- **Sites:** Hub-and-spoke, 10+ branch locations, all with FortiGate/FortiSwitch/FortiAP
- **Autopilot:** Hardware hashes registered but OOBE enrollment not consistently used
- **Regulatory:** NCUA/FFIEC — endpoint management is examinable

---

## The Problem Space

### What we discovered on a single device (Dell OptiPlex 7060)

A device registered in Autopilot never completed MDM enrollment. It had an MDE-only
stub in Intune (no primary user, no IME, no real management). Troubleshooting revealed
SIX stacked failure conditions:

1. **MmpcEnrollmentFlag = 0x2** — MDE Security Settings Management had created a
   phantom enrollment that blocked real MDM auto-enrollment
2. **No IME-triggering policy assigned** — even after enrollment succeeded, IME never
   installed because no Win32 app or PowerShell script was targeted at the device
3. **Clock skew (10 minutes behind)** — broke Kerberos token validation, causing
   silent enrollment failures and poisoning all enrollment attempts during the skew
4. **deviceenroller.exe run as admin account** — error 0xCAA9004D because the admin
   account lacked an Intune license / valid AAD token for enrollment
5. **SCCM remnants** — WMI_Bridge_SCCM_Server enrollment type present, causing Intune
   to report the device as "co-managed" with ConfigMgr despite no SCCM infrastructure
6. **Windows 11 Enterprise subscription expired** — showing Pro instead of Enterprise
   because the broken enrollment prevented subscription activation renewal

### What we suspect fleet-wide

- Multiple devices with MDE-only stubs instead of real MDM enrollment
- Devices stuck on Windows 11 Pro due to KB5036980 subscription activation bug
- WNS push notifications possibly disabled by CIS Level 2 hardening GPO
- SCCM remnants on machines from a previous deployment
- Inconsistent Autopilot state (registered but not OOBE-enrolled)

---

## What To Build

### Deliverable 1: Fleet Diagnostic Script (`Invoke-IntuneHealthCheck.ps1`)

A single PowerShell script that runs on any Windows 11 endpoint and checks all known
enrollment failure patterns. Must be:

- **Read-only** — no registry writes, no service changes, no remediation actions
- **Safe to run on production endpoints** during business hours
- **Runnable as SYSTEM** (for Intune Proactive Remediation deployment) or as admin
- **Output: JSON** to stdout, one object per machine, structured for aggregation
- **Exit code:** 0 = healthy, 1 = issues detected (for Proactive Remediation compat)
- **Well-commented** — Michael's team needs to understand what each check does and why

#### Diagnostic checks (in priority order)

**1. Device Identity & Hybrid Join Health**
- Parse `dsregcmd /status` for: AzureAdJoined, DomainJoined, AzureAdPrt, MDMUrl,
  TenantId, DeviceId
- AzureAdPrt = NO is the highest-severity finding (blocks everything)
- MDMUrl blank means auto-enrollment will never fire
- Flag if device is Azure AD Registered instead of Hybrid Joined

**2. MDM Enrollment Registry Analysis**
- Enumerate all GUIDs under `HKLM:\SOFTWARE\Microsoft\Enrollments\`
- For each: capture ProviderID, EnrollmentType, EnrollmentState,
  DiscoveryServiceFullURL, UPN
- Classify each enrollment as: Intune MDM, MDE-only, SCCM, Azure AD Join,
  Device Credential, Unknown
- Check MmpcEnrollmentFlag (0x2 = blocking)
- Check ExternallyManaged (1 = blocking)
- Check SenseCM enrollment status at `HKLM:\SOFTWARE\Microsoft\SenseCM`

**3. Intune Management Extension Status**
- Service existence and state: IntuneManagementExtension
- Install directory exists: `C:\Program Files (x86)\Microsoft Intune Management Extension\`
- Log directory exists: `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\`
- Check if MSI was downloaded but not installed:
  `C:\Windows\System32\config\systemprofile\AppData\Local\mdm\`

**4. EnterpriseMgmt Scheduled Tasks**
- Enumerate task GUIDs under `C:\windows\system32\tasks\Microsoft\Windows\EnterpriseMgmt`
- Cross-reference against enrollment registry GUIDs
- Flag orphaned tasks (task exists, no matching enrollment)
- Flag missing tasks (enrollment exists, no matching tasks)
- Check for PushLaunch task specifically (indicates WNS integration)

**5. Push Notification / WNS Health**
- Service status: dmwappushservice (must be Running/Automatic)
- Service status: WpnService (must be Running/Automatic)
- GPO check: `HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications`
  NoCloudApplicationNotification (1 = push disabled, breaks Intune real-time sync)
- WpnService start type from registry (4 = disabled)
- Note: CIS Level 2 benchmarks commonly disable these in financial institutions

**6. Windows Edition & Subscription Activation**
- Current EditionID (Professional vs Enterprise)
- Current build + UBR (to determine if KB5041585 fix is applied: UBR >= 4037)
- MfaRequiredInClipRenew registry key existence
- LicenseAcquisition scheduled task: last run time, last result
  (0x80070005 = the KB5036980 bug is present)
- License status via SoftwareLicensingProduct WMI

**7. SCCM Remnants**
- Service: CcmExec (SMS Agent Host)
- Registry: `HKLM:\SOFTWARE\Microsoft\CCM`
- WMI namespace: `root\ccm`
- Filesystem: `C:\Windows\CCM\`, `C:\Windows\smscfg.ini`
- Any enrollment with WMI_Bridge_SCCM_Server provider
- CoManagementHandler.log existence

**8. MDM Certificate Health**
- Check `Cert:\LocalMachine\My` for certs issued by "Microsoft Intune MDM Device CA"
- Flag expired certs
- Flag missing certs (enrollment exists but no cert = enrollment is broken)

**9. SSL Deep Inspection Spot Check**
- Test certificate chain on manage.microsoft.com and login.microsoftonline.com
- Flag if issuer is NOT Microsoft/DigiCert/Baltimore/GlobalSign
- This is relevant because CFCU runs FortiGate SSL deep inspection

**10. Network Connectivity**
- TCP 443 test to: manage.microsoft.com, login.microsoftonline.com,
  client.wns.windows.com, enterpriseregistration.windows.net
- DNS resolution test for same endpoints
- Note: dm.microsoft.com and notify.windows.com are parent domains that
  intentionally return SOA only — do NOT flag these as failures

**11. GPO Auto-Enrollment Configuration**
- `HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM`
  AutoEnrollMDM value and UseAADCredentialType value
- 1 = User Credential (standard for hybrid join)
- 2 = Device Credential (co-management/AVD only)

**12. Clock Skew**
- Compare local time against `w32tm /query /source` and `w32tm /query /status`
- Flag if source is "Local CMOS Clock" or "Free-Running System Clock"
  (means domain time hierarchy is broken)
- Flag skew > 2 minutes (Kerberos tolerance is 5, but 2+ is warning-worthy)

**13. Recent Enrollment Events**
- Pull last 10 events with ID 75 (success) or 76 (failure) from
  Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin
- Include timestamp and truncated message

#### Output Schema

```json
{
  "ComputerName": "string",
  "Timestamp": "ISO8601",
  "Identity": {
    "AzureAdJoined": "YES|NO",
    "DomainJoined": "YES|NO",
    "AzureAdPrt": "YES|NO",
    "MdmUrl": "string|MISSING",
    "TenantId": "string|MISSING"
  },
  "Enrollment": {
    "MmpcEnrollmentFlag": "number|null",
    "ExternallyManaged": "number|null",
    "SenseCMStatus": "number|null",
    "Entries": [
      {
        "GUID": "string",
        "ProviderID": "string|null",
        "EnrollmentType": "number",
        "Classification": "IntuneMDM|MDEOnly|SCCM|AzureADJoin|DeviceCredential|Unknown",
        "UPN": "string|null",
        "DiscoveryURL": "string|null"
      }
    ],
    "HasValidIntuneMDM": "boolean"
  },
  "IME": {
    "ServiceExists": "boolean",
    "ServiceStatus": "string|null",
    "InstallDirExists": "boolean",
    "MSIDownloaded": "boolean"
  },
  "ScheduledTasks": {
    "EnterpriseMgmtGUIDs": ["string"],
    "OrphanedGUIDs": ["string"],
    "MissingTaskGUIDs": ["string"],
    "PushLaunchExists": "boolean"
  },
  "PushNotifications": {
    "DmwappushStatus": "string",
    "WpnServiceStatus": "string",
    "NoCloudNotification": "number|null",
    "WpnStartType": "number"
  },
  "WindowsEdition": {
    "EditionID": "string",
    "Build": "string",
    "UBR": "number",
    "KB5041585Applied": "boolean",
    "MfaRegKeyExists": "boolean",
    "LicenseTaskLastResult": "string",
    "LicenseTaskLastRun": "string|null",
    "LicenseStatus": "number|null"
  },
  "SCCMRemnants": {
    "CcmExecService": "boolean",
    "CCMRegistryKey": "boolean",
    "CCMWmiNamespace": "boolean",
    "CCMDirectory": "boolean",
    "SmsCfgIni": "boolean",
    "HasSCCMEnrollment": "boolean"
  },
  "MDMCertificate": {
    "Present": "boolean",
    "Expiry": "string|null",
    "Valid": "boolean"
  },
  "SSLInspection": [
    {
      "Host": "string",
      "Issuer": "string|null",
      "Intercepted": "boolean|UNKNOWN"
    }
  ],
  "Connectivity": {
    "manage.microsoft.com": "boolean",
    "login.microsoftonline.com": "boolean",
    "client.wns.windows.com": "boolean",
    "enterpriseregistration.windows.net": "boolean"
  },
  "GPOConfig": {
    "AutoEnrollMDM": "number|null",
    "UseAADCredentialType": "number|null"
  },
  "ClockHealth": {
    "TimeSource": "string",
    "SkewSeconds": "number|null",
    "DomainHierarchyBroken": "boolean"
  },
  "RecentEvents": [
    {
      "Time": "string",
      "EventID": "number",
      "Message": "string"
    }
  ],
  "HealthScore": {
    "Healthy": "boolean",
    "Findings": ["string"]
  }
}
```

#### Health Score Logic

The `HealthScore.Healthy` field should be `true` only when ALL of these are true:
- AzureAdJoined = YES AND DomainJoined = YES AND AzureAdPrt = YES
- MdmUrl is not MISSING
- HasValidIntuneMDM = true
- MmpcEnrollmentFlag != 2
- ExternallyManaged != 1
- IME service exists and is Running
- MDM certificate is present and valid (not expired)
- dmwappushservice is Running
- WpnService is Running
- NoCloudApplicationNotification != 1
- No orphaned EnterpriseMgmt tasks
- PushLaunch task exists
- No SCCM remnants (all false)
- No SSL interception detected
- All connectivity checks pass
- Clock source is not Local CMOS / Free-Running

The `HealthScore.Findings` array should contain human-readable strings for every
failed check, e.g.:
- "CRITICAL: AzureAdPrt is NO — device cannot authenticate to Entra ID"
- "HIGH: MmpcEnrollmentFlag is 0x2 — MDE blocking MDM enrollment"
- "HIGH: IME service not installed — no Win32 app deployment capability"
- "MEDIUM: SCCM remnants detected (CcmExec service, CCM registry key)"
- "LOW: Windows Edition is Professional — subscription activation not working"

Use severity levels: CRITICAL, HIGH, MEDIUM, LOW.

---

### Deliverable 2: Fleet Aggregation Script (`Invoke-FleetScan.ps1`)

A wrapper script that runs Deliverable 1 across multiple endpoints via PSRemoting
and aggregates results.

- Accept input: list of computer names (from AD query, CSV, or parameter)
- Run `Invoke-IntuneHealthCheck.ps1` via `Invoke-Command` with `-ThrottleLimit 50`
- Parse JSON output from each machine
- Produce two outputs:
  1. **Full JSON** — complete diagnostic data for all machines
  2. **Summary CSV** — one row per machine with key health indicators:
     ComputerName, AzureAdPrt, HasIntuneMDM, IMEInstalled, EditionID,
     MmpcFlag, ExternallyManaged, SCCMRemnants, PushHealthy, MDMCertValid,
     SSLIntercepted, ClockHealthy, Healthy, FindingsCount, TopFinding
- Handle unreachable machines gracefully (log as "UNREACHABLE" in output)
- Default AD query: all enabled computer objects in workstation OUs

---

### Deliverable 3: Fleet Health Summary Report (`New-FleetHealthReport.ps1`)

Takes the output from Deliverable 2 and generates a human-readable report. Format
should be Michael's preferred printable format: **compact black-and-white HTML** with
Courier New monospace, bordered sections, checkbox squares for action items.

Report sections:
1. **Executive Summary** — total devices scanned, healthy count, unhealthy count,
   unreachable count, top 3 most common findings
2. **Finding Distribution** — count of devices affected by each finding, sorted by
   severity then count
3. **Device Detail** — one row per unhealthy device showing hostname, all findings,
   and recommended next step
4. **Recommended Actions** — prioritized list of fleet-wide fixes based on finding
   frequency, with estimated impact (number of devices fixed)

---

## Technical Notes for Claude Code

### Things that matter
- Script must work over PSRemoting (no WMI/WMIC — use Get-CimInstance instead)
- `dsregcmd /status` output parsing needs regex — the format is `  KeyName : Value`
  with variable whitespace
- The EnterpriseMgmt scheduled tasks are partially hidden from `Get-ScheduledTask` —
  must check the filesystem at `C:\windows\system32\tasks\` directly
- SSL inspection check uses `Net.Sockets.TcpClient` and `Net.Security.SslStream` —
  this works over PSRemoting but can timeout on slow links, needs try/catch
- Clock skew check: `w32tm /query /source` returns the NTP source as a string. 
  "Local CMOS Clock" and "Free-Running System Clock" mean domain time is broken.
  For skew measurement, parse `w32tm /query /status` for "Phase Offset"
- Some checks touch `HKLM:\SOFTWARE\Microsoft\SenseCM` which only exists on
  MDE-onboarded devices — always wrap in `-ErrorAction SilentlyContinue`
- EnrollmentType values: 0=user, 2=device credential GPO, 6=hybrid AADJ GPO, 
  14=MDE/local, 18=Azure AD join, 32=device credential
- dm.microsoft.com and notify.windows.com return SOA only (no A record) — this is
  normal. Do NOT include these in connectivity checks.

### Things to avoid
- No remediation actions of any kind — this is diagnostic only
- No collection of actual IP addresses, hostnames beyond computer name, or user data
- No dependency on external modules (Az, Microsoft.Graph, etc.) — pure built-in
  PowerShell only
- No internet access required from the script itself (SSL check connects to 
  Microsoft endpoints but that's existing traffic, not new)
- Don't use `wmic` — it's deprecated and fails over PSRemoting (we learned this
  the hard way today)

### Reference material
- The deep research artifact in this conversation has the complete technical details
  for every check, including exact registry paths, event IDs, error codes, and
  enrollment type classifications
- Michael's environment.md (in the project) has the full infrastructure context
- The intune-improvement-plan-handoff.md (already created) covers the broader
  improvement roadmap this diagnostic feeds into

---

## Success Criteria

The diagnostic tool is successful when Michael can:
1. Run it against his entire fleet in under 30 minutes
2. Get a clear picture of how many devices have each failure pattern
3. Prioritize remediation work based on finding frequency and severity
4. Use the report to justify the Intune improvement plan to his boss
5. Re-run it after remediation to measure progress

The report should be defensible in an NCUA/FFIEC exam context — it demonstrates
systematic assessment of endpoint management health, which is exactly what examiners
want to see.
