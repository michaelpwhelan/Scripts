# CFCU — IT Environment Reference

> **DLP Notice:** This document is intentionally sanitized for use with external AI
> assistants on personal accounts. It contains no hostnames, IP addresses, credentials,
> member data, or internal network specifics. It describes architecture patterns,
> product names, and versions only.

---

## Organization Context

- **Type:** Credit union (referred to as "CFCU" in AI sessions)
- **IT org size:** Small — fewer than 10 IT staff
- **Primary IT role:** Sysadmin / Network Engineer
- **Regulatory body:** NCUA
- **Examination framework:** FFIEC IT Examination Handbook
- **Microsoft licensing:** M365 E5 (includes Entra ID P2, Defender for Endpoint P2,
  Defender for Identity, Purview, full audit logging stack)

---

## Site Structure

CFCU operates a hub-and-spoke topology across multiple branch locations. Sites are
referred to by three-digit codes internally.

| Site | Role |
|---|---|
| 009 | Primary datacenter / hub |
| 012 | DR site / secondary failover branch; future merge target for 013 and 112 |
| 001 | Main branch location; contains server infrastructure; primary spoke |
| 002, 003, 007, 011, 014, 018 | Standard branch spokes |
| 013, 112 | Active spokes; pending merge into 012 when new facility opens |

- **009** is the primary hub and hosts the majority of server and network infrastructure
- **001** is an operationally significant spoke with local server presence
- **012** serves dual purpose as DR site and active branch
- Centralized routing model — traffic is funneled through hub to minimize the number
  of IP addresses exposed to vendors

---

## Network Topology & WAN

- **Design:** Hub-and-spoke; 009 as primary hub, 012 as secondary/DR hub
- **WAN redundancy:**
  - Hubs (009, 012): Dual-WAN with two ISPs (fiber primary, cable/coax secondary)
  - Spokes: Dual-WAN with wired ISP + WWAN (4G/LTE) failover
- **SD-WAN:** FortiOS SD-WAN (`virtual-wan-link`) with SLA-based health checks;
  prefers primary WAN over secondary WAN or WWAN; automatic steering based on
  link quality
- **WAN circuit types in use:** Fiber, cable/coax, 4G/LTE (WWAN failover at branches)
- **Overlay:** IKEv2 IPsec tunnels (route-based, interface mode) with PSK
  authentication; hub-to-spoke and spoke-to-hub; spokes communicate via hub
  (no direct spoke-to-spoke / no ADVPN)
- **Routing protocol:** iBGP between FortiGates for overlay routing; static routes
  supplement where needed
- **Firewall platform:** Fortinet FortiGate — **FortiOS 7.6.x**
- **Firewall management:** FortiManager (all policy pushes centralized; no local
  policy overrides at branches; single VDOM architecture)
- **Log aggregation:** FortiAnalyzer (primary log store and reporting; de facto SIEM —
  no dedicated SIEM platform currently deployed)
- **Internet traffic:** Split tunnel — branches break out locally for internet traffic;
  not all traffic hairpinned through hub

---

## LAN Infrastructure

### Switching
- **Primary fleet:** Fortinet FortiSwitches across all sites, managed via
  FortiLink from FortiGate/FortiManager
- **Secondary:** ~2 Ubiquiti UniFi switches in limited deployment, managed via
  UniFi controller
- **No Layer 3 distribution switches** — all inter-VLAN routing handled at FortiGate

### VLANs
- VLANs are centrally defined and pushed from FortiManager to all FortiGates
- Mostly overlapping VLAN IDs across sites (consistent design)
- Key VLANs include (at minimum):
  - Server VLAN
  - Voice / VoIP VLAN
  - Employee workstation VLAN
  - Kiosk VLAN (isolated)
  - Guest / member WiFi VLAN (planned: DHCP moved to FortiGate for isolation)

### Wireless
- **Hardware:** FortiAP access points exclusively; managed via FortiGate/FortiManager
- **SSIDs:**

| SSID | Purpose | Notes |
|---|---|---|
| CFCU_Internal | Employee wireless | Corporate network access |
| CFCU_Public | Member-facing WiFi | Guest/public segment |
| CFCU_Conference | Conference room wireless | Likely isolated segment |
| CFCU_Kiosk | Kiosk devices | Hidden SSID; isolated |

---

## DHCP Architecture

- **Primary:** Windows DHCP server handles most VLANs; FortiGates relay via
  IP helper to centralized Windows DHCP
- **FortiLink exception:** FortiGate acts as DHCP server for FortiLink/FortiSwitch
  management segment
- **Planned change:** CFCU_Public (member WiFi) DHCP to be migrated from Windows
  to FortiGate — security decision to isolate member devices from touching
  core Windows infrastructure

---

## DNS Architecture

- **Resolvers:** Internal Windows DNS servers (AD-integrated)
- **RODC dependency:** Branch sites use Read-Only Domain Controllers (RODCs) as
  local DNS resolvers; conditional forwarders route specific zones to MDT
  (core banking DNS dependency)
- **DNS flow:** Client → local RODC → conditional forwarder to MDT for
  banking-related zones → standard AD DNS for internal zones
- **No public DNS (8.8.8.8 / 1.1.1.1) used internally**
- **No FortiGuard DNS filtering or DoH blocking confirmed**
- **Split DNS:** Effectively yes — internal zones via AD DNS, banking zones
  via MDT forwarders

---

## Core Infrastructure Services (On-Premises)

| Service | Platform | Notes |
|---|---|---|
| DNS | Windows Server (AD-integrated) + RODCs at branches | Conditional forwarders to MDT |
| DHCP | Windows Server (primary) + FortiGate (FortiLink segment) | Public WiFi migration planned |
| RADIUS / NAC | Windows NPS (Network Policy Server) | 802.1X enforcement |
| Certificate Authority | Two-tier PKI | Offline Root CA + online Issuing CA |
| NTP | AD-inherited | No dedicated NTP appliance |
| IPAM | None | No IPAM platform in use |
| Syslog | FortiAnalyzer | No standalone syslog server |

**PKI detail:** Two-tier CA hierarchy — air-gapped/offline Root CA for trust anchor,
online Issuing CA for day-to-day certificate operations. Internal certificates
likely used for infrastructure auth and 802.1X.

**NPS/RADIUS:** Windows NPS hosted on-prem; no FortiAuthenticator; no confirmed
RADIUS redundancy — single point of failure risk worth noting.

---

## FortiGate Security Profiles

All managed centrally via FortiManager. Active profiles include:

| Profile | Status |
|---|---|
| Web filtering | Active (FortiGuard categories) |
| Application control | Active |
| IPS / IDS | Active |
| SSL deep inspection | Active |
| Antivirus (perimeter) | Active |
| DNS filtering | Not confirmed |

---

## Server Infrastructure

- **Datacenter model:** On-premises only — no Azure IaaS/PaaS, no AWS
- **Primary datacenter:** Site 009
- **Secondary/DR compute:** Site 012; server presence also at Site 001
- **Physical servers:** Bare metal in use alongside virtualized workloads
- **Virtualization:** Microsoft Hyper-V (no VMware/vSphere)
- **Storage:** NAS / SAN (specific vendor not documented here)
- **Power:** UPS / PDU management at datacenter sites
- **Server OS fleet:**
  - Windows Server 2022 (primary)
  - Windows Server 2019 (legacy/mixed)
  - Ubuntu Linux (version varies by workload)

---

## Endpoint Infrastructure

- **Primary OS:** Windows 11
- **Hardware:** Standard workstations and Surface Pro devices
- **Mobile/tablet:** Branch tablet rollout in progress (Surface Pro, Windows 11)
- **Endpoint management:** Co-managed — Group Policy (GPO) + Microsoft Intune
- **Patching:** WSUS (on-prem Windows Server Update Services)
- **No thin clients, kiosk workstations, or third-party patching tools**

---

## Identity & Access Management

- **On-prem directory:** Active Directory with Group Policy; RODCs deployed
  at branch sites
- **Cloud identity:** Entra ID P2 (via M365 E5)
- **Sync:** Entra Connect (AD → Entra ID hybrid sync)
- **Endpoint join type:** Hybrid Entra ID join
- **MFA:** Microsoft Authenticator / Entra MFA
- **Conditional Access:** Policies deployed
- **Endpoint MDM:** Microsoft Intune (co-managed with GPO)
- **Network access control:** RADIUS / 802.1X via Windows NPS
- **Privileged identity:** Entra ID P2 includes PIM and Identity Protection
- **No Okta, Duo, RSA, or third-party IdP**

---

## Security Stack & Tooling

| Layer | Product | Notes |
|---|---|---|
| Firewall / NGFW | FortiGate (FortiOS 7.6.x) | All sites |
| SD-WAN | FortiOS SD-WAN | IKEv2 IPsec overlays, iBGP |
| Firewall management | FortiManager | Centralized; all policy pushes |
| Log aggregation / de facto SIEM | FortiAnalyzer | No Sentinel/Splunk deployed |
| EDR / AV | Microsoft Defender AV | Built-in, Intune-managed |
| XDR | Microsoft Defender for Endpoint P2 | M365 E5 |
| Identity threat detection | Microsoft Defender for Identity | M365 E5; monitors AD |
| Data protection / DLP | Microsoft Purview | M365 E5 |
| Wireless security | FortiAP + FortiGate policies | SSID-to-VLAN isolation |
| Perimeter AV/IPS/filtering | FortiGate security profiles | Web filter, app control, IPS, SSL inspect, AV |

**Notable gaps / future considerations:**
- No dedicated SIEM (Microsoft Sentinel available via E5 but not deployed)
- No IPAM platform
- No FortiAuthenticator — NPS is sole RADIUS; no confirmed redundancy
- PSK-based IPsec auth (no certificate-based tunnel auth)
- Public WiFi DHCP still on Windows server (migration planned)

---

## Monitoring & Alerting

| Tool | Coverage | Method |
|---|---|---|
| Zabbix | FortiGates | SNMP (migration to HTTP API planned) |
| Zabbix | FortiSwitches | SNMP (migration to HTTP API planned) |
| Zabbix | Windows servers | Zabbix agent |
| UptimeRobot | Public-facing services | External HTTP/ping checks |
| FortiAnalyzer | Firewall logs and events | Log correlation and reporting |

**Alerting flow:**
- Zabbix triggers → email alerts
- Zabbix triggers → osTicket API → auto-creates helpdesk tickets
- UptimeRobot → email alerts

**Planned improvement:** Migrate Zabbix network monitoring from SNMP polling to
FortiGate/FortiSwitch HTTP API for richer and more reliable data.

---

## Email, Collaboration & File Storage

| Service | Platform |
|---|---|
| Email | Exchange Online (M365) — fully cloud, no on-prem Exchange |
| Collaboration | Microsoft Teams |
| Cloud file storage | SharePoint Online + OneDrive (M365) |
| On-prem file storage | On-premises Windows file servers |

- Hybrid file storage posture — on-prem shares coexist with SharePoint/OneDrive
- Migration to cloud file storage likely ongoing or partial

---

## Backup & Disaster Recovery

- **Backup platform:** Veeam Backup & Replication (on-prem)
- **Primary backup target:** On-premises storage at 009 and 012
- **Secondary/offsite target:** Backblaze B2 (immutable cloud destination)
- **Strategy:** 3-2-1 (3 copies, 2 media types, 1 offsite)
- **DR site:** Site 012 (active branch + secondary failover)
- **Immutability:** Backblaze B2 configured as immutable — ransomware resilient
- **Testing:** Backup testing and DR drills performed regularly

---

## Vendor & Third-Party Dependencies

| Vendor | Product | Role |
|---|---|---|
| Fortinet | FortiGate / FortiOS 7.6.x | Firewall, SD-WAN, IPsec, wireless controller |
| Fortinet | FortiManager | Centralized firewall, switch, and AP management |
| Fortinet | FortiAnalyzer | Log aggregation, reporting, de facto SIEM |
| Fortinet | FortiSwitch | LAN switching (primary fleet) |
| Fortinet | FortiAP | Wireless access points |
| Ubiquiti | UniFi switches | Limited deployment (~2 switches) |
| Microsoft | M365 E5 | Productivity, security, identity, compliance |
| Microsoft | Entra ID P2 | Hybrid identity, Conditional Access, PIM |
| Microsoft | Intune | MDM/MAM endpoint management |
| Microsoft | Defender for Endpoint P2 | EDR/XDR |
| Microsoft | Defender for Identity | AD/hybrid identity threat detection |
| Microsoft | Purview | DLP, compliance, data governance |
| Microsoft | Exchange Online | Email |
| Microsoft | SharePoint / OneDrive | Cloud file storage and collaboration |
| Microsoft | Teams | Internal collaboration |
| Microsoft | Hyper-V | Server virtualization |
| Microsoft | WSUS | On-prem Windows patching |
| Microsoft | NPS | RADIUS / 802.1X enforcement |
| Jack Henry | Symitar | Core banking platform (critical dependency) |
| MDT | (product TBD) | Secondary banking/operations vendor; DNS dependency via conditional forwarders |
| Veeam | Veeam Backup & Replication | On-prem backup orchestration |
| Backblaze | Backblaze B2 | Immutable offsite cloud backup target |
| Zabbix | Zabbix | Internal network and infrastructure monitoring |
| UptimeRobot | UptimeRobot | External uptime and availability monitoring |
| LastPass | LastPass Business | Org-wide password management |
| Snipe-IT | Snipe-IT | IT asset inventory |
| osTicket | osTicket | Helpdesk ticketing; receives alerts from Zabbix via API |

---

## Compliance & Security Program

| Element | Status |
|---|---|
| NCUA annual IT examination | Active — subject to regular exam cycle |
| FFIEC IT Examination Handbook | Governing framework |
| GLBA / FTC Safeguards Rule | Applicable — information security program required |
| Incident Response Plan (IRP) | Formally in place |
| Business Continuity / DR Plan | Formally in place |
| Vendor / third-party risk assessments | Formally in place |
| Penetration testing / vulnerability scanning | Performed periodically |
| Written Information Security Program (WISP) | Not confirmed as standalone document |
| PCI-DSS | Not in scope |
| HIPAA | Not in scope |
| SOC audit | Not in scope |

**Key third-party risk focus:** Jack Henry (Symitar) and MDT are critical dependencies
with direct access to core banking data and member records. MDT also serves as a DNS
dependency via conditional forwarders. Vendor risk assessments are conducted per
NCUA/FFIEC guidance.

---

## IT Operations Tooling Summary

| Function | Tool |
|---|---|
| Helpdesk / ticketing | osTicket (receives Zabbix alerts via API) |
| Network monitoring | Zabbix (SNMP → API migration planned) + UptimeRobot |
| Asset inventory | Snipe-IT |
| Password management | LastPass |
| Remote admin access | Internal RDP jumpbox |
| Firewall / network management | FortiManager |
| Log review and reporting | FortiAnalyzer |
| Endpoint management | Intune + GPO (co-managed) |
| Backup management | Veeam console |
| Patching | WSUS |

---

## What This Document Is Safe To Share

This document is appropriate for use in external AI tools on personal accounts
because it contains:

- ✅ Product names and versions
- ✅ Architecture patterns and topology descriptions
- ✅ Site roles (by anonymous numeric code only — no names, addresses, or geography)
- ✅ Vendor relationships (publicly known)
- ✅ Regulatory and compliance context (publicly known obligations)
- ✅ Security program posture (high-level only)
- ✅ Known gaps and planned improvements (no exploitable specifics)

It does **not** contain:

- ❌ Hostnames, FQDNs, or IP addresses
- ❌ Credentials, API keys, or secrets
- ❌ Internal network diagrams or subnet details
- ❌ Member or employee data of any kind
- ❌ Org-specific configuration details or firewall rules
- ❌ Security vulnerabilities, open findings, or audit results
- ❌ Physical addresses or identifiable location details
- ❌ Staffing names or org chart details
