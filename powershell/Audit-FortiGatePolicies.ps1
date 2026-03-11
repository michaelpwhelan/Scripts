<#
.SYNOPSIS
    Audits a FortiGate configuration backup for policy risks, system hardening
    gaps, VPN weaknesses, and hygiene issues.

.DESCRIPTION
    Parses a FortiGate .conf backup file offline and runs ~36 security checks
    across five domains:

      Policy analysis     — shadow rules, overly permissive rules, disabled
                            policies, logging gaps, missing security profiles,
                            missing SSL inspection, any-interface usage, missing
                            policy comments, deny rules without logging, IPv6
                            policy gaps, UTM profile depth (monitor-only AV/IPS)
      Object hygiene      — duplicate addresses, overly broad subnets, unused
                            address/service objects, overlapping subnets, address
                            and service group hygiene (orphaned members, empty
                            groups, deep nesting)
      System hardening    — admin trusted-hosts & MFA, insecure interface services,
                            password policy, SNMP defaults, DNS/NTP config,
                            central logging, global crypto settings, insecure LDAP,
                            expired schedules, certificate checks (default certs,
                            weak SSL inspection profiles)
      VPN configuration   — weak IKE/IPsec crypto, deprecated DH groups, IKEv1
                            usage, SSL VPN hardening
      Infrastructure      — VIP interface exposure, local-in policies, HA
                            encryption, firmware version / known CVEs, routing
                            protocol authentication (BGP/OSPF), DoS policy
                            coverage on WAN interfaces

    Findings are rated by severity (CRITICAL / HIGH / MEDIUM / LOW / INFO) and
    exported to a timestamped CSV.  An optional self-contained HTML report can
    be generated for stakeholder distribution.  A color-coded summary is printed
    to the console.

.NOTES
    Author:       Michael Whelan
    Created:      2026-03-11
    Dependencies: None (stdlib only). Requires a FortiGate .conf backup file.

.PARAMETER ConfigFile
    Path to a FortiGate .conf backup file. Overrides $Config.ConfigFile.

.EXAMPLE
    .\Audit-FortiGatePolicies.ps1 -ConfigFile .\backups\fw01.conf
    Audits the specified config file.

.EXAMPLE
    .\Audit-FortiGatePolicies.ps1
    Audits the config file specified in $Config.ConfigFile (default: firewall.conf).
#>
#Requires -Version 5.1
param(
    [string]$ConfigFile
)

# =============================================================================
# CONFIGURATION
# =============================================================================
$Config = @{
    ScriptName            = "Audit-FortiGatePolicies"
    LogDir                = "$PSScriptRoot\logs"
    OutputDir             = "$PSScriptRoot\output"

    # --- Input (override with -ConfigFile parameter) ---
    ConfigFile            = "firewall.conf"

    # --- Policy checks ---
    CheckShadowRules      = $true
    CheckPermissiveRules  = $true
    CheckDisabledPolicies = $true
    CheckLoggingDisabled  = $true
    CheckDenyNoLogging    = $true    # Deny rules with logging off
    CheckMissingProfiles  = $true    # IPS, AV, Web Filter, App Control
    CheckMissingSSL       = $true    # Accept rules without ssl-ssh-profile
    CheckAnyInterface     = $true    # Policies using "any" interface
    CheckMissingComments  = $true    # Accept policies with no comments
    CheckIPv6Policies     = $true    # IPv6 policy gap detection
    CheckUTMProfileDepth  = $true    # UTM profile effectiveness (monitor-only, weak settings)

    # --- Object hygiene ---
    CheckDuplicateAddrs   = $true
    CheckBroadAddresses   = $true
    CheckUnusedAddresses  = $true
    CheckOverlappingAddrs = $true    # Subnet containment detection
    CheckUnusedServices   = $true    # Service objects not in any policy
    CheckGroupHygiene     = $true    # Address/service group member validation

    # --- System hardening ---
    CheckAdminSecurity    = $true    # Trusted-hosts
    CheckAdminMFA         = $true    # Two-factor auth
    CheckInterfaceAccess  = $true    # HTTP/Telnet/SNMP on interfaces
    CheckPasswordPolicy   = $true
    CheckSNMP             = $true    # Default community strings
    CheckLoggingConfig    = $true    # Syslog / FortiAnalyzer
    CheckGlobalSettings   = $true    # strong-crypto, timeouts, banner
    CheckDnsNtp           = $true
    CheckInsecureLDAP     = $true    # LDAP without SSL/TLS
    CheckExpiredSchedules = $true    # One-time schedules past end date
    CheckCertificates     = $true    # SSL inspection profiles & default certs

    # --- VPN ---
    CheckVpnCrypto        = $true    # Weak IKE/IPsec crypto
    CheckSSLVPN           = $true    # SSL VPN hardening

    # --- Infrastructure ---
    CheckVipInterface     = $true    # VIPs with extintf "any"
    CheckLocalInPolicies  = $true    # Missing local-in policies
    CheckHASecurity       = $true    # HA without encryption
    CheckFirmware         = $true    # Known-vulnerable firmware
    CheckRoutingAuth      = $true    # BGP/OSPF authentication
    CheckDoSPolicies      = $true    # DoS policy coverage on WAN interfaces

    # --- Shadow detection ---
    ShadowSameInterfaceOnly = $true

    # --- Broad-subnet threshold ---
    BroadSubnetMaxPrefix  = 8

    # --- Reporting ---
    GenerateHtmlReport    = $true
}
# =============================================================================

# --- Parameter override ---
if ($ConfigFile) { $Config.ConfigFile = $ConfigFile }

# --- Logging setup ---
$Script:LogFile = $null
if ($Config.LogDir) {
    if (-not (Test-Path $Config.LogDir)) {
        New-Item -ItemType Directory -Path $Config.LogDir | Out-Null
    }
    $Script:LogFile = Join-Path $Config.LogDir (
        "{0}_{1}.log" -f $Config.ScriptName, (Get-Date -Format "yyyyMMdd_HHmmss")
    )
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR")][string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"
    switch ($Level) {
        "INFO"    { Write-Host $line -ForegroundColor Cyan }
        "WARNING" { Write-Host $line -ForegroundColor Yellow }
        "ERROR"   { Write-Host $line -ForegroundColor Red }
    }
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $line }
}

function Write-Summary {
    param([string]$Line, [string]$Color = "White")
    Write-Host $Line -ForegroundColor $Color
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $Line }
}

# =============================================================================
# PARSERS
# =============================================================================

function ConvertTo-FortiSections {
    <#  Parses a FortiGate config file into a hashtable of top-level sections.
        Tracks nesting depth so inner config/end pairs are captured as content.  #>
    param([string]$FilePath)
    $sections = @{}
    $key      = $null
    $lines    = [System.Collections.Generic.List[string]]::new()
    $depth    = 0
    foreach ($raw in [System.IO.File]::ReadLines($FilePath)) {
        $trimmed = $raw.TrimEnd()
        if ($trimmed -match '^config ' -and $depth -eq 0) {
            $key = $trimmed; $depth = 1; $lines.Clear()
        }
        elseif ($trimmed -match '^config ' -and $depth -gt 0) {
            $depth++; $lines.Add($trimmed)
        }
        elseif ($trimmed -eq 'end' -and $depth -eq 1) {
            $sections[$key] = $lines.ToArray(); $depth = 0; $key = $null
        }
        elseif ($trimmed -eq 'end' -and $depth -gt 1) {
            $depth--; $lines.Add($trimmed)
        }
        elseif ($depth -gt 0) { $lines.Add($trimmed) }
    }
    return $sections
}

function ConvertTo-EditBlocks {
    <#  Generic parser for edit/next blocks within a section.  Handles nested
        config/end blocks (e.g. config hosts inside snmp community) by tracking
        sub-depth and skipping inner content.  #>
    param([string[]]$Lines)
    $blocks   = [System.Collections.Generic.List[hashtable]]::new()
    $current  = $null
    $subDepth = 0
    foreach ($raw in $Lines) {
        $trimmed = $raw.Trim()
        if ($null -ne $current -and $trimmed -match '^config ' -and $subDepth -ge 0) {
            $subDepth++; continue
        }
        if ($subDepth -gt 0 -and $trimmed -eq 'end') { $subDepth--; continue }
        if ($subDepth -gt 0) { continue }
        if ($trimmed -match '^\s*edit\s+"?([^"]+)"?\s*$') {
            $current = @{ '_id' = $Matches[1] }; $subDepth = 0; continue
        }
        if ($trimmed -eq 'next' -and $null -ne $current) {
            $blocks.Add($current); $current = $null; $subDepth = 0; continue
        }
        if ($null -ne $current -and $trimmed -match '^\s*set\s+(\S+)\s+(.+)$') {
            $field = $Matches[1]; $value = $Matches[2]
            $quotedValues = [regex]::Matches($value, '"([^"]*)"')
            if ($quotedValues.Count -gt 0) {
                $parsed = @($quotedValues | ForEach-Object { $_.Groups[1].Value })
                $current[$field] = if ($parsed.Count -eq 1) { $parsed[0] } else { $parsed }
            } else {
                $current[$field] = $value.Trim()
            }
        }
    }
    return ,$blocks
}

function ConvertTo-PolicyObjects {
    <#  Parses firewall policy section lines into an ordered list of policy
        hashtables with well-known fields and defaults.  #>
    param([string[]]$Lines)
    $policies  = [System.Collections.Generic.List[hashtable]]::new()
    $current   = $null
    $arrayKeys = @('srcintf','dstintf','srcaddr','dstaddr','service','groups')
    foreach ($raw in $Lines) {
        $trimmed = $raw.Trim()
        if ($trimmed -match '^\s*edit\s+(\d+)\s*$') {
            $current = @{
                policyid = [int]$Matches[1]; name = ""; srcintf = @(); dstintf = @()
                srcaddr = @(); dstaddr = @(); service = @(); action = "deny"
                status = "enable"; logtraffic = "disable"; 'utm-status' = "disable"
                'av-profile' = ""; 'webfilter-profile' = ""; 'ips-sensor' = ""
                'application-list' = ""; 'ssl-ssh-profile' = ""; 'dnsfilter-profile' = ""
                'inspection-mode' = ""; schedule = "always"; comments = ""
                groups = @(); nat = "disable"
            }
            continue
        }
        if ($trimmed -eq 'next' -and $null -ne $current) {
            $policies.Add($current); $current = $null; continue
        }
        if ($null -ne $current -and $trimmed -match '^\s*set\s+(\S+)\s+(.+)$') {
            $field = $Matches[1]; $value = $Matches[2]
            $quotedValues = [regex]::Matches($value, '"([^"]*)"')
            if ($quotedValues.Count -gt 0) {
                $parsed = @($quotedValues | ForEach-Object { $_.Groups[1].Value })
                if ($field -in $arrayKeys) {
                    $current[$field] = $parsed
                } elseif ($current.ContainsKey($field)) {
                    $current[$field] = if ($parsed.Count -eq 1) { $parsed[0] } else { $parsed -join " " }
                }
            } else {
                $scalar = $value.Trim()
                if ($field -in $arrayKeys) {
                    $current[$field] = @($scalar)
                } elseif ($current.ContainsKey($field)) {
                    $current[$field] = $scalar
                }
            }
        }
    }
    return ,$policies
}

function ConvertTo-AddressObjects {
    <#  Parses firewall address section into a hashtable keyed by object name.  #>
    param([string[]]$Lines)
    $addresses = @{}; $current = $null; $currentName = $null
    foreach ($raw in $Lines) {
        $trimmed = $raw.Trim()
        if ($trimmed -match '^\s*edit\s+"([^"]+)"') {
            $currentName = $Matches[1]
            $current = @{ name = $currentName; subnet = ""; type = "ipmask"; fqdn = "" }
            continue
        }
        if ($trimmed -eq 'next' -and $null -ne $current) {
            $addresses[$currentName] = $current
            $current = $null; $currentName = $null; continue
        }
        if ($null -ne $current -and $trimmed -match '^\s*set\s+(\S+)\s+(.+)$') {
            $current[$Matches[1]] = $Matches[2].Trim().Trim('"')
        }
    }
    return $addresses
}

function Get-FirmwareInfo {
    <#  Parses the #config-version header line to extract model, version, and
        build number.  Returns a hashtable or $null if unparseable.  #>
    param([string]$FilePath)
    $firstLine = [System.IO.File]::ReadLines($FilePath) |
        Select-Object -First 1
    if ($firstLine -match '#config-version=(\S+?)-(\d+\.\d+\.\d+)-FW-build(\d+)-(\d+)') {
        return @{
            Model   = $Matches[1]
            Version = $Matches[2]
            Build   = $Matches[3]
            Date    = $Matches[4]
            Raw     = $firstLine
        }
    }
    return $null
}

# =============================================================================
# HELPERS
# =============================================================================

function Test-PolicyCovers {
    <#  Returns $true if policy Q fully covers policy P on all traffic dimensions.  #>
    param([hashtable]$PolicyQ, [hashtable]$PolicyP)
    foreach ($dim in @('srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'service')) {
        $qValues = @($PolicyQ[$dim] | ForEach-Object { $_.ToLower() })
        $pValues = @($PolicyP[$dim] | ForEach-Object { $_.ToLower() })
        if ($qValues -contains 'all' -or $qValues -contains 'any') { continue }
        foreach ($pv in $pValues) {
            if ($qValues -notcontains $pv) { return $false }
        }
    }
    return $true
}

function New-Finding {
    param([string]$Severity, [string]$Category, $PolicyId, [string]$PolicyName,
          [string]$Detail, [string]$Recommendation)
    $Script:FindingCounter++
    return [PSCustomObject]@{
        FindingId      = "F{0:D3}" -f $Script:FindingCounter
        Severity       = $Severity
        Category       = $Category
        PolicyId       = $PolicyId
        PolicyName     = $PolicyName
        Detail         = $Detail
        Recommendation = $Recommendation
    }
}

function Get-SectionOrEmpty {
    param([hashtable]$Sections, [string]$Key)
    if ($Sections.ContainsKey($Key)) { return $Sections[$Key] } else { return @() }
}

function Get-SubnetPrefix {
    <#  Extracts prefix length from a FortiGate subnet string like "10.0.0.0 255.0.0.0".  #>
    param([string]$Subnet)
    $parts = $Subnet -split '\s+'
    if ($parts.Count -lt 2) { return -1 }
    try {
        $bits = 0
        foreach ($o in ($parts[1].Split('.') | ForEach-Object { [int]$_ })) {
            $b = [convert]::ToString($o, 2)
            $bits += ($b.ToCharArray() | Where-Object { $_ -eq '1' }).Count
        }
        return $bits
    } catch { return -1 }
}

function Get-SubnetNetwork {
    <#  Returns the network address and prefix from a FortiGate subnet string
        as a tuple @(networkUint32, prefixLen) for containment checks.  #>
    param([string]$Subnet)
    $parts = $Subnet -split '\s+'
    if ($parts.Count -lt 2) { return $null }
    try {
        $ipOctets   = $parts[0].Split('.') | ForEach-Object { [int]$_ }
        $maskOctets = $parts[1].Split('.') | ForEach-Object { [int]$_ }
        $ip   = ([uint32]$ipOctets[0] -shl 24) -bor ([uint32]$ipOctets[1] -shl 16) -bor
                ([uint32]$ipOctets[2] -shl 8) -bor [uint32]$ipOctets[3]
        $mask = ([uint32]$maskOctets[0] -shl 24) -bor ([uint32]$maskOctets[1] -shl 16) -bor
                ([uint32]$maskOctets[2] -shl 8) -bor [uint32]$maskOctets[3]
        $bits = 0
        foreach ($o in $maskOctets) {
            $b = [convert]::ToString($o, 2)
            $bits += ($b.ToCharArray() | Where-Object { $_ -eq '1' }).Count
        }
        return @(($ip -band $mask), $bits)
    } catch { return $null }
}

function Test-SubnetContains {
    <#  Returns $true if subnet A fully contains subnet B.
        Both are FortiGate subnet strings ("10.0.0.0 255.0.0.0").  #>
    param([string]$SubnetA, [string]$SubnetB)
    $a = Get-SubnetNetwork -Subnet $SubnetA
    $b = Get-SubnetNetwork -Subnet $SubnetB
    if ($null -eq $a -or $null -eq $b) { return $false }
    # A contains B if A's prefix is shorter AND B's network masked by A's mask equals A's network
    if ($a[1] -ge $b[1]) { return $false }  # A must be broader
    $aMask = if ($a[1] -eq 0) { [uint32]0 } else { ([uint32]::MaxValue) -shl (32 - $a[1]) }
    return (($b[0] -band $aMask) -eq $a[0])
}

function Compare-FortiVersion {
    <#  Compares two FortiOS version strings.  Returns -1 if A < B, 0 if equal, 1 if A > B.  #>
    param([string]$VersionA, [string]$VersionB)
    $a = $VersionA -split '\.' | ForEach-Object { [int]$_ }
    $b = $VersionB -split '\.' | ForEach-Object { [int]$_ }
    for ($i = 0; $i -lt [Math]::Max($a.Count, $b.Count); $i++) {
        $va = if ($i -lt $a.Count) { $a[$i] } else { 0 }
        $vb = if ($i -lt $b.Count) { $b[$i] } else { 0 }
        if ($va -lt $vb) { return -1 }
        if ($va -gt $vb) { return  1 }
    }
    return 0
}

# =============================================================================
# POLICY CHECKS
# =============================================================================

function Find-ShadowRules {
    param([System.Collections.Generic.List[hashtable]]$Policies)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    for ($p = 1; $p -lt $Policies.Count; $p++) {
        $policyP = $Policies[$p]
        if ($policyP['status'] -eq 'disable') { continue }
        for ($q = 0; $q -lt $p; $q++) {
            $policyQ = $Policies[$q]
            if ($policyQ['status'] -eq 'disable') { continue }
            if ($Config.ShadowSameInterfaceOnly) {
                $sameSrc = (($policyQ['srcintf'] | Sort-Object) -join ',') -eq (($policyP['srcintf'] | Sort-Object) -join ',')
                $sameDst = (($policyQ['dstintf'] | Sort-Object) -join ',') -eq (($policyP['dstintf'] | Sort-Object) -join ',')
                if (-not ($sameSrc -and $sameDst)) { continue }
            }
            if ($policyQ['action'] -ne $policyP['action']) { continue }
            if (Test-PolicyCovers -PolicyQ $policyQ -PolicyP $policyP) {
                $detail = "Policy $($policyP['policyid']) is fully shadowed by policy $($policyQ['policyid']) ($($policyQ['name']))"
                $findings.Add((New-Finding -Severity "CRITICAL" -Category "Shadow Rule" `
                    -PolicyId $policyP['policyid'] -PolicyName $policyP['name'] `
                    -Detail $detail -Recommendation "Review and remove shadowed policy or adjust scope"))
                break
            }
        }
    }
    return ,$findings
}

function Find-PermissiveRules {
    param([System.Collections.Generic.List[hashtable]]$Policies)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($pol in $Policies) {
        if ($pol['action'] -ne 'accept' -or $pol['status'] -eq 'disable') { continue }
        $srcAll = @($pol['srcaddr'] | ForEach-Object { $_.ToLower() }) -contains 'all'
        $dstAll = @($pol['dstaddr'] | ForEach-Object { $_.ToLower() }) -contains 'all'
        $svcAll = @($pol['service'] | ForEach-Object { $_.ToLower() }) -contains 'all'
        $noUtm  = $pol['utm-status'] -ne 'enable'
        if ($srcAll -and $dstAll -and $svcAll) {
            $sev = if ($noUtm) { "HIGH" } else { "MEDIUM" }
            $utmNote = if ($noUtm) { ", no UTM" } else { ", UTM enabled" }
            $detail = "Policy $($pol['policyid']) ($($pol['name'])) — src/dst/svc all$utmNote"
            $findings.Add((New-Finding -Severity $sev -Category "Permissive Rule" `
                -PolicyId $pol['policyid'] -PolicyName $pol['name'] `
                -Detail $detail -Recommendation "Restrict source/destination/service scope or enable UTM inspection"))
        }
        elseif ($srcAll -or $dstAll) {
            $which = @()
            if ($srcAll) { $which += 'srcaddr "all"' }
            if ($dstAll) { $which += 'dstaddr "all"' }
            $detail = "Policy $($pol['policyid']) ($($pol['name'])) — $($which -join ', ')"
            $findings.Add((New-Finding -Severity "MEDIUM" -Category "Permissive Rule" `
                -PolicyId $pol['policyid'] -PolicyName $pol['name'] `
                -Detail $detail -Recommendation "Narrow source or destination to specific address objects"))
        }
    }
    return ,$findings
}

function Find-DisabledPolicies {
    param([System.Collections.Generic.List[hashtable]]$Policies)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($pol in $Policies) {
        if ($pol['status'] -eq 'disable') {
            $findings.Add((New-Finding -Severity "INFO" -Category "Disabled Policy" `
                -PolicyId $pol['policyid'] -PolicyName $pol['name'] `
                -Detail "Policy $($pol['policyid']) ($($pol['name'])) is disabled" `
                -Recommendation "Remove if no longer needed or document reason for keeping disabled"))
        }
    }
    return ,$findings
}

function Find-LoggingDisabled {
    param([System.Collections.Generic.List[hashtable]]$Policies)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($pol in $Policies) {
        if ($pol['status'] -ne 'enable' -or $pol['action'] -ne 'accept') { continue }
        if ($pol['logtraffic'] -eq 'disable') {
            $findings.Add((New-Finding -Severity "MEDIUM" -Category "Logging Disabled" `
                -PolicyId $pol['policyid'] -PolicyName $pol['name'] `
                -Detail "Policy $($pol['policyid']) ($($pol['name'])) — logtraffic disable" `
                -Recommendation "Enable traffic logging (logtraffic all) for audit trail"))
        }
    }
    return ,$findings
}

function Find-DenyNoLogging {
    <#  Deny rules without logging miss visibility into blocked traffic.  #>
    param([System.Collections.Generic.List[hashtable]]$Policies)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($pol in $Policies) {
        if ($pol['status'] -ne 'enable' -or $pol['action'] -ne 'deny') { continue }
        if ($pol['logtraffic'] -eq 'disable') {
            $findings.Add((New-Finding -Severity "MEDIUM" -Category "Deny No Logging" `
                -PolicyId $pol['policyid'] -PolicyName $pol['name'] `
                -Detail "Deny policy $($pol['policyid']) ($($pol['name'])) has logging disabled" `
                -Recommendation "Enable logging on deny rules for visibility into blocked traffic"))
        }
    }
    return ,$findings
}

function Find-MissingSecurityProfiles {
    param([System.Collections.Generic.List[hashtable]]$Policies)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $profileKeys = @(
        @{ Key = 'av-profile';       Label = 'Antivirus' },
        @{ Key = 'ips-sensor';       Label = 'IPS' },
        @{ Key = 'webfilter-profile'; Label = 'Web Filter' },
        @{ Key = 'application-list'; Label = 'App Control' }
    )
    foreach ($pol in $Policies) {
        if ($pol['action'] -ne 'accept' -or $pol['status'] -eq 'disable') { continue }
        $missing = @()
        foreach ($pk in $profileKeys) {
            if (-not $pol[$pk.Key] -or $pol[$pk.Key] -eq '') { $missing += $pk.Label }
        }
        if ($missing.Count -eq 0) { continue }
        $sev = if ($missing.Count -eq 4) { "HIGH" } else { "MEDIUM" }
        $findings.Add((New-Finding -Severity $sev -Category "Missing Security Profile" `
            -PolicyId $pol['policyid'] -PolicyName $pol['name'] `
            -Detail "Policy $($pol['policyid']) ($($pol['name'])) — missing: $($missing -join ', ')" `
            -Recommendation "Assign appropriate UTM/security profiles to inspect traffic"))
    }
    return ,$findings
}

function Find-MissingSSLInspection {
    param([System.Collections.Generic.List[hashtable]]$Policies)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($pol in $Policies) {
        if ($pol['action'] -ne 'accept' -or $pol['status'] -eq 'disable') { continue }
        if (-not $pol['ssl-ssh-profile'] -or $pol['ssl-ssh-profile'] -eq '') {
            $findings.Add((New-Finding -Severity "MEDIUM" -Category "No SSL Inspection" `
                -PolicyId $pol['policyid'] -PolicyName $pol['name'] `
                -Detail "Policy $($pol['policyid']) ($($pol['name'])) — no SSL/SSH inspection profile" `
                -Recommendation "Assign an SSL/SSH inspection profile for encrypted traffic visibility"))
        }
    }
    return ,$findings
}

function Find-AnyInterface {
    param([System.Collections.Generic.List[hashtable]]$Policies)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($pol in $Policies) {
        if ($pol['status'] -eq 'disable') { continue }
        $srcAny = @($pol['srcintf'] | ForEach-Object { $_.ToLower() }) -contains 'any'
        $dstAny = @($pol['dstintf'] | ForEach-Object { $_.ToLower() }) -contains 'any'
        if (-not ($srcAny -or $dstAny)) { continue }
        $which = @()
        if ($srcAny) { $which += 'srcintf' }
        if ($dstAny) { $which += 'dstintf' }
        $findings.Add((New-Finding -Severity "MEDIUM" -Category "Any Interface" `
            -PolicyId $pol['policyid'] -PolicyName $pol['name'] `
            -Detail "Policy $($pol['policyid']) ($($pol['name'])) — $($which -join ' & ') set to `"any`"" `
            -Recommendation "Bind policy to specific source/destination interfaces for tighter control"))
    }
    return ,$findings
}

function Find-MissingComments {
    param([System.Collections.Generic.List[hashtable]]$Policies)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($pol in $Policies) {
        if ($pol['action'] -ne 'accept' -or $pol['status'] -eq 'disable') { continue }
        if (-not $pol['comments'] -or $pol['comments'] -eq '') {
            $findings.Add((New-Finding -Severity "LOW" -Category "Missing Comments" `
                -PolicyId $pol['policyid'] -PolicyName $pol['name'] `
                -Detail "Policy $($pol['policyid']) ($($pol['name'])) — no comments/documentation" `
                -Recommendation "Add a comment describing business justification and owner"))
        }
    }
    return ,$findings
}

function Find-IPv6PolicyIssues {
    <#  Flags missing or weak IPv6 firewall policies.  If interfaces have IPv6
        addresses but no policy6 section exists, that's a gap.  If policy6 exists,
        checks for logging and UTM coverage.  #>
    param([hashtable]$Sections)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Check if any interface has an IPv6 address configured
    $hasIPv6 = $false
    $ifaceKey = 'config system interface'
    if ($Sections.ContainsKey($ifaceKey)) {
        $ifaceContent = $Sections[$ifaceKey] -join "`n"
        if ($ifaceContent -match 'set ip6-address' -or $ifaceContent -match 'config ipv6') {
            $hasIPv6 = $true
        }
    }

    $policyKey = 'config firewall policy6'
    if (-not $Sections.ContainsKey($policyKey)) {
        if ($hasIPv6) {
            $findings.Add((New-Finding -Severity "HIGH" -Category "No IPv6 Policies" `
                -PolicyId $null -PolicyName "" `
                -Detail "IPv6 addresses configured on interfaces but no firewall policy6 section exists — all IPv6 traffic unfiltered" `
                -Recommendation "Create IPv6 firewall policies (config firewall policy6) mirroring IPv4 rule sets"))
        } else {
            $findings.Add((New-Finding -Severity "INFO" -Category "No IPv6 Policies" `
                -PolicyId $null -PolicyName "" `
                -Detail "No IPv6 firewall policies configured (no IPv6 addresses detected on interfaces)" `
                -Recommendation "If IPv6 is planned, pre-configure deny-all IPv6 policies before enabling"))
        }
        return ,$findings
    }

    # policy6 exists — parse and check quality
    $policies6 = ConvertTo-PolicyObjects -Lines $Sections[$policyKey]
    foreach ($pol in $policies6) {
        if ($pol['status'] -eq 'disable') { continue }
        if ($pol['action'] -ne 'accept') { continue }
        if ($pol['logtraffic'] -eq 'disable') {
            $findings.Add((New-Finding -Severity "MEDIUM" -Category "IPv6 Logging Disabled" `
                -PolicyId $pol['policyid'] -PolicyName $pol['name'] `
                -Detail "IPv6 policy $($pol['policyid']) ($($pol['name'])) — logtraffic disabled" `
                -Recommendation "Enable logging on IPv6 accept policies for audit visibility"))
        }
        if ($pol['utm-status'] -ne 'enable') {
            $findings.Add((New-Finding -Severity "MEDIUM" -Category "IPv6 No UTM" `
                -PolicyId $pol['policyid'] -PolicyName $pol['name'] `
                -Detail "IPv6 policy $($pol['policyid']) ($($pol['name'])) — no UTM inspection" `
                -Recommendation "Apply security profiles (AV, IPS, web filter) to IPv6 policies"))
        }
    }
    return ,$findings
}

function Find-UTMProfileDepthIssues {
    <#  Checks whether UTM profiles assigned to policies are actually effective.
        Detects AV profiles in monitor-only mode, IPS sensors with action=pass,
        and web filter profiles allowing all categories.  #>
    param([hashtable]$Sections, [System.Collections.Generic.List[hashtable]]$Policies)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Collect profile names referenced by active policies
    $usedAV  = @{}; $usedIPS = @{}; $usedWF = @{}; $usedApp = @{}
    foreach ($pol in $Policies) {
        if ($pol['status'] -eq 'disable' -or $pol['action'] -ne 'accept') { continue }
        if ($pol['av-profile'])        { $usedAV[$pol['av-profile']]        = $true }
        if ($pol['ips-sensor'])        { $usedIPS[$pol['ips-sensor']]       = $true }
        if ($pol['webfilter-profile']) { $usedWF[$pol['webfilter-profile']] = $true }
        if ($pol['application-list'])  { $usedApp[$pol['application-list']] = $true }
    }

    # Check AV profiles — scan raw section lines for monitor/pass actions
    $avKey = 'config antivirus profile'
    if ($Sections.ContainsKey($avKey)) {
        $currentName = $null; $hasMonitor = $false; $hasScanDisable = $false
        foreach ($raw in $Sections[$avKey]) {
            $trimmed = $raw.Trim()
            if ($trimmed -match '^\s*edit\s+"([^"]+)"') {
                $currentName = $Matches[1]; $hasMonitor = $false; $hasScanDisable = $false
            }
            if ($null -ne $currentName) {
                if ($trimmed -match 'set\s+av-scan\s+disable') { $hasScanDisable = $true }
                if ($trimmed -match 'set\s+(?:outbreak-prevention|content-disarm)\s+disable') { $hasMonitor = $true }
            }
            if ($trimmed -eq 'next' -and $null -ne $currentName) {
                if ($usedAV.ContainsKey($currentName) -and $hasScanDisable) {
                    $findings.Add((New-Finding -Severity "HIGH" -Category "AV Profile Scan Disabled" `
                        -PolicyId $null -PolicyName $currentName `
                        -Detail "Antivirus profile `"$currentName`" has av-scan disabled on one or more protocols" `
                        -Recommendation "Enable AV scanning on all protocols (HTTP, SMTP, FTP, IMAP, POP3)"))
                }
                $currentName = $null
            }
        }
    }

    # Check IPS sensors — look for entries with action=pass (monitor-only)
    $ipsKey = 'config ips sensor'
    if ($Sections.ContainsKey($ipsKey)) {
        $currentName = $null; $hasPassAll = $false; $inEntries = $false; $entryCount = 0; $passCount = 0
        foreach ($raw in $Sections[$ipsKey]) {
            $trimmed = $raw.Trim()
            if ($trimmed -match '^\s*edit\s+"([^"]+)"') {
                $currentName = $Matches[1]; $hasPassAll = $false; $inEntries = $false; $entryCount = 0; $passCount = 0
            }
            if ($trimmed -eq 'config entries') { $inEntries = $true }
            if ($inEntries) {
                if ($trimmed -match '^\s*edit\s+\d+') { $entryCount++ }
                if ($trimmed -match 'set\s+action\s+pass') { $passCount++ }
            }
            if ($trimmed -eq 'end' -and $inEntries) { $inEntries = $false }
            if ($trimmed -eq 'next' -and $null -ne $currentName -and -not $inEntries) {
                if ($usedIPS.ContainsKey($currentName) -and $entryCount -gt 0 -and $passCount -eq $entryCount) {
                    $findings.Add((New-Finding -Severity "HIGH" -Category "IPS Sensor Monitor Only" `
                        -PolicyId $null -PolicyName $currentName `
                        -Detail "IPS sensor `"$currentName`" has all entries set to action=pass (monitor only, no blocking)" `
                        -Recommendation "Set IPS entry actions to 'block' or 'reset' for active threat prevention"))
                }
                $currentName = $null
            }
        }
    }

    # Check application-list — look for broad allow-all
    $appKey = 'config application list'
    if ($Sections.ContainsKey($appKey)) {
        $currentName = $null; $hasDefaultAllow = $false
        foreach ($raw in $Sections[$appKey]) {
            $trimmed = $raw.Trim()
            if ($trimmed -match '^\s*edit\s+"([^"]+)"') {
                $currentName = $Matches[1]; $hasDefaultAllow = $false
            }
            if ($null -ne $currentName -and $trimmed -match 'set\s+other-application-action\s+pass') {
                $hasDefaultAllow = $true
            }
            if ($null -ne $currentName -and $trimmed -match 'set\s+unknown-application-action\s+pass') {
                $hasDefaultAllow = $true
            }
            if ($trimmed -eq 'next' -and $null -ne $currentName) {
                if ($usedApp.ContainsKey($currentName) -and $hasDefaultAllow) {
                    $findings.Add((New-Finding -Severity "MEDIUM" -Category "App Control Permissive" `
                        -PolicyId $null -PolicyName $currentName `
                        -Detail "Application list `"$currentName`" allows unknown or uncategorized applications" `
                        -Recommendation "Set unknown-application-action and other-application-action to 'block' or 'monitor'"))
                }
                $currentName = $null
            }
        }
    }

    return ,$findings
}

# =============================================================================
# OBJECT HYGIENE CHECKS
# =============================================================================

function Find-DuplicateAddresses {
    param([hashtable]$Addresses)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $valueMap = @{}
    foreach ($name in $Addresses.Keys) {
        $obj = $Addresses[$name]
        $key = if ($obj['subnet'] -and $obj['subnet'] -ne '') { "subnet:$($obj['subnet'])" }
               elseif ($obj['fqdn'] -and $obj['fqdn'] -ne '') { "fqdn:$($obj['fqdn'])" }
               else { $null }
        if ($key) {
            if (-not $valueMap.ContainsKey($key)) { $valueMap[$key] = [System.Collections.Generic.List[string]]::new() }
            $valueMap[$key].Add($name)
        }
    }
    foreach ($key in $valueMap.Keys) {
        $names = $valueMap[$key]
        if ($names.Count -le 1) { continue }
        $sorted   = $names | Sort-Object
        $valDisp  = $key -replace '^(subnet|fqdn):', ''
        $typeDisp = ($key -split ':')[0]
        for ($i = 0; $i -lt $sorted.Count - 1; $i++) {
            for ($j = $i + 1; $j -lt $sorted.Count; $j++) {
                $findings.Add((New-Finding -Severity "LOW" -Category "Duplicate Address" `
                    -PolicyId $null -PolicyName "" `
                    -Detail "`"$($sorted[$i])`" and `"$($sorted[$j])`" have same $typeDisp $valDisp" `
                    -Recommendation "Consolidate duplicate address objects to reduce config complexity"))
            }
        }
    }
    return ,$findings
}

function Find-BroadAddresses {
    param([hashtable]$Addresses, [int]$MaxPrefix)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($name in $Addresses.Keys) {
        $obj = $Addresses[$name]
        if (-not $obj['subnet'] -or $obj['subnet'] -eq '') { continue }
        $prefix = Get-SubnetPrefix -Subnet $obj['subnet']
        if ($prefix -ge 0 -and $prefix -le $MaxPrefix) {
            $findings.Add((New-Finding -Severity "MEDIUM" -Category "Broad Address" `
                -PolicyId $null -PolicyName $name `
                -Detail "Address `"$name`" has /$prefix subnet ($($obj['subnet']))" `
                -Recommendation "Narrow subnet scope or document business justification for broad range"))
        }
    }
    return ,$findings
}

function Find-UnusedAddresses {
    param([hashtable]$Addresses, [System.Collections.Generic.List[hashtable]]$Policies)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $referenced = @{}
    foreach ($pol in $Policies) {
        foreach ($addr in @($pol['srcaddr']) + @($pol['dstaddr'])) {
            $referenced[$addr.ToLower()] = $true
        }
    }
    $builtins = @('all', 'none', 'login.microsoftonline.com', 'login.microsoft.com',
                  'wildcard.google.com', 'wildcard.dropbox.com', 'swscan.apple.com',
                  'update.microsoft.com', 'fctuid.fortinet.net')
    foreach ($name in ($Addresses.Keys | Sort-Object)) {
        if ($name.ToLower() -in $builtins) { continue }
        if (-not $referenced.ContainsKey($name.ToLower())) {
            $findings.Add((New-Finding -Severity "LOW" -Category "Unused Address" `
                -PolicyId $null -PolicyName $name `
                -Detail "Address `"$name`" is not referenced by any firewall policy" `
                -Recommendation "Remove unused address objects to reduce config bloat"))
        }
    }
    return ,$findings
}

function Find-OverlappingAddresses {
    <#  Detects address objects where one subnet fully contains another (e.g. /8 contains /24).
        Excludes duplicate pairs (already caught by Find-DuplicateAddresses).  #>
    param([hashtable]$Addresses)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $subnetAddrs = @()
    foreach ($name in $Addresses.Keys) {
        $obj = $Addresses[$name]
        if (-not $obj['subnet'] -or $obj['subnet'] -eq '') { continue }
        $prefix = Get-SubnetPrefix -Subnet $obj['subnet']
        if ($prefix -lt 0) { continue }
        $subnetAddrs += @{ Name = $name; Subnet = $obj['subnet']; Prefix = $prefix }
    }
    # Sort by prefix length (broadest first) for efficient comparison
    $subnetAddrs = $subnetAddrs | Sort-Object { $_.Prefix }
    for ($i = 0; $i -lt $subnetAddrs.Count; $i++) {
        for ($j = $i + 1; $j -lt $subnetAddrs.Count; $j++) {
            $a = $subnetAddrs[$i]; $b = $subnetAddrs[$j]
            if ($a.Prefix -eq $b.Prefix) { continue }  # Same prefix = duplicate, not overlap
            if ($a.Subnet -eq $b.Subnet) { continue }   # Exact duplicate, skip
            if (Test-SubnetContains -SubnetA $a.Subnet -SubnetB $b.Subnet) {
                $findings.Add((New-Finding -Severity "LOW" -Category "Overlapping Address" `
                    -PolicyId $null -PolicyName "" `
                    -Detail "`"$($a.Name)`" (/$($a.Prefix)) contains `"$($b.Name)`" (/$($b.Prefix))" `
                    -Recommendation "Review if both objects are needed or consolidate into the broader object"))
            }
        }
    }
    return ,$findings
}

function Find-UnusedServices {
    <#  Finds custom service objects not referenced by any firewall policy.  #>
    param([System.Collections.Generic.List[hashtable]]$Services, [System.Collections.Generic.List[hashtable]]$Policies)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $referenced = @{}
    foreach ($pol in $Policies) {
        foreach ($svc in @($pol['service'])) {
            $referenced[$svc.ToLower()] = $true
        }
    }
    foreach ($svc in $Services) {
        $name = $svc['_id']
        if ($name.ToLower() -in $referenced.Keys) { continue }
        $findings.Add((New-Finding -Severity "LOW" -Category "Unused Service" `
            -PolicyId $null -PolicyName $name `
            -Detail "Service `"$name`" is not referenced by any firewall policy" `
            -Recommendation "Remove unused service objects to reduce config bloat"))
    }
    return ,$findings
}

function Find-GroupHygieneIssues {
    <#  Checks address and service groups for orphaned members, empty groups,
        and excessively nested groups (group-of-groups-of-groups).  #>
    param([hashtable]$Sections, [hashtable]$Addresses,
          [System.Collections.Generic.List[hashtable]]$Services)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Build sets of known address and service names
    $knownAddrs = @{}
    foreach ($name in $Addresses.Keys) { $knownAddrs[$name.ToLower()] = $true }
    $knownAddrs['all'] = $true; $knownAddrs['none'] = $true

    $knownSvcs = @{}
    foreach ($svc in $Services) { $knownSvcs[$svc['_id'].ToLower()] = $true }
    # Built-in services
    foreach ($s in @('all','http','https','dns','smtp','ssh','ftp','ping','all_icmp','all_icmp6',
                     'ntp','snmp','ldap','smb','rdp','telnet','imap','pop3','sip')) {
        $knownSvcs[$s] = $true
    }

    # --- Address groups ---
    $addrGrpKey = 'config firewall addrgrp'
    $addrGroups = @{}
    if ($Sections.ContainsKey($addrGrpKey)) {
        $blocks = ConvertTo-EditBlocks -Lines $Sections[$addrGrpKey]
        foreach ($block in $blocks) {
            $name = $block['_id']
            $addrGroups[$name.ToLower()] = $block
            # Add to known addresses so nested group refs resolve
            $knownAddrs[$name.ToLower()] = $true
        }
        # Check each group
        foreach ($block in $blocks) {
            $name = $block['_id']
            $members = $block['member']
            if (-not $members) {
                $findings.Add((New-Finding -Severity "MEDIUM" -Category "Empty Address Group" `
                    -PolicyId $null -PolicyName $name `
                    -Detail "Address group `"$name`" has no members" `
                    -Recommendation "Remove empty groups or add appropriate member objects"))
                continue
            }
            $memberList = if ($members -is [array]) { $members } else { @($members) }
            foreach ($m in $memberList) {
                if (-not $knownAddrs.ContainsKey($m.ToLower())) {
                    $findings.Add((New-Finding -Severity "HIGH" -Category "Orphaned Group Member" `
                        -PolicyId $null -PolicyName $name `
                        -Detail "Address group `"$name`" references `"$m`" which does not exist" `
                        -Recommendation "Remove the orphaned reference or recreate the missing address object"))
                }
            }
        }
        # Check nesting depth (group containing group containing group)
        foreach ($block in $blocks) {
            $name = $block['_id']
            $members = $block['member']
            if (-not $members) { continue }
            $memberList = if ($members -is [array]) { $members } else { @($members) }
            foreach ($m in $memberList) {
                if ($addrGroups.ContainsKey($m.ToLower())) {
                    $innerBlock = $addrGroups[$m.ToLower()]
                    $innerMembers = $innerBlock['member']
                    if ($innerMembers) {
                        $innerList = if ($innerMembers -is [array]) { $innerMembers } else { @($innerMembers) }
                        foreach ($im in $innerList) {
                            if ($addrGroups.ContainsKey($im.ToLower())) {
                                $findings.Add((New-Finding -Severity "MEDIUM" -Category "Deeply Nested Group" `
                                    -PolicyId $null -PolicyName $name `
                                    -Detail "Address group `"$name`" -> `"$m`" -> `"$im`" — 3+ levels of nesting" `
                                    -Recommendation "Flatten group hierarchy to improve readability and reduce error risk"))
                                break
                            }
                        }
                    }
                }
            }
        }
    }

    # --- Service groups ---
    $svcGrpKey = 'config firewall service group'
    if ($Sections.ContainsKey($svcGrpKey)) {
        $blocks = ConvertTo-EditBlocks -Lines $Sections[$svcGrpKey]
        foreach ($block in $blocks) {
            $name = $block['_id']
            $knownSvcs[$name.ToLower()] = $true
        }
        foreach ($block in $blocks) {
            $name = $block['_id']
            $members = $block['member']
            if (-not $members) {
                $findings.Add((New-Finding -Severity "MEDIUM" -Category "Empty Service Group" `
                    -PolicyId $null -PolicyName $name `
                    -Detail "Service group `"$name`" has no members" `
                    -Recommendation "Remove empty groups or add appropriate member services"))
                continue
            }
            $memberList = if ($members -is [array]) { $members } else { @($members) }
            foreach ($m in $memberList) {
                if (-not $knownSvcs.ContainsKey($m.ToLower())) {
                    $findings.Add((New-Finding -Severity "HIGH" -Category "Orphaned Group Member" `
                        -PolicyId $null -PolicyName $name `
                        -Detail "Service group `"$name`" references `"$m`" which does not exist" `
                        -Recommendation "Remove the orphaned reference or recreate the missing service object"))
                }
            }
        }
    }

    return ,$findings
}

# =============================================================================
# SYSTEM HARDENING CHECKS
# =============================================================================

function Find-AdminIssues {
    param([System.Collections.Generic.List[hashtable]]$Admins)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($admin in $Admins) {
        $name = $admin['_id']
        $hasTrusted = $false
        foreach ($key in $admin.Keys) {
            if ($key -match '^trusthost\d+$' -and $admin[$key] -and $admin[$key] -ne '0.0.0.0 0.0.0.0') {
                $hasTrusted = $true; break
            }
        }
        if (-not $hasTrusted) {
            $findings.Add((New-Finding -Severity "HIGH" -Category "Admin No Trusted Host" `
                -PolicyId $null -PolicyName $name `
                -Detail "Admin `"$name`" has no trusted-host restriction — management access from any IP" `
                -Recommendation "Set trusthost1-10 to restrict admin login to known management IPs"))
        }
    }
    return ,$findings
}

function Find-AdminMFAIssues {
    <#  Flags admin accounts without two-factor authentication.  #>
    param([System.Collections.Generic.List[hashtable]]$Admins)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($admin in $Admins) {
        $name = $admin['_id']
        $twoFactor = $admin['two-factor']
        if (-not $twoFactor -or $twoFactor -eq 'disable') {
            $findings.Add((New-Finding -Severity "MEDIUM" -Category "Admin No MFA" `
                -PolicyId $null -PolicyName $name `
                -Detail "Admin `"$name`" does not have two-factor authentication enabled" `
                -Recommendation "Enable MFA (fortitoken, fortitoken-cloud, or email) for all admin accounts"))
        }
    }
    return ,$findings
}

function Find-InterfaceAccessIssues {
    param([System.Collections.Generic.List[hashtable]]$Interfaces)
    $findings  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $insecure  = @('http', 'telnet')
    $advisory  = @('ping', 'snmp')
    foreach ($iface in $Interfaces) {
        $name = $iface['_id']
        $allowaccess = $iface['allowaccess']
        if (-not $allowaccess) { continue }
        $protocols = if ($allowaccess -is [array]) { $allowaccess } else { $allowaccess -split '\s+' }
        $protocols = @($protocols | ForEach-Object { $_.ToLower() })
        $found = @($insecure | Where-Object { $protocols -contains $_ })
        if ($found.Count -gt 0) {
            $findings.Add((New-Finding -Severity "HIGH" -Category "Insecure Interface Access" `
                -PolicyId $null -PolicyName $name `
                -Detail "Interface `"$name`" allows insecure protocols: $($found -join ', ')" `
                -Recommendation "Disable HTTP and Telnet; use HTTPS and SSH for management access"))
        }
        $warn = @($advisory | Where-Object { $protocols -contains $_ })
        if ($warn.Count -gt 0) {
            $findings.Add((New-Finding -Severity "LOW" -Category "Interface Access Advisory" `
                -PolicyId $null -PolicyName $name `
                -Detail "Interface `"$name`" allows advisory-risk protocols: $($warn -join ', ')" `
                -Recommendation "Restrict PING and SNMP to trusted management networks via local-in policies"))
        }
    }
    return ,$findings
}

function Find-PasswordPolicyIssues {
    param([hashtable]$Sections)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $key = 'config system password-policy'
    if (-not $Sections.ContainsKey($key)) {
        $findings.Add((New-Finding -Severity "HIGH" -Category "No Password Policy" `
            -PolicyId $null -PolicyName "" `
            -Detail "No system password-policy section found in config" `
            -Recommendation "Configure a password policy enforcing minimum length, complexity, and expiry"))
        return ,$findings
    }
    $settings = @{}
    foreach ($raw in $Sections[$key]) {
        if ($raw.Trim() -match '^\s*set\s+(\S+)\s+(.+)$') { $settings[$Matches[1]] = $Matches[2].Trim() }
    }
    if ($settings['status'] -and $settings['status'] -eq 'disable') {
        $findings.Add((New-Finding -Severity "HIGH" -Category "Password Policy Disabled" `
            -PolicyId $null -PolicyName "" `
            -Detail "System password-policy is set to disable" `
            -Recommendation "Enable the password policy and set minimum requirements"))
    }
    if ($settings['min-length']) {
        $len = [int]$settings['min-length']
        if ($len -lt 8) {
            $findings.Add((New-Finding -Severity "MEDIUM" -Category "Weak Password Policy" `
                -PolicyId $null -PolicyName "" `
                -Detail "Minimum password length is $len (recommended >= 8)" `
                -Recommendation "Increase min-length to at least 8 characters"))
        }
    }
    return ,$findings
}

function Find-SNMPIssues {
    param([hashtable]$Sections)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $key = 'config system snmp community'
    if (-not $Sections.ContainsKey($key)) { return ,$findings }
    $blocks = ConvertTo-EditBlocks -Lines $Sections[$key]
    $defaults = @('public', 'private')
    foreach ($block in $blocks) {
        $community = $block['name']
        if (-not $community) { continue }
        if ($community.ToLower() -in $defaults) {
            $findings.Add((New-Finding -Severity "HIGH" -Category "SNMP Default Community" `
                -PolicyId $null -PolicyName $community `
                -Detail "SNMP community `"$community`" uses a well-known default string" `
                -Recommendation "Change SNMP community string to a non-default, complex value or use SNMPv3"))
        }
    }
    return ,$findings
}

function Find-LoggingConfigIssues {
    param([hashtable]$Sections)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $hasSyslog = $false; $hasFaz = $false
    foreach ($key in @('config log syslogd setting', 'config log syslogd2 setting',
                       'config log syslogd3 setting', 'config log syslogd4 setting')) {
        if ($Sections.ContainsKey($key)) {
            $content = $Sections[$key] -join ' '
            if ($content -match 'set status enable') { $hasSyslog = $true; break }
        }
    }
    foreach ($key in @('config log fortianalyzer setting', 'config log fortianalyzer2 setting',
                       'config log fortianalyzer3 setting')) {
        if ($Sections.ContainsKey($key)) {
            $content = $Sections[$key] -join ' '
            if ($content -match 'set status enable') { $hasFaz = $true; break }
        }
    }
    if (-not $hasSyslog -and -not $hasFaz) {
        $findings.Add((New-Finding -Severity "HIGH" -Category "No Central Logging" `
            -PolicyId $null -PolicyName "" `
            -Detail "Neither syslog nor FortiAnalyzer logging is enabled" `
            -Recommendation "Configure log forwarding to a syslog server or FortiAnalyzer for centralized audit"))
    }
    return ,$findings
}

function Find-GlobalSettingIssues {
    param([hashtable]$Sections)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $key = 'config system global'
    if (-not $Sections.ContainsKey($key)) { return ,$findings }
    $settings = @{}
    foreach ($raw in $Sections[$key]) {
        if ($raw.Trim() -match '^\s*set\s+(\S+)\s+(.+)$') { $settings[$Matches[1]] = $Matches[2].Trim() }
    }
    if (-not $settings['strong-crypto'] -or $settings['strong-crypto'] -ne 'enable') {
        $findings.Add((New-Finding -Severity "HIGH" -Category "Strong Crypto Disabled" `
            -PolicyId $null -PolicyName "" `
            -Detail "strong-crypto is not enabled — weak TLS ciphers may be used for management" `
            -Recommendation "Set 'set strong-crypto enable' under config system global"))
    }
    if ($settings['admin-https-redirect'] -and $settings['admin-https-redirect'] -eq 'disable') {
        $findings.Add((New-Finding -Severity "MEDIUM" -Category "HTTPS Redirect Disabled" `
            -PolicyId $null -PolicyName "" `
            -Detail "HTTP-to-HTTPS redirect is disabled for admin GUI" `
            -Recommendation "Enable admin-https-redirect to prevent plaintext admin sessions"))
    }
    if ($settings['admintimeout']) {
        $timeout = [int]$settings['admintimeout']
        if ($timeout -gt 30 -or $timeout -eq 0) {
            $val = if ($timeout -eq 0) { "disabled" } else { "$timeout minutes" }
            $findings.Add((New-Finding -Severity "MEDIUM" -Category "Long Admin Timeout" `
                -PolicyId $null -PolicyName "" `
                -Detail "Admin session timeout is $val (recommended <= 15 minutes)" `
                -Recommendation "Set admintimeout to 15 or lower to limit idle admin sessions"))
        }
    }
    if (-not $settings['pre-login-banner'] -or $settings['pre-login-banner'] -ne 'enable') {
        $findings.Add((New-Finding -Severity "LOW" -Category "No Login Banner" `
            -PolicyId $null -PolicyName "" `
            -Detail "Pre-login banner is not enabled" `
            -Recommendation "Enable pre-login-banner with a legal notice for unauthorized access deterrence"))
    }
    return ,$findings
}

function Find-DnsNtpIssues {
    param([hashtable]$Sections)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    if (-not $Sections.ContainsKey('config system dns')) {
        $findings.Add((New-Finding -Severity "MEDIUM" -Category "DNS Not Configured" `
            -PolicyId $null -PolicyName "" `
            -Detail "No system DNS section found in config" `
            -Recommendation "Configure DNS servers for hostname resolution and FortiGuard updates"))
    }
    if (-not $Sections.ContainsKey('config system ntp')) {
        $findings.Add((New-Finding -Severity "MEDIUM" -Category "NTP Not Configured" `
            -PolicyId $null -PolicyName "" `
            -Detail "No system NTP section found in config" `
            -Recommendation "Configure NTP for accurate timestamps in logs and certificate validation"))
    } else {
        $ntpContent = $Sections['config system ntp'] -join ' '
        if ($ntpContent -match 'set ntpsync disable') {
            $findings.Add((New-Finding -Severity "MEDIUM" -Category "NTP Sync Disabled" `
                -PolicyId $null -PolicyName "" `
                -Detail "NTP synchronization is disabled" `
                -Recommendation "Enable NTP sync (set ntpsync enable) for accurate log timestamps"))
        }
    }
    return ,$findings
}

function Find-InsecureLDAP {
    <#  Checks LDAP server configs for plaintext connections.  #>
    param([hashtable]$Sections)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $key = 'config user ldap'
    if (-not $Sections.ContainsKey($key)) { return ,$findings }
    $blocks = ConvertTo-EditBlocks -Lines $Sections[$key]
    foreach ($block in $blocks) {
        $name   = $block['_id']
        $secure = $block['secure']
        if (-not $secure -or $secure -eq 'disable') {
            $findings.Add((New-Finding -Severity "HIGH" -Category "Insecure LDAP" `
                -PolicyId $null -PolicyName $name `
                -Detail "LDAP server `"$name`" uses plaintext (port $($block['port'] ?? '389')) — credentials sent unencrypted" `
                -Recommendation "Set 'set secure ldaps' or 'set secure starttls' for encrypted LDAP communication"))
        }
    }
    return ,$findings
}

function Find-ExpiredSchedules {
    <#  Finds one-time schedules whose end date has passed.  #>
    param([hashtable]$Sections)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $key = 'config firewall schedule onetime'
    if (-not $Sections.ContainsKey($key)) { return ,$findings }
    $blocks = ConvertTo-EditBlocks -Lines $Sections[$key]
    $now = Get-Date
    foreach ($block in $blocks) {
        $name    = $block['_id']
        $endStr  = $block['end']
        if (-not $endStr) { continue }
        # Format: "HH:mm yyyy/MM/dd" — extract date portion
        if ($endStr -match '(\d{4}/\d{2}/\d{2})') {
            try {
                $endDate = [datetime]::ParseExact($Matches[1], 'yyyy/MM/dd', $null)
                if ($endDate -lt $now) {
                    $daysAgo = [int]($now - $endDate).TotalDays
                    $findings.Add((New-Finding -Severity "MEDIUM" -Category "Expired Schedule" `
                        -PolicyId $null -PolicyName $name `
                        -Detail "One-time schedule `"$name`" expired $daysAgo day(s) ago ($($endDate.ToString('yyyy-MM-dd')))" `
                        -Recommendation "Remove expired schedules and any policies referencing them"))
                }
            } catch { }
        }
    }
    return ,$findings
}

function Find-CertificateIssues {
    <#  Checks SSL inspection profiles for certificate-inspection (weak) vs
        deep-inspection, admin GUI cert for default Fortinet_Factory, and VPN
        tunnels using default certificates.  #>
    param([hashtable]$Sections)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Check admin HTTPS certificate
    $globalKey = 'config system global'
    if ($Sections.ContainsKey($globalKey)) {
        $settings = @{}
        foreach ($raw in $Sections[$globalKey]) {
            if ($raw.Trim() -match '^\s*set\s+(\S+)\s+(.+)$') { $settings[$Matches[1]] = $Matches[2].Trim().Trim('"') }
        }
        $cert = $settings['admin-server-cert']
        if (-not $cert -or $cert -eq 'Fortinet_Factory') {
            $findings.Add((New-Finding -Severity "MEDIUM" -Category "Default Admin Certificate" `
                -PolicyId $null -PolicyName "" `
                -Detail "Admin HTTPS uses default `"Fortinet_Factory`" certificate — self-signed and untrusted" `
                -Recommendation "Replace with a CA-signed certificate for management HTTPS (set admin-server-cert)"))
        }
    }

    # Check SSL inspection profiles
    $sslKey = 'config firewall ssl-ssh-profile'
    if ($Sections.ContainsKey($sslKey)) {
        $currentName = $null; $isCertInspection = $false
        foreach ($raw in $Sections[$sslKey]) {
            $trimmed = $raw.Trim()
            if ($trimmed -match '^\s*edit\s+"([^"]+)"') {
                $currentName = $Matches[1]; $isCertInspection = $false
            }
            if ($null -ne $currentName -and $trimmed -match 'set\s+inspect-all\s+certificate-inspection') {
                $isCertInspection = $true
            }
            if ($trimmed -eq 'next' -and $null -ne $currentName) {
                # Skip the built-in "certificate-inspection" profile — it's expected to be cert-only
                if ($isCertInspection -and $currentName -ne 'certificate-inspection') {
                    $findings.Add((New-Finding -Severity "MEDIUM" -Category "Weak SSL Inspection" `
                        -PolicyId $null -PolicyName $currentName `
                        -Detail "SSL profile `"$currentName`" uses certificate-inspection — encrypted payloads not inspected" `
                        -Recommendation "Switch to deep-inspection mode for full TLS traffic visibility (requires CA cert deployment)"))
                }
                $currentName = $null
            }
        }
    }

    # Check VPN tunnels for default certificates
    foreach ($phaseKey in @('config vpn ipsec phase1-interface', 'config vpn ipsec phase1')) {
        if (-not $Sections.ContainsKey($phaseKey)) { continue }
        $blocks = ConvertTo-EditBlocks -Lines $Sections[$phaseKey]
        foreach ($block in $blocks) {
            $name = $block['_id']
            $cert = $block['certificate']
            if ($cert -and $cert -eq 'Fortinet_Factory') {
                $findings.Add((New-Finding -Severity "MEDIUM" -Category "VPN Default Certificate" `
                    -PolicyId $null -PolicyName $name `
                    -Detail "VPN tunnel `"$name`" uses default `"Fortinet_Factory`" certificate" `
                    -Recommendation "Use a CA-signed or custom certificate for VPN authentication"))
            }
        }
    }

    return ,$findings
}

# =============================================================================
# VPN CHECKS
# =============================================================================

function Find-VpnCryptoIssues {
    param([hashtable]$Sections)
    $findings   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $weakCipher = @('des', '3des', 'null')
    $weakDH     = @('1', '2', '5')
    $weakHash   = @('md5')

    # Phase 1
    foreach ($key in @('config vpn ipsec phase1-interface', 'config vpn ipsec phase1')) {
        $lines = Get-SectionOrEmpty -Sections $Sections -Key $key
        if ($lines.Count -eq 0) { continue }
        $blocks = ConvertTo-EditBlocks -Lines $lines
        foreach ($block in $blocks) {
            $name = $block['_id']
            if ($block['ike-version'] -and $block['ike-version'] -eq '1') {
                $findings.Add((New-Finding -Severity "MEDIUM" -Category "VPN IKEv1" `
                    -PolicyId $null -PolicyName $name `
                    -Detail "VPN tunnel `"$name`" uses IKEv1 — deprecated and less secure" `
                    -Recommendation "Migrate to IKEv2 for improved security and performance"))
            }
            $proposal = $block['proposal']
            if ($proposal) {
                $algos = if ($proposal -is [array]) { $proposal } else { $proposal -split '\s+' }
                foreach ($algo in $algos) {
                    $cipher = ($algo -split '-')[0].ToLower()
                    if ($cipher -in $weakCipher) {
                        $findings.Add((New-Finding -Severity "HIGH" -Category "VPN Weak Cipher" `
                            -PolicyId $null -PolicyName $name `
                            -Detail "VPN `"$name`" phase1 uses weak cipher: $algo" `
                            -Recommendation "Use AES-128 or AES-256 based proposals"))
                        break
                    }
                }
            }
            $dhgrp = $block['dhgrp']
            if ($dhgrp) {
                $groups = if ($dhgrp -is [array]) { $dhgrp } else { $dhgrp -split '\s+' }
                $weak = @($groups | Where-Object { $_ -in $weakDH })
                if ($weak.Count -gt 0) {
                    $findings.Add((New-Finding -Severity "HIGH" -Category "VPN Weak DH Group" `
                        -PolicyId $null -PolicyName $name `
                        -Detail "VPN `"$name`" phase1 includes deprecated DH group(s): $($weak -join ', ')" `
                        -Recommendation "Use DH groups 14, 19, 20, or 21 for adequate key strength"))
                }
            }
        }
    }

    # Phase 2
    foreach ($key in @('config vpn ipsec phase2-interface', 'config vpn ipsec phase2')) {
        $lines = Get-SectionOrEmpty -Sections $Sections -Key $key
        if ($lines.Count -eq 0) { continue }
        $blocks = ConvertTo-EditBlocks -Lines $lines
        foreach ($block in $blocks) {
            $name = $block['_id']
            $proposal = $block['proposal']
            if ($proposal) {
                $algos = if ($proposal -is [array]) { $proposal } else { $proposal -split '\s+' }
                foreach ($algo in $algos) {
                    $parts  = $algo -split '-'
                    $cipher = $parts[0].ToLower()
                    $hash   = if ($parts.Count -ge 2) { $parts[-1].ToLower() } else { '' }
                    if ($cipher -in $weakCipher) {
                        $findings.Add((New-Finding -Severity "HIGH" -Category "VPN Weak Cipher" `
                            -PolicyId $null -PolicyName $name `
                            -Detail "VPN `"$name`" phase2 uses weak cipher: $algo" `
                            -Recommendation "Use AES-128 or AES-256 based proposals"))
                        break
                    }
                    if ($hash -in $weakHash) {
                        $findings.Add((New-Finding -Severity "MEDIUM" -Category "VPN Weak Hash" `
                            -PolicyId $null -PolicyName $name `
                            -Detail "VPN `"$name`" phase2 uses weak hash: $algo" `
                            -Recommendation "Use SHA-256 or SHA-384 instead of MD5"))
                        break
                    }
                }
            }
            if ($block['pfs'] -and $block['pfs'] -eq 'disable') {
                $findings.Add((New-Finding -Severity "MEDIUM" -Category "VPN No PFS" `
                    -PolicyId $null -PolicyName $name `
                    -Detail "VPN `"$name`" phase2 has Perfect Forward Secrecy disabled" `
                    -Recommendation "Enable PFS to ensure session key compromise does not expose other sessions"))
            }
        }
    }

    return ,$findings
}

function Find-SSLVPNIssues {
    <#  Audits SSL VPN settings for legacy TLS, weak ciphers, and broad access.  #>
    param([hashtable]$Sections)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $key = 'config vpn ssl settings'
    if (-not $Sections.ContainsKey($key)) { return ,$findings }
    $settings = @{}
    foreach ($raw in $Sections[$key]) {
        if ($raw.Trim() -match '^\s*set\s+(\S+)\s+(.+)$') { $settings[$Matches[1]] = $Matches[2].Trim().Trim('"') }
    }
    # Legacy TLS
    if ($settings['tlsv1-0'] -and $settings['tlsv1-0'] -eq 'enable') {
        $findings.Add((New-Finding -Severity "HIGH" -Category "SSL VPN Legacy TLS" `
            -PolicyId $null -PolicyName "" `
            -Detail "SSL VPN allows TLS 1.0 — vulnerable to POODLE, BEAST, and other attacks" `
            -Recommendation "Disable TLS 1.0 (set tlsv1-0 disable) and use TLS 1.2+ only"))
    }
    if ($settings['tlsv1-1'] -and $settings['tlsv1-1'] -eq 'enable') {
        $findings.Add((New-Finding -Severity "HIGH" -Category "SSL VPN Legacy TLS" `
            -PolicyId $null -PolicyName "" `
            -Detail "SSL VPN allows TLS 1.1 — deprecated and insecure" `
            -Recommendation "Disable TLS 1.1 (set tlsv1-1 disable) and use TLS 1.2+ only"))
    }
    # Weak algorithm
    if ($settings['algorithm'] -and $settings['algorithm'] -in @('low', 'medium')) {
        $findings.Add((New-Finding -Severity "MEDIUM" -Category "SSL VPN Weak Cipher" `
            -PolicyId $null -PolicyName "" `
            -Detail "SSL VPN cipher strength set to `"$($settings['algorithm'])`"" `
            -Recommendation "Set algorithm to 'high' for strong cipher suites"))
    }
    # Unrestricted source
    if ($settings['source-address'] -and $settings['source-address'].ToLower() -eq 'all') {
        $findings.Add((New-Finding -Severity "MEDIUM" -Category "SSL VPN Open Source" `
            -PolicyId $null -PolicyName "" `
            -Detail "SSL VPN accepts connections from any source address" `
            -Recommendation "Restrict source-address to specific IP ranges or geo-locations"))
    }
    # Unsafe renegotiation
    if ($settings['unsafe-legacy-renegotiation'] -and $settings['unsafe-legacy-renegotiation'] -eq 'enable') {
        $findings.Add((New-Finding -Severity "MEDIUM" -Category "SSL VPN Unsafe Renegotiation" `
            -PolicyId $null -PolicyName "" `
            -Detail "SSL VPN allows unsafe legacy renegotiation — vulnerable to MitM attacks" `
            -Recommendation "Disable unsafe-legacy-renegotiation"))
    }
    return ,$findings
}

# =============================================================================
# INFRASTRUCTURE CHECKS
# =============================================================================

function Find-VipIssues {
    <#  Flags VIPs with extintf set to "any" — exposes services on all interfaces.  #>
    param([hashtable]$Sections)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $key = 'config firewall vip'
    if (-not $Sections.ContainsKey($key)) { return ,$findings }
    $blocks = ConvertTo-EditBlocks -Lines $Sections[$key]
    foreach ($block in $blocks) {
        $name    = $block['_id']
        $extintf = $block['extintf']
        if ($extintf -and $extintf.ToLower() -eq 'any') {
            $extip = $block['extip']
            $findings.Add((New-Finding -Severity "HIGH" -Category "VIP Any Interface" `
                -PolicyId $null -PolicyName $name `
                -Detail "VIP `"$name`" ($extip) has extintf `"any`" — exposed on all interfaces" `
                -Recommendation "Set extintf to the specific WAN interface to limit exposure"))
        }
    }
    return ,$findings
}

function Find-LocalInPolicyIssues {
    <#  Checks if local-in policies exist to restrict management plane access.  #>
    param([hashtable]$Sections)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $key = 'config firewall local-in-policy'
    if (-not $Sections.ContainsKey($key)) {
        $findings.Add((New-Finding -Severity "INFO" -Category "No Local-In Policies" `
            -PolicyId $null -PolicyName "" `
            -Detail "No local-in policies configured — management access controlled only by interface allowaccess" `
            -Recommendation "Consider adding local-in policies for granular management plane access control"))
    }
    return ,$findings
}

function Find-HAIssues {
    <#  Checks HA cluster settings for encryption and authentication.  #>
    param([hashtable]$Sections)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    $key = 'config system ha'
    if (-not $Sections.ContainsKey($key)) { return ,$findings }
    $settings = @{}
    foreach ($raw in $Sections[$key]) {
        if ($raw.Trim() -match '^\s*set\s+(\S+)\s+(.+)$') { $settings[$Matches[1]] = $Matches[2].Trim() }
    }
    # Only check if HA is active (not standalone)
    if (-not $settings['mode'] -or $settings['mode'] -eq 'standalone') { return ,$findings }
    if (-not $settings['encryption'] -or $settings['encryption'] -eq 'disable') {
        $findings.Add((New-Finding -Severity "MEDIUM" -Category "HA No Encryption" `
            -PolicyId $null -PolicyName "" `
            -Detail "HA heartbeat encryption is disabled — cluster traffic sent in cleartext" `
            -Recommendation "Enable HA encryption (set encryption enable) to protect cluster communication"))
    }
    if (-not $settings['authentication'] -or $settings['authentication'] -eq 'disable') {
        $findings.Add((New-Finding -Severity "MEDIUM" -Category "HA No Authentication" `
            -PolicyId $null -PolicyName "" `
            -Detail "HA heartbeat authentication is disabled — cluster vulnerable to rogue member injection" `
            -Recommendation "Enable HA authentication (set authentication enable) to validate cluster members"))
    }
    return ,$findings
}

function Find-FirmwareIssues {
    <#  Checks firmware version against known-vulnerable FortiOS releases.  #>
    param($FirmwareInfo)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()
    if ($null -eq $FirmwareInfo) { return ,$findings }
    $ver = $FirmwareInfo.Version
    # Major.minor branch
    $branch = ($ver -split '\.')[0..1] -join '.'
    # Known CVE thresholds — array of @(branch, fixedVersion, CVE, description, severity)
    $cveChecks = @(
        @('7.4', '7.4.3',  'CVE-2024-21762', 'SSL VPN out-of-bounds write (RCE)',    'CRITICAL'),
        @('7.2', '7.2.7',  'CVE-2024-21762', 'SSL VPN out-of-bounds write (RCE)',    'CRITICAL'),
        @('7.0', '7.0.14', 'CVE-2024-21762', 'SSL VPN out-of-bounds write (RCE)',    'CRITICAL'),
        @('7.2', '7.2.5',  'CVE-2023-27997', 'Heap buffer overflow in SSL VPN',      'CRITICAL'),
        @('7.0', '7.0.12', 'CVE-2023-27997', 'Heap buffer overflow in SSL VPN',      'CRITICAL'),
        @('6.4', '6.4.13', 'CVE-2023-27997', 'Heap buffer overflow in SSL VPN',      'CRITICAL'),
        @('7.2', '7.2.2',  'CVE-2022-40684', 'Authentication bypass on admin API',   'CRITICAL'),
        @('7.0', '7.0.7',  'CVE-2022-40684', 'Authentication bypass on admin API',   'CRITICAL')
    )
    foreach ($check in $cveChecks) {
        if ($branch -ne $check[0]) { continue }
        if ((Compare-FortiVersion -VersionA $ver -VersionB $check[1]) -lt 0) {
            $findings.Add((New-Finding -Severity $check[4] -Category "Vulnerable Firmware" `
                -PolicyId $null -PolicyName "" `
                -Detail "FortiOS $ver is vulnerable to $($check[2]): $($check[3]). Fixed in $($check[1])" `
                -Recommendation "Upgrade firmware to FortiOS $($check[1]) or later immediately"))
            break  # One CVE is enough to flag
        }
    }
    # End-of-life branches
    $eolBranches = @('5.0', '5.2', '5.4', '5.6', '6.0', '6.2')
    if ($branch -in $eolBranches) {
        $findings.Add((New-Finding -Severity "HIGH" -Category "End-of-Life Firmware" `
            -PolicyId $null -PolicyName "" `
            -Detail "FortiOS $ver ($branch branch) is end-of-life and no longer receives security patches" `
            -Recommendation "Plan upgrade to a supported FortiOS branch (7.0+) as soon as possible"))
    }
    return ,$findings
}

function Find-RoutingAuthIssues {
    <#  Checks BGP neighbors and OSPF interfaces for missing authentication.
        Unauthenticated routing peers can be spoofed to inject malicious routes.  #>
    param([hashtable]$Sections)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # --- BGP neighbors ---
    $bgpKey = 'config router bgp'
    if ($Sections.ContainsKey($bgpKey)) {
        # Scan raw lines for neighbor edit blocks within nested "config neighbor"
        $inNeighbor = $false; $neighborDepth = 0
        $currentPeer = $null; $hasPassword = $false
        foreach ($raw in $Sections[$bgpKey]) {
            $trimmed = $raw.Trim()
            if ($trimmed -eq 'config neighbor') { $inNeighbor = $true; $neighborDepth = 1; continue }
            if (-not $inNeighbor) { continue }
            if ($trimmed -match '^config ') { $neighborDepth++; continue }
            if ($trimmed -eq 'end') {
                $neighborDepth--
                if ($neighborDepth -le 0) { $inNeighbor = $false }
                continue
            }
            if ($neighborDepth -ne 1) { continue }
            if ($trimmed -match '^\s*edit\s+"?([^"]+)"?\s*$') {
                if ($null -ne $currentPeer -and -not $hasPassword) {
                    $findings.Add((New-Finding -Severity "HIGH" -Category "BGP No Auth" `
                        -PolicyId $null -PolicyName $currentPeer `
                        -Detail "BGP neighbor $currentPeer has no MD5 password — vulnerable to route injection" `
                        -Recommendation "Set 'set password' on BGP neighbors for TCP MD5 authentication"))
                }
                $currentPeer = $Matches[1]; $hasPassword = $false; continue
            }
            if ($trimmed -eq 'next') {
                if ($null -ne $currentPeer -and -not $hasPassword) {
                    $findings.Add((New-Finding -Severity "HIGH" -Category "BGP No Auth" `
                        -PolicyId $null -PolicyName $currentPeer `
                        -Detail "BGP neighbor $currentPeer has no MD5 password — vulnerable to route injection" `
                        -Recommendation "Set 'set password' on BGP neighbors for TCP MD5 authentication"))
                }
                $currentPeer = $null; continue
            }
            if ($null -ne $currentPeer -and $trimmed -match '^\s*set\s+password\s+') {
                $hasPassword = $true
            }
        }
    }

    # --- OSPF interfaces ---
    $ospfKey = 'config router ospf'
    if ($Sections.ContainsKey($ospfKey)) {
        $inOspfIntf = $false; $ospfDepth = 0
        $currentIntf = $null; $hasAuth = $false
        foreach ($raw in $Sections[$ospfKey]) {
            $trimmed = $raw.Trim()
            if ($trimmed -eq 'config ospf-interface') { $inOspfIntf = $true; $ospfDepth = 1; continue }
            if (-not $inOspfIntf) { continue }
            if ($trimmed -match '^config ') { $ospfDepth++; continue }
            if ($trimmed -eq 'end') {
                $ospfDepth--
                if ($ospfDepth -le 0) { $inOspfIntf = $false }
                continue
            }
            if ($ospfDepth -ne 1) { continue }
            if ($trimmed -match '^\s*edit\s+"?([^"]+)"?\s*$') {
                if ($null -ne $currentIntf -and -not $hasAuth) {
                    $findings.Add((New-Finding -Severity "HIGH" -Category "OSPF No Auth" `
                        -PolicyId $null -PolicyName $currentIntf `
                        -Detail "OSPF interface `"$currentIntf`" has no authentication — vulnerable to route injection" `
                        -Recommendation "Set 'set authentication md5' with md5-keys on OSPF interfaces"))
                }
                $currentIntf = $Matches[1]; $hasAuth = $false; continue
            }
            if ($trimmed -eq 'next') {
                if ($null -ne $currentIntf -and -not $hasAuth) {
                    $findings.Add((New-Finding -Severity "HIGH" -Category "OSPF No Auth" `
                        -PolicyId $null -PolicyName $currentIntf `
                        -Detail "OSPF interface `"$currentIntf`" has no authentication — vulnerable to route injection" `
                        -Recommendation "Set 'set authentication md5' with md5-keys on OSPF interfaces"))
                }
                $currentIntf = $null; continue
            }
            if ($null -ne $currentIntf -and $trimmed -match '^\s*set\s+authentication\s+(md5|text)') {
                $hasAuth = $true
            }
        }
    }

    return ,$findings
}

function Find-DoSPolicyIssues {
    <#  Checks if DoS policies exist to protect WAN-facing interfaces.
        Missing DoS policies leave the firewall vulnerable to volumetric attacks.  #>
    param([hashtable]$Sections)
    $findings = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Identify WAN-facing interfaces
    $wanInterfaces = [System.Collections.Generic.List[string]]::new()
    $ifaceKey = 'config system interface'
    if ($Sections.ContainsKey($ifaceKey)) {
        $blocks = ConvertTo-EditBlocks -Lines $Sections[$ifaceKey]
        foreach ($block in $blocks) {
            $name = $block['_id']
            $role = $block['role']
            $type = $block['type']
            # Detect WAN interfaces by role, type, or naming convention
            $isWan = ($role -eq 'wan') -or
                     ($name -match '(?i)^(wan|internet|isp|ext|outside)') -or
                     ($type -eq 'physical' -and $block['mode'] -eq 'dhcp' -and $name -match '(?i)wan')
            if ($isWan) { $wanInterfaces.Add($name) }
        }
    }

    if ($wanInterfaces.Count -eq 0) { return ,$findings }

    # Check if DoS policies exist
    $dosKey = 'config firewall DoS-policy'
    if (-not $Sections.ContainsKey($dosKey)) {
        $findings.Add((New-Finding -Severity "MEDIUM" -Category "No DoS Policies" `
            -PolicyId $null -PolicyName "" `
            -Detail "No DoS policies configured — WAN interfaces ($($wanInterfaces -join ', ')) have no volumetric attack protection" `
            -Recommendation "Configure DoS policies on WAN interfaces with flood thresholds for TCP SYN, UDP, ICMP"))
        return ,$findings
    }

    # Check if WAN interfaces are covered
    $dosBlocks = ConvertTo-EditBlocks -Lines $Sections[$dosKey]
    $coveredInterfaces = @{}
    foreach ($block in $dosBlocks) {
        if ($block['status'] -eq 'disable') { continue }
        $srcintf = $block['srcintf']
        if ($srcintf) {
            $intfList = if ($srcintf -is [array]) { $srcintf } else { @($srcintf) }
            foreach ($intf in $intfList) {
                $coveredInterfaces[$intf.ToLower()] = $true
            }
        }
    }

    foreach ($wan in $wanInterfaces) {
        if (-not $coveredInterfaces.ContainsKey($wan.ToLower()) -and -not $coveredInterfaces.ContainsKey('any')) {
            $findings.Add((New-Finding -Severity "MEDIUM" -Category "WAN No DoS Policy" `
                -PolicyId $null -PolicyName $wan `
                -Detail "WAN interface `"$wan`" is not covered by any DoS policy" `
                -Recommendation "Add a DoS policy with srcintf `"$wan`" to protect against volumetric attacks"))
        }
    }

    return ,$findings
}

# =============================================================================
# HTML REPORT
# =============================================================================

function Export-HtmlReport {
    param(
        [System.Collections.Generic.List[PSCustomObject]]$Findings,
        [string]$OutputPath,
        [string]$ConfigFile,
        $FirmwareInfo,
        [int]$PolicyCount,
        [int]$AddressCount,
        [int]$SectionCount
    )
    $critical = @($Findings | Where-Object { $_.Severity -eq 'CRITICAL' }).Count
    $high     = @($Findings | Where-Object { $_.Severity -eq 'HIGH' }).Count
    $medium   = @($Findings | Where-Object { $_.Severity -eq 'MEDIUM' }).Count
    $low      = @($Findings | Where-Object { $_.Severity -eq 'LOW' }).Count
    $info     = @($Findings | Where-Object { $_.Severity -eq 'INFO' }).Count
    $now      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $fwVer    = if ($FirmwareInfo) { "$($FirmwareInfo.Model) — FortiOS $($FirmwareInfo.Version) (build $($FirmwareInfo.Build))" } else { "Unknown" }
    $sevClass = @{ CRITICAL = 'critical'; HIGH = 'high'; MEDIUM = 'medium'; LOW = 'low'; INFO = 'info' }

    # Build findings table rows
    $rows = [System.Text.StringBuilder]::new()
    foreach ($f in $Findings) {
        $cls = $sevClass[$f.Severity]
        $polId = if ($f.PolicyId) { $f.PolicyId } else { "-" }
        [void]$rows.AppendLine("  <tr>")
        [void]$rows.AppendLine("    <td>$($f.FindingId)</td>")
        [void]$rows.AppendLine("    <td><span class=`"sev $cls`">$($f.Severity)</span></td>")
        [void]$rows.AppendLine("    <td>$([System.Net.WebUtility]::HtmlEncode($f.Category))</td>")
        [void]$rows.AppendLine("    <td>$polId</td>")
        [void]$rows.AppendLine("    <td>$([System.Net.WebUtility]::HtmlEncode($f.Detail))</td>")
        [void]$rows.AppendLine("    <td>$([System.Net.WebUtility]::HtmlEncode($f.Recommendation))</td>")
        [void]$rows.AppendLine("  </tr>")
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>FortiGate Policy Audit Report</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;color:#1a1a2e;line-height:1.5;padding:2rem}
.wrap{max-width:1400px;margin:0 auto}
.header{background:#1a1a2e;color:#fff;padding:1.5rem 2rem;border-radius:10px 10px 0 0}
.header h1{font-size:1.5rem;margin-bottom:.3rem}
.header .meta{opacity:.8;font-size:.85rem}
.cards{display:flex;gap:.75rem;padding:1.25rem 2rem;background:#fff;border-bottom:1px solid #e0e0e0}
.card{flex:1;padding:1rem;border-radius:8px;text-align:center}
.card .count{font-size:2rem;font-weight:700}
.card .label{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;margin-top:.25rem}
.card.critical{background:#fef2f2;color:#dc2626}
.card.high{background:#fff7ed;color:#ea580c}
.card.medium{background:#fefce8;color:#ca8a04}
.card.low{background:#f0fdf4;color:#16a34a}
.card.info{background:#eff6ff;color:#2563eb}
.section{background:#fff;padding:1.5rem 2rem;border-bottom:1px solid #e0e0e0}
.section:last-child{border-radius:0 0 10px 10px;border-bottom:none}
.section h2{font-size:1.1rem;margin-bottom:1rem;color:#1a1a2e}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{text-align:left;padding:.6rem .5rem;border-bottom:2px solid #d1d5db;color:#6b7280;font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}
td{padding:.6rem .5rem;border-bottom:1px solid #f3f4f6;vertical-align:top}
tr:hover{background:#f9fafb}
.sev{font-weight:600;padding:2px 10px;border-radius:4px;font-size:.75rem;display:inline-block;min-width:70px;text-align:center}
.critical{background:#dc2626;color:#fff}
.high{background:#ea580c;color:#fff}
.medium{background:#ca8a04;color:#fff}
.low{background:#16a34a;color:#fff}
.info{background:#2563eb;color:#fff}
.footer{text-align:center;padding:1rem;color:#9ca3af;font-size:.8rem}
.config-meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:.75rem}
.config-meta .item{background:#f9fafb;padding:.75rem 1rem;border-radius:6px;border:1px solid #e5e7eb}
.config-meta .item .label{font-size:.75rem;color:#6b7280;text-transform:uppercase}
.config-meta .item .value{font-size:1rem;font-weight:600;margin-top:.15rem}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <h1>FortiGate Policy Audit Report</h1>
    <div class="meta">Generated: $now &mdash; Config: $([System.Net.WebUtility]::HtmlEncode($ConfigFile))</div>
  </div>
  <div class="cards">
    <div class="card critical"><div class="count">$critical</div><div class="label">Critical</div></div>
    <div class="card high"><div class="count">$high</div><div class="label">High</div></div>
    <div class="card medium"><div class="count">$medium</div><div class="label">Medium</div></div>
    <div class="card low"><div class="count">$low</div><div class="label">Low</div></div>
    <div class="card info"><div class="count">$info</div><div class="label">Info</div></div>
  </div>
  <div class="section">
    <h2>Configuration Details</h2>
    <div class="config-meta">
      <div class="item"><div class="label">Firmware</div><div class="value">$([System.Net.WebUtility]::HtmlEncode($fwVer))</div></div>
      <div class="item"><div class="label">Sections</div><div class="value">$SectionCount</div></div>
      <div class="item"><div class="label">Policies</div><div class="value">$PolicyCount</div></div>
      <div class="item"><div class="label">Addresses</div><div class="value">$AddressCount</div></div>
      <div class="item"><div class="label">Total Findings</div><div class="value">$($Findings.Count)</div></div>
    </div>
  </div>
  <div class="section">
    <h2>Findings</h2>
    <table>
      <thead><tr><th>ID</th><th>Severity</th><th>Category</th><th>Policy</th><th>Detail</th><th>Recommendation</th></tr></thead>
      <tbody>
$($rows.ToString())      </tbody>
    </table>
  </div>
</div>
<div class="footer">Audit-FortiGatePolicies &mdash; FortiGate offline configuration audit tool</div>
</body>
</html>
"@

    [System.IO.File]::WriteAllText($OutputPath, $html, [System.Text.Encoding]::UTF8)
}

# =============================================================================
# MAIN
# =============================================================================

try {
    $Script:FindingCounter = 0
    $allFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

    Write-Log "Starting $($Config.ScriptName)"

    if (-not (Test-Path $Config.ConfigFile)) {
        Write-Log "Config file not found: $($Config.ConfigFile)" -Level ERROR
        exit 1
    }
    Write-Log "Config file: $($Config.ConfigFile)"

    if (-not (Test-Path $Config.OutputDir)) {
        New-Item -ItemType Directory -Path $Config.OutputDir | Out-Null
    }

    # --- Parse firmware info from header ---
    $firmwareInfo = Get-FirmwareInfo -FilePath $Config.ConfigFile
    if ($firmwareInfo) {
        Write-Log "Firmware: $($firmwareInfo.Model) — FortiOS $($firmwareInfo.Version) (build $($firmwareInfo.Build))"
    }

    # --- Parse sections ---
    Write-Log "Parsing FortiGate configuration..."
    $sections = ConvertTo-FortiSections -FilePath $Config.ConfigFile
    $sectionCount = $sections.Count

    # --- Parse policies ---
    $policyKey = "config firewall policy"
    if ($sections.ContainsKey($policyKey)) {
        Write-Log "Parsing firewall policies..."
        $policies = ConvertTo-PolicyObjects -Lines $sections[$policyKey]
        Write-Log "Found $($policies.Count) firewall policies"
    } else {
        Write-Log "No firewall policy section found in config" -Level WARNING
        $policies = [System.Collections.Generic.List[hashtable]]::new()
    }

    # --- Parse addresses ---
    $addrKey = "config firewall address"
    if ($sections.ContainsKey($addrKey)) {
        Write-Log "Parsing address objects..."
        $addresses = ConvertTo-AddressObjects -Lines $sections[$addrKey]
        Write-Log "Found $($addresses.Count) address objects"
    } else {
        Write-Log "No firewall address section found in config" -Level WARNING
        $addresses = @{}
    }

    # --- Parse services ---
    $svcKey = "config firewall service custom"
    if ($sections.ContainsKey($svcKey)) {
        $services = ConvertTo-EditBlocks -Lines $sections[$svcKey]
    } else {
        $services = [System.Collections.Generic.List[hashtable]]::new()
    }

    # =========================================================================
    # RUN CHECKS
    # =========================================================================

    # --- Policy checks ---

    if ($Config.CheckShadowRules -and $policies.Count -gt 1) {
        Write-Log "Checking for shadow rules..."
        $results = Find-ShadowRules -Policies $policies
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Shadow rule check: $($results.Count) finding(s)"
    }

    if ($Config.CheckPermissiveRules -and $policies.Count -gt 0) {
        Write-Log "Checking for overly permissive rules..."
        $results = Find-PermissiveRules -Policies $policies
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Permissive rule check: $($results.Count) finding(s)"
    }

    if ($Config.CheckDisabledPolicies -and $policies.Count -gt 0) {
        Write-Log "Checking for disabled policies..."
        $results = Find-DisabledPolicies -Policies $policies
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Disabled policy check: $($results.Count) finding(s)"
    }

    if ($Config.CheckLoggingDisabled -and $policies.Count -gt 0) {
        Write-Log "Checking for accept rules with logging disabled..."
        $results = Find-LoggingDisabled -Policies $policies
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Accept logging check: $($results.Count) finding(s)"
    }

    if ($Config.CheckDenyNoLogging -and $policies.Count -gt 0) {
        Write-Log "Checking for deny rules with logging disabled..."
        $results = Find-DenyNoLogging -Policies $policies
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Deny logging check: $($results.Count) finding(s)"
    }

    if ($Config.CheckMissingProfiles -and $policies.Count -gt 0) {
        Write-Log "Checking for missing security profiles..."
        $results = Find-MissingSecurityProfiles -Policies $policies
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Security profile check: $($results.Count) finding(s)"
    }

    if ($Config.CheckMissingSSL -and $policies.Count -gt 0) {
        Write-Log "Checking for missing SSL/SSH inspection..."
        $results = Find-MissingSSLInspection -Policies $policies
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "SSL inspection check: $($results.Count) finding(s)"
    }

    if ($Config.CheckAnyInterface -and $policies.Count -gt 0) {
        Write-Log "Checking for any-interface policies..."
        $results = Find-AnyInterface -Policies $policies
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Any-interface check: $($results.Count) finding(s)"
    }

    if ($Config.CheckMissingComments -and $policies.Count -gt 0) {
        Write-Log "Checking for missing policy comments..."
        $results = Find-MissingComments -Policies $policies
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Missing comments check: $($results.Count) finding(s)"
    }

    if ($Config.CheckIPv6Policies) {
        Write-Log "Checking IPv6 policy coverage..."
        $results = Find-IPv6PolicyIssues -Sections $sections
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "IPv6 policy check: $($results.Count) finding(s)"
    }

    if ($Config.CheckUTMProfileDepth -and $policies.Count -gt 0) {
        Write-Log "Checking UTM profile effectiveness..."
        $results = Find-UTMProfileDepthIssues -Sections $sections -Policies $policies
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "UTM profile depth check: $($results.Count) finding(s)"
    }

    # --- Object hygiene ---

    if ($Config.CheckDuplicateAddrs -and $addresses.Count -gt 0) {
        Write-Log "Checking for duplicate address objects..."
        $results = Find-DuplicateAddresses -Addresses $addresses
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Duplicate address check: $($results.Count) finding(s)"
    }

    if ($Config.CheckBroadAddresses -and $addresses.Count -gt 0) {
        Write-Log "Checking for overly broad address objects..."
        $results = Find-BroadAddresses -Addresses $addresses -MaxPrefix $Config.BroadSubnetMaxPrefix
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Broad address check: $($results.Count) finding(s)"
    }

    if ($Config.CheckUnusedAddresses -and $addresses.Count -gt 0 -and $policies.Count -gt 0) {
        Write-Log "Checking for unused address objects..."
        $results = Find-UnusedAddresses -Addresses $addresses -Policies $policies
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Unused address check: $($results.Count) finding(s)"
    }

    if ($Config.CheckOverlappingAddrs -and $addresses.Count -gt 1) {
        Write-Log "Checking for overlapping address objects..."
        $results = Find-OverlappingAddresses -Addresses $addresses
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Overlapping address check: $($results.Count) finding(s)"
    }

    if ($Config.CheckUnusedServices -and $services.Count -gt 0 -and $policies.Count -gt 0) {
        Write-Log "Checking for unused service objects..."
        $results = Find-UnusedServices -Services $services -Policies $policies
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Unused service check: $($results.Count) finding(s)"
    }

    if ($Config.CheckGroupHygiene) {
        Write-Log "Checking address/service group hygiene..."
        $results = Find-GroupHygieneIssues -Sections $sections -Addresses $addresses -Services $services
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Group hygiene check: $($results.Count) finding(s)"
    }

    # --- System hardening ---

    $adminKey = 'config system admin'
    $admins = if ($sections.ContainsKey($adminKey)) {
        ConvertTo-EditBlocks -Lines $sections[$adminKey]
    } else { [System.Collections.Generic.List[hashtable]]::new() }

    if ($Config.CheckAdminSecurity -and $admins.Count -gt 0) {
        Write-Log "Checking admin account security..."
        $results = Find-AdminIssues -Admins $admins
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Admin trusted-host check: $($results.Count) finding(s)"
    }

    if ($Config.CheckAdminMFA -and $admins.Count -gt 0) {
        Write-Log "Checking admin MFA..."
        $results = Find-AdminMFAIssues -Admins $admins
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Admin MFA check: $($results.Count) finding(s)"
    }

    if ($Config.CheckInterfaceAccess) {
        $ifaceKey = 'config system interface'
        if ($sections.ContainsKey($ifaceKey)) {
            Write-Log "Checking interface access settings..."
            $interfaces = ConvertTo-EditBlocks -Lines $sections[$ifaceKey]
            $results = Find-InterfaceAccessIssues -Interfaces $interfaces
            foreach ($f in $results) { $allFindings.Add($f) }
            Write-Log "Interface access check: $($results.Count) finding(s)"
        }
    }

    if ($Config.CheckPasswordPolicy) {
        Write-Log "Checking password policy..."
        $results = Find-PasswordPolicyIssues -Sections $sections
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Password policy check: $($results.Count) finding(s)"
    }

    if ($Config.CheckSNMP) {
        Write-Log "Checking SNMP configuration..."
        $results = Find-SNMPIssues -Sections $sections
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "SNMP check: $($results.Count) finding(s)"
    }

    if ($Config.CheckLoggingConfig) {
        Write-Log "Checking central logging configuration..."
        $results = Find-LoggingConfigIssues -Sections $sections
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Central logging check: $($results.Count) finding(s)"
    }

    if ($Config.CheckGlobalSettings) {
        Write-Log "Checking global system settings..."
        $results = Find-GlobalSettingIssues -Sections $sections
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Global settings check: $($results.Count) finding(s)"
    }

    if ($Config.CheckDnsNtp) {
        Write-Log "Checking DNS and NTP configuration..."
        $results = Find-DnsNtpIssues -Sections $sections
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "DNS/NTP check: $($results.Count) finding(s)"
    }

    if ($Config.CheckInsecureLDAP) {
        Write-Log "Checking LDAP configuration..."
        $results = Find-InsecureLDAP -Sections $sections
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "LDAP check: $($results.Count) finding(s)"
    }

    if ($Config.CheckExpiredSchedules) {
        Write-Log "Checking for expired schedules..."
        $results = Find-ExpiredSchedules -Sections $sections
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Expired schedule check: $($results.Count) finding(s)"
    }

    if ($Config.CheckCertificates) {
        Write-Log "Checking certificate configuration..."
        $results = Find-CertificateIssues -Sections $sections
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Certificate check: $($results.Count) finding(s)"
    }

    # --- VPN ---

    if ($Config.CheckVpnCrypto) {
        Write-Log "Checking VPN crypto settings..."
        $results = Find-VpnCryptoIssues -Sections $sections
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "VPN crypto check: $($results.Count) finding(s)"
    }

    if ($Config.CheckSSLVPN) {
        Write-Log "Checking SSL VPN settings..."
        $results = Find-SSLVPNIssues -Sections $sections
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "SSL VPN check: $($results.Count) finding(s)"
    }

    # --- Infrastructure ---

    if ($Config.CheckVipInterface) {
        Write-Log "Checking VIP interface exposure..."
        $results = Find-VipIssues -Sections $sections
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "VIP check: $($results.Count) finding(s)"
    }

    if ($Config.CheckLocalInPolicies) {
        Write-Log "Checking local-in policies..."
        $results = Find-LocalInPolicyIssues -Sections $sections
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Local-in policy check: $($results.Count) finding(s)"
    }

    if ($Config.CheckHASecurity) {
        Write-Log "Checking HA security..."
        $results = Find-HAIssues -Sections $sections
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "HA check: $($results.Count) finding(s)"
    }

    if ($Config.CheckFirmware -and $firmwareInfo) {
        Write-Log "Checking firmware version..."
        $results = Find-FirmwareIssues -FirmwareInfo $firmwareInfo
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Firmware check: $($results.Count) finding(s)"
    }

    if ($Config.CheckRoutingAuth) {
        Write-Log "Checking routing protocol authentication..."
        $results = Find-RoutingAuthIssues -Sections $sections
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "Routing auth check: $($results.Count) finding(s)"
    }

    if ($Config.CheckDoSPolicies) {
        Write-Log "Checking DoS policy coverage..."
        $results = Find-DoSPolicyIssues -Sections $sections
        foreach ($f in $results) { $allFindings.Add($f) }
        Write-Log "DoS policy check: $($results.Count) finding(s)"
    }

    Write-Log "Total findings: $($allFindings.Count)"

    # =========================================================================
    # EXPORT CSV
    # =========================================================================

    $csvTimestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $csvFile = Join-Path $Config.OutputDir "PolicyAudit_$csvTimestamp.csv"
    if ($allFindings.Count -gt 0) {
        $allFindings | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
        Write-Log "CSV exported: $csvFile"
    } else {
        Write-Log "No findings to export"
    }

    # =========================================================================
    # HTML REPORT
    # =========================================================================

    $htmlFile = $null
    if ($Config.GenerateHtmlReport -and $allFindings.Count -gt 0) {
        $htmlFile = Join-Path $Config.OutputDir "PolicyAudit_$csvTimestamp.html"
        Export-HtmlReport -Findings $allFindings -OutputPath $htmlFile `
            -ConfigFile $Config.ConfigFile -FirmwareInfo $firmwareInfo `
            -PolicyCount $policies.Count -AddressCount $addresses.Count `
            -SectionCount $sectionCount
        Write-Log "HTML report: $htmlFile"
    }

    # =========================================================================
    # CONSOLE SUMMARY
    # =========================================================================

    $separator = "=" * 72
    $divider   = "-" * 72
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $enabledPolicies  = @($policies | Where-Object { $_['status'] -eq 'enable' }).Count
    $disabledPolicies = $policies.Count - $enabledPolicies

    $critical = @($allFindings | Where-Object { $_.Severity -eq "CRITICAL" })
    $high     = @($allFindings | Where-Object { $_.Severity -eq "HIGH" })
    $medium   = @($allFindings | Where-Object { $_.Severity -eq "MEDIUM" })
    $low      = @($allFindings | Where-Object { $_.Severity -eq "LOW" })
    $info     = @($allFindings | Where-Object { $_.Severity -eq "INFO" })

    # Domain groupings
    $policyCats  = @('Shadow Rule','Permissive Rule','Disabled Policy','Logging Disabled','Deny No Logging',
                     'Missing Security Profile','No SSL Inspection','Any Interface','Missing Comments',
                     'No IPv6 Policies','IPv6 Logging Disabled','IPv6 No UTM',
                     'AV Profile Scan Disabled','IPS Sensor Monitor Only','App Control Permissive')
    $objectCats  = @('Duplicate Address','Broad Address','Unused Address','Overlapping Address','Unused Service',
                     'Empty Address Group','Empty Service Group','Orphaned Group Member','Deeply Nested Group')
    $systemCats  = @('Admin No Trusted Host','Admin No MFA','Insecure Interface Access','Interface Access Advisory',
                     'No Password Policy','Password Policy Disabled','Weak Password Policy',
                     'SNMP Default Community','No Central Logging','Strong Crypto Disabled',
                     'HTTPS Redirect Disabled','Long Admin Timeout','No Login Banner',
                     'DNS Not Configured','NTP Not Configured','NTP Sync Disabled',
                     'Insecure LDAP','Expired Schedule',
                     'Default Admin Certificate','Weak SSL Inspection','VPN Default Certificate')
    $vpnCats     = @('VPN IKEv1','VPN Weak Cipher','VPN Weak DH Group','VPN Weak Hash','VPN No PFS',
                     'SSL VPN Legacy TLS','SSL VPN Weak Cipher','SSL VPN Open Source','SSL VPN Unsafe Renegotiation')
    $infraCats   = @('VIP Any Interface','No Local-In Policies','HA No Encryption','HA No Authentication',
                     'Vulnerable Firmware','End-of-Life Firmware',
                     'BGP No Auth','OSPF No Auth','No DoS Policies','WAN No DoS Policy')

    $policyFindings = @($allFindings | Where-Object { $_.Category -in $policyCats })
    $objectFindings = @($allFindings | Where-Object { $_.Category -in $objectCats })
    $systemFindings = @($allFindings | Where-Object { $_.Category -in $systemCats })
    $vpnFindings    = @($allFindings | Where-Object { $_.Category -in $vpnCats })
    $infraFindings  = @($allFindings | Where-Object { $_.Category -in $infraCats })

    $severityColors = @{ CRITICAL = "Red"; HIGH = "Red"; MEDIUM = "Yellow"; LOW = "White"; INFO = "DarkGray" }

    Write-Summary ""
    Write-Summary $separator -Color Yellow
    Write-Summary "  FortiGate Policy Audit  —  $timestamp" -Color Yellow
    Write-Summary "  Config: $($Config.ConfigFile)" -Color Yellow
    if ($firmwareInfo) {
        Write-Summary "  Firmware: $($firmwareInfo.Model) — FortiOS $($firmwareInfo.Version) (build $($firmwareInfo.Build))" -Color Yellow
    }
    Write-Summary "  Sections: $sectionCount  |  Policies: $($policies.Count) ($enabledPolicies enabled, $disabledPolicies disabled)  |  Addresses: $($addresses.Count)" -Color Yellow
    Write-Summary $separator -Color Yellow
    Write-Summary ""

    foreach ($group in @(
        @{ Label = "CRITICAL"; Items = $critical },
        @{ Label = "HIGH";     Items = $high },
        @{ Label = "MEDIUM";   Items = $medium },
        @{ Label = "LOW";      Items = $low },
        @{ Label = "INFO";     Items = $info }
    )) {
        if ($group.Items.Count -eq 0) { continue }
        $color = $severityColors[$group.Label]
        $countLabel = if ($group.Items.Count -eq 1) { "finding" } else { "findings" }

        Write-Summary "  $($group.Label) ($($group.Items.Count) $countLabel)" -Color $color
        Write-Summary $divider -Color $color

        if ($group.Label -eq "INFO") {
            $disabledItems = @($group.Items | Where-Object { $_.Category -eq "Disabled Policy" })
            $otherItems    = @($group.Items | Where-Object { $_.Category -ne "Disabled Policy" })
            foreach ($f in $otherItems) {
                Write-Summary "  $($f.FindingId)  $($f.Category.PadRight(25)) $($f.Detail)" -Color $color
            }
            if ($disabledItems.Count -gt 0) {
                $ids = @($disabledItems | ForEach-Object { $_.PolicyId }) -join ', '
                Write-Summary "  $($disabledItems.Count) disabled policies (IDs: $ids)" -Color $color
            }
        } else {
            foreach ($f in $group.Items) {
                Write-Summary "  $($f.FindingId)  $($f.Category.PadRight(25)) $($f.Detail)" -Color $color
            }
        }
        Write-Summary ""
    }

    if ($allFindings.Count -eq 0) {
        Write-Summary "  No findings. Configuration looks clean." -Color Green
        Write-Summary ""
    }

    if ($allFindings.Count -gt 0) {
        Write-Summary "  DOMAIN BREAKDOWN" -Color Cyan
        Write-Summary $divider -Color Cyan
        Write-Summary ("  Policy analysis:    {0,3} finding(s)" -f $policyFindings.Count)
        Write-Summary ("  Object hygiene:     {0,3} finding(s)" -f $objectFindings.Count)
        Write-Summary ("  System hardening:   {0,3} finding(s)" -f $systemFindings.Count)
        Write-Summary ("  VPN configuration:  {0,3} finding(s)" -f $vpnFindings.Count)
        Write-Summary ("  Infrastructure:     {0,3} finding(s)" -f $infraFindings.Count)
        Write-Summary ""
    }

    Write-Summary $separator -Color Yellow
    Write-Summary ("  RISK SUMMARY: {0} critical  |  {1} high  |  {2} medium  |  {3} low  |  {4} info" -f
        $critical.Count, $high.Count, $medium.Count, $low.Count, $info.Count) -Color Yellow
    if ($allFindings.Count -gt 0) {
        Write-Summary "  CSV:  $csvFile" -Color Yellow
        if ($htmlFile) {
            Write-Summary "  HTML: $htmlFile" -Color Yellow
        }
    }
    Write-Summary $separator -Color Yellow
    Write-Summary ""

    Write-Log "Completed $($Config.ScriptName) successfully"
    exit 0
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    exit 1
}
