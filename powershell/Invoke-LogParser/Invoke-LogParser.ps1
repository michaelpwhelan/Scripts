#Requires -Version 5.1

<#
.SYNOPSIS
    Universal Log Parser - CLI tool for parsing, filtering, analyzing, and
    reporting on infrastructure log files.

.DESCRIPTION
    Parses FortiGate configs, FortiGate traffic/event logs, FortiClient EMS
    logs, FortiSwitch logs, and Windows Event Viewer exports. Supports
    filtering, analysis, interactive query mode, and multi-format report
    generation.

.PARAMETER Path
    Path to one or more log files to parse.

.PARAMETER Format
    Explicit log format. If omitted, format is auto-detected.
    Valid values: FortiGateConf, FortiGateKV, FortiClientLocal,
    FortiSwitchEvent, WindowsEvtx

.PARAMETER Filter
    Query string to filter events (e.g., "action:deny", "severity:high").

.PARAMETER Analyze
    Run an analysis engine on the parsed data.
    Valid values: FailedLogins, VpnSessions, IpsecTunnel, Summary

.PARAMETER Report
    Generate a report.
    Valid values: Summary, Morning, Audit, Compliance, Timeline

.PARAMETER OutputFormat
    Console output format.
    Valid values: Table (default), Grid, List, Raw, Json, Csv

.PARAMETER ExportPath
    File path to export a report.

.PARAMETER ExportFormat
    Export file format. Valid values: Html, Csv, Json

.PARAMETER Fields
    Comma-separated list of fields to display (overrides defaults).

.PARAMETER MaxResults
    Maximum number of events to display.

.PARAMETER StatsOnly
    Show only parse statistics, not individual events.

.PARAMETER Interactive
    Launch interactive query mode (REPL).

.PARAMETER NoColor
    Disable colored output.

.PARAMETER Tail
    Monitor the log file in real-time.

.PARAMETER TailLines
    Number of existing lines to show before tailing. Default: 20.

.PARAMETER Regex
    Filter events by regex pattern matched against raw log lines.

.PARAMETER Highlight
    Color-highlight text matching this pattern without filtering events out.

.PARAMETER Context
    Show N raw log lines before and after each matching event (like grep -C).

.PARAMETER Surround
    Show all events within N seconds of each matching event.

.PARAMETER Section
    Extract a specific config section from a FortiGate config file.

.PARAMETER DiffPath
    Compare the file in -Path against this file.

.PARAMETER Clipboard
    Copy output to Windows clipboard (via Set-Clipboard).

.PARAMETER Open
    Auto-open the exported file after creation.

.PARAMETER EmailTo
    Email address to send the report to. Requires -SmtpServer.

.PARAMETER SmtpServer
    SMTP server for email delivery.

.PARAMETER InputObject
    Accept piped input. Requires -Format since auto-detection needs a file.

.PARAMETER ListParsers
    List available log format parsers.

.PARAMETER ListAnalyzers
    List available analysis engines.

.PARAMETER ListReports
    List available report types.

.EXAMPLE
    .\Invoke-LogParser.ps1 -Path firewall.log
    Parse and display with auto-detection.

.EXAMPLE
    .\Invoke-LogParser.ps1 -Path logs-export.zip
    Extract zip and parse all recognized log files inside.

.EXAMPLE
    .\Invoke-LogParser.ps1 -Path firewall.log -Filter "action:deny" -OutputFormat Grid
    Parse, filter denied traffic, display as compact grid.

.EXAMPLE
    .\Invoke-LogParser.ps1 -Path firewall.log -Analyze FailedLogins -Report Summary -ExportPath report.html -ExportFormat Html
    Parse, analyze failed logins, generate summary report, export to HTML.

.EXAMPLE
    .\Invoke-LogParser.ps1 -Path firewall.log -Interactive
    Parse and enter interactive query mode.

.EXAMPLE
    .\Invoke-LogParser.ps1 -Path config.conf,firewall.log,switch.log
    Parse multiple files simultaneously.

.EXAMPLE
    .\Invoke-LogParser.ps1 -Path firewall.log -Tail -Filter "action:deny"
    Live-tail the log file, only showing denied traffic in real-time.

.EXAMPLE
    .\Invoke-LogParser.ps1 -Path firewall.log -Filter "severity:critical" -Surround 30
    Show all events within 30 seconds of any critical event.

.EXAMPLE
    .\Invoke-LogParser.ps1 -Path firewall.log -Highlight "10\.12\.1\.50" -OutputFormat Grid
    Show all events with the IP 10.12.1.50 highlighted in color.

.EXAMPLE
    .\Invoke-LogParser.ps1 -Path config-old.conf -DiffPath config-new.conf -Section "firewall policy"
    Diff two FortiGate configs, showing only firewall policy changes.

.EXAMPLE
    .\Invoke-LogParser.ps1 -Path firewall.log -Filter "action:deny" -Clipboard
    Parse, filter denied traffic, and copy results to clipboard.

.EXAMPLE
    .\Invoke-LogParser.ps1 -Path *.log -StatsOnly
    Quick digest of all log files in the current directory.

.EXAMPLE
    .\Invoke-LogParser.ps1 -Path firewall.log -Report Summary -ExportPath report.html -ExportFormat Html -Open
    Generate summary report, save as HTML, and open in browser.

.EXAMPLE
    Get-Content firewall.log | .\Invoke-LogParser.ps1 -Format FortiGateKV -Filter "dstport:3389"
    Parse piped input and filter for RDP traffic.

.EXAMPLE
    .\Invoke-LogParser.ps1 -Path firewall.log -Regex "tunnel.*down" -Context 5
    Find tunnel down events with 5 lines of context before and after.
#>

[CmdletBinding(DefaultParameterSetName = 'Parse')]
param(
    [Parameter(Position = 0, ParameterSetName = 'Parse')]
    [string[]]$Path,

    [Parameter(ParameterSetName = 'Parse')]
    [ValidateSet('FortiGateConf','FortiGateKV','FortiClientLocal','FortiSwitchEvent','WindowsEvtx')]
    [string]$Format,

    [Parameter(ParameterSetName = 'Parse')]
    [string]$Filter,

    [Parameter(ParameterSetName = 'Parse')]
    [ValidateSet('FailedLogins','VpnSessions','IpsecTunnel','Summary')]
    [string]$Analyze,

    [Parameter(ParameterSetName = 'Parse')]
    [ValidateSet('Summary','Morning','Audit','Compliance','Timeline')]
    [string]$Report,

    [Parameter(ParameterSetName = 'Parse')]
    [ValidateSet('Table','Grid','List','Raw','Json','Csv')]
    [string]$OutputFormat = 'Table',

    [Parameter(ParameterSetName = 'Parse')]
    [string]$ExportPath,

    [Parameter(ParameterSetName = 'Parse')]
    [ValidateSet('Html','Csv','Json')]
    [string]$ExportFormat = 'Html',

    [Parameter(ParameterSetName = 'Parse')]
    [string]$Fields,

    [Parameter(ParameterSetName = 'Parse')]
    [int]$MaxResults = 0,

    [Parameter(ParameterSetName = 'Parse')]
    [switch]$StatsOnly,

    [Parameter(ParameterSetName = 'Parse')]
    [switch]$Interactive,

    [Parameter(ParameterSetName = 'Parse')]
    [switch]$NoColor,

    [Parameter(ParameterSetName = 'Parse')]
    [switch]$Quiet,

    [Parameter(ParameterSetName = 'Parse')]
    [switch]$Tail,

    [Parameter(ParameterSetName = 'Parse')]
    [int]$TailLines = 20,

    [Parameter(ParameterSetName = 'Parse')]
    [string]$Regex,

    [Parameter(ParameterSetName = 'Parse')]
    [string]$Highlight,

    [Parameter(ParameterSetName = 'Parse')]
    [int]$Context = 0,

    [Parameter(ParameterSetName = 'Parse')]
    [int]$Surround = 0,

    [Parameter(ParameterSetName = 'Parse')]
    [string]$Section,

    [Parameter(ParameterSetName = 'Parse')]
    [string[]]$DiffPath,

    [Parameter(ParameterSetName = 'Parse')]
    [switch]$Clipboard,

    [Parameter(ParameterSetName = 'Parse')]
    [switch]$Open,

    [Parameter(ParameterSetName = 'Parse')]
    [string]$EmailTo,

    [Parameter(ParameterSetName = 'Parse')]
    [string]$SmtpServer,

    [Parameter(ParameterSetName = 'Parse', ValueFromPipeline)]
    [string[]]$InputObject,

    [Parameter(ParameterSetName = 'ListParsers')]
    [switch]$ListParsers,

    [Parameter(ParameterSetName = 'ListAnalyzers')]
    [switch]$ListAnalyzers,

    [Parameter(ParameterSetName = 'ListReports')]
    [switch]$ListReports
)

begin {

# ============================================================================
# SECTION 1: Configuration
# ============================================================================

$script:Version = '6.0.0'
$script:UseAnsi = ($env:WT_SESSION) -or ($PSVersionTable.PSVersion.Major -ge 7) -or ($env:TERM_PROGRAM -eq 'vscode') -or ($env:COLORTERM -eq 'truecolor')
$script:NoColorFlag = $NoColor.IsPresent
$script:QuietFlag = $Quiet.IsPresent
$script:PipedLines = [System.Collections.Generic.List[string]]::new()
$script:TempDirs = [System.Collections.Generic.List[string]]::new()
$script:RawFileLines = @{}
$script:Bookmarks = [System.Collections.Generic.List[object]]::new()

$script:OutputRedirected = $false
try { $script:OutputRedirected = [Console]::IsOutputRedirected } catch {}

if ($script:OutputRedirected -and -not $PSBoundParameters.ContainsKey('OutputFormat')) {
    $OutputFormat = 'Raw'
    $script:NoColorFlag = $true
}

# ANSI color codes (use [char]27 for PS 5.1 compat — `e requires PS 6+)
$esc = [char]27
$script:C = @{
    Reset     = "$esc[0m"
    Bold      = "$esc[1m"
    Dim       = "$esc[2m"
    Red       = "$esc[91m"
    Green     = "$esc[92m"
    Yellow    = "$esc[93m"
    Blue      = "$esc[94m"
    Cyan      = "$esc[96m"
    White     = "$esc[97m"
    Gray      = "$esc[90m"
    BgYellow  = "$esc[43m"
    BgRed     = "$esc[41m"
    BoldRed   = "$esc[1;91m"
    BoldWhite = "$esc[1;97m"
    BoldCyan  = "$esc[1;96m"
}

if ($script:NoColorFlag -or -not $script:UseAnsi) {
    foreach ($k in @($script:C.Keys)) { $script:C[$k] = '' }
}

$script:SevColor = @{
    Critical = $script:C.BoldRed
    High     = $script:C.Red
    Medium   = $script:C.Yellow
    Low      = $script:C.Cyan
    Info     = $script:C.White
}

# ============================================================================
# SECTION 2: Enrichment Data
# ============================================================================

$script:FortiSubtypeLookup = @{
    "traffic/forward"="Forwarded traffic";"traffic/local"="Local traffic";"traffic/sniffer"="Sniffer"
    "utm/webfilter"="Web filter";"utm/av"="Antivirus";"utm/ips"="IPS";"utm/app-ctrl"="Application control"
    "utm/dlp"="DLP";"utm/dns"="DNS filter";"utm/ssl"="SSL inspection";"utm/emailfilter"="Email filter"
    "utm/cifs"="CIFS";"utm/ssh"="SSH inspection"
    "event/system"="System event";"event/vpn"="VPN event";"event/user"="User event";"event/ha"="HA event"
    "event/wad"="WAD event";"event/ipsecvpn"="IPsec VPN";"event/route"="Routing"
    "event/connector"="Fabric connector";"event/fortiextender"="FortiExtender";"event/wireless"="Wireless"
}

$script:FortiClientModuleLookup = @{
    "sslvpn"="VPN";"vpn"="VPN";"av"="Antivirus";"malware"="Antivirus";"webfilter"="Web Filter"
    "ems"="EMS";"update"="Update";"endpoint"="Endpoint";"sandbox"="Sandbox";"firewall"="Firewall"
}

$script:FortiGateLogIdRanges = @{
    "0001"="Traffic: Forward";"0002"="Traffic: Local";"0003"="Traffic: Multicast"
    "0100"="Event: System";"0101"="Event: IPsec";"0102"="Event: HA";"0103"="Event: Compliance"
    "0104"="Event: VPN";"0200"="Event: User";"0300"="Event: Router";"0400"="Event: WAD"
    "1600"="UTM: Virus";"1700"="UTM: Web Filter";"1800"="UTM: IPS";"1900"="UTM: Email Filter"
    "2000"="UTM: DLP";"2100"="UTM: App Control";"2200"="UTM: VoIP";"2300"="UTM: DNS"
}

$script:EventIdLookup = @{
    1="Application Error";2="Application Hang";41="Kernel power failure (unexpected shutdown)"
    104="Event log cleared";1000="Application Error (faulting module)";1001="Windows Error Reporting"
    1002="Application Hang (not responding)";1014="DNS name resolution timeout"
    1102="Security audit log cleared (tampering indicator)";2004="Resource exhaustion diagnosis"
    4624="Successful logon";4625="Failed logon";4634="Account logoff";4647="User initiated logoff"
    4648="Logon with explicit credentials (runas/lateral movement)"
    4656="Handle to object requested";4657="Registry value modified";4663="Attempt to access object"
    4670="Permissions on object changed";4672="Special privileges assigned to new logon"
    4673="Privileged service called";4688="New process created";4689="Process exited"
    4692="Backup of data protection master key";4697="Service installed on the system"
    4698="Scheduled task created";4699="Scheduled task deleted"
    4700="Scheduled task enabled";4701="Scheduled task disabled";4702="Scheduled task updated"
    4719="System audit policy changed";4720="User account created";4722="User account enabled"
    4723="Password change attempted";4724="Password reset attempted"
    4725="User account disabled";4726="User account deleted"
    4727="Security-enabled global group created";4728="Member added to global group"
    4729="Member removed from global group";4730="Global group deleted"
    4731="Security-enabled local group created";4732="Member added to local group"
    4733="Member removed from local group";4734="Local group deleted";4735="Local group changed"
    4738="User account changed";4740="Account locked out"
    4741="Computer account created";4742="Computer account changed";4743="Computer account deleted"
    4756="Member added to universal group";4757="Member removed from universal group"
    4767="Account unlocked";4768="Kerberos TGT requested";4769="Kerberos service ticket requested"
    4770="Kerberos service ticket renewed";4771="Kerberos pre-authentication failed"
    4776="NTLM credential validation";4778="Session reconnected";4779="Session disconnected"
    4797="Blank password query";4798="User local group membership enumerated"
    4799="Security-enabled local group membership enumerated"
    4800="Workstation locked";4801="Workstation unlocked"
    4946="Firewall rule added";4947="Firewall rule modified";4948="Firewall rule deleted"
    4950="Firewall setting changed";5024="Firewall service started";5025="Firewall service stopped"
    5038="Code integrity: image hash not valid";5136="Directory service object modified"
    5140="Network share accessed";5142="Network share added";5144="Network share deleted"
    5145="Detailed file share check";5152="WFP packet dropped";5156="WFP connection allowed"
    5157="WFP connection blocked";6005="Event Log started (boot)";6006="Event Log stopped (shutdown)"
    6008="Unexpected shutdown";6013="System uptime"
    6272="NPS granted access";6273="NPS denied access";6274="NPS discarded request"
    6275="NPS discarded accounting";6276="NPS quarantined user"
    7001="User logon notification";7002="User logoff notification"
    7034="Service crashed";7036="Service state change";7040="Service start type changed"
    7045="New service installed";800="PowerShell pipeline execution"
    4103="PowerShell Module Logging";4104="PowerShell Script Block Logging"
    1006="Defender: Malware detected";1007="Defender: Action taken on malware"
    1116="Defender: Real-time protection threat";1117="Defender: Real-time protection action"
    5001="Defender: Real-time protection disabled"
    18500="Hyper-V VM started";18502="Hyper-V VM stopped";18512="Hyper-V VM migration started"
    10="DHCP: New lease";11="DHCP: Lease renewed";12="DHCP: Lease released";15="DHCP: Lease denied"
}

$script:NpsReasonLookup = @{
    0="IAS_SUCCESS";1="IAS_INTERNAL_ERROR";2="IAS_ACCESS_DENIED";3="IAS_MALFORMED_REQUEST"
    4="IAS_GLOBAL_CATALOG_UNAVAILABLE";5="IAS_DOMAIN_UNAVAILABLE";6="IAS_SERVER_UNAVAILABLE"
    7="IAS_NO_SUCH_DOMAIN";8="IAS_NO_SUCH_USER"
    16="Authentication failed: credentials mismatch";17="Change password failure"
    18="Unable to use specified auth type";21="IAS_CHANGE_PASSWORD_FAILURE"
    22="Client not authenticated (certificate)";23="IAS_UNEXPECTED_ERROR"
    32="IAS_LOCAL_USERS_ONLY";33="IAS_PASSWORD_MUST_CHANGE"
    34="IAS_ACCOUNT_DISABLED";35="IAS_ACCOUNT_EXPIRED";36="IAS_ACCOUNT_LOCKED_OUT"
    37="IAS_INVALID_DAY_OF_WEEK";38="IAS_INVALID_TIME_OF_DAY"
    48="No matching connection request policy";49="No matching network policy"
    64="IAS_DIALIN_LOCKED_OUT";65="No dial-in permission";66="Restricted to called station"
    67="Restricted to calling station";68="Restricted to port type";69="Restricted to auth type"
    70="Invalid EAP type";73="Session timed out";80="IAS_NO_RECORD"
    96="IAS_SESSION_TIMEOUT";112="Remote RADIUS server no response"
    113="Remote RADIUS server unreachable";256="IAS_NO_POLICY_MATCH"
}

# ============================================================================
# SECTION 3: Parsers
# ============================================================================

# Compiled regex patterns for performance
$script:KvRegex = [regex]::new('(\w+)=("(?:[^"\\]|\\.)*"|[^\s]+)', 'Compiled')
$script:FortiClientPattern = [regex]::new('^\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\]\s+\[(\w+)\]\s+\[([\w.-]+)\]\s+(.*)', 'Compiled')

function New-LogEvent {
    param(
        [datetime]$Timestamp = [datetime]::MinValue,
        [string]$Severity = 'Low',
        [string]$Source = '',
        [string]$Message = '',
        [string]$RawLine = '',
        [string]$SourceFile = '',
        [string]$SourceFormat = '',
        [int]$LineNumber = -1,
        [hashtable]$Extra = @{}
    )
    [PSCustomObject]@{
        Timestamp    = $Timestamp
        Severity     = $Severity
        Source       = $Source
        Message      = $Message
        RawLine      = $RawLine
        SourceFile   = $SourceFile
        SourceFormat = $SourceFormat
        LineNumber   = $LineNumber
        Extra        = $Extra
    }
}

function Get-SeverityFromFortiLevel {
    param([string]$Level, [string]$Action, [string]$Type, [string]$RawLine)
    if ($Level) {
        switch ($Level.ToLower()) {
            'emergency'   { return 'Critical' }
            'alert'       { return 'Critical' }
            'critical'    { return 'Critical' }
            'error'       { return 'High' }
            'warning'     { return 'Medium' }
            'notice'      { return 'Low' }
            'information' { return 'Low' }
            'debug'       { return 'Info' }
        }
    }
    if ($Action) {
        $a = $Action.ToLower()
        if ($a -in @('deny','block','dropped')) { return 'High' }
        if ($a -eq 'timeout') { return 'Medium' }
        if ($a -eq 'accept' -and $Type -eq 'utm') { return 'Medium' }
        if ($a -eq 'accept') { return 'Low' }
    }
    return Get-SeverityFromText $RawLine
}

function Get-SeverityFromText {
    param([string]$Text)
    if (-not $Text) { return 'Low' }
    $t = $Text.ToLower()
    if ($t -match 'critical|emergency|fatal') { return 'Critical' }
    if ($t -match '\berror\b|\bfail\b|denied|block|drop') { return 'High' }
    if ($t -match '\bwarn|timeout|expire|\bdown\b') { return 'Medium' }
    if ($t -match '\bdebug\b|\btrace\b|\bverbose\b') { return 'Info' }
    return 'Low'
}

function Invoke-ParseFortiGateConf {
    param([string]$FilePath, [string]$SourceFile = '')
    $entries = [System.Collections.Generic.List[object]]::new()
    $lines = [System.IO.File]::ReadAllLines($FilePath)
    $hostname = ''; $firmware = ''; $model = ''
    $headerExtra = @{}

    foreach ($line in $lines) {
        if ($line -match '^#config-version=(\w+)-([^:]+):') {
            $model = $Matches[1]; $firmware = $Matches[2]
            $headerExtra['Model'] = $model; $headerExtra['Firmware'] = $firmware
        }
        if ($line -match '^#buildno=(\d+)') { $headerExtra['BuildNo'] = $Matches[1] }
        if (-not $line.StartsWith('#')) { break }
    }

    $sectionStack = [System.Collections.Generic.List[string]]::new()
    $currentSection = ''
    $editId = ''; $editSettings = [ordered]@{}
    $editRawLines = [System.Collections.Generic.List[string]]::new()
    $inEdit = $false; $nestDepth = 0; $idx = 0

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i].Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }

        if ($line -match '^config\s+(.+)$') {
            if ($inEdit) { $nestDepth++; $editRawLines.Add($lines[$i]) }
            else { $sectionStack.Add($Matches[1]); $currentSection = $sectionStack -join ' > ' }
            continue
        }
        if ($line -eq 'end') {
            if ($inEdit -and $nestDepth -gt 0) { $nestDepth--; $editRawLines.Add($lines[$i]); continue }
            if ($inEdit) { $inEdit = $false }
            if ($sectionStack.Count -gt 0) {
                $sectionStack.RemoveAt($sectionStack.Count - 1)
                $currentSection = if ($sectionStack.Count -gt 0) { $sectionStack -join ' > ' } else { '' }
            }
            continue
        }
        if ($line -match '^edit\s+"?([^"]+)"?$') {
            $editId = $Matches[1]; $editSettings = [ordered]@{}
            $editRawLines = [System.Collections.Generic.List[string]]::new()
            $editRawLines.Add($lines[$i]); $inEdit = $true; $nestDepth = 0
            continue
        }
        if ($line -eq 'next' -and $inEdit) {
            $editRawLines.Add($lines[$i]); $inEdit = $false
            if ($currentSection -match 'system global' -and $editSettings['hostname']) {
                $hostname = $editSettings['hostname']
            }
            $severity = 'Low'
            $flags = [System.Collections.Generic.List[string]]::new()

            if ($editSettings['status'] -eq 'disable') { $severity = 'Medium'; $flags.Add('DISABLED') }
            if ($currentSection -match 'firewall policy') {
                $sa = $editSettings['srcaddr']; $da = $editSettings['dstaddr']; $svc = $editSettings['service']
                if ($sa -match '\ball\b' -and $da -match '\ball\b' -and $svc -match '\bALL\b') {
                    $severity = 'Medium'; $flags.Add('PERMISSIVE')
                }
                $act = if ($editSettings['action']) { $editSettings['action'] } else { 'deny' }
                if ($act -eq 'accept') {
                    $hasUtm = $editSettings.Keys | Where-Object { $_ -match 'utm-status|av-profile|webfilter-profile|ips-sensor|application-list|ssl-ssh-profile' }
                    if (-not $hasUtm) { $flags.Add('NO-UTM') }
                    if (-not $editSettings['ips-sensor']) { $severity = 'Medium'; $flags.Add('NO-IPS') }
                }
                $logTraffic = $editSettings['logtraffic']
                if ($logTraffic -eq 'disable' -or (-not $logTraffic -and $act -eq 'accept')) {
                    $severity = 'Medium'; $flags.Add('NO-LOGGING')
                }
                if ($editSettings['ssl-ssh-profile'] -match 'certificate-inspection') { $flags.Add('WEAK-SSL-INSPECT') }
            }
            if ($currentSection -match 'system interface') {
                if ($editSettings['allowaccess'] -match '\b(http|telnet)\b') { $severity = 'High'; $flags.Add('INSECURE-MGMT') }
            }
            if ($currentSection -match 'system password-policy') {
                $minLen = $editSettings['minimum-length'] -as [int]
                if ($minLen -and $minLen -lt 8) { $severity = 'Medium'; $flags.Add('WEAK-PASSWD-POLICY') }
                if ($editSettings['status'] -eq 'disable') { $severity = 'Medium'; $flags.Add('WEAK-PASSWD-POLICY') }
            }

            $secPart = $currentSection.Split('>')[-1].Trim()
            $name = if ($editSettings['name']) { $editSettings['name'] } else { $editId }
            $msgParts = [System.Collections.Generic.List[string]]::new()
            $msgParts.Add("[$secPart $editId] $name")
            if ($currentSection -match 'firewall policy') {
                $si = if ($editSettings['srcintf']) { $editSettings['srcintf'] } else { '?' }
                $di = if ($editSettings['dstintf']) { $editSettings['dstintf'] } else { '?' }
                $msgParts.Add("$si->$di")
                if ($editSettings['srcaddr']) { $msgParts.Add("srcaddr=$($editSettings['srcaddr'])") }
                if ($editSettings['dstaddr']) { $msgParts.Add("dstaddr=$($editSettings['dstaddr'])") }
                if ($editSettings['action']) { $msgParts.Add("action=$($editSettings['action'])") }
            }
            if ($flags.Count -gt 0) { $msgParts.Add("[$($flags -join ',')]") }

            $extra = [ordered]@{}
            foreach ($k in $editSettings.Keys) { $extra[$k] = $editSettings[$k] }
            foreach ($k in $headerExtra.Keys) { $extra["Config_$k"] = $headerExtra[$k] }
            $extra['Section'] = $currentSection

            $entries.Add((New-LogEvent -Timestamp ([datetime]::MinValue) -Severity $severity `
                -Source $secPart -Message ($msgParts -join ': ') -RawLine ($editRawLines -join "`n") `
                -SourceFile $SourceFile -SourceFormat 'FortiGateConf' -LineNumber $i -Extra $extra))
            $idx++
            continue
        }
        if ($inEdit -and $line -match '^set\s+(\S+)\s+(.+)$') {
            $editRawLines.Add($lines[$i]); $editSettings[$Matches[1]] = $Matches[2].Trim('"')
            continue
        }
        if ($inEdit -and $line -match '^unset\s+(\S+)') { $editRawLines.Add($lines[$i]); continue }
        if ($inEdit) { $editRawLines.Add($lines[$i]) }
        if (-not $inEdit -and $line -match '^set\s+(\S+)\s+(.+)$') {
            if ($currentSection -match 'system global' -and $Matches[1] -eq 'hostname') { $hostname = $Matches[2].Trim('"') }
        }
    }
    return $entries
}

function Invoke-ParseFortiGateKV {
    param([string]$FilePath, [string]$SourceFile = '')
    $entries = [System.Collections.Generic.List[object]]::new()
    $reader = [System.IO.StreamReader]::new($FilePath, [System.Text.Encoding]::UTF8, $true)
    $lineNum = 0
    try {
        while (-not $reader.EndOfStream) {
            $rawLine = $reader.ReadLine(); $lineNum++
            if ([string]::IsNullOrWhiteSpace($rawLine)) { continue }

            $kvLine = $rawLine
            if ($kvLine -match '^\s*<\d+>') {
                $kvLine = $kvLine -replace '^\s*<\d+>\S*\s+\S+\s+\S+\s+\S+\s+\S+\s+', ''
                if ($kvLine -eq $rawLine) { $kvLine = $rawLine -replace '^\s*<\d+>', '' }
            }

            $extra = @{}
            $matches2 = $script:KvRegex.Matches($kvLine)
            foreach ($m in $matches2) { $extra[$m.Groups[1].Value] = $m.Groups[2].Value.Trim('"') }

            $ts = [datetime]::MinValue
            if ($extra['date'] -and $extra['time']) { [datetime]::TryParse("$($extra['date']) $($extra['time'])", [ref]$ts) | Out-Null }

            if ($extra['devid']) {
                $devid = $extra['devid']
                $extra['DeviceType'] = if ($devid.StartsWith('FG')) { 'FortiGate' }
                    elseif ($devid.StartsWith('FTC')) { 'FortiClient' }
                    elseif ($devid.StartsWith('FAZ')) { 'FortiAnalyzer' }
                    elseif ($devid.StartsWith('FSW')) { 'FortiSwitch' }
                    elseif ($devid.StartsWith('FAP')) { 'FortiAP' }
                    else { 'Fortinet' }
            }

            if ($extra['type'] -and $extra['subtype']) {
                $ts2 = "$($extra['type'])/$($extra['subtype'])"
                if ($script:FortiSubtypeLookup.ContainsKey($ts2)) { $extra['SubtypeDescription'] = $script:FortiSubtypeLookup[$ts2] }
            }

            $severity = Get-SeverityFromFortiLevel -Level $extra['level'] -Action $extra['action'] -Type $extra['type'] -RawLine $rawLine
            $source = if ($extra['devname']) { $extra['devname'] } elseif ($extra['srcip']) { $extra['srcip'] } else { '' }

            $msg = if ($extra['type'] -eq 'traffic') {
                $parts = @()
                if ($extra['action']) { $parts += $extra['action'] }
                if ($extra['srcip']) { $parts += "srcip=$($extra['srcip'])" }
                if ($extra['dstip']) { $parts += "dstip=$($extra['dstip'])" }
                if ($extra['srcport']) { $parts += "srcport=$($extra['srcport'])" }
                if ($extra['dstport']) { $parts += "dstport=$($extra['dstport'])" }
                if ($extra['policyid']) { $parts += "policy=$($extra['policyid'])" }
                $parts -join ' '
            } elseif ($extra['type'] -eq 'utm' -and $extra['subtype'] -eq 'webfilter') {
                $parts = @()
                if ($extra['action']) { $parts += $extra['action'] }
                if ($extra['url']) { $parts += "url=$($extra['url'])" }
                if ($extra['hostname']) { $parts += "host=$($extra['hostname'])" }
                if ($extra['catdesc']) { $parts += "cat=$($extra['catdesc'])" }
                $parts -join ' '
            } elseif ($extra['type'] -eq 'event' -and $extra['subtype'] -eq 'vpn') {
                $parts = @()
                if ($extra['action']) { $parts += $extra['action'] }
                if ($extra['tunnelip']) { $parts += "tunnel=$($extra['tunnelip'])" }
                if ($extra['tunneltype']) { $parts += "type=$($extra['tunneltype'])" }
                if ($extra['remip']) { $parts += "remote=$($extra['remip'])" }
                $parts -join ' '
            } elseif ($extra['msg']) { $extra['msg'] }
            elseif ($extra['action']) { $extra['action'] }
            else { $kvLine.Substring(0, [Math]::Min(200, $kvLine.Length)) }

            if ($extra['SubtypeDescription'] -and $msg) { $msg = "[$($extra['SubtypeDescription'])] $msg" }

            $entries.Add((New-LogEvent -Timestamp $ts -Severity $severity -Source $source `
                -Message $msg -RawLine $rawLine -SourceFile $SourceFile -SourceFormat 'FortiGateKV' `
                -LineNumber $lineNum -Extra $extra))
        }
    } finally { $reader.Close(); $reader.Dispose() }
    return $entries
}

function Invoke-ParseFortiClientLocal {
    param([string]$FilePath, [string]$SourceFile = '')
    $entries = [System.Collections.Generic.List[object]]::new()
    $reader = [System.IO.StreamReader]::new($FilePath, [System.Text.Encoding]::UTF8, $true)
    $lineNum = 0; $prevEntry = $null
    try {
        while (-not $reader.EndOfStream) {
            $rawLine = $reader.ReadLine(); $lineNum++
            if ([string]::IsNullOrWhiteSpace($rawLine)) { continue }
            $m = $script:FortiClientPattern.Match($rawLine)
            if ($m.Success) {
                $ts = [datetime]::MinValue
                [datetime]::TryParse($m.Groups[1].Value, [ref]$ts) | Out-Null
                $rawLevel = $m.Groups[2].Value.ToUpper()
                $severity = switch ($rawLevel) {
                    'CRITICAL' { 'Critical' } 'ERROR' { 'High' } 'WARNING' { 'Medium' }
                    'INFO' { 'Low' } 'DEBUG' { 'Info' } default { Get-SeverityFromText $rawLevel }
                }
                $module = $m.Groups[3].Value
                $moduleName = if ($script:FortiClientModuleLookup.ContainsKey($module.ToLower())) {
                    $script:FortiClientModuleLookup[$module.ToLower()]
                } else { $module }
                $extra = @{ Module = $module; ModuleName = $moduleName }
                $prevEntry = New-LogEvent -Timestamp $ts -Severity $severity -Source $moduleName `
                    -Message $m.Groups[4].Value -RawLine $rawLine -SourceFile $SourceFile `
                    -SourceFormat 'FortiClientLocal' -LineNumber $lineNum -Extra $extra
                $entries.Add($prevEntry)
            } elseif ($prevEntry) {
                $prevEntry.RawLine += "`n$rawLine"
                $prevEntry.Message += "`n$rawLine"
            }
        }
    } finally { $reader.Close(); $reader.Dispose() }
    return $entries
}

function Invoke-ParseFortiSwitchEvent {
    param([string]$FilePath, [string]$SourceFile = '')
    $entries = [System.Collections.Generic.List[object]]::new()
    $reader = [System.IO.StreamReader]::new($FilePath, [System.Text.Encoding]::UTF8, $true)
    $lineNum = 0
    try {
        while (-not $reader.EndOfStream) {
            $rawLine = $reader.ReadLine(); $lineNum++
            if ([string]::IsNullOrWhiteSpace($rawLine)) { continue }

            $kvLine = $rawLine
            if ($kvLine -match '^\s*<\d+>') {
                $kvLine = $kvLine -replace '^\s*<\d+>\S*\s+\S+\s+\S+\s+\S+\s+\S+\s+', ''
                if ($kvLine -eq $rawLine) { $kvLine = $rawLine -replace '^\s*<\d+>', '' }
            }

            $extra = @{}
            $matches2 = $script:KvRegex.Matches($kvLine)
            foreach ($m2 in $matches2) { $extra[$m2.Groups[1].Value] = $m2.Groups[2].Value.Trim('"') }

            $ts = [datetime]::MinValue
            if ($extra['date'] -and $extra['time']) { [datetime]::TryParse("$($extra['date']) $($extra['time'])", [ref]$ts) | Out-Null }

            if ($extra['type'] -and $extra['subtype']) {
                $ts2 = "$($extra['type'])/$($extra['subtype'])"
                if ($script:FortiSubtypeLookup.ContainsKey($ts2)) { $extra['SubtypeDescription'] = $script:FortiSubtypeLookup[$ts2] }
            }

            $msgField = if ($extra['msg']) { $extra['msg'] } else { '' }
            $msgLower = $msgField.ToLower()

            # Extract switch-specific fields
            $portName = if ($extra['port']) { $extra['port'] }
                elseif ($extra['interface']) { $extra['interface'] }
                elseif ($extra['portname']) { $extra['portname'] }
                elseif ($msgField -match '(?:port|interface)\s+([\w/.-]+)') { $Matches[1] }
                else { '' }
            $extra['PortName'] = $portName

            $portStatus = if ($extra['portstatus']) { $extra['portstatus'] }
                elseif ($extra['linkstatus']) { $extra['linkstatus'] }
                elseif ($msgLower -match '(?:port|link)\s+(?:is\s+)?(up|down)') { $Matches[1] }
                else { '' }
            $extra['PortStatus'] = $portStatus

            $macAddress = if ($extra['mac']) { $extra['mac'] }
                elseif ($extra['srcmac']) { $extra['srcmac'] }
                elseif ($extra['macaddr']) { $extra['macaddr'] }
                elseif ($msgField -match '([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})') { $Matches[1] }
                else { '' }
            $extra['MacAddress'] = $macAddress

            $authResult = if ($extra['authresult']) { $extra['authresult'] }
                elseif ($extra['authstatus']) { $extra['authstatus'] }
                elseif ($msgLower -match '802\.1x\s+auth(?:entication)?\s+(success|fail\w*|reject\w*|timeout)') { $Matches[1] }
                else { '' }
            $extra['AuthResult'] = $authResult

            $stpState = if ($extra['stpstate']) { $extra['stpstate'] }
                elseif ($msgLower -match 'stp\s+(?:state\s+)?(\w+)') { $Matches[1] }
                else { '' }
            $extra['StpState'] = $stpState

            $vlanId = if ($extra['vlan']) { $extra['vlan'] }
                elseif ($extra['vlanid']) { $extra['vlanid'] }
                elseif ($msgField -match '(?:vlan|VLAN)\s*(\d+)') { $Matches[1] }
                else { '' }
            $extra['VlanId'] = $vlanId

            # Determine severity
            $fgLevel = if ($extra['level']) { $extra['level'].ToLower() } else { '' }
            $severity = switch ($fgLevel) {
                'emergency' { 'Critical' } 'alert' { 'Critical' } 'critical' { 'Critical' }
                'error' { 'High' } 'warning' { 'Medium' } 'notice' { 'Low' } 'information' { 'Low' } 'debug' { 'Info' }
                default {
                    if ($authResult -match '(?i)fail|reject|denied') { 'High' }
                    elseif ($portStatus -eq 'down' -or $msgLower -match 'port\s+down|link\s+down') { 'Medium' }
                    elseif ($msgLower -match 'stp\s+(?:topology\s+change|tcn)') { 'Medium' }
                    elseif ($portStatus -eq 'up') { 'Low' }
                    else { Get-SeverityFromText $rawLine }
                }
            }
            $source = if ($extra['devname']) { $extra['devname'] } else { '' }

            # Build message
            $msg = if ($msgLower -match '802\.1x|dot1x' -or $authResult) {
                $parts = @(); $r2 = if ($authResult) { $authResult } else { 'event' }
                $parts += "802.1X auth $r2"
                if ($macAddress) { $parts += "for $macAddress" }
                if ($portName) { $parts += "on $portName" }
                $parts -join ' '
            } elseif ($msgLower -match 'stp|spanning[\s-]tree') {
                $parts = @('STP topology change')
                if ($portName) { $parts += "on $portName" }
                if ($stpState) { $parts += "state=$stpState" }
                $parts -join ' '
            } elseif ($msgLower -match 'mac\s+(learn|age|move|flush)' -or $macAddress) {
                $macAction = if ($msgField -match '(?i)mac\s+(learn\w*|age\w*|move\w*|flush\w*)') { $Matches[1].ToLower() } else { 'event' }
                $parts = @()
                if ($macAddress) { $parts += "MAC $macAddress" } else { $parts += 'MAC' }
                $parts += $macAction
                if ($portName) { $parts += "on $portName" }
                if ($vlanId) { $parts += "VLAN $vlanId" }
                $parts -join ' '
            } elseif ($portName -and ($portStatus -or $msgLower -match 'port|link|interface')) {
                $s2 = if ($portStatus) { $portStatus } else { 'event' }
                $r3 = "Port $portName $s2"
                if ($extra['speed']) { $r3 += " speed=$($extra['speed'])" }
                if ($extra['duplex']) { $r3 += " duplex=$($extra['duplex'])" }
                $r3
            } elseif ($msgField) { $msgField }
            elseif ($extra['action']) { $extra['action'] }
            else { $kvLine.Substring(0, [Math]::Min(200, $kvLine.Length)) }

            if ($extra['SubtypeDescription'] -and $msg) { $msg = "[$($extra['SubtypeDescription'])] $msg" }

            $entries.Add((New-LogEvent -Timestamp $ts -Severity $severity -Source $source `
                -Message $msg -RawLine $rawLine -SourceFile $SourceFile -SourceFormat 'FortiSwitchEvent' `
                -LineNumber $lineNum -Extra $extra))
        }
    } finally { $reader.Close(); $reader.Dispose() }
    return $entries
}

function Invoke-ParseWindowsEvtx {
    param([string]$FilePath, [string]$SourceFile = '')
    $entries = [System.Collections.Generic.List[object]]::new()
    $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()

    if ($ext -eq '.evtx') {
        # Binary EVTX - Windows only via Get-WinEvent
        if (-not (Get-Command Get-WinEvent -ErrorAction SilentlyContinue)) {
            Write-Warning "Binary .evtx files require Windows with Get-WinEvent. Export to XML first for cross-platform use."
            return $entries
        }
        try {
            $events = Get-WinEvent -Path $FilePath -ErrorAction Stop
            $lineNum = 0
            foreach ($evt in $events) {
                $lineNum++
                $extra = @{ EventID = $evt.Id; ProviderName = $evt.ProviderName; LogName = $evt.LogName }
                if ($script:EventIdLookup.ContainsKey([int]$evt.Id)) {
                    $extra['EventDescription'] = $script:EventIdLookup[[int]$evt.Id]
                }
                try {
                    $evtXml = [xml]$evt.ToXml()
                    $eventData = $evtXml.Event.EventData
                    if ($eventData) {
                        foreach ($data in $eventData.Data) {
                            if ($data.Name -and $data.'#text') { $extra[$data.Name] = $data.'#text' }
                        }
                    }
                    $userData = $evtXml.Event.UserData
                    if ($userData) {
                        foreach ($child in $userData.ChildNodes) {
                            foreach ($sub in $child.ChildNodes) {
                                if ($sub.LocalName -and $sub.InnerText) { $extra[$sub.LocalName] = $sub.InnerText }
                            }
                        }
                    }
                } catch {}
                $severity = switch ($evt.Level) {
                    1 { 'Critical' } 2 { 'High' } 3 { 'Medium' } 4 { 'Low' } 5 { 'Info' }
                    0 { if ($evt.Id -eq 1102) { 'Medium' } else { 'Low' } }
                    default { 'Low' }
                }
                $msg = $evt.Message
                if (-not $msg -and $extra['EventDescription']) { $msg = $extra['EventDescription'] }
                $entries.Add((New-LogEvent -Timestamp $evt.TimeCreated -Severity $severity `
                    -Source $evt.ProviderName -Message $msg `
                    -RawLine ($evt.ToXml()) -SourceFile $SourceFile -SourceFormat 'WindowsEvtx' `
                    -LineNumber $lineNum -Extra $extra))
            }
        } catch { Write-Warning "EVTX parse error: $_" }
    } else {
        # XML export format
        try {
            $content = [System.IO.File]::ReadAllText($FilePath)
            if ($content -notmatch '<Event') {
                Write-Warning "No Event elements found in XML file: $FilePath"
                return $entries
            }
            # Wrap in root if needed
            if ($content -notmatch '<Events[\s>]') { $content = "<Events>$content</Events>" }
            # Strip namespace for simpler XPath (common approach for Event XML)
            $content = $content -replace 'xmlns="[^"]*"', ''
            $xml = [xml]$content
            $eventNodes = $xml.SelectNodes('//Event')
            if (-not $eventNodes -or $eventNodes.Count -eq 0) {
                $eventNodes = $xml.GetElementsByTagName('Event')
            }
            $lineNum = 0
            foreach ($evtNode in $eventNodes) {
                $lineNum++
                $sys = $evtNode.System
                $eid = 0; $provider = ''; $computer = ''; $channel = ''; $level = 0
                $timeStr = ''
                if ($sys) {
                    if ($sys.EventID) { $eid = [int]$(if ($sys.EventID.InnerText) { $sys.EventID.InnerText } else { $sys.EventID }) }
                    if ($sys.Provider) { $provider = $sys.Provider.Name }
                    if ($sys.Computer) { $computer = $sys.Computer }
                    if ($sys.Channel) { $channel = $sys.Channel }
                    if ($sys.Level) { $level = [int]$(if ($sys.Level.InnerText) { $sys.Level.InnerText } else { $sys.Level }) }
                    if ($sys.TimeCreated) { $timeStr = $sys.TimeCreated.SystemTime }
                }
                $ts = [datetime]::MinValue
                if ($timeStr) { [datetime]::TryParse($timeStr, [ref]$ts) | Out-Null }
                $extra = @{ EventID = $eid; ProviderName = $provider; LogName = $channel; Computer = $computer }
                if ($script:EventIdLookup.ContainsKey($eid)) { $extra['EventDescription'] = $script:EventIdLookup[$eid] }
                $eventData = $evtNode.EventData
                if ($eventData) {
                    foreach ($data in $eventData.Data) {
                        if ($data.Name -and $data.InnerText) { $extra[$data.Name] = $data.InnerText }
                    }
                }
                $severity = switch ($level) {
                    1 { 'Critical' } 2 { 'High' } 3 { 'Medium' } 4 { 'Low' } 5 { 'Info' }
                    0 { if ($eid -eq 1102) { 'Medium' } else { 'Low' } }
                    default { 'Low' }
                }
                $msg = $extra['EventDescription']
                if (-not $msg) { $msg = "Event $eid" }
                if ($extra['TargetUserName']) { $msg += " - User: $($extra['TargetUserName'])" }
                $entries.Add((New-LogEvent -Timestamp $ts -Severity $severity -Source $provider `
                    -Message $msg -RawLine $evtNode.OuterXml -SourceFile $SourceFile `
                    -SourceFormat 'WindowsEvtx' -LineNumber $lineNum -Extra $extra))
            }
        } catch { Write-Warning "XML parse error: $_" }
    }
    return $entries
}

function Invoke-DetectLogFormat {
    param([string]$FilePath)
    $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()
    if ($ext -eq '.evtx') { return 'WindowsEvtx' }
    if ($ext -eq '.conf') { return 'FortiGateConf' }

    try {
        $reader = [System.IO.StreamReader]::new($FilePath, [System.Text.Encoding]::UTF8, $true)
        $firstLines = [System.Collections.Generic.List[string]]::new()
        for ($i = 0; $i -lt 20 -and -not $reader.EndOfStream; $i++) { $firstLines.Add($reader.ReadLine()) }
        $reader.Close(); $reader.Dispose()
    } catch { return $null }
    if ($firstLines.Count -eq 0) { return $null }

    # Check for binary
    foreach ($line in $firstLines) {
        if ($line -and $line -match '[\x00-\x08\x0E-\x1F]') { return $null }
    }

    # FortiGate Config
    foreach ($line in $firstLines) {
        if ($line -match '^#config-version=FG') { return 'FortiGateConf' }
        if ($line -match '^\s*config system global\s*$') { return 'FortiGateConf' }
    }

    # FortiSwitch Event (check before generic KV)
    $fswMatch = 0
    foreach ($line in $firstLines) {
        if ($line -match '(\w+)=' -and ($line -match 'devid="?FS\w' -or $line -match 'devid="?S\d' -or $line -match 'devid="?FSW' -or $line -match 'devtype="FortiSwitch"')) { $fswMatch++ }
    }
    if ($fswMatch -ge 2) { return 'FortiSwitchEvent' }

    # FortiGate KV
    foreach ($line in $firstLines) {
        if ($line -match 'logid=' -and $line -match 'type=' -and ($line -match 'devname=' -or $line -match 'devid=')) { return 'FortiGateKV' }
    }

    # FortiClient Local
    $fcMatch = 0
    foreach ($line in $firstLines) {
        if ($line -match '^\[[\d-]+ [\d:]+\]\s+\[\w+\]\s+\[[\w.-]+\]') { $fcMatch++ }
    }
    if ($fcMatch -ge 2) { return 'FortiClientLocal' }

    # Windows Event XML
    foreach ($line in $firstLines) {
        if ($line -match '<Events[\s>]' -or $line -match '<Event\s+xmlns=') { return 'WindowsEvtx' }
    }

    return $null
}

function Invoke-ParseLogFile {
    param(
        [string]$FilePath,
        [string]$Format,
        [string]$SourceFile = ''
    )
    if (-not $SourceFile) { $SourceFile = $FilePath }
    $sf = [System.IO.Path]::GetFileName($SourceFile)

    switch ($Format) {
        'FortiGateConf'    { return Invoke-ParseFortiGateConf -FilePath $FilePath -SourceFile $sf }
        'FortiGateKV'      { return Invoke-ParseFortiGateKV -FilePath $FilePath -SourceFile $sf }
        'FortiClientLocal' { return Invoke-ParseFortiClientLocal -FilePath $FilePath -SourceFile $sf }
        'FortiSwitchEvent' { return Invoke-ParseFortiSwitchEvent -FilePath $FilePath -SourceFile $sf }
        'WindowsEvtx'      { return Invoke-ParseWindowsEvtx -FilePath $FilePath -SourceFile $sf }
        default {
            Write-Warning "Unknown format: $Format for $sf"
            return [System.Collections.Generic.List[object]]::new()
        }
    }
}

# ============================================================================
# SECTION 4: Filter Engine
# ============================================================================

function Invoke-FilterEvents {
    param(
        [System.Collections.Generic.List[object]]$Events,
        [string]$Query
    )
    if (-not $Events) { return [System.Collections.Generic.List[object]]::new() }
    if ([string]::IsNullOrWhiteSpace($Query)) { return $Events }

    # Split on pipe for pipeline operators
    $parts = $Query -split '\s*\|\s*'
    $filterPart = $parts[0].Trim()
    $pipelineOps = if ($parts.Count -gt 1) { $parts[1..($parts.Count - 1)] } else { @() }

    # Apply filter
    $filtered = [System.Collections.Generic.List[object]]::new()
    if ([string]::IsNullOrWhiteSpace($filterPart)) {
        if ($Events.Count -gt 0) { $filtered.AddRange($Events) }
    } else {
        $conditions = Parse-FilterConditions $filterPart
        foreach ($event in $Events) {
            if (Test-FilterMatch -Event $event -Conditions $conditions) {
                $filtered.Add($event)
            }
        }
    }

    # Apply pipeline operators
    foreach ($op in $pipelineOps) {
        $filtered = Invoke-PipelineOp -Events $filtered -Op $op.Trim()
    }
    return $filtered
}

function Parse-FilterConditions {
    param([string]$FilterText)
    $conditions = [System.Collections.Generic.List[object]]::new()
    $tokens = [regex]::Matches($FilterText, '(NOT\s+)?(\w+):("(?:[^"\\]|\\.)*"|[^\s]+)|AND|OR')
    $logicOp = 'AND'
    foreach ($tok in $tokens) {
        $val = $tok.Value
        if ($val -eq 'AND') { $logicOp = 'AND'; continue }
        if ($val -eq 'OR') { $logicOp = 'OR'; continue }
        $negate = $false
        if ($val -match '^NOT\s+') { $negate = $true; $val = $val -replace '^NOT\s+', '' }
        if ($val -match '^(\w+):(.+)$') {
            $field = $Matches[1]; $pattern = $Matches[2].Trim('"')
            $op = 'eq'
            if ($pattern.StartsWith('>')) { $op = 'gt'; $pattern = $pattern.Substring(1) }
            elseif ($pattern.StartsWith('<')) { $op = 'lt'; $pattern = $pattern.Substring(1) }
            elseif ($pattern.Contains('*')) { $op = 'wildcard' }
            $conditions.Add(@{ Field = $field; Pattern = $pattern; Op = $op; Negate = $negate; Logic = $logicOp })
        }
        $logicOp = 'AND'
    }
    return $conditions
}

function Test-FilterMatch {
    param($Event, $Conditions)
    if ($Conditions.Count -eq 0) { return $true }
    $result = $true
    foreach ($cond in $Conditions) {
        $fieldVal = Get-EventFieldValue -Event $Event -Field $cond.Field
        $match = Test-FieldCondition -Value $fieldVal -Pattern $cond.Pattern -Op $cond.Op
        if ($cond.Negate) { $match = -not $match }
        if ($cond.Logic -eq 'OR') { $result = $result -or $match }
        else { $result = $result -and $match }
    }
    return $result
}

function Get-EventFieldValue {
    param($Event, [string]$Field)
    if (-not $Event -or -not $Field) { return $null }
    $fl = $Field.ToLower()
    switch ($fl) {
        'severity' { return $Event.Severity }
        'source'   { return $Event.Source }
        'message'  { return $Event.Message }
        'timestamp' { if ($Event.Timestamp -ne [datetime]::MinValue) { return $Event.Timestamp.ToString('yyyy-MM-dd HH:mm:ss') } else { return '' } }
        'sourcefile' { return $Event.SourceFile }
        'sourceformat' { return $Event.SourceFormat }
        default {
            if (-not $Event.Extra) { return $null }
            if ($Event.Extra.ContainsKey($Field)) { return $Event.Extra[$Field] }
            # Case-insensitive search in Extra
            foreach ($k in $Event.Extra.Keys) {
                if ($k -eq $Field) { return $Event.Extra[$k] }
            }
            return $null
        }
    }
}

function Test-FieldCondition {
    param($Value, [string]$Pattern, [string]$Op)
    if ($null -eq $Value) { return $false }
    $strVal = [string]$Value
    switch ($Op) {
        'eq' { return $strVal -ieq $Pattern -or $strVal -like $Pattern }
        'wildcard' { return $strVal -like $Pattern }
        'gt' { $n = $strVal -as [double]; $p = $Pattern -as [double]; if ($null -ne $n -and $null -ne $p) { return $n -gt $p }; return $false }
        'lt' { $n = $strVal -as [double]; $p = $Pattern -as [double]; if ($null -ne $n -and $null -ne $p) { return $n -lt $p }; return $false }
    }
    return $false
}

function Invoke-PipelineOp {
    param([System.Collections.Generic.List[object]]$Events, [string]$Op)
    if (-not $Events) { $Events = [System.Collections.Generic.List[object]]::new() }
    if ($Op -match '^count$') {
        $countObj = New-LogEvent -Message "Count: $($Events.Count)" -Severity 'Low'
        $countObj | Add-Member -NotePropertyName '_AggResult' -NotePropertyValue @(@{ Label = 'Count'; Value = $Events.Count })
        $result = [System.Collections.Generic.List[object]]::new(); $result.Add($countObj)
        return $result
    }
    if ($Op -match '^count\s+by\s+(\w+)$') {
        $field = $Matches[1]; $groups = @{}
        foreach ($e in $Events) {
            $val = Get-EventFieldValue -Event $e -Field $field
            $key = if ($val) { [string]$val } else { '(empty)' }
            if ($groups.ContainsKey($key)) { $groups[$key]++ } else { $groups[$key] = 1 }
        }
        $sorted = $groups.GetEnumerator() | Sort-Object Value -Descending
        $result = [System.Collections.Generic.List[object]]::new()
        foreach ($g in $sorted) {
            $obj = New-LogEvent -Message "$($g.Key): $($g.Value)" -Severity 'Low'
            $obj | Add-Member -NotePropertyName '_AggField' -NotePropertyValue $field
            $obj | Add-Member -NotePropertyName '_AggKey' -NotePropertyValue $g.Key
            $obj | Add-Member -NotePropertyName '_AggCount' -NotePropertyValue $g.Value
            $result.Add($obj)
        }
        return $result
    }
    if ($Op -match '^top\s+(\d+)') {
        $n = [int]$Matches[1]
        if ($Events.Count -gt $n) {
            $result = [System.Collections.Generic.List[object]]::new()
            $result.AddRange($Events[0..([Math]::Min($n - 1, $Events.Count - 1))])
            return $result
        }
        return $Events
    }
    if ($Op -match '^sort\s+(\w+)\s*(asc|desc)?$') {
        $field = $Matches[1]; $desc = ($Matches[2] -eq 'desc')
        if ($Events.Count -eq 0) { return $Events }
        $sorted = $Events | Sort-Object { Get-EventFieldValue -Event $_ -Field $field } -Descending:$desc
        $result = [System.Collections.Generic.List[object]]::new()
        if ($null -ne $sorted) { $result.AddRange(@($sorted)) }
        return $result
    }
    if ($Op -match '^head\s+(\d+)$') {
        $n = [int]$Matches[1]
        $result = [System.Collections.Generic.List[object]]::new()
        if ($Events.Count -gt 0) {
            $result.AddRange($Events[0..([Math]::Min($n - 1, $Events.Count - 1))])
        }
        return $result
    }
    if ($Op -match '^tail\s+(\d+)$') {
        $n = [int]$Matches[1]; $start = [Math]::Max(0, $Events.Count - $n)
        $result = [System.Collections.Generic.List[object]]::new()
        if ($Events.Count -gt 0) {
            $result.AddRange($Events[$start..($Events.Count - 1)])
        }
        return $result
    }
    if ($Op -match '^table\s+(.+)$') {
        $fields = ($Matches[1] -split ',') | ForEach-Object { $_.Trim() }
        foreach ($e in $Events) { $e | Add-Member -NotePropertyName '_TableFields' -NotePropertyValue $fields -Force }
        return $Events
    }
    if ($Op -match '^timeline\s+(\w+)$') {
        $interval = $Matches[1]
        $bucketSize = switch -Regex ($interval) {
            '1m'  { [timespan]::FromMinutes(1) }
            '5m'  { [timespan]::FromMinutes(5) }
            '1h'  { [timespan]::FromHours(1) }
            '1d'  { [timespan]::FromDays(1) }
            default { [timespan]::FromHours(1) }
        }
        $groups = [ordered]@{}
        foreach ($e in $Events) {
            if ($e.Timestamp -eq [datetime]::MinValue) { continue }
            $ticks = [long]([Math]::Floor($e.Timestamp.Ticks / $bucketSize.Ticks)) * $bucketSize.Ticks
            $bucket = ([datetime]$ticks).ToString('yyyy-MM-dd HH:mm')
            if ($groups.ContainsKey($bucket)) { $groups[$bucket]++ } else { $groups[$bucket] = 1 }
        }
        $result = [System.Collections.Generic.List[object]]::new()
        foreach ($g in $groups.GetEnumerator()) {
            $obj = New-LogEvent -Message "$($g.Key): $($g.Value)" -Severity 'Low'
            $obj | Add-Member -NotePropertyName '_AggKey' -NotePropertyValue $g.Key
            $obj | Add-Member -NotePropertyName '_AggCount' -NotePropertyValue $g.Value
            $result.Add($obj)
        }
        return $result
    }
    return $Events
}

# ============================================================================
# SECTION 5: Analysis Engines
# ============================================================================

function Invoke-AnalyzeFailedLogins {
    param([System.Collections.Generic.List[object]]$Events)
    if (-not $Events) { return @() }
    $aggregated = @{}
    foreach ($entry in $Events) {
        $user = $null; $sourceIp = $null; $isFailedLogin = $false
        $ex = $entry.Extra

        if ($ex['EventID'] -and [int]$ex['EventID'] -eq 4625) {
            $user = $ex['TargetUserName']; $sourceIp = if ($ex['IpAddress']) { $ex['IpAddress'] } else { $ex['WorkstationName'] }
            $isFailedLogin = $true
        } elseif ($ex['PacketTypeName'] -eq 'Access-Reject') {
            $user = if ($ex['User-Name']) { $ex['User-Name'] } else { $ex['SAM-Account-Name'] }
            $sourceIp = if ($ex['Calling-Station-Id']) { $ex['Calling-Station-Id'] } else { $ex['Client-IP-Address'] }
            $isFailedLogin = $true
        } elseif ($ex['type'] -eq 'event' -and $ex['subtype'] -eq 'user' -and $ex['action'] -match 'deny|fail') {
            $user = $ex['user']; $sourceIp = $ex['srcip']; $isFailedLogin = $true
        } elseif ($ex['action'] -match 'deny' -and $ex['subtype'] -eq 'auth') {
            $user = $ex['user']; $sourceIp = $ex['srcip']; $isFailedLogin = $true
        } elseif ($ex['EventID'] -and [int]$ex['EventID'] -eq 4771) {
            $user = $ex['TargetUserName']; $sourceIp = $ex['IpAddress']; $isFailedLogin = $true
        } elseif ($ex['EventID'] -and [int]$ex['EventID'] -eq 6273) {
            $user = if ($ex['SubjectUserName']) { $ex['SubjectUserName'] } else { $ex['FullyQualifiedSubjectUserName'] }
            $sourceIp = $ex['CallingStationID']; $isFailedLogin = $true
        }

        if (-not $isFailedLogin -or -not $user) { continue }
        if (-not $sourceIp) { $sourceIp = '(unknown)' }
        $key = $user.ToLower()
        if (-not $aggregated.ContainsKey($key)) {
            $aggregated[$key] = @{
                User = $user; Count = 0
                SourceIPs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                FirstSeen = $entry.Timestamp; LastSeen = $entry.Timestamp
                Sources = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            }
        }
        $agg = $aggregated[$key]; $agg.Count++
        $agg.SourceIPs.Add($sourceIp) | Out-Null
        if ($entry.SourceFormat) { $agg.Sources.Add($entry.SourceFormat) | Out-Null }
        if ($entry.Timestamp -ne [datetime]::MinValue) {
            if ($entry.Timestamp -lt $agg.FirstSeen -or $agg.FirstSeen -eq [datetime]::MinValue) { $agg.FirstSeen = $entry.Timestamp }
            if ($entry.Timestamp -gt $agg.LastSeen) { $agg.LastSeen = $entry.Timestamp }
        }
    }
    return @($aggregated.Values | Sort-Object { $_.Count } -Descending)
}

function Invoke-AnalyzeVpnSessions {
    param([System.Collections.Generic.List[object]]$Events)
    if (-not $Events) { return @{ Sessions = @{}; ImpossibleTravel = @() } }
    $sessions = @{}; $travelFlags = [System.Collections.Generic.List[object]]::new()

    foreach ($entry in $Events) {
        $ex = $entry.Extra; if (-not $ex) { continue }
        $user = $null; $action = $null; $remoteIp = $null; $sentBytes = 0; $rcvdBytes = 0

        if ($ex['type'] -eq 'event' -and $ex['subtype'] -eq 'vpn') {
            $user = $ex['user']; $action = $ex['action']
            $remoteIp = if ($ex['remip']) { $ex['remip'] } else { $ex['srcip'] }
            if ($ex['sentbyte']) { $sentBytes = $ex['sentbyte'] -as [long] }
            if ($ex['rcvdbyte']) { $rcvdBytes = $ex['rcvdbyte'] -as [long] }
        } elseif ($entry.Message -match 'tunnel-(up|down)') {
            $action = "tunnel-$($Matches[1])"; $user = $ex['user']
            $remoteIp = if ($ex['remip']) { $ex['remip'] } else { $ex['srcip'] }
        } elseif ($ex['action'] -match 'ssl-') {
            $user = $ex['user']; $action = $ex['action']; $remoteIp = $ex['srcip']
        }
        if (-not $user -or -not $action) { continue }
        $userKey = $user.ToLower()
        if (-not $sessions.ContainsKey($userKey)) {
            $sessions[$userKey] = [System.Collections.Generic.List[object]]::new()
        }
        if ($action -match 'tunnel-up|ssl-new-con|login') {
            $sessions[$userKey].Add(@{
                User = $user; StartTime = $entry.Timestamp; EndTime = $null; Duration = $null
                RemoteIP = $remoteIp; SentBytes = 0; RcvdBytes = 0; Active = $true
            })
        } elseif ($action -match 'tunnel-down|ssl-exit|logout') {
            $open = $sessions[$userKey] | Where-Object { $_.Active } | Select-Object -Last 1
            if ($open) {
                $open.EndTime = $entry.Timestamp; $open.Active = $false
                $open.SentBytes = $sentBytes; $open.RcvdBytes = $rcvdBytes
                if ($open.StartTime -ne [datetime]::MinValue -and $entry.Timestamp -ne [datetime]::MinValue) {
                    $open.Duration = $entry.Timestamp - $open.StartTime
                }
            }
        }
    }

    # Impossible travel detection
    foreach ($userKey in $sessions.Keys) {
        $userSessions = $sessions[$userKey] | Sort-Object { $_.StartTime }
        for ($i = 1; $i -lt $userSessions.Count; $i++) {
            $prev = $userSessions[$i - 1]; $curr = $userSessions[$i]
            if (-not $prev.RemoteIP -or -not $curr.RemoteIP) { continue }
            if ($curr.StartTime -eq [datetime]::MinValue -or $prev.StartTime -eq [datetime]::MinValue) { continue }
            $timeDiff = ($curr.StartTime - $prev.StartTime).TotalMinutes
            if ($timeDiff -le 30 -and $timeDiff -ge 0) {
                $pp = $prev.RemoteIP -split '\.'; $cp = $curr.RemoteIP -split '\.'
                if ($pp.Count -ge 2 -and $cp.Count -ge 2 -and "$($pp[0]).$($pp[1])" -ne "$($cp[0]).$($cp[1])") {
                    $travelFlags.Add(@{
                        User = $prev.User; IP1 = $prev.RemoteIP; Time1 = $prev.StartTime
                        IP2 = $curr.RemoteIP; Time2 = $curr.StartTime
                        MinutesBetween = [Math]::Round($timeDiff, 1)
                    })
                }
            }
        }
    }
    return @{ Sessions = $sessions; ImpossibleTravel = $travelFlags }
}

function Invoke-AnalyzeIpsecTunnel {
    param([System.Collections.Generic.List[object]]$Events)
    if (-not $Events) { return @{ Tunnels = @{}; Failures = @(); Summary = @{ TotalTunnels = 0; UpCount = 0; DownCount = 0; FlapCount = 0 } } }
    $tunnels = @{}; $failures = [System.Collections.Generic.List[object]]::new()

    foreach ($entry in $Events) {
        $ex = $entry.Extra; if (-not $ex) { continue }
        $tunnelName = $ex['TunnelName']; $isIpsec = $false

        if ($tunnelName) { $isIpsec = $true }
        elseif ($ex['subtype'] -eq 'ipsec' -or $ex['subtype'] -eq 'vpn') {
            if ($entry.Message -match 'IPsec|ipsec|IKE|ike|phase[12]|SA |tunnel|DPD|dpd') {
                $isIpsec = $true
                if (-not $tunnelName -and $entry.Message -match 'tunnel\s+"?([^"]+)"?') { $tunnelName = $Matches[1].Trim() }
                if (-not $tunnelName -and $ex['tunnelid']) { $tunnelName = "tunnel-$($ex['tunnelid'])" }
            }
        } elseif ($ex['type'] -eq 'event' -and $entry.Message -match 'IPsec|ipsec|IKE|ike') {
            $isIpsec = $true
            if ($entry.Message -match 'tunnel\s+"?([^"]+)"?') { $tunnelName = $Matches[1].Trim() }
        }
        if (-not $isIpsec) { continue }
        if (-not $tunnelName) { $tunnelName = '(unknown)' }
        if (-not $tunnels.ContainsKey($tunnelName)) {
            $tunnels[$tunnelName] = @{
                TunnelName = $tunnelName; Status = 'Unknown'
                UpEvents = [System.Collections.Generic.List[object]]::new()
                DownEvents = [System.Collections.Generic.List[object]]::new()
                NegotiationOK = 0; NegotiationFail = 0; DpdTimeouts = 0; RekeyEvents = 0; FlapCount = 0
                LastFailureReason = $null; FirstSeen = [datetime]::MaxValue; LastSeen = [datetime]::MinValue
                TotalUpSeconds = 0; RemoteGateway = $ex['remip']
            }
        }
        $tun = $tunnels[$tunnelName]
        if ($entry.Timestamp -ne [datetime]::MinValue) {
            if ($entry.Timestamp -lt $tun.FirstSeen) { $tun.FirstSeen = $entry.Timestamp }
            if ($entry.Timestamp -gt $tun.LastSeen) { $tun.LastSeen = $entry.Timestamp }
        }
        if (-not $tun.RemoteGateway -and $ex['remip']) { $tun.RemoteGateway = $ex['remip'] }

        $action = $ex['action']; $msg = $entry.Message
        if ($action -match 'tunnel-up' -or ($msg -match 'tunnel.*up|SA.*established|phase[12].*completed')) {
            $tun.Status = 'Up'; $tun.UpEvents.Add(@{ Timestamp = $entry.Timestamp; Message = $msg }); $tun.NegotiationOK++
        } elseif ($action -match 'tunnel-down' -or ($msg -match 'tunnel.*down|SA.*deleted|SA.*expired')) {
            $tun.Status = 'Down'; $tun.DownEvents.Add(@{ Timestamp = $entry.Timestamp; Message = $msg })
        } elseif ($msg -match 'negotiation.*fail|phase[12].*fail|IKE.*fail|proposal.*mismatch|no.*proposal.*chosen|auth.*fail') {
            $tun.NegotiationFail++
            $reason = if ($msg -match 'proposal.*mismatch') { 'Proposal Mismatch' }
                elseif ($msg -match 'auth.*fail') { 'Authentication Failure' }
                elseif ($msg -match 'timeout') { 'Timeout' }
                else { 'Negotiation Failure' }
            $tun.LastFailureReason = $reason
            $failures.Add(@{ TunnelName = $tunnelName; Timestamp = $entry.Timestamp; Reason = $reason; Message = $msg })
        } elseif ($msg -match 'DPD.*timeout|dead.*peer|dpd.*fail') {
            $tun.DpdTimeouts++; $tun.LastFailureReason = 'DPD Timeout'
            $failures.Add(@{ TunnelName = $tunnelName; Timestamp = $entry.Timestamp; Reason = 'DPD Timeout'; Message = $msg })
        } elseif ($msg -match 'rekey|rekeying') { $tun.RekeyEvents++ }
    }

    $upCount = 0; $downCount = 0; $totalFlaps = 0
    foreach ($tn in $tunnels.Keys) {
        $tun = $tunnels[$tn]
        # Calculate flaps
        $allToggle = @()
        foreach ($e in $tun.UpEvents) { $allToggle += @{ Type = 'Up'; Timestamp = $e.Timestamp } }
        foreach ($e in $tun.DownEvents) { $allToggle += @{ Type = 'Down'; Timestamp = $e.Timestamp } }
        $allToggle = $allToggle | Where-Object { $_.Timestamp -ne [datetime]::MinValue } | Sort-Object { $_.Timestamp }
        $flapCount = 0
        for ($i = 1; $i -lt $allToggle.Count; $i++) {
            if ($allToggle[$i].Type -ne $allToggle[$i-1].Type) {
                $gap = ($allToggle[$i].Timestamp - $allToggle[$i-1].Timestamp).TotalMinutes
                if ($gap -le 5) { $flapCount++ }
            }
        }
        $tun.FlapCount = $flapCount; $totalFlaps += $flapCount
        # Calculate uptime
        if ($tun.UpEvents.Count -gt 0 -and $tun.FirstSeen -ne [datetime]::MaxValue -and $tun.LastSeen -ne [datetime]::MinValue) {
            $totalSpan = ($tun.LastSeen - $tun.FirstSeen).TotalSeconds
            if ($totalSpan -gt 0) {
                $upSec = 0; $lastUp = $null
                foreach ($evt in $allToggle) {
                    if ($evt.Type -eq 'Up') { $lastUp = $evt.Timestamp }
                    elseif ($evt.Type -eq 'Down' -and $lastUp) { $upSec += ($evt.Timestamp - $lastUp).TotalSeconds; $lastUp = $null }
                }
                if ($lastUp) { $upSec += ($tun.LastSeen - $lastUp).TotalSeconds }
                $tun.TotalUpSeconds = $upSec
            }
        }
        if ($tun.Status -eq 'Up') { $upCount++ } else { $downCount++ }
    }
    return @{ Tunnels = $tunnels; Failures = @($failures); Summary = @{ TotalTunnels = $tunnels.Count; UpCount = $upCount; DownCount = $downCount; FlapCount = $totalFlaps } }
}

function Get-LogStatistics {
    param([System.Collections.Generic.List[object]]$Events)
    if (-not $Events) { $Events = [System.Collections.Generic.List[object]]::new() }
    $counts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
    $sources = @{}; $eventIds = @{}; $perHour = @{}; $perFile = @{}

    $minTs = [datetime]::MaxValue; $maxTs = [datetime]::MinValue
    foreach ($e in $Events) {
        if ($counts.ContainsKey($e.Severity)) { $counts[$e.Severity]++ }
        if ($e.Source) { if ($sources.ContainsKey($e.Source)) { $sources[$e.Source]++ } else { $sources[$e.Source] = 1 } }
        if ($e.Extra['EventID']) {
            $eid = [string]$e.Extra['EventID']
            if ($eventIds.ContainsKey($eid)) { $eventIds[$eid]++ } else { $eventIds[$eid] = 1 }
        }
        if ($e.Timestamp -ne [datetime]::MinValue) {
            if ($e.Timestamp -lt $minTs) { $minTs = $e.Timestamp }
            if ($e.Timestamp -gt $maxTs) { $maxTs = $e.Timestamp }
            $hr = $e.Timestamp.Hour
            if ($perHour.ContainsKey($hr)) { $perHour[$hr]++ } else { $perHour[$hr] = 1 }
        }
        $sf = if ($e.SourceFile) { $e.SourceFile } else { '(single file)' }
        if (-not $perFile.ContainsKey($sf)) { $perFile[$sf] = @{ Total = 0; Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0; Format = '' } }
        $perFile[$sf].Total++
        if ($perFile[$sf].ContainsKey($e.Severity)) { $perFile[$sf][$e.Severity]++ }
        if (-not $perFile[$sf].Format -and $e.SourceFormat) { $perFile[$sf].Format = $e.SourceFormat }
    }

    # Top source IPs
    $srcIps = @{}; $dstIps = @{}
    foreach ($e in $Events) {
        if ($e.Extra['srcip']) { $ip = $e.Extra['srcip']; if ($srcIps.ContainsKey($ip)) { $srcIps[$ip]++ } else { $srcIps[$ip] = 1 } }
        if ($e.Extra['dstip']) { $ip = $e.Extra['dstip']; if ($dstIps.ContainsKey($ip)) { $dstIps[$ip]++ } else { $dstIps[$ip] = 1 } }
    }

    return @{
        Total = $Events.Count; SeverityCounts = $counts
        TimeRange = @{ Min = $minTs; Max = $maxTs }
        TopSources = ($sources.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10)
        TopEventIds = ($eventIds.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10)
        TopSrcIPs = ($srcIps.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10)
        TopDstIPs = ($dstIps.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10)
        PerHour = $perHour; PerFile = $perFile
    }
}

# ============================================================================
# SECTION 6: Output Formatter
# ============================================================================

function Get-TerminalWidth {
    try { return [Console]::WindowWidth } catch { return 120 }
}

function Write-ColorText {
    param([string]$Text, [string]$Color = '', [switch]$NoNewline)
    if ($script:NoColorFlag -or -not $Color) {
        if ($NoNewline) { Write-Host $Text -NoNewline } else { Write-Host $Text }
    } else {
        if ($NoNewline) { Write-Host "$Color$Text$($script:C.Reset)" -NoNewline }
        else { Write-Host "$Color$Text$($script:C.Reset)" }
    }
}

function Get-SeverityAbbrev {
    param([string]$Sev)
    switch ($Sev) { 'Critical' { 'CRIT' } 'High' { 'HIGH' } 'Medium' { 'MED' } 'Low' { 'LOW' } 'Info' { 'INFO' } default { $Sev } }
}

function Add-Highlight {
    param([string]$Text, [string]$Pattern)
    if (-not $Pattern -or $script:NoColorFlag) { return $Text }
    try {
        return [regex]::Replace($Text, $Pattern, { param($m) "$($script:C.BgYellow)$($script:C.Bold)$($m.Value)$($script:C.Reset)" }, 'IgnoreCase')
    } catch { return $Text }
}

function Format-Truncate {
    param([string]$Text, [int]$Width)
    if (-not $Text) { return ''.PadRight($Width) }
    if ($Text.Length -le $Width) { return $Text.PadRight($Width) }
    return $Text.Substring(0, $Width - 1) + [char]0x2026
}

function Format-Number {
    param([int]$N)
    return $N.ToString('N0')
}

function Format-LogTable {
    param(
        [System.Collections.Generic.List[object]]$Events,
        [string[]]$FieldList,
        [string]$HighlightPattern = '',
        [int]$Max = 0
    )
    if ($Events.Count -eq 0) { Write-ColorText 'No events to display.' $script:C.Dim; return }

    $termWidth = Get-TerminalWidth
    $displayEvents = if ($Max -gt 0 -and $Events.Count -gt $Max) { $Events[0..($Max - 1)] } else { $Events }

    # Check for aggregation results
    if ($displayEvents[0].PSObject.Properties['_AggCount']) {
        $fieldLabel = if ($displayEvents[0].PSObject.Properties['_AggField']) { $displayEvents[0]._AggField.ToUpper() } else { 'KEY' }
        $maxKeyMeasure = ($displayEvents | ForEach-Object { ([string]$_._AggKey).Length } | Measure-Object -Maximum).Maximum
        $maxKey = [Math]::Max($(if ($maxKeyMeasure) { $maxKeyMeasure } else { 3 }), $fieldLabel.Length)
        $maxCountMeasure = ($displayEvents | ForEach-Object { (Format-Number $_._AggCount).Length } | Measure-Object -Maximum).Maximum
        $maxCount = [Math]::Max($(if ($maxCountMeasure) { $maxCountMeasure } else { 5 }), 5)

        $hdr = '  ' + $fieldLabel.PadRight($maxKey + 2) + 'COUNT'.PadLeft($maxCount)
        Write-ColorText $hdr $script:C.BoldWhite
        Write-ColorText ('  ' + ([string][char]0x2500 * ($maxKey + $maxCount + 4))) $script:C.Gray
        foreach ($e in $displayEvents) {
            $line = '  ' + ([string]$e._AggKey).PadRight($maxKey + 2) + (Format-Number $e._AggCount).PadLeft($maxCount)
            Write-ColorText $line $script:C.White
        }
        return
    }

    # Determine columns
    if (-not $FieldList -or $FieldList.Count -eq 0) {
        $FieldList = @('Timestamp', 'Severity', 'Source', 'Message')
    }
    $colWidths = @{}
    $colWidths['Timestamp'] = 21; $colWidths['Severity'] = 10; $colWidths['Source'] = 16
    foreach ($f in $FieldList) { if (-not $colWidths.ContainsKey($f)) { $colWidths[$f] = [Math]::Max($f.Length + 2, 12) } }

    # Calculate Message column width (fills remaining space)
    $fixedWidth = 1  # left border
    foreach ($f in $FieldList) { if ($f -ne 'Message') { $fixedWidth += $colWidths[$f] + 3 } }
    $fixedWidth += 1  # right border
    $msgWidth = $termWidth - $fixedWidth - 3
    if ($msgWidth -lt 20) { $msgWidth = 40 }
    $colWidths['Message'] = $msgWidth

    # Check if columns fit; drop rightmost if needed
    $usedFields = [System.Collections.Generic.List[string]]::new()
    $totalW = 1
    foreach ($f in $FieldList) {
        $needed = $colWidths[$f] + 3
        if ($totalW + $needed + 1 -le $termWidth) { $usedFields.Add($f); $totalW += $needed }
        else { break }
    }
    $hiddenCount = $FieldList.Count - $usedFields.Count

    # Draw table
    $hLine = [char]0x2500; $vLine = [char]0x2502
    $tlc = [char]0x250C; $trc = [char]0x2510; $blc = [char]0x2514; $brc = [char]0x2518
    $ltee = [char]0x251C; $rtee = [char]0x2524; $ttee = [char]0x252C; $btee = [char]0x2534; $cross = [char]0x253C

    # Top border
    $topParts = @()
    foreach ($f in $usedFields) { $topParts += ([string]$hLine * ($colWidths[$f] + 2)) }
    Write-ColorText "$tlc$($topParts -join $ttee)$trc" $script:C.Gray

    # Header
    $hdrParts = @()
    foreach ($f in $usedFields) { $hdrParts += " $(Format-Truncate $f $colWidths[$f]) " }
    Write-ColorText "$vLine$($hdrParts -join $vLine)$vLine" $script:C.BoldWhite

    # Header separator
    $sepParts = @()
    foreach ($f in $usedFields) { $sepParts += ([string]$hLine * ($colWidths[$f] + 2)) }
    Write-ColorText "$ltee$($sepParts -join $cross)$rtee" $script:C.Gray

    # Data rows
    foreach ($e in $displayEvents) {
        $cellParts = @()
        foreach ($f in $usedFields) {
            $val = switch ($f) {
                'Timestamp' { if ($e.Timestamp -ne [datetime]::MinValue) { $e.Timestamp.ToString('yyyy-MM-dd HH:mm:ss') } else { '' } }
                'Severity' { $e.Severity }
                'Source' { $e.Source }
                'Message' { ($e.Message -replace "`n", ' ') }
                default { $fv = Get-EventFieldValue -Event $e -Field $f; if ($fv) { [string]$fv } else { '' } }
            }
            $formatted = Format-Truncate $val $colWidths[$f]
            if ($f -eq 'Severity' -and $script:SevColor.ContainsKey($e.Severity)) {
                $cellParts += " $($script:SevColor[$e.Severity])$(Format-Truncate $val $colWidths[$f])$($script:C.Reset) "
            } else {
                if ($HighlightPattern) { $formatted = Add-Highlight $formatted $HighlightPattern }
                $cellParts += " $formatted "
            }
        }
        Write-Host "$($script:C.Gray)$vLine$($script:C.Reset)$($cellParts -join "$($script:C.Gray)$vLine$($script:C.Reset)")$($script:C.Gray)$vLine$($script:C.Reset)"
    }

    # Bottom border
    $botParts = @()
    foreach ($f in $usedFields) { $botParts += ([string]$hLine * ($colWidths[$f] + 2)) }
    Write-ColorText "$blc$($botParts -join $btee)$brc" $script:C.Gray

    # Footer
    $footerParts = @()
    $footerParts += "$(Format-Number $displayEvents.Count) events"
    if ($Max -gt 0 -and $Events.Count -gt $Max) { $footerParts[0] += " (of $(Format-Number $Events.Count))" }
    if ($hiddenCount -gt 0) { $footerParts += "(+$hiddenCount fields hidden)" }
    Write-ColorText " $($footerParts -join ' | ')" $script:C.Dim
}

function Format-LogGrid {
    param(
        [System.Collections.Generic.List[object]]$Events,
        [string[]]$FieldList,
        [string]$HighlightPattern = '',
        [int]$Max = 0
    )
    if ($Events.Count -eq 0) { Write-ColorText 'No events.' $script:C.Dim; return }
    $displayEvents = if ($Max -gt 0 -and $Events.Count -gt $Max) { $Events[0..($Max - 1)] } else { $Events }

    # Aggregation results
    if ($displayEvents[0].PSObject.Properties['_AggCount']) {
        Format-LogTable -Events $Events -FieldList $FieldList -HighlightPattern $HighlightPattern -Max $Max
        return
    }

    if (-not $FieldList -or $FieldList.Count -eq 0) { $FieldList = @('Timestamp', 'Severity', 'Source', 'Message') }
    $termWidth = Get-TerminalWidth
    $colWidths = @{}; $colWidths['Timestamp'] = 21; $colWidths['Severity'] = 7; $colWidths['Source'] = 16
    $fixedW = 0
    foreach ($f in $FieldList) {
        if ($f -ne 'Message') {
            if (-not $colWidths.ContainsKey($f)) { $colWidths[$f] = [Math]::Max($f.Length, 10) }
            $fixedW += $colWidths[$f] + 4
        }
    }
    $colWidths['Message'] = [Math]::Max($termWidth - $fixedW - 4, 20)

    # Header
    $hdr = ''
    foreach ($f in $FieldList) {
        $label = if ($f -eq 'Severity') { 'SEV' } elseif ($f -eq 'Timestamp') { 'TIMESTAMP' } else { $f.ToUpper() }
        $hdr += (Format-Truncate $label $colWidths[$f]) + '    '
    }
    Write-ColorText $hdr.TrimEnd() $script:C.BoldWhite

    foreach ($e in $displayEvents) {
        $line = ''
        foreach ($f in $FieldList) {
            $val = switch ($f) {
                'Timestamp' { if ($e.Timestamp -ne [datetime]::MinValue) { $e.Timestamp.ToString('yyyy-MM-dd HH:mm:ss') } else { '' } }
                'Severity' { Get-SeverityAbbrev $e.Severity }
                'Source' { $e.Source }
                'Message' { ($e.Message -replace "`n", ' ') }
                default { $fv = Get-EventFieldValue -Event $e -Field $f; if ($fv) { [string]$fv } else { '' } }
            }
            $formatted = Format-Truncate $val $colWidths[$f]
            if ($f -eq 'Severity' -and $script:SevColor.ContainsKey($e.Severity)) {
                $line += "$($script:SevColor[$e.Severity])$formatted$($script:C.Reset)    "
            } else {
                if ($HighlightPattern) { $formatted = Add-Highlight $formatted $HighlightPattern }
                $line += "$formatted    "
            }
        }
        Write-Host $line.TrimEnd()
    }
    Write-ColorText "$([string][char]0x2500 * 3) $(Format-Number $displayEvents.Count) events $([string][char]0x2500 * 3)" $script:C.Dim
}

function Format-LogList {
    param(
        [System.Collections.Generic.List[object]]$Events,
        [string]$HighlightPattern = '',
        [int]$Max = 0
    )
    if ($Events.Count -eq 0) { Write-ColorText 'No events.' $script:C.Dim; return }
    $displayEvents = if ($Max -gt 0 -and $Events.Count -gt $Max) { $Events[0..($Max - 1)] } else { $Events }
    $idx = 0
    foreach ($e in $displayEvents) {
        $idx++
        Write-ColorText "$([string][char]0x2500 * 3) Event $idx of $(Format-Number $displayEvents.Count) $([string][char]0x2500 * 40)" $script:C.Dim
        $fields = [ordered]@{}
        $fields['Timestamp'] = if ($e.Timestamp -ne [datetime]::MinValue) { $e.Timestamp.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
        $fields['Severity'] = $e.Severity
        $fields['Source'] = $e.Source
        if ($e.Extra) { foreach ($k in $e.Extra.Keys) { $fields[$k] = $e.Extra[$k] } }
        $msgText = if ($e.Message) { $e.Message } else { '' }
        $rawText = if ($e.RawLine) { $e.RawLine } else { '' }
        $fields['Message'] = ($msgText -replace "`n", "`n              ")
        $fields['Raw'] = ($rawText -replace "`n", "`n              ").Substring(0, [Math]::Min(500, $rawText.Length))
        $maxLabelMeasure = ($fields.Keys | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
        $maxLabel = if ($maxLabelMeasure) { $maxLabelMeasure } else { 10 }
        foreach ($kv in $fields.GetEnumerator()) {
            $label = $kv.Key.PadLeft($maxLabel)
            $val = [string]$kv.Value
            if ($HighlightPattern) { $val = Add-Highlight $val $HighlightPattern }
            if ($kv.Key -eq 'Severity' -and $script:SevColor.ContainsKey($e.Severity)) {
                Write-Host "  $label : $($script:SevColor[$e.Severity])$val$($script:C.Reset)"
            } else {
                Write-Host "  $label : $val"
            }
        }
    }
}

function Format-LogRaw {
    param([System.Collections.Generic.List[object]]$Events, [int]$Max = 0)
    $displayEvents = if ($Max -gt 0 -and $Events.Count -gt $Max) { $Events[0..($Max - 1)] } else { $Events }
    foreach ($e in $displayEvents) {
        $obj = [ordered]@{
            Timestamp = $e.Timestamp; Severity = $e.Severity; Source = $e.Source; Message = $e.Message
        }
        foreach ($k in $e.Extra.Keys) {
            if ($k -notin @('Timestamp','Severity','Source','Message','RawLine')) { $obj[$k] = $e.Extra[$k] }
        }
        [PSCustomObject]$obj
    }
}

function Format-LogJson {
    param([System.Collections.Generic.List[object]]$Events, [int]$Max = 0)
    $displayEvents = if ($Max -gt 0 -and $Events.Count -gt $Max) { $Events[0..($Max - 1)] } else { $Events }
    foreach ($e in $displayEvents) {
        $obj = [ordered]@{
            Timestamp = if ($e.Timestamp -ne [datetime]::MinValue) { $e.Timestamp.ToString('o') } else { $null }
            Severity = $e.Severity; Source = $e.Source; Message = $e.Message
        }
        foreach ($k in $e.Extra.Keys) { $obj[$k] = $e.Extra[$k] }
        $obj | ConvertTo-Json -Compress
    }
}

function Format-LogCsv {
    param([System.Collections.Generic.List[object]]$Events, [int]$Max = 0)
    $displayEvents = if ($Max -gt 0 -and $Events.Count -gt $Max) { $Events[0..($Max - 1)] } else { $Events }
    # Discover all extra fields
    $allExtraKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($e in $displayEvents) { foreach ($k in $e.Extra.Keys) { $allExtraKeys.Add($k) | Out-Null } }
    $headers = @('Timestamp','Severity','Source','Message') + @($allExtraKeys | Sort-Object)
    $headers -join ','
    foreach ($e in $displayEvents) {
        $vals = @()
        $vals += if ($e.Timestamp -ne [datetime]::MinValue) { "`"$($e.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))`"" } else { '""' }
        $vals += "`"$($e.Severity)`""
        $vals += "`"$($e.Source -replace '"','""')`""
        $vals += "`"$(($e.Message -replace '"','""' -replace "`n",' '))`""
        foreach ($k in ($allExtraKeys | Sort-Object)) {
            $v = if ($e.Extra.ContainsKey($k)) { $e.Extra[$k] -replace '"','""' } else { '' }
            $vals += "`"$v`""
        }
        $vals -join ','
    }
}

function Write-LogStats {
    param([hashtable]$Stats, [string[]]$SourceFiles = @(), [string[]]$Formats = @(), [double]$ParseTime = 0)
    $c = $script:C; $hLine = [string][char]0x2500

    Write-ColorText "$($hLine * 3) Parse Summary $($hLine * 40)" $c.BoldWhite
    $format = if ($Formats.Count -eq 1) { $Formats[0] } else { "$($Formats.Count) formats" }
    $files = if ($SourceFiles.Count -eq 1) { $SourceFiles[0] } else { "$($SourceFiles.Count) files" }
    Write-Host "  Source     : $format"
    Write-Host "  File       : $files"
    Write-Host "  Total      : $(Format-Number $Stats.Total) events"
    if ($Stats.TimeRange.Min -ne [datetime]::MaxValue) {
        Write-Host "  Time Range : $($Stats.TimeRange.Min.ToString('yyyy-MM-dd HH:mm:ss')) -> $($Stats.TimeRange.Max.ToString('yyyy-MM-dd HH:mm:ss'))"
    }
    if ($ParseTime -gt 0) { Write-Host "  Parse Time : $([Math]::Round($ParseTime, 2))s" }

    # Severity distribution
    Write-Host ''
    Write-ColorText "$($hLine * 3) Severity $($hLine * 44)" $c.BoldWhite
    $maxCount = ($Stats.SeverityCounts.Values | Measure-Object -Maximum).Maximum
    if (-not $maxCount -or $maxCount -eq 0) { $maxCount = 1 }
    $barWidth = [Math]::Max(10, (Get-TerminalWidth) - 40)
    foreach ($sev in @('Critical','High','Medium','Low','Info')) {
        $count = $Stats.SeverityCounts[$sev]
        $pct = if ($Stats.Total -gt 0) { [Math]::Round(($count / $Stats.Total) * 100, 2) } else { 0 }
        $bw = [Math]::Max(0, [int](($count / $maxCount) * $barWidth))
        $bar = [string][char]0x2588 * $bw
        $sevColor = if ($script:SevColor.ContainsKey($sev)) { $script:SevColor[$sev] } else { '' }
        Write-Host "  $sevColor$(($sev.ToUpper()).PadRight(10))$($c.Reset) $($c.Cyan)$bar$($c.Reset)  $(Format-Number $count)  ($pct%)"
    }

    # Top Source IPs
    if ($Stats.TopSrcIPs -and @($Stats.TopSrcIPs).Count -gt 0) {
        Write-Host ''
        Write-ColorText "$($hLine * 3) Top Source IPs $($hLine * 38)" $c.BoldWhite
        $maxIP = ($Stats.TopSrcIPs | Select-Object -First 5 | ForEach-Object { $_.Value } | Measure-Object -Maximum).Maximum
        if ($maxIP -eq 0) { $maxIP = 1 }
        foreach ($ip in ($Stats.TopSrcIPs | Select-Object -First 5)) {
            $bw = [Math]::Max(0, [int](($ip.Value / $maxIP) * $barWidth))
            $bar = [string][char]0x2588 * $bw
            Write-Host "  $($ip.Key.PadRight(18)) $($c.Cyan)$bar$($c.Reset)  $(Format-Number $ip.Value)"
        }
    }
}

function Write-QuickDigest {
    param([hashtable]$Stats)
    $c = $script:C
    Write-ColorText "$([string][char]0x2500 * 3) Quick Digest $([string][char]0x2500 * 50)" $c.BoldWhite
    $hdr = '  {0,-30} {1,-18} {2,-10} {3,-6} {4,-6} {5,-8} {6}' -f 'FILE','FORMAT','EVENTS','CRIT','HIGH','MEDIUM','TIME RANGE'
    Write-ColorText $hdr $c.BoldWhite
    $totalEvents = 0; $totalCrit = 0; $totalHigh = 0; $totalMed = 0
    foreach ($file in $Stats.PerFile.Keys) {
        $f = $Stats.PerFile[$file]
        $totalEvents += $f.Total; $totalCrit += $f.Critical; $totalHigh += $f.High; $totalMed += $f.Medium
        $crit = if ($f.Critical -gt 0) { "$($c.Red)$($f.Critical)$($c.Reset)" } else { "$($f.Critical)" }
        $high = if ($f.High -gt 0) { "$($c.Red)$($f.High)$($c.Reset)" } else { "$($f.High)" }
        Write-Host ('  {0,-30} {1,-18} {2,-10} ' -f (Format-Truncate $file 28), $f.Format, (Format-Number $f.Total)) -NoNewline
        Write-Host "$crit".PadRight(6) -NoNewline
        Write-Host " $high".PadRight(6) -NoNewline
        Write-Host " $(Format-Number $f.Medium)".PadRight(8)
    }
    Write-ColorText "  $([string][char]0x2500 * 80)" $c.Dim
    Write-Host ('  {0,-30} {1,-18} {2,-10} {3,-6} {4,-6} {5}' -f 'TOTAL', '', (Format-Number $totalEvents), $totalCrit, $totalHigh, $totalMed)
}

function Write-ContextBlock {
    param([object]$Event, [int]$ContextLines, [string[]]$AllRawLines)
    if ($ContextLines -le 0 -or $Event.LineNumber -le 0 -or -not $AllRawLines) { return }
    $c = $script:C
    $start = [Math]::Max(0, $Event.LineNumber - 1 - $ContextLines)
    $end = [Math]::Min($AllRawLines.Count - 1, $Event.LineNumber - 1 + $ContextLines)
    Write-ColorText "  $([string][char]0x2500 * 3) Context: $ContextLines lines before/after $([string][char]0x2500 * 30)" $c.Dim
    for ($i = $start; $i -le $end; $i++) {
        if ($i -eq ($Event.LineNumber - 1)) {
            $sevC = if ($script:SevColor.ContainsKey($Event.Severity)) { $script:SevColor[$Event.Severity] } else { $c.White }
            $ts = if ($Event.Timestamp -ne [datetime]::MinValue) { $Event.Timestamp.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
            Write-Host "  $($sevC)>>> $ts  $($Event.Severity.ToUpper())  $($Event.Message)  <<<$($c.Reset)"
        } else {
            Write-ColorText "  [raw] $($AllRawLines[$i])" $c.Dim
        }
    }
    Write-ColorText "  $([string][char]0x2500 * 60)" $c.Dim
}

# ============================================================================
# SECTION 7: Config Tools (FortiGate-specific)
# ============================================================================

function Get-ConfigSection {
    param([string]$FilePath, [string]$SectionName)
    $lines = [System.IO.File]::ReadAllLines($FilePath)
    $results = [System.Collections.Generic.List[string]]::new()
    $inSection = $false; $depth = 0; $useWildcard = $SectionName.Contains('*')

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i].Trim()
        if (-not $inSection -and $line -match '^config\s+(.+)$') {
            $secName = $Matches[1]
            $matches2 = if ($useWildcard) { $secName -like $SectionName } else { $secName -eq $SectionName }
            if ($matches2) { $inSection = $true; $depth = 1; $results.Add($lines[$i]); continue }
        }
        if ($inSection) {
            $results.Add($lines[$i])
            if ($line -match '^config\s+') { $depth++ }
            if ($line -eq 'end') { $depth--; if ($depth -le 0) { $inSection = $false; $results.Add('') } }
        }
    }
    return $results
}

function Compare-Configs {
    param([string]$File1, [string]$File2, [string]$SectionFilter = '')
    $lines1 = if ($SectionFilter) { Get-ConfigSection $File1 $SectionFilter } else { [System.IO.File]::ReadAllLines($File1) }
    $lines2 = if ($SectionFilter) { Get-ConfigSection $File2 $SectionFilter } else { [System.IO.File]::ReadAllLines($File2) }

    $set1 = @{}; $set2 = @{}
    $idx = 0; foreach ($l in $lines1) { $set1[$l.Trim()] = $idx; $idx++ }
    $idx = 0; foreach ($l in $lines2) { $set2[$l.Trim()] = $idx; $idx++ }

    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($l in $lines1) {
        $t = $l.Trim()
        if (-not $set2.ContainsKey($t)) {
            $results.Add(@{ Type = 'Removed'; Line = $l; Section = '' })
        }
    }
    foreach ($l in $lines2) {
        $t = $l.Trim()
        if (-not $set1.ContainsKey($t)) {
            $results.Add(@{ Type = 'Added'; Line = $l; Section = '' })
        }
    }
    return @{ Diffs = $results; Lines1 = $lines1; Lines2 = $lines2 }
}

function Format-ConfigDiff {
    param($DiffResult)
    $c = $script:C
    if ($DiffResult.Diffs.Count -eq 0) {
        Write-ColorText 'No differences found.' $c.Green
        return
    }
    Write-ColorText "$([string][char]0x2500 * 3) Config Diff $([string][char]0x2500 * 45)" $c.BoldWhite
    Write-Host "  $($c.Red)--- Removed: $($DiffResult.Lines1.Count) lines$($c.Reset)"
    Write-Host "  $($c.Green)+++ Added: $($DiffResult.Lines2.Count) lines$($c.Reset)"
    Write-Host ''
    foreach ($d in $DiffResult.Diffs) {
        if ($d.Type -eq 'Removed') { Write-Host "$($c.Red)- $($d.Line)$($c.Reset)" }
        elseif ($d.Type -eq 'Added') { Write-Host "$($c.Green)+ $($d.Line)$($c.Reset)" }
    }
}

function Format-ConfigSection {
    param([string[]]$Lines)
    $c = $script:C
    foreach ($line in $Lines) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^config\s+' -or $trimmed -eq 'end') {
            Write-ColorText $line $c.BoldCyan
        } elseif ($trimmed -match '^edit\s+' -or $trimmed -eq 'next') {
            Write-ColorText $line $c.Bold
        } elseif ($trimmed -match '^set\s+') {
            Write-ColorText $line $c.White
        } elseif ($trimmed.StartsWith('#')) {
            Write-ColorText $line $c.Dim
        } else {
            Write-Host $line
        }
    }
}

# ============================================================================
# SECTION 8: Report Engine
# ============================================================================

function New-ReportData {
    param([string]$Title, [System.Collections.Generic.List[object]]$Sections)
    [PSCustomObject]@{ Title = $Title; Sections = $Sections }
}

function New-ReportSection {
    param([string]$Heading, [string]$Type, $Data, [string[]]$Columns = @())
    [PSCustomObject]@{ Heading = $Heading; Type = $Type; Data = $Data; Columns = $Columns }
}

function New-SummaryReport {
    param([System.Collections.Generic.List[object]]$Events)
    $stats = Get-LogStatistics $Events
    $sections = [System.Collections.Generic.List[object]]::new()

    $sections.Add((New-ReportSection 'Overview' 'KeyValue' ([ordered]@{
        'Total Events' = Format-Number $stats.Total
        'Time Range' = if ($stats.TimeRange.Min -ne [datetime]::MaxValue) {
            "$($stats.TimeRange.Min.ToString('yyyy-MM-dd HH:mm:ss')) - $($stats.TimeRange.Max.ToString('yyyy-MM-dd HH:mm:ss'))"
        } else { 'N/A' }
        'Sources' = ($stats.TopSources | ForEach-Object { $_.Key }) -join ', '
    })))

    $sevData = @()
    foreach ($sev in @('Critical','High','Medium','Low','Info')) {
        $sevData += @{ Label = $sev; Value = $stats.SeverityCounts[$sev] }
    }
    $sections.Add((New-ReportSection 'Severity Distribution' 'BarChart' $sevData))

    if (@($stats.TopSrcIPs).Count -gt 0) {
        $ipData = @($stats.TopSrcIPs | Select-Object -First 10 | ForEach-Object {
            @{ Destination = $_.Key; Count = $_.Value }
        })
        $sections.Add((New-ReportSection 'Top Source IPs' 'Table' $ipData -Columns @('Destination','Count')))
    }

    if (@($stats.TopEventIds).Count -gt 0) {
        $eidData = @($stats.TopEventIds | Select-Object -First 10 | ForEach-Object {
            $desc = if ($script:EventIdLookup.ContainsKey([int]$_.Key)) { $script:EventIdLookup[[int]$_.Key] } else { '' }
            @{ EventID = $_.Key; Count = $_.Value; Description = $desc }
        })
        $sections.Add((New-ReportSection 'Top Event IDs' 'Table' $eidData -Columns @('EventID','Count','Description')))
    }

    return New-ReportData 'Summary Report' $sections
}

function New-MorningBriefing {
    param([System.Collections.Generic.List[object]]$Events)
    $stats = Get-LogStatistics $Events
    $sections = [System.Collections.Generic.List[object]]::new()

    $sections.Add((New-ReportSection 'Overnight Summary' 'KeyValue' ([ordered]@{
        'Total Events' = Format-Number $stats.Total
        'Critical' = $stats.SeverityCounts.Critical
        'High' = $stats.SeverityCounts.High
        'Medium' = $stats.SeverityCounts.Medium
    })))

    # IPsec tunnel status
    $ipsecResult = Invoke-AnalyzeIpsecTunnel $Events
    if ($ipsecResult.Tunnels.Count -gt 0) {
        $tunData = @()
        foreach ($tn in $ipsecResult.Tunnels.Keys) {
            $t = $ipsecResult.Tunnels[$tn]
            $tunData += @{ Tunnel = $tn; Status = $t.Status; Flaps = $t.FlapCount; LastFailure = $t.LastFailureReason }
        }
        $sections.Add((New-ReportSection 'IPsec Tunnel Status' 'Table' $tunData -Columns @('Tunnel','Status','Flaps','LastFailure')))
    }

    # Failed logins
    $failedLogins = Invoke-AnalyzeFailedLogins $Events
    if ($failedLogins.Count -gt 0) {
        $flData = @($failedLogins | Select-Object -First 10 | ForEach-Object {
            @{ User = $_.User; Count = $_.Count; UniqueIPs = $_.SourceIPs.Count; Sources = ($_.Sources -join ', ') }
        })
        $sections.Add((New-ReportSection 'Failed Logins (Top 10)' 'Table' $flData -Columns @('User','Count','UniqueIPs','Sources')))
    }

    # Security alerts
    $secEvents = @($Events | Where-Object { $_.Severity -in @('Critical','High') })
    if ($secEvents.Count -gt 0) {
        $secData = @($secEvents | Select-Object -First 20 | ForEach-Object {
            $msgText = if ($_.Message) { $_.Message } else { '' }
            @{ Time = $_.Timestamp.ToString('HH:mm:ss'); Severity = $_.Severity; Source = $_.Source; Message = $msgText.Substring(0, [Math]::Min(80, $msgText.Length)) }
        })
        $sections.Add((New-ReportSection 'Security Alerts' 'Table' $secData -Columns @('Time','Severity','Source','Message')))
    }

    return New-ReportData 'Morning Briefing' $sections
}

function New-AuditReport {
    param([System.Collections.Generic.List[object]]$Events)
    $sections = [System.Collections.Generic.List[object]]::new()
    $sections.Add((New-ReportSection 'Audit Overview' 'KeyValue' ([ordered]@{
        'Total Events' = Format-Number $Events.Count
        'Time Range' = if ($Events.Count -gt 0 -and $Events[0].Timestamp -ne [datetime]::MinValue) {
            "$($Events[0].Timestamp.ToString('yyyy-MM-dd')) - $(($Events[-1]).Timestamp.ToString('yyyy-MM-dd'))"
        } else { 'N/A' }
    })))

    # Privileged activity (Event 4672, 4648)
    $privEvents = @($Events | Where-Object { $_.Extra['EventID'] -and [int]$_.Extra['EventID'] -in @(4672,4648,4697,7045) })
    if ($privEvents.Count -gt 0) {
        $privData = @($privEvents | Select-Object -First 50 | ForEach-Object {
            $msgText = if ($_.Message) { $_.Message } else { '' }
            @{ Time = $_.Timestamp.ToString('yyyy-MM-dd HH:mm'); EventID = $_.Extra['EventID']; User = $_.Extra['TargetUserName']; Description = $msgText.Substring(0, [Math]::Min(60, $msgText.Length)) }
        })
        $sections.Add((New-ReportSection 'Privileged Activity' 'Table' $privData -Columns @('Time','EventID','User','Description')))
    }

    # Account changes
    $acctEvents = @($Events | Where-Object { $_.Extra['EventID'] -and [int]$_.Extra['EventID'] -in @(4720,4722,4725,4726,4738,4740,4767) })
    if ($acctEvents.Count -gt 0) {
        $acctData = @($acctEvents | Select-Object -First 50 | ForEach-Object {
            $desc = if ($script:EventIdLookup.ContainsKey([int]$_.Extra['EventID'])) { $script:EventIdLookup[[int]$_.Extra['EventID']] } else { '' }
            @{ Time = $_.Timestamp.ToString('yyyy-MM-dd HH:mm'); EventID = $_.Extra['EventID']; Target = $_.Extra['TargetUserName']; Action = $desc }
        })
        $sections.Add((New-ReportSection 'Account Changes' 'Table' $acctData -Columns @('Time','EventID','Target','Action')))
    }

    $failedLogins = Invoke-AnalyzeFailedLogins $Events
    if ($failedLogins.Count -gt 0) {
        $flData = @($failedLogins | ForEach-Object {
            @{ User = $_.User; Count = $_.Count; UniqueIPs = $_.SourceIPs.Count; TimeSpan = if ($_.LastSeen -ne [datetime]::MinValue -and $_.FirstSeen -ne [datetime]::MinValue) { ($_.LastSeen - $_.FirstSeen).ToString('d\.hh\:mm') } else { '' } }
        })
        $sections.Add((New-ReportSection 'Failed Authentication Summary' 'Table' $flData -Columns @('User','Count','UniqueIPs','TimeSpan')))
    }

    return New-ReportData 'Audit Report' $sections
}

function New-ComplianceReport {
    param([System.Collections.Generic.List[object]]$Events)
    $sections = [System.Collections.Generic.List[object]]::new()
    $controls = @(
        @{ ID = 'AC-1'; Name = 'Access Control Policy'; Pattern = 'EventID:(4624|4625|4740)'; Description = 'Logon events and account lockouts' }
        @{ ID = 'AC-2'; Name = 'Account Management'; Pattern = 'EventID:(4720|4722|4725|4726)'; Description = 'Account creation, enable, disable, delete' }
        @{ ID = 'AU-1'; Name = 'Audit Logging'; Pattern = 'EventID:(1102|4719)'; Description = 'Audit log cleared or policy changed' }
        @{ ID = 'CM-1'; Name = 'Configuration Management'; Pattern = 'action:.*config|EventID:4657'; Description = 'Config changes and registry modifications' }
        @{ ID = 'IA-1'; Name = 'Authentication'; Pattern = 'EventID:(4771|4776)|subtype:auth'; Description = 'Kerberos and NTLM authentication' }
        @{ ID = 'SC-1'; Name = 'Network Protection'; Pattern = 'action:(deny|block)|subtype:ips'; Description = 'Network deny/block actions and IPS' }
        @{ ID = 'IR-1'; Name = 'Incident Response'; Pattern = 'severity:(Critical|High)'; Description = 'Critical and high severity events' }
    )

    $controlData = @()
    foreach ($ctrl in $controls) {
        $matchCount = 0
        foreach ($e in $Events) {
            $matched = $false
            if ($ctrl.Pattern -match 'EventID:\(([^)]+)\)') {
                $ids = $Matches[1] -split '\|'
                if ($e.Extra['EventID'] -and $e.Extra['EventID'] -in $ids) { $matched = $true }
            }
            if ($ctrl.Pattern -match 'action:.*?(\w+)') {
                if ($e.Extra['action'] -match $Matches[1]) { $matched = $true }
            }
            if ($ctrl.Pattern -match 'subtype:(\w+)') {
                if ($e.Extra['subtype'] -eq $Matches[1]) { $matched = $true }
            }
            if ($ctrl.Pattern -match 'severity:\(([^)]+)\)') {
                $sevs = $Matches[1] -split '\|'
                if ($e.Severity -in $sevs) { $matched = $true }
            }
            if ($matched) { $matchCount++ }
        }
        $coverage = if ($matchCount -gt 10) { 'Sufficient' } elseif ($matchCount -gt 0) { 'Partial' } else { 'Insufficient' }
        $controlData += @{ ControlID = $ctrl.ID; Control = $ctrl.Name; Evidence = $matchCount; Coverage = $coverage; Description = $ctrl.Description }
    }
    $sections.Add((New-ReportSection 'FFIEC Control Mapping' 'Table' $controlData -Columns @('ControlID','Control','Evidence','Coverage','Description')))

    return New-ReportData 'Compliance Report' $sections
}

function New-TimelineReport {
    param([System.Collections.Generic.List[object]]$Events)
    $sections = [System.Collections.Generic.List[object]]::new()
    $sorted = @($Events | Where-Object { $null -ne $_ -and $_.Timestamp -ne [datetime]::MinValue } | Sort-Object Timestamp)
    $timelineData = @($sorted | Select-Object -First 200 | ForEach-Object {
        $msgText = if ($_.Message) { $_.Message } else { '' }
        @{
            Time = $_.Timestamp.ToString('yyyy-MM-dd HH:mm:ss')
            Severity = $_.Severity; Source = $_.Source
            Message = $msgText.Substring(0, [Math]::Min(80, $msgText.Length))
            SourceFile = $_.SourceFile
        }
    })
    $sections.Add((New-ReportSection 'Event Timeline' 'Table' $timelineData -Columns @('Time','Severity','Source','Message','SourceFile')))
    return New-ReportData 'Timeline Report' $sections
}

function ConvertTo-HtmlReport {
    param([PSCustomObject]$ReportData, [System.Collections.Generic.List[object]]$Events)
    if (-not $Events) { $Events = [System.Collections.Generic.List[object]]::new() }
    $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $sourceFiles = if ($Events.Count -gt 0) { ($Events | ForEach-Object { $_.SourceFile } | Sort-Object -Unique) -join ', ' } else { '' }
    $totalEvents = Format-Number $Events.Count
    $minTs = [datetime]::MaxValue; $maxTs = [datetime]::MinValue
    foreach ($e in $Events) {
        if ($e.Timestamp -ne [datetime]::MinValue) {
            if ($e.Timestamp -lt $minTs) { $minTs = $e.Timestamp }
            if ($e.Timestamp -gt $maxTs) { $maxTs = $e.Timestamp }
        }
    }
    $timeRange = if ($minTs -ne [datetime]::MaxValue) { "$($minTs.ToString('yyyy-MM-dd HH:mm')) - $($maxTs.ToString('yyyy-MM-dd HH:mm'))" } else { 'N/A' }

    $contentHtml = ''
    foreach ($sec in $ReportData.Sections) {
        $contentHtml += "<h2>$([System.Net.WebUtility]::HtmlEncode($sec.Heading))</h2>`n"
        switch ($sec.Type) {
            'KeyValue' {
                $contentHtml += "<div class='kv'>`n"
                foreach ($kv in $sec.Data.GetEnumerator()) {
                    $contentHtml += "<span class='kv-label'>$([System.Net.WebUtility]::HtmlEncode($kv.Key))</span><span>$([System.Net.WebUtility]::HtmlEncode([string]$kv.Value))</span>`n"
                }
                $contentHtml += "</div>`n"
            }
            'BarChart' {
                $maxVal = ($sec.Data | ForEach-Object { $_.Value } | Measure-Object -Maximum).Maximum
                if (-not $maxVal -or $maxVal -eq 0) { $maxVal = 1 }
                $contentHtml += "<table><tr><th>LABEL</th><th>COUNT</th><th>BAR</th></tr>`n"
                foreach ($item in $sec.Data) {
                    $barW = [Math]::Max(1, [int](($item.Value / $maxVal) * 200))
                    $sevClass = "sev-$($item.Label.ToLower())"
                    $contentHtml += "<tr><td class='$sevClass'>$($item.Label)</td><td>$(Format-Number $item.Value)</td><td><span class='stat-bar' style='width:${barW}px'></span></td></tr>`n"
                }
                $contentHtml += "</table>`n"
            }
            'Table' {
                if ($sec.Data.Count -eq 0) { $contentHtml += "<p>No data.</p>`n"; continue }
                $cols = if ($sec.Columns.Count -gt 0) { $sec.Columns } else { @($sec.Data[0].Keys) }
                $contentHtml += "<table><tr>"
                foreach ($col in $cols) { $contentHtml += "<th>$([System.Net.WebUtility]::HtmlEncode($col))</th>" }
                $contentHtml += "</tr>`n"
                foreach ($row in $sec.Data) {
                    $contentHtml += '<tr>'
                    foreach ($col in $cols) {
                        $val = if ($row.ContainsKey($col)) { [string]$row[$col] } else { '' }
                        $class = ''
                        if ($col -eq 'Severity' -or $col -eq 'Status') {
                            $class = switch ($val) { 'Critical' { 'sev-critical' } 'High' { 'sev-high' } 'Medium' { 'sev-medium' } 'Low' { 'sev-low' }
                                'Up' { 'status-up' } 'Down' { 'status-down' } default { '' } }
                        }
                        $contentHtml += "<td$(if($class){" class='$class'"})>$([System.Net.WebUtility]::HtmlEncode($val))</td>"
                    }
                    $contentHtml += "</tr>`n"
                }
                $contentHtml += "</table>`n"
            }
            'Text' { $contentHtml += "<div class='code'>$([System.Net.WebUtility]::HtmlEncode([string]$sec.Data))</div>`n" }
        }
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>$([System.Net.WebUtility]::HtmlEncode($ReportData.Title))</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Cascadia Mono','Consolas','Courier New',monospace;font-size:11px;line-height:1.5;color:#111;background:#fff;max-width:1100px;margin:0 auto;padding:24px}
h1{font-size:15px;letter-spacing:.5px;text-transform:uppercase;border-bottom:2px solid #111;padding-bottom:6px;margin-bottom:16px}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.3px;background:#eee;border-left:4px solid #333;padding:5px 10px;margin:24px 0 10px 0}
h3{font-size:11px;font-weight:bold;margin:14px 0 6px 0;padding-bottom:2px;border-bottom:1px solid #ccc}
p{margin:6px 0}
table{border-collapse:collapse;width:100%;margin:8px 0 16px 0;font-size:10px}
th,td{border:1px solid #aaa;padding:3px 8px;text-align:left;vertical-align:top}
th{background:#e0e0e0;font-weight:bold;text-transform:uppercase;font-size:9px;letter-spacing:.3px}
tr:nth-child(even){background:#f7f7f7}
.sev-critical{color:#b00;font-weight:bold}.sev-high{color:#b00}.sev-medium{color:#a06000}.sev-low{color:#006}.sev-info{color:#444}
.stat-bar{display:inline-block;height:10px;background:#333;vertical-align:middle}
.status-up{color:#060;font-weight:bold}.status-down{color:#b00;font-weight:bold}.status-warn{color:#a06000;font-weight:bold}
.code{background:#f5f5f5;border:1px solid #ccc;padding:8px 10px;overflow-x:auto;white-space:pre;font-size:10px;margin:6px 0}
.kv{display:grid;grid-template-columns:140px 1fr;gap:2px 12px;margin:6px 0}
.kv-label{font-weight:bold;color:#444}
.footer{margin-top:36px;padding-top:8px;border-top:1px solid #aaa;font-size:9px;color:#888}
.diff-add{color:#060;background:#e6ffe6}.diff-del{color:#b00;background:#ffe6e6}
@media print{body{font-size:9px;padding:12px;max-width:none}h1{font-size:13px}h2{font-size:10px;background:#ddd!important;print-color-adjust:exact}table{font-size:8px}th{background:#ddd!important;print-color-adjust:exact}tr:nth-child(even){background:#f0f0f0!important;print-color-adjust:exact}.footer{font-size:7px}}
</style>
</head>
<body>
<h1>$([System.Net.WebUtility]::HtmlEncode($ReportData.Title))</h1>
<div class="kv">
<span class="kv-label">Generated</span><span>$ts</span>
<span class="kv-label">Source Files</span><span>$([System.Net.WebUtility]::HtmlEncode($sourceFiles))</span>
<span class="kv-label">Total Events</span><span>$totalEvents</span>
<span class="kv-label">Time Range</span><span>$timeRange</span>
</div>
$contentHtml
<div class="footer">Invoke-LogParser v$($script:Version) | $ts</div>
</body>
</html>
"@
    return $html
}

function Render-ReportToConsole {
    param([PSCustomObject]$ReportData)
    $c = $script:C; $hLine = [string][char]0x2500
    Write-ColorText "$($hLine * 3) $($ReportData.Title) $($hLine * 40)" $c.BoldWhite
    foreach ($sec in $ReportData.Sections) {
        Write-Host ''
        Write-ColorText "$($hLine * 3) $($sec.Heading) $($hLine * 40)" $c.BoldWhite
        switch ($sec.Type) {
            'KeyValue' { foreach ($kv in $sec.Data.GetEnumerator()) { Write-Host "  $($kv.Key.PadRight(16)) : $($kv.Value)" } }
            'BarChart' {
                $maxVal = ($sec.Data | ForEach-Object { $_.Value } | Measure-Object -Maximum).Maximum
                if (-not $maxVal -or $maxVal -eq 0) { $maxVal = 1 }
                $barWidth = [Math]::Max(10, (Get-TerminalWidth) - 40)
                foreach ($item in $sec.Data) {
                    $bw = [Math]::Max(0, [int](($item.Value / $maxVal) * $barWidth))
                    $bar = [string][char]0x2588 * $bw
                    $sevC = if ($script:SevColor.ContainsKey($item.Label)) { $script:SevColor[$item.Label] } else { '' }
                    Write-Host "  $sevC$($item.Label.ToUpper().PadRight(10))$($c.Reset) $($c.Cyan)$bar$($c.Reset)  $(Format-Number $item.Value)"
                }
            }
            'Table' {
                if ($sec.Data.Count -eq 0) { Write-Host '  (no data)'; continue }
                $cols = if ($sec.Columns.Count -gt 0) { $sec.Columns } else { @($sec.Data[0].Keys) }
                $widths = @{}; foreach ($col in $cols) { $widths[$col] = $col.Length + 2 }
                foreach ($row in $sec.Data) {
                    foreach ($col in $cols) {
                        $val = if ($row.ContainsKey($col)) { ([string]$row[$col]).Length } else { 0 }
                        if ($val + 2 -gt $widths[$col]) { $widths[$col] = [Math]::Min($val + 2, 40) }
                    }
                }
                $hdr = '  '; foreach ($col in $cols) { $hdr += (Format-Truncate $col $widths[$col]) + '  ' }
                Write-ColorText $hdr $c.BoldWhite
                Write-ColorText "  $($hLine * 80)" $c.Dim
                foreach ($row in $sec.Data) {
                    $line = '  '
                    foreach ($col in $cols) {
                        $val = if ($row.ContainsKey($col)) { [string]$row[$col] } else { '' }
                        $line += (Format-Truncate $val $widths[$col]) + '  '
                    }
                    Write-Host $line
                }
            }
            'Text' { Write-Host "  $($sec.Data)" }
        }
    }
}

function Export-Report {
    param(
        [string]$Path,
        [string]$Format,
        [PSCustomObject]$ReportData,
        [System.Collections.Generic.List[object]]$Events
    )
    switch ($Format) {
        'Html' {
            $html = ConvertTo-HtmlReport -ReportData $ReportData -Events $Events
            [System.IO.File]::WriteAllText($Path, $html)
        }
        'Csv' {
            $csv = Format-LogCsv -Events $Events
            [System.IO.File]::WriteAllLines($Path, @($csv))
        }
        'Json' {
            $json = Format-LogJson -Events $Events
            [System.IO.File]::WriteAllLines($Path, @($json))
        }
    }
    if (-not $script:QuietFlag) { Write-ColorText "Exported to $Path" $script:C.Green }
}

# ============================================================================
# SECTION 9: Interactive Mode (REPL)
# ============================================================================


# --- A1: Command Registry ---
$script:ILPCommands = [ordered]@{}
function Register-ILPCommand {
    param([string]$Name, [string]$Pattern, [string]$Category, [string]$Usage, [string]$Help, [scriptblock]$Handler)
    $script:ILPCommands[$Name] = [PSCustomObject]@{ Name = $Name; Pattern = $Pattern; Category = $Category; Usage = $Usage; Help = $Help; Handler = $Handler }
}

# --- A3: Event Field Index ---
function Update-FieldIndex {
    param([PSCustomObject]$Session, [string[]]$Fields)
    $total = $Session.AllEvents.Count
    foreach ($field in $Fields) {
        $idx = @{}
        for ($i = 0; $i -lt $total; $i++) {
            $val = Get-EventFieldValue -Event $Session.AllEvents[$i] -Field $field
            if ($val) { $vs = "$val"; if (-not $idx.ContainsKey($vs)) { $idx[$vs] = [System.Collections.Generic.List[int]]::new() }; $idx[$vs].Add($i) }
            if ($i % 50000 -eq 0 -and $total -gt 10000) { Write-ILPProgress "Indexing $field" $i $total }
        }
        $Session.FieldIndex[$field] = $idx
    }
}

# --- A4: Config Loading ---
function Import-ILPConfig {
    $config = @{ maxUndoDepth = 50; pageSize = 0; journalAutoLog = $true; autoIndex = @('srcip','dstip','user','action','severity') }
    foreach ($dir in @($PSScriptRoot, $HOME, (Get-Location).Path)) {
        if (-not $dir) { continue }
        $p = Join-Path $dir '.ilp-config.json'
        if (Test-Path $p) {
            try { $loaded = Get-Content $p -Raw | ConvertFrom-Json; foreach ($prop in $loaded.PSObject.Properties) { $config[$prop.Name] = $prop.Value } } catch {}
            break
        }
    }
    return $config
}

# --- 1d: Progress Indicator ---
function Write-ILPProgress {
    param([string]$Label, [int]$Current, [int]$Total)
    if ($Total -le 0) { return }
    $pct = [Math]::Min(100, [int](($Current / $Total) * 100))
    $filled = [int]($pct / 5); $empty = 20 - $filled
    $bar = ([string][char]0x2588 * $filled) + ([string][char]0x2591 * $empty)
    Write-Host "`r  [$bar] $pct% - $Label" -NoNewline
    if ($Current -ge $Total) { Write-Host '' }
}

# --- 1c: Fuzzy Match ---
function Get-LevenshteinDistance {
    param([string]$s, [string]$t)
    $n = $s.Length; $m = $t.Length
    if ($n -eq 0) { return $m }; if ($m -eq 0) { return $n }
    $d = New-Object 'int[,]' ($n+1),($m+1)
    for ($i = 0; $i -le $n; $i++) { $d[$i,0] = $i }
    for ($j = 0; $j -le $m; $j++) { $d[0,$j] = $j }
    for ($i = 1; $i -le $n; $i++) { for ($j = 1; $j -le $m; $j++) {
        $cost = if ($s[$i-1] -eq $t[$j-1]) { 0 } else { 1 }
        $d[$i,$j] = [Math]::Min([Math]::Min($d[($i-1),$j]+1, $d[$i,($j-1)]+1), $d[($i-1),($j-1)]+$cost)
    }}
    return $d[$n,$m]
}

# --- Duration Parser ---
function ConvertTo-TimeSpanFromDuration {
    param([string]$Dur)
    if ($Dur -match '^(\d+)([smhd])$') {
        $v = [int]$Matches[1]
        switch ($Matches[2]) { 's' { [timespan]::FromSeconds($v) } 'm' { [timespan]::FromMinutes($v) } 'h' { [timespan]::FromHours($v) } 'd' { [timespan]::FromDays($v) } }
    } else { $null }
}

# --- Kerberos Encryption Types ---
$script:KerberosEtypeLookup = @{
    '0x1'='DES-CBC-CRC'; '0x3'='DES-CBC-MD5'; '0x11'='AES128-CTS-HMAC-SHA1-96'
    '0x12'='AES256-CTS-HMAC-SHA1-96'; '0x17'='RC4-HMAC-MD5'; '0x18'='RC4-HMAC-MD5-EXP'
}

# ============================================================================
# Command Registrations
# ============================================================================

# --- INSPECTION ---
Register-ILPCommand -Name 'show' -Pattern '^show\s+(\d+)$' -Category 'Inspection' -Usage 'show <N>' `
    -Help "Display all fields for event #N.`nExample: show 1" -Handler {
    param($s,$m); $c = $script:C; $idx = [int]$m[1] - 1
    if ($idx -lt 0 -or $idx -ge $s.FilteredEvents.Count) { Write-Host "Event index out of range (1-$($s.FilteredEvents.Count))"; return }
    $ev = $s.FilteredEvents[$idx]; $hl = [string][char]0x2500
    Write-ColorText "$($hl*3) Event #$($m[1]) $($hl*40)" $c.BoldWhite
    $flds = [ordered]@{}
    $flds['Timestamp'] = if ($ev.Timestamp -ne [datetime]::MinValue) { $ev.Timestamp.ToString('yyyy-MM-dd HH:mm:ss.fff') } else { '(none)' }
    $flds['Severity'] = $ev.Severity; $flds['Source'] = $ev.Source; $flds['Message'] = $ev.Message
    foreach ($k in ($ev.Extra.Keys | Sort-Object)) { $flds[$k] = $ev.Extra[$k] }
    $flds['SourceFile'] = $ev.SourceFile; $flds['SourceFormat'] = $ev.SourceFormat
    if ($ev.LineNumber -gt 0) { $flds['LineNumber'] = $ev.LineNumber }
    $ml = ($flds.Keys | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
    foreach ($k in $flds.Keys) {
        $val = "$($flds[$k])"; if ($s.Highlight) { $val = Add-Highlight $val $s.Highlight }
        $sc = if ($k -eq 'Severity' -and $script:SevColor.ContainsKey("$($flds[$k])")) { $script:SevColor["$($flds[$k])"] } else { '' }
        $wm = ''; if ($s.Watchlist.Count -gt 0 -and $s.Watchlist.ContainsKey($k)) { foreach ($wv in $s.Watchlist[$k]) { if ("$($flds[$k])" -eq $wv) { $wm = " $($c.BgRed)!WATCH$($c.Reset)" } } }
        Write-Host "  $($c.Cyan)$($k.PadRight($ml))$($c.Reset)  $sc$val$($c.Reset)$wm"
    }
    if ($ev.RawLine) { Write-Host ''; Write-ColorText "  $($hl*3) Raw $($hl*48)" $c.Dim; $rd = if ($s.Highlight) { Add-Highlight $ev.RawLine $s.Highlight } else { $ev.RawLine }; Write-Host "  $rd" }
    Write-ColorText "$($hl*55)" $c.Dim
}

Register-ILPCommand -Name 'raw' -Pattern '^raw\s+(\d+)$' -Category 'Inspection' -Usage 'raw <N>' `
    -Help "Display raw log line for event #N." -Handler {
    param($s,$m); $idx = [int]$m[1] - 1
    if ($idx -lt 0 -or $idx -ge $s.FilteredEvents.Count) { Write-Host "Event index out of range (1-$($s.FilteredEvents.Count))"; return }
    $rl = $s.FilteredEvents[$idx].RawLine; if (-not $rl) { Write-Host '(no raw line available)'; return }
    if ($s.Highlight) { $rl = Add-Highlight $rl $s.Highlight }; Write-Host $rl
}

Register-ILPCommand -Name 'context' -Pattern '^context\s+(\d+)(\s+(\d+))?$' -Category 'Inspection' -Usage 'context <N> [lines]' `
    -Help "Show surrounding raw lines from source file. Default: 3 lines." -Handler {
    param($s,$m); $idx = [int]$m[1] - 1; $cl = if ($m[3]) { [int]$m[3] } else { 3 }
    if ($idx -lt 0 -or $idx -ge $s.FilteredEvents.Count) { Write-Host "Event index out of range (1-$($s.FilteredEvents.Count))"; return }
    $ev = $s.FilteredEvents[$idx]; $sf = $ev.SourceFile
    if (-not $sf -or -not $ev.LineNumber) { Write-Host 'No source file or line number.'; return }
    if (-not $script:RawFileLines.ContainsKey($sf)) { try { $script:RawFileLines[$sf] = [System.IO.File]::ReadAllLines($sf) } catch { Write-Host "Could not read: $_"; return } }
    Write-ContextBlock -Event $ev -ContextLines $cl -AllRawLines $script:RawFileLines[$sf]
}

Register-ILPCommand -Name 'page' -Pattern '^(next|prev)$' -Category 'Inspection' -Usage 'next / prev' `
    -Help "Page through results. Auto-detects terminal height." -Handler {
    param($s,$m); $dir = $m[1]; if ($s.FilteredEvents.Count -eq 0) { Write-Host 'No events.'; return }
    $ps = if ($s.Config.pageSize -gt 0) { $s.Config.pageSize } else { try { [Math]::Max(5, [console]::WindowHeight - 5) } catch { 20 } }
    $mp = [Math]::Max(0, [Math]::Ceiling($s.FilteredEvents.Count / $ps) - 1)
    if ($dir -eq 'next') { $s.PageIndex = [Math]::Min($s.PageIndex + 1, $mp) } else { $s.PageIndex = [Math]::Max($s.PageIndex - 1, 0) }
    $si = $s.PageIndex * $ps; $ei = [Math]::Min($si + $ps, $s.FilteredEvents.Count)
    Write-Host "$($script:C.Dim)Events $($si+1)-$ei of $($s.FilteredEvents.Count)$($script:C.Reset)"
    $pe = [System.Collections.Generic.List[object]]::new(); for ($i = $si; $i -lt $ei; $i++) { $pe.Add($s.FilteredEvents[$i]) }
    switch ($s.OutputFormat) {
        'Table' { Format-LogTable -Events $pe -HighlightPattern $s.Highlight -FieldList $s.DisplayColumns -Max $ps }
        'List'  { Format-LogList -Events $pe -HighlightPattern $s.Highlight -Max $ps }
        default { Format-LogGrid -Events $pe -HighlightPattern $s.Highlight -FieldList $s.DisplayColumns -Max $ps }
    }
}

Register-ILPCommand -Name 'goto' -Pattern '^goto\s+(\d+)$' -Category 'Inspection' -Usage 'goto <N>' `
    -Help "Jump to page containing event #N." -Handler {
    param($s,$m); $tn = [int]$m[1]; if ($s.FilteredEvents.Count -eq 0) { Write-Host 'No events.'; return }
    if ($tn -lt 1 -or $tn -gt $s.FilteredEvents.Count) { Write-Host "Out of range (1-$($s.FilteredEvents.Count))"; return }
    $ps = if ($s.Config.pageSize -gt 0) { $s.Config.pageSize } else { try { [Math]::Max(5, [console]::WindowHeight - 5) } catch { 20 } }
    $s.PageIndex = [Math]::Floor(($tn - 1) / $ps)
    $si = $s.PageIndex * $ps; $ei = [Math]::Min($si + $ps, $s.FilteredEvents.Count)
    Write-Host "$($script:C.Dim)Events $($si+1)-$ei of $($s.FilteredEvents.Count)$($script:C.Reset)"
    $pe = [System.Collections.Generic.List[object]]::new(); for ($i = $si; $i -lt $ei; $i++) { $pe.Add($s.FilteredEvents[$i]) }
    switch ($s.OutputFormat) {
        'Table' { Format-LogTable -Events $pe -HighlightPattern $s.Highlight -FieldList $s.DisplayColumns -Max $ps }
        'List'  { Format-LogList -Events $pe -HighlightPattern $s.Highlight -Max $ps }
        default { Format-LogGrid -Events $pe -HighlightPattern $s.Highlight -FieldList $s.DisplayColumns -Max $ps }
    }
}

Register-ILPCommand -Name 'diff' -Pattern '^diff\s+(\d+)\s+(\d+)$' -Category 'Inspection' -Usage 'diff <N> <M>' `
    -Help "Compare two events side-by-side, showing differing fields." -Handler {
    param($s,$m); $c = $script:C; $i1 = [int]$m[1]-1; $i2 = [int]$m[2]-1
    if ($i1 -lt 0 -or $i1 -ge $s.FilteredEvents.Count -or $i2 -lt 0 -or $i2 -ge $s.FilteredEvents.Count) { Write-Host "Out of range (1-$($s.FilteredEvents.Count))"; return }
    $e1 = $s.FilteredEvents[$i1]; $e2 = $s.FilteredEvents[$i2]; $ak = [ordered]@{}
    foreach ($k in @('Timestamp','Severity','Source','Message')) { $ak[$k] = $true }
    foreach ($k in $e1.Extra.Keys) { $ak[$k] = $true }; foreach ($k in $e2.Extra.Keys) { $ak[$k] = $true }
    Write-ColorText "$([string][char]0x2500*3) Diff: #$($m[1]) vs #$($m[2]) $([string][char]0x2500*30)" $c.BoldWhite
    Write-Host "  $($c.Dim)$('FIELD'.PadRight(18))  $('#'+$m[1]+' VALUE').PadRight(30)  $('#'+$m[2]+' VALUE')$($c.Reset)"
    foreach ($k in $ak.Keys) {
        $v1 = if ($e1.PSObject.Properties[$k]) { "$($e1.$k)" } elseif ($e1.Extra.ContainsKey($k)) { "$($e1.Extra[$k])" } else { '(absent)' }
        $v2 = if ($e2.PSObject.Properties[$k]) { "$($e2.$k)" } elseif ($e2.Extra.ContainsKey($k)) { "$($e2.Extra[$k])" } else { '(absent)' }
        if ($v1 -ne $v2) { $l = if ($k.Length -gt 18) { $k.Substring(0,15)+'...' } else { $k }; $d1 = if ($v1.Length -gt 30) { $v1.Substring(0,27)+'...' } else { $v1 }; $d2 = if ($v2.Length -gt 30) { $v2.Substring(0,27)+'...' } else { $v2 }
            Write-Host "  $($c.Yellow)$($l.PadRight(18))$($c.Reset)  $($c.Red)$($d1.PadRight(30))$($c.Reset)  $($c.Green)$d2$($c.Reset)" }
    }
}

# --- INVESTIGATION ---
Register-ILPCommand -Name 'whois' -Pattern '^(whois|inspect)\s+([\w-]+)$' -Category 'Investigation' -Usage 'whois <field>' `
    -Help "Field value summary with bar chart (top 20). Alias: inspect" -Handler {
    param($s,$m); $c = $script:C; $field = $m[2]; $vc = @{}
    foreach ($ev in $s.FilteredEvents) { $val = Get-EventFieldValue -Event $ev -Field $field; if ($null -ne $val) { $vs = "$val"; if (-not $vc.ContainsKey($vs)) { $vc[$vs] = 0 }; $vc[$vs]++ } }
    if ($vc.Count -eq 0) { Write-Host "No values for '$field'"; return }
    $sorted = $vc.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 20
    $mx = ($sorted | Select-Object -First 1).Value; if ($mx -eq 0) { $mx = 1 }
    $bw = [Math]::Max(10, (Get-TerminalWidth) - 45); $mkl = [Math]::Min(20, ($sorted | ForEach-Object { $_.Key.Length } | Measure-Object -Maximum).Maximum)
    Write-ColorText "$([string][char]0x2500*3) $field ($($vc.Count) unique) $([string][char]0x2500*30)" $c.BoldWhite
    foreach ($e in $sorted) { $b = [string][char]0x2588 * [Math]::Max(0, [int](($e.Value/$mx)*$bw)); $lb = if ($e.Key.Length -gt 20) { $e.Key.Substring(0,17)+'...' } else { $e.Key }
        $wm = ''; if ($s.Watchlist.ContainsKey($field) -and $s.Watchlist[$field] -contains $e.Key) { $wm = " $($c.BgRed)!$($c.Reset)" }
        Write-Host "  $($lb.PadRight($mkl))  $($c.Cyan)$b$($c.Reset)  $(Format-Number $e.Value)$wm" }
}

Register-ILPCommand -Name 'timeline' -Pattern '^timeline(\s+--severity)?$' -Category 'Investigation' -Usage 'timeline [--severity]' `
    -Help "ASCII histogram of events over time. --severity adds color-coded severity." -Handler {
    param($s,$m); $c = $script:C; $showSev = [bool]$m[1]
    $wt = $s.FilteredEvents | Where-Object { $_.Timestamp -ne [datetime]::MinValue }
    if (-not $wt -or @($wt).Count -eq 0) { Write-Host 'No timestamped events.'; return }
    $minTs = ($wt | ForEach-Object { $_.Timestamp } | Measure-Object -Minimum).Minimum
    $maxTs = ($wt | ForEach-Object { $_.Timestamp } | Measure-Object -Maximum).Maximum
    $span = $maxTs - $minTs
    if ($span.TotalHours -lt 2) { $bm = 5; $fmt = 'HH:mm' } elseif ($span.TotalHours -lt 48) { $bm = 60; $fmt = 'MM-dd HH:mm' } else { $bm = 1440; $fmt = 'yyyy-MM-dd' }
    $bks = [ordered]@{}; $bkSev = @{}
    $cur = if ($bm -ge 1440) { $minTs.Date } else { $minTs.AddMinutes(-($minTs.Minute % $bm)).AddSeconds(-$minTs.Second) }
    while ($cur -le $maxTs) { $bks[$cur] = 0; $bkSev[$cur] = 0; $cur = $cur.AddMinutes($bm) }
    foreach ($ev in $wt) { $bk = if ($bm -ge 1440) { $ev.Timestamp.Date } else { $ev.Timestamp.AddMinutes(-($ev.Timestamp.Minute % $bm)).AddSeconds(-$ev.Timestamp.Second) }
        if ($bks.Contains($bk)) { $bks[$bk]++ } else { $bks[$bk] = 1 }
        if ($ev.Severity -in @('Critical','High')) { if ($bkSev.ContainsKey($bk)) { $bkSev[$bk]++ } else { $bkSev[$bk] = 1 } } }
    $mx = ($bks.Values | Measure-Object -Maximum).Maximum; if ($mx -eq 0) { $mx = 1 }
    $bw = [Math]::Max(10, (Get-TerminalWidth) - 30)
    Write-ColorText "$([string][char]0x2500*3) Timeline $([string][char]0x2500*44)" $c.BoldWhite
    foreach ($bk in $bks.Keys) { $cnt = $bks[$bk]; $w = [Math]::Max(0, [int](($cnt/$mx)*$bw)); $bar = [string][char]0x2588 * $w
        $bc = if ($showSev -and $cnt -gt 0 -and ($bkSev[$bk]/$cnt) -gt 0.3) { $c.Red } else { $c.Cyan }
        $suf = if ($showSev -and $cnt -gt 0) { "  (H:$($bkSev[$bk]))" } else { '' }
        Write-Host "  $($bk.ToString($fmt).PadRight(16))  $bc$bar$($c.Reset)  $cnt$suf" }
}

Register-ILPCommand -Name 'correlate' -Pattern '^correlate\s+([\w-]+)(\s+using\s+\$(\w+))?$' -Category 'Investigation' -Usage 'correlate <field> [using $var]' `
    -Help "Pivot: find ALL events sharing field values with current results.`nOptionally use stored variable values instead." -Handler {
    param($s,$m); $field = $m[1]; $varName = $m[3]
    $values = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($varName -and $s.Variables.ContainsKey($varName)) { foreach ($v in $s.Variables[$varName]) { $values.Add("$v") | Out-Null } }
    else { foreach ($ev in $s.FilteredEvents) { $val = Get-EventFieldValue -Event $ev -Field $field; if ($val) { $values.Add("$val") | Out-Null } } }
    if ($values.Count -eq 0) { Write-Host "No values for '$field'."; return }
    $s.FilterHistory.Add(@{ Filter = $s.ActiveFilter; Events = $s.FilteredEvents })
    $cor = [System.Collections.Generic.List[object]]::new()
    if ($s.FieldIndex.ContainsKey($field)) { foreach ($v in $values) { if ($s.FieldIndex[$field].ContainsKey($v)) { foreach ($i in $s.FieldIndex[$field][$v]) { $cor.Add($s.AllEvents[$i]) } } } }
    else { foreach ($ev in $s.AllEvents) { $val = Get-EventFieldValue -Event $ev -Field $field; if ($val -and $values.Contains("$val")) { $cor.Add($ev) } } }
    $s.FilteredEvents = $cor; $s.ActiveFilter = "correlate:$field"; $s.PageIndex = 0
    Write-Host "Correlated on $($values.Count) unique $field values: $(Format-Number $s.FilteredEvents.Count) events"
    if ($s.FilteredEvents.Count -gt 0 -and $s.FilteredEvents.Count -le 50) { Format-LogGrid -Events $s.FilteredEvents -HighlightPattern $s.Highlight -FieldList $s.DisplayColumns -Max 50 }
}

Register-ILPCommand -Name 'search' -Pattern '^search\s+(.+)$' -Category 'Investigation' -Usage 'search <text>' `
    -Help "Free-text case-insensitive search across all fields." -Handler {
    param($s,$m); $st = $m[1]; $s.FilterHistory.Add(@{ Filter = $s.ActiveFilter; Events = $s.FilteredEvents })
    $found = [System.Collections.Generic.List[object]]::new()
    foreach ($ev in $s.FilteredEvents) { $hit = $false
        if ($ev.Severity -and $ev.Severity.IndexOf($st, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $hit = $true }
        if (-not $hit -and $ev.Source -and $ev.Source.IndexOf($st, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $hit = $true }
        if (-not $hit -and $ev.Message -and $ev.Message.IndexOf($st, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $hit = $true }
        if (-not $hit -and $ev.RawLine -and $ev.RawLine.IndexOf($st, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $hit = $true }
        if (-not $hit -and $ev.Extra) { foreach ($v in $ev.Extra.Values) { if ("$v".IndexOf($st, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $hit = $true; break } } }
        if ($hit) { $found.Add($ev) } }
    $s.FilteredEvents = $found; $s.ActiveFilter = "search:$st"; $s.PageIndex = 0
    Write-Host "$(Format-Number $s.FilteredEvents.Count) events matching '$st'"
    if ($s.FilteredEvents.Count -gt 0 -and $s.FilteredEvents.Count -le 50) { Format-LogGrid -Events $s.FilteredEvents -HighlightPattern $s.Highlight -FieldList $s.DisplayColumns -Max 50 }
}

Register-ILPCommand -Name 'exclude' -Pattern '^exclude\s+([\w-]+):(.+)$' -Category 'Investigation' -Usage 'exclude <field>:<value>' `
    -Help "Remove matching events. Supports wildcards.`nExample: exclude severity:Info" -Handler {
    param($s,$m); $ef = $m[1]; $ev2 = $m[2]; $s.FilterHistory.Add(@{ Filter = $s.ActiveFilter; Events = $s.FilteredEvents })
    $kept = [System.Collections.Generic.List[object]]::new()
    foreach ($ev in $s.FilteredEvents) { $fv = Get-EventFieldValue -Event $ev -Field $ef; if (-not $fv -or -not ([string]$fv -like $ev2)) { $kept.Add($ev) } }
    $s.FilteredEvents = $kept; $s.ActiveFilter = "exclude $ef`:$ev2"; $s.PageIndex = 0
    Write-Host "$(Format-Number $s.FilteredEvents.Count) events (excluded $ef=$ev2)"
    if ($s.FilteredEvents.Count -gt 0 -and $s.FilteredEvents.Count -le 50) { Format-LogGrid -Events $s.FilteredEvents -HighlightPattern $s.Highlight -FieldList $s.DisplayColumns -Max 50 }
}

Register-ILPCommand -Name 'unique' -Pattern '^unique\s+([\w-]+)$' -Category 'Investigation' -Usage 'unique <field>' `
    -Help "Deduplicate by field value, keeping first event per value." -Handler {
    param($s,$m); $uf = $m[1]; $s.FilterHistory.Add(@{ Filter = $s.ActiveFilter; Events = $s.FilteredEvents })
    $oc = $s.FilteredEvents.Count; $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $dd = [System.Collections.Generic.List[object]]::new()
    foreach ($ev in $s.FilteredEvents) { $val = Get-EventFieldValue -Event $ev -Field $uf; $k = if ($val) { "$val" } else { '(empty)' }; if ($seen.Add($k)) { $dd.Add($ev) } }
    $s.FilteredEvents = $dd; $s.ActiveFilter = "unique:$uf"; $s.PageIndex = 0
    Write-Host "$(Format-Number $dd.Count) unique $uf values (from $(Format-Number $oc) events)"
}

Register-ILPCommand -Name 'highlight' -Pattern '^highlight\s+(.+)$' -Category 'Investigation' -Usage 'highlight <pattern>' `
    -Help "Highlight matching text in yellow. Same pattern again clears." -Handler {
    param($s,$m); $p = $m[1]; if ($s.Highlight -eq $p) { $s.Highlight = ''; Write-Host 'Highlight cleared.' } else { $s.Highlight = $p; Write-Host "Highlighting: $($script:C.BgYellow)$($script:C.Bold)$p$($script:C.Reset)" }
}
Register-ILPCommand -Name 'unhighlight' -Pattern '^unhighlight$' -Category 'Investigation' -Usage 'unhighlight' -Help 'Clear highlight.' -Handler { param($s,$m); $s.Highlight = ''; Write-Host 'Highlight cleared.' }

Register-ILPCommand -Name 'follow' -Pattern '^follow\s+([\w-]+)\s+->\s+([\w-]+)(\s+(\d+))?$' -Category 'Investigation' -Usage 'follow <src> -> <dst> [hops]' `
    -Help "Multi-hop correlation for lateral movement tracing.`nDefault 2 hops, max 5." -Handler {
    param($s,$m); $c = $script:C; $sf = $m[1]; $df = $m[2]; $hops = if ($m[4]) { [Math]::Min([int]$m[4], 5) } else { 2 }
    $s.FilterHistory.Add(@{ Filter = $s.ActiveFilter; Events = $s.FilteredEvents })
    $allSeen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $allEvents = [System.Collections.Generic.List[object]]::new()
    $seedVals = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($ev in $s.FilteredEvents) { $v = Get-EventFieldValue -Event $ev -Field $sf; if ($v) { $seedVals.Add("$v") | Out-Null; $allSeen.Add("$v") | Out-Null }; $allEvents.Add($ev) }
    Write-ColorText "$([string][char]0x2500*3) Follow: $sf -> $df ($hops hops) $([string][char]0x2500*25)" $c.BoldWhite
    Write-Host "  Hop 0 (seed): $($seedVals.Count) $sf values from $(Format-Number $s.FilteredEvents.Count) events"
    $currentVals = $seedVals
    for ($h = 1; $h -le $hops; $h++) {
        $newVals = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase); $hopEvents = 0
        foreach ($ev in $s.AllEvents) { $dv = Get-EventFieldValue -Event $ev -Field $df
            if ($dv -and $currentVals.Contains("$dv")) { $allEvents.Add($ev); $hopEvents++
                $sv = Get-EventFieldValue -Event $ev -Field $sf; if ($sv -and $allSeen.Add("$sv")) { $newVals.Add("$sv") | Out-Null } } }
        Write-Host "  Hop $h`: $($newVals.Count) new $sf values, $(Format-Number $hopEvents) events"
        if ($newVals.Count -eq 0) { break }; $currentVals = $newVals }
    $s.FilteredEvents = $allEvents; $s.ActiveFilter = "follow:$sf->$df"; $s.PageIndex = 0
    Write-Host "  Total: $($allSeen.Count) unique endpoints, $(Format-Number $allEvents.Count) events"
}

# --- TIME-BASED ---
Register-ILPCommand -Name 'anchor' -Pattern '^anchor\s+(\d+)\s+(\d+[smhd])(\s+(before|after))?$' -Category 'Time' -Usage 'anchor <N> <duration> [before|after]' `
    -Help "Find events within duration of event #N's timestamp." -Handler {
    param($s,$m); $idx = [int]$m[1] - 1; $dur = ConvertTo-TimeSpanFromDuration $m[2]; $dir = $m[4]
    if ($idx -lt 0 -or $idx -ge $s.FilteredEvents.Count) { Write-Host "Out of range (1-$($s.FilteredEvents.Count))"; return }
    if (-not $dur) { Write-Host 'Invalid duration. Use: 30s, 5m, 2h, 1d'; return }
    $ts = $s.FilteredEvents[$idx].Timestamp; if ($ts -eq [datetime]::MinValue) { Write-Host 'Event has no timestamp.'; return }
    $s.FilterHistory.Add(@{ Filter = $s.ActiveFilter; Events = $s.FilteredEvents })
    $found = [System.Collections.Generic.List[object]]::new()
    foreach ($ev in $s.AllEvents) { if ($ev.Timestamp -eq [datetime]::MinValue) { continue }; $d = $ev.Timestamp - $ts
        $inRange = switch ($dir) { 'before' { $d.TotalSeconds -ge (-$dur.TotalSeconds) -and $d.TotalSeconds -le 0 } 'after' { $d.TotalSeconds -ge 0 -and $d.TotalSeconds -le $dur.TotalSeconds } default { [Math]::Abs($d.TotalSeconds) -le $dur.TotalSeconds } }
        if ($inRange) { $found.Add($ev) } }
    $s.FilteredEvents = $found; $s.ActiveFilter = "anchor:#$($m[1])+-$($m[2])"; $s.PageIndex = 0
    Write-Host "$(Format-Number $found.Count) events within $($m[2]) of event #$($m[1])"
}

Register-ILPCommand -Name 'between' -Pattern '^between\s+(.+?)\s+to\s+(.+)$' -Category 'Time' -Usage 'between <start> to <end>' `
    -Help "Filter to time window. Flexible formats: HH:mm, MM-dd HH:mm, yyyy-MM-dd HH:mm:ss" -Handler {
    param($s,$m); $fmts = @('yyyy-MM-dd HH:mm:ss','yyyy-MM-dd HH:mm','MM-dd HH:mm','HH:mm:ss','HH:mm')
    $startTs = $null; $endTs = $null
    foreach ($f in $fmts) { if ([datetime]::TryParseExact($m[1], $f, $null, 'None', [ref]$startTs)) { break } }
    foreach ($f in $fmts) { if ([datetime]::TryParseExact($m[2], $f, $null, 'None', [ref]$endTs)) { break } }
    if (-not $startTs -or -not $endTs) { Write-Host 'Could not parse timestamps. Use: HH:mm, MM-dd HH:mm, or yyyy-MM-dd HH:mm:ss'; return }
    if ($startTs.Year -eq 1) { $refDate = ($s.AllEvents | Where-Object { $_.Timestamp -ne [datetime]::MinValue } | Select-Object -First 1).Timestamp.Date; $startTs = $refDate.Add($startTs.TimeOfDay); $endTs = $refDate.Add($endTs.TimeOfDay) }
    $s.FilterHistory.Add(@{ Filter = $s.ActiveFilter; Events = $s.FilteredEvents })
    $found = [System.Collections.Generic.List[object]]::new()
    foreach ($ev in $s.AllEvents) { if ($ev.Timestamp -ge $startTs -and $ev.Timestamp -le $endTs) { $found.Add($ev) } }
    $s.FilteredEvents = $found; $s.ActiveFilter = "between:$($m[1])-$($m[2])"; $s.PageIndex = 0
    Write-Host "$(Format-Number $found.Count) events between $($startTs.ToString('yyyy-MM-dd HH:mm:ss')) and $($endTs.ToString('yyyy-MM-dd HH:mm:ss'))"
}

Register-ILPCommand -Name 'window' -Pattern '^(window|since)\s+(\d+[smhd])$' -Category 'Time' -Usage 'window <duration>' `
    -Help "Show events from the last N seconds/minutes/hours/days." -Handler {
    param($s,$m); $dur = ConvertTo-TimeSpanFromDuration $m[2]; if (-not $dur) { Write-Host 'Invalid duration.'; return }
    $maxTs = ($s.AllEvents | Where-Object { $_.Timestamp -ne [datetime]::MinValue } | ForEach-Object { $_.Timestamp } | Measure-Object -Maximum).Maximum
    if (-not $maxTs) { Write-Host 'No timestamped events.'; return }
    $cutoff = $maxTs - $dur; $s.FilterHistory.Add(@{ Filter = $s.ActiveFilter; Events = $s.FilteredEvents })
    $found = [System.Collections.Generic.List[object]]::new()
    foreach ($ev in $s.AllEvents) { if ($ev.Timestamp -ge $cutoff) { $found.Add($ev) } }
    $s.FilteredEvents = $found; $s.ActiveFilter = "window:$($m[2])"; $s.PageIndex = 0
    Write-Host "$(Format-Number $found.Count) events in last $($m[2])"
}

# --- ANALYSIS & DISPLAY ---
Register-ILPCommand -Name 'stats' -Pattern '^stats$' -Category 'Analysis' -Usage 'stats' -Help 'Full statistics for current events.' -Handler {
    param($s,$m); $stats = Get-LogStatistics $s.FilteredEvents; Write-LogStats -Stats $stats -SourceFiles $s.SourceFiles -Formats @()
}

Register-ILPCommand -Name 'top-talkers' -Pattern '^top-talkers$' -Category 'Analysis' -Usage 'top-talkers' -Help 'Quick summary of top IPs, sources, event IDs.' -Handler {
    param($s,$m); $c = $script:C; $stats = Get-LogStatistics $s.FilteredEvents; $bw = [Math]::Max(10, (Get-TerminalWidth) - 40); $hl = [string][char]0x2500
    foreach ($sec in @(@{T='Top Source IPs';D=$stats.TopSrcIPs}, @{T='Top Dest IPs';D=$stats.TopDstIPs}, @{T='Top Sources';D=$stats.TopSources}, @{T='Top Event IDs';D=$stats.TopEventIds})) {
        $items = @($sec.D) | Select-Object -First 5; if (-not $items -or $items.Count -eq 0) { continue }
        Write-ColorText "$($hl*3) $($sec.T) $($hl * (40 - $sec.T.Length))" $c.BoldWhite
        $mx = ($items | ForEach-Object { $_.Value } | Measure-Object -Maximum).Maximum; if ($mx -eq 0) { $mx = 1 }
        foreach ($it in $items) { $b = [string][char]0x2588 * [Math]::Max(0, [int](($it.Value/$mx)*$bw)); Write-Host "  $("$($it.Key)".PadRight(20))  $($c.Cyan)$b$($c.Reset)  $(Format-Number $it.Value)" }
        Write-Host '' }
}

Register-ILPCommand -Name 'severity' -Pattern '^severity$' -Category 'Analysis' -Usage 'severity' -Help 'Severity breakdown with bar chart.' -Handler {
    param($s,$m); $c = $script:C; $sc = @{Critical=0;High=0;Medium=0;Low=0;Info=0}
    foreach ($ev in $s.FilteredEvents) { if ($sc.ContainsKey($ev.Severity)) { $sc[$ev.Severity]++ } else { $sc['Info']++ } }
    $total = $s.FilteredEvents.Count; if ($total -eq 0) { $total = 1 }
    $mx = ($sc.Values | Measure-Object -Maximum).Maximum; if ($mx -eq 0) { $mx = 1 }; $bw = [Math]::Max(10, (Get-TerminalWidth) - 40)
    Write-ColorText "$([string][char]0x2500*3) Severity Breakdown $([string][char]0x2500*34)" $c.BoldWhite
    foreach ($sev in @('Critical','High','Medium','Low','Info')) { $cnt = $sc[$sev]; $pct = [Math]::Round(($cnt/$total)*100,1)
        $b = [string][char]0x2588 * [Math]::Max(0, [int](($cnt/$mx)*$bw)); $sevC = if ($script:SevColor.ContainsKey($sev)) { $script:SevColor[$sev] } else { '' }
        Write-Host "  $sevC$($sev.ToUpper().PadRight(10))$($c.Reset) $($c.Cyan)$b$($c.Reset)  $(Format-Number $cnt) ($pct%)" }
}

Register-ILPCommand -Name 'heatmap' -Pattern '^heatmap$' -Category 'Analysis' -Usage 'heatmap' -Help '24-hour event density grid. Red = high severity.' -Handler {
    param($s,$m); $c = $script:C; $wt = $s.FilteredEvents | Where-Object { $_.Timestamp -ne [datetime]::MinValue }
    if (-not $wt -or @($wt).Count -eq 0) { Write-Host 'No timestamped events.'; return }
    $hc = @{}; $hs = @{}; for ($h=0; $h -lt 24; $h++) { $hc[$h] = 0; $hs[$h] = 0 }
    foreach ($ev in $wt) { $h = $ev.Timestamp.Hour; $hc[$h]++; if ($ev.Severity -in @('Critical','High')) { $hs[$h]++ } }
    $mx = ($hc.Values | Measure-Object -Maximum).Maximum; if ($mx -eq 0) { $mx = 1 }; $bw = [Math]::Max(10, (Get-TerminalWidth) - 25)
    Write-ColorText "$([string][char]0x2500*3) 24-Hour Heatmap $([string][char]0x2500*37)" $c.BoldWhite
    for ($h=0; $h -lt 24; $h++) { $cnt = $hc[$h]; $w = [Math]::Max(0, [int](($cnt/$mx)*$bw)); $sp = if ($cnt -gt 0) { $hs[$h]/$cnt } else { 0 }
        $bc = if ($sp -gt 0.3) { $c.Red } else { $c.Cyan }; $bar = [string][char]0x2588 * $w
        Write-Host "  $($c.Dim)$('{0:D2}:00' -f $h)$($c.Reset)  $bc$bar$($c.Reset)  $cnt" }
}

Register-ILPCommand -Name 'map' -Pattern '^map\s+([\w-]+)\s+->\s+([\w-]+)(:([\w-]+))?$' -Category 'Analysis' -Usage 'map <src> -> <dst[:sub]>' `
    -Help "Connection map showing communication patterns.`nExample: map srcip -> dstip:dstport" -Handler {
    param($s,$m); $c = $script:C; $sf = $m[1]; $df = $m[2]; $sub = $m[4]
    $adj = [ordered]@{}
    foreach ($ev in $s.FilteredEvents) { $sv = Get-EventFieldValue -Event $ev -Field $sf; if (-not $sv) { continue }; $sv = "$sv"
        $dv = Get-EventFieldValue -Event $ev -Field $df; if (-not $dv) { continue }; $dv = "$dv"
        if ($sub) { $subv = Get-EventFieldValue -Event $ev -Field $sub; if ($subv) { $dv = "$dv`:$subv" } }
        if (-not $adj.Contains($sv)) { $adj[$sv] = @{} }; if (-not $adj[$sv].ContainsKey($dv)) { $adj[$sv][$dv] = 0 }; $adj[$sv][$dv]++ }
    $sorted = $adj.GetEnumerator() | Sort-Object { ($_.Value.Values | Measure-Object -Sum).Sum } -Descending | Select-Object -First 20
    Write-ColorText "$([string][char]0x2500*3) Map: $sf -> $df $([string][char]0x2500*35)" $c.BoldWhite
    foreach ($src in $sorted) { Write-Host "$($c.BoldWhite)$($src.Key)$($c.Reset)"
        $dests = $src.Value.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
        foreach ($d in $dests) { $wm = ''; if ($s.Watchlist.ContainsKey($df) -and $s.Watchlist[$df] -contains ($d.Key -split ':')[0]) { $wm = "  $($c.BgRed)! WATCH$($c.Reset)" }
            Write-Host "  -> $($d.Key.PadRight(25)) ($($d.Value))$wm" } }
}

Register-ILPCommand -Name 'analyze' -Pattern '^analyze\s+(.+)$' -Category 'Analysis' -Usage 'analyze <engine>' `
    -Help "Run analysis: failed-logins, vpn-sessions, ipsec-tunnel" -Handler {
    param($s,$m); $eng = $m[1].Trim(); $c = $script:C
    switch -Wildcard ($eng) {
        'failed*' { $r = Invoke-AnalyzeFailedLogins $s.FilteredEvents
            if ($r.Count -eq 0) { Write-Host 'No failed login events.'; return }
            Write-ColorText "$([string][char]0x2500*3) Failed Login Analysis $([string][char]0x2500*35)" $c.BoldWhite
            Write-Host "  $($c.BoldWhite)$('User'.PadRight(30)) $('Count'.PadRight(8)) $('IPs'.PadRight(6)) $('First'.PadRight(18)) $('Last'.PadRight(18)) Sources$($c.Reset)"
            foreach ($x in $r) { $cl = if ($x.Count -ge 10) { $c.Red } elseif ($x.Count -ge 5) { $c.Yellow } else { '' }
                $fs = if ($x.FirstSeen -ne [datetime]::MinValue) { $x.FirstSeen.ToString('yyyy-MM-dd HH:mm') } else { '' }
                $ls = if ($x.LastSeen -ne [datetime]::MinValue) { $x.LastSeen.ToString('yyyy-MM-dd HH:mm') } else { '' }
                Write-Host "  $cl$($x.User.PadRight(30)) $($x.Count.ToString().PadRight(8)) $($x.SourceIPs.Count.ToString().PadRight(6)) $($fs.PadRight(18)) $($ls.PadRight(18)) $($x.Sources -join ', ')$($c.Reset)" } }
        'vpn*' { $r = Invoke-AnalyzeVpnSessions $s.FilteredEvents; Write-ColorText "$([string][char]0x2500*3) VPN Session Analysis $([string][char]0x2500*35)" $c.BoldWhite
            foreach ($uk in $r.Sessions.Keys) { foreach ($x in $r.Sessions[$uk]) { $st = if ($x.StartTime -ne [datetime]::MinValue) { $x.StartTime.ToString('yyyy-MM-dd HH:mm') } else { '' }; $et = if ($x.EndTime) { $x.EndTime.ToString('yyyy-MM-dd HH:mm') } else { '(active)' }
                Write-Host "  $($x.User.PadRight(25)) $($st.PadRight(18)) $($et.PadRight(18)) $($x.RemoteIP)" } }
            if ($r.ImpossibleTravel.Count -gt 0) { Write-Host ''; Write-ColorText "  IMPOSSIBLE TRAVEL ($($r.ImpossibleTravel.Count)):" $c.Red
                foreach ($tf in $r.ImpossibleTravel) { Write-ColorText "    $($tf.User): $($tf.IP1) @ $($tf.Time1.ToString('HH:mm')) -> $($tf.IP2) @ $($tf.Time2.ToString('HH:mm')) ($($tf.MinutesBetween)m)" $c.Yellow } } }
        'ipsec*' { $r = Invoke-AnalyzeIpsecTunnel $s.FilteredEvents; Write-ColorText "$([string][char]0x2500*3) IPsec Tunnel Analysis $([string][char]0x2500*35)" $c.BoldWhite
            Write-Host "  Total: $($r.Summary.TotalTunnels) | Up: $($r.Summary.UpCount) | Down: $($r.Summary.DownCount) | Flaps: $($r.Summary.FlapCount)"
            foreach ($tn in $r.Tunnels.Keys) { $t = $r.Tunnels[$tn]; $cl = if ($t.Status -eq 'Down') { $c.Red } elseif ($t.FlapCount -gt 0) { $c.Yellow } else { $c.Green }
                Write-Host "  $cl$($t.TunnelName.PadRight(25)) $($t.Status.PadRight(8)) Flaps:$($t.FlapCount.ToString().PadRight(5)) $(if ($t.LastFailureReason) { $t.LastFailureReason } else { '-' })$($c.Reset)" } }
        default { Write-Host "Unknown: $eng. Use: failed-logins, vpn-sessions, ipsec-tunnel" } }
}

Register-ILPCommand -Name 'report' -Pattern '^report\s+(.+)$' -Category 'Analysis' -Usage 'report <type> [--export <path>]' `
    -Help "Generate report: summary, morning, audit, compliance, timeline" -Handler {
    param($s,$m); $ra = $m[1].Trim(); $ep = $null
    if ($ra -match '--export\s+(\S+)') { $ep = $Matches[1]; $ra = ($ra -replace '--export\s+\S+', '').Trim() }
    $rd = switch -Wildcard ($ra) { 'summary*' { New-SummaryReport $s.FilteredEvents } 'morning*' { New-MorningBriefing $s.FilteredEvents } 'audit*' { New-AuditReport $s.FilteredEvents } 'compliance*' { New-ComplianceReport $s.FilteredEvents } 'timeline*' { New-TimelineReport $s.FilteredEvents } default { Write-Host "Unknown report: $ra"; $null } }
    if ($rd) { Render-ReportToConsole $rd; if ($ep) { $fmt = if ($ep -match '\.csv$') { 'Csv' } elseif ($ep -match '\.json$') { 'Json' } else { 'Html' }; Export-Report -Path $ep -Format $fmt -ReportData $rd -Events $s.FilteredEvents } }
}

# --- ENRICHMENT ---
Register-ILPCommand -Name 'explain' -Pattern '^explain\s+(.+)$' -Category 'Enrichment' -Usage 'explain <value>' `
    -Help "Look up event IDs, NPS codes, FortiGate log IDs, Kerberos encryption types." -Handler {
    param($s,$m); $c = $script:C; $val = $m[1].Trim(); $found = $false
    # Hex -> Kerberos etype
    if ($val -match '^0x[\da-fA-F]+$') { if ($script:KerberosEtypeLookup.ContainsKey($val.ToLower())) { Write-Host "Kerberos Encryption Type $val`: $($script:KerberosEtypeLookup[$val.ToLower()])"; $found = $true
        if ($val -eq '0x17') { Write-ColorText "  Significance: Legacy RC4-HMAC. Consider AES migration." $c.Yellow } } }
    # Numeric -> Event ID, NPS code, FortiGate log range
    if ($val -match '^\d+$') { $num = [int]$val
        if ($script:EventIdLookup.ContainsKey($num)) { Write-Host "Windows Event ID $num`: $($script:EventIdLookup[$num])"; $found = $true
            if ($num -in @(4625,4771)) { Write-ColorText "  Significance: Brute force indicator when clustered." $c.Yellow } elseif ($num -in @(4720,4726)) { Write-ColorText "  Significance: Account lifecycle change - verify authorization." $c.Yellow } }
        if ($script:NpsReasonLookup.ContainsKey($num)) { Write-Host "NPS Reason Code $num`: $($script:NpsReasonLookup[$num])"; $found = $true }
        $prefix = $val.PadLeft(4, '0'); foreach ($k in $script:FortiGateLogIdRanges.Keys) { if ($prefix -like "$k*" -or $prefix -eq $k) { Write-Host "FortiGate Log Range $k`: $($script:FortiGateLogIdRanges[$k])"; $found = $true } } }
    # subtype lookup
    if ($val -match '/') { if ($script:FortiSubtypeLookup.ContainsKey($val)) { Write-Host "FortiGate Subtype $val`: $($script:FortiSubtypeLookup[$val])"; $found = $true } }
    # Broad search
    if (-not $found) { foreach ($k in $script:EventIdLookup.Keys) { if ($script:EventIdLookup[$k] -like "*$val*") { Write-Host "  Event $k`: $($script:EventIdLookup[$k])"; $found = $true } }
        foreach ($k in $script:NpsReasonLookup.Keys) { if ($script:NpsReasonLookup[$k] -like "*$val*") { Write-Host "  NPS $k`: $($script:NpsReasonLookup[$k])"; $found = $true } } }
    if (-not $found) { Write-Host "No match for '$val'" }
}

Register-ILPCommand -Name 'ioc' -Pattern '^ioc(\s+(.+))?$' -Category 'Enrichment' -Usage 'ioc import|match|export' `
    -Help "ioc import <path> -- Load IOCs from file`nioc match -- Scan events against loaded IOCs`nioc export <path> -- Export matches" -Handler {
    param($s,$m); $args2 = if ($m[2]) { $m[2].Trim() } else { '' }
    if ($args2 -match '^import\s+(.+)$') { $p = $Matches[1].Trim('"',"'"); if (-not (Test-Path $p)) { Write-Host "File not found: $p"; return }
        $lines = Get-Content $p | Where-Object { $_ -and $_.Trim() -and -not $_.StartsWith('#') }; $iocSet = @{}
        foreach ($l in $lines) { $parts = $l -split ',',2; $iocSet[$parts[0].Trim()] = if ($parts.Count -gt 1) { $parts[1].Trim() } else { 'unknown' } }
        $vn = "_ioc_$(Split-Path $p -Leaf)"; $s.Variables[$vn] = $iocSet; Write-Host "Loaded $($iocSet.Count) IOCs as `$$vn" }
    elseif ($args2 -eq 'match') { $allIocs = @{}; foreach ($vk in $s.Variables.Keys) { if ($vk -like '_ioc_*' -and $s.Variables[$vk] -is [hashtable]) { foreach ($ik in $s.Variables[$vk].Keys) { $allIocs[$ik] = $s.Variables[$vk][$ik] } } }
        if ($allIocs.Count -eq 0) { Write-Host 'No IOCs loaded. Use: ioc import <path>'; return }
        $s.FilterHistory.Add(@{ Filter = $s.ActiveFilter; Events = $s.FilteredEvents })
        $hits = [System.Collections.Generic.List[object]]::new(); $matched = @{}
        foreach ($ev in $s.FilteredEvents) { $rl = "$($ev.Severity) $($ev.Source) $($ev.Message) $($ev.RawLine)"
            foreach ($ioc in $allIocs.Keys) { if ($rl.IndexOf($ioc, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { $hits.Add($ev); $matched[$ioc] = ($matched[$ioc] ?? 0) + 1; break } } }
        $s.FilteredEvents = $hits; $s.ActiveFilter = 'ioc:match'; $s.PageIndex = 0
        Write-Host "$(Format-Number $hits.Count) events matched $($matched.Count)/$($allIocs.Count) IOCs"
        foreach ($mk in ($matched.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10)) { Write-Host "  $($mk.Key): $($mk.Value) hits" } }
    elseif ($args2 -match '^export\s+(.+)$') { $p = $Matches[1].Trim('"',"'"); $rd = New-SummaryReport $s.FilteredEvents; Export-Report -Path $p -Format 'Csv' -ReportData $rd -Events $s.FilteredEvents; Write-Host "Exported to $p" }
    else { Write-Host 'Usage: ioc import <path> | ioc match | ioc export <path>' }
}

Register-ILPCommand -Name 'policy' -Pattern '^policy\s+(\d+)$' -Category 'Enrichment' -Usage 'policy <id>' `
    -Help "Look up FortiGate policy by ID (requires loaded config)." -Handler {
    param($s,$m); $pid2 = $m[1]
    $policyEvents = $s.AllEvents | Where-Object { $_.Extra.ContainsKey('policyid') -and $_.Extra['policyid'] -eq $pid2 }
    if (@($policyEvents).Count -eq 0) { Write-Host "No events reference policy $pid2"; return }
    $sample = $policyEvents | Select-Object -First 1; $c = $script:C
    Write-ColorText "$([string][char]0x2500*3) Policy $pid2 $([string][char]0x2500*45)" $c.BoldWhite
    foreach ($k in @('srcintf','dstintf','srcip','dstip','service','action','logtraffic')) { $v = $sample.Extra[$k]; if ($v) { Write-Host "  $($k.PadRight(14)) $v" } }
    Write-Host "  Events       $(Format-Number @($policyEvents).Count)"
}

Register-ILPCommand -Name 'policy-stats' -Pattern '^policy-stats$' -Category 'Enrichment' -Usage 'policy-stats' `
    -Help "Group events by policy ID with counts." -Handler {
    param($s,$m); $c = $script:C; $pc = @{}
    foreach ($ev in $s.FilteredEvents) { $pid2 = $ev.Extra['policyid']; if ($pid2) { if (-not $pc.ContainsKey($pid2)) { $pc[$pid2] = 0 }; $pc[$pid2]++ } }
    if ($pc.Count -eq 0) { Write-Host 'No policyid field found in events.'; return }
    $sorted = $pc.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 15
    $mx = ($sorted | Select-Object -First 1).Value; $bw = [Math]::Max(10, (Get-TerminalWidth) - 35)
    Write-ColorText "$([string][char]0x2500*3) Policy Stats $([string][char]0x2500*40)" $c.BoldWhite
    foreach ($e in $sorted) { $b = [string][char]0x2588 * [Math]::Max(0, [int](($e.Value/$mx)*$bw)); Write-Host "  Policy $($e.Key.PadRight(8))  $($c.Cyan)$b$($c.Reset)  $(Format-Number $e.Value)" }
}

# --- DATA MANAGEMENT ---
Register-ILPCommand -Name 'load' -Pattern '^load\s+(.+)$' -Category 'Data' -Usage 'load <file>' -Help 'Load additional log file.' -Handler {
    param($s,$m); $lp = $m[1].Trim('"',"'"); if (-not (Test-Path $lp)) { Write-Host "File not found: $lp"; return }
    $fmt = Invoke-DetectLogFormat $lp; if (-not $fmt) { Write-Host "Unknown format: $lp"; return }
    $ne = Invoke-ParseLogFile -FilePath $lp -Format $fmt -SourceFile $lp
    if ($null -ne $ne) { Add-EventsToList $s.AllEvents $ne; $s.AllEvents = [System.Collections.Generic.List[object]]($s.AllEvents | Sort-Object Timestamp)
        $s.FilteredEvents = $s.AllEvents; $s.ActiveFilter = ''; $s.SourceFiles += $lp
        Write-Host "Loaded $(Format-Number $ne.Count) events from $lp ($fmt). Total: $(Format-Number $s.AllEvents.Count)" }
}

Register-ILPCommand -Name 'sources' -Pattern '^sources$' -Category 'Data' -Usage 'sources' -Help 'List loaded sources.' -Handler {
    param($s,$m); $g = @{}; foreach ($e in $s.AllEvents) { $sf = if ($e.SourceFile) { $e.SourceFile } else { '(unknown)' }; if (-not $g.ContainsKey($sf)) { $g[$sf] = @{Format=$e.SourceFormat;Count=0} }; $g[$sf].Count++ }
    $i = 1; foreach ($sf in $g.Keys) { Write-Host "  $i. $($sf.PadRight(25)) $($g[$sf].Format.PadRight(20)) $(Format-Number $g[$sf].Count) events"; $i++ }
}

Register-ILPCommand -Name 'fields' -Pattern '^fields$' -Category 'Data' -Usage 'fields' -Help 'List available fields.' -Handler {
    param($s,$m); $af = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    @('Timestamp','Severity','Source','Message','SourceFile','SourceFormat') | ForEach-Object { $af.Add($_) | Out-Null }
    foreach ($e in $s.AllEvents) { foreach ($k in $e.Extra.Keys) { $af.Add($k) | Out-Null } }
    Write-Host "Available fields: $($af -join ', ')"
}

Register-ILPCommand -Name 'export' -Pattern '^export\s+(\w+)\s+(.+)$' -Category 'Data' -Usage 'export <fmt> <path>' -Help 'Export events: csv, json, html' -Handler {
    param($s,$m); $fmt = $m[1]; $p = $m[2].Trim('"',"'")
    $ef = switch ($fmt.ToLower()) { 'csv' { 'Csv' } 'json' { 'Json' } 'html' { 'Html' } default { 'Csv' } }
    $rd = New-SummaryReport $s.FilteredEvents; Export-Report -Path $p -Format $ef -ReportData $rd -Events $s.FilteredEvents
}

Register-ILPCommand -Name 'clear' -Pattern '^clear$' -Category 'Data' -Usage 'clear' -Help 'Clear active filter.' -Handler {
    param($s,$m); $s.FilterHistory.Add(@{ Filter = $s.ActiveFilter; Events = $s.FilteredEvents })
    $s.FilteredEvents = $s.AllEvents; $s.ActiveFilter = ''; $s.PageIndex = 0; Write-Host 'Filter cleared.'
    if ($s.PinnedEvents.Count -gt 0) { Write-Host "$($script:C.Dim)($($s.PinnedEvents.Count) pinned events available)$($script:C.Reset)" }
}

Register-ILPCommand -Name 'undo' -Pattern '^undo$' -Category 'Data' -Usage 'undo' -Help 'Restore previous filter state.' -Handler {
    param($s,$m); if ($s.FilterHistory.Count -eq 0) { Write-Host 'Nothing to undo.'; return }
    $prev = $s.FilterHistory[$s.FilterHistory.Count - 1]; $s.FilterHistory.RemoveAt($s.FilterHistory.Count - 1)
    $s.FilteredEvents = $prev.Events; $s.ActiveFilter = $prev.Filter; $s.PageIndex = 0
    Write-Host "Restored. $(Format-Number $s.FilteredEvents.Count) events$(if ($s.ActiveFilter) { " ($($s.ActiveFilter))" })"
}

# --- SESSION ---
Register-ILPCommand -Name 'history' -Pattern '^history$' -Category 'Session' -Usage 'history' -Help 'Show last 30 commands. Use !N to re-run.' -Handler {
    param($s,$m); $c = $script:C; $cnt = [Math]::Min(30, $s.CommandHistory.Count); $st = $s.CommandHistory.Count - $cnt
    for ($i = $st; $i -lt $s.CommandHistory.Count; $i++) { Write-Host "  $($c.Dim)$($i+1).$($c.Reset) $($s.CommandHistory[$i])" }
}

Register-ILPCommand -Name 'alias-set' -Pattern '^alias\s+(\S+)\s+(.+)$' -Category 'Session' -Usage 'alias <name> <query>' -Help 'Create query alias.' -Handler {
    param($s,$m); $s.Aliases[$m[1]] = $m[2]; Write-Host "Alias '$($m[1])' -> '$($m[2])'"
}
Register-ILPCommand -Name 'alias-list' -Pattern '^alias$' -Category 'Session' -Usage 'alias' -Help 'List aliases.' -Handler {
    param($s,$m); $c = $script:C; if ($s.Aliases.Count -eq 0) { Write-Host 'No aliases.' } else { foreach ($a in $s.Aliases.GetEnumerator()) { Write-Host "  $($c.Cyan)$($a.Key)$($c.Reset) -> $($a.Value)" } }
}

Register-ILPCommand -Name 'pin' -Pattern '^pin$' -Category 'Session' -Usage 'pin' -Help 'Save current results as pinned.' -Handler {
    param($s,$m); $s.PinnedEvents = [System.Collections.Generic.List[object]]::new($s.FilteredEvents); Write-Host "Pinned $(Format-Number $s.PinnedEvents.Count) events."
}
Register-ILPCommand -Name 'unpin' -Pattern '^unpin$' -Category 'Session' -Usage 'unpin' -Help 'Clear pinned events.' -Handler { param($s,$m); $s.PinnedEvents = [System.Collections.Generic.List[object]]::new(); Write-Host 'Pins cleared.' }
Register-ILPCommand -Name 'pinned' -Pattern '^pinned$' -Category 'Session' -Usage 'pinned' -Help 'Switch to pinned events.' -Handler {
    param($s,$m); if ($s.PinnedEvents.Count -eq 0) { Write-Host 'No pinned events.'; return }
    $s.FilterHistory.Add(@{ Filter = $s.ActiveFilter; Events = $s.FilteredEvents })
    $s.FilteredEvents = [System.Collections.Generic.List[object]]::new($s.PinnedEvents); $s.ActiveFilter = 'pinned'; $s.PageIndex = 0
    Write-Host "Switched to $(Format-Number $s.PinnedEvents.Count) pinned events"
}

Register-ILPCommand -Name 'columns' -Pattern '^columns\s+(.+)$' -Category 'Session' -Usage 'columns <fields> | reset' -Help "Set display columns.`nExample: columns Timestamp,srcip,dstip,action,Message" -Handler {
    param($s,$m); $arg = $m[1].Trim(); if ($arg -eq 'reset') { $s.DisplayColumns = @(); Write-Host 'Columns reset.' } else { $s.DisplayColumns = ($arg -split ',') | ForEach-Object { $_.Trim() }; Write-Host "Columns: $($s.DisplayColumns -join ', ')" }
}
Register-ILPCommand -Name 'width' -Pattern '^width\s+([\w-]+)\s+(\d+)$' -Category 'Session' -Usage 'width <field> <N>' -Help 'Set column width.' -Handler {
    param($s,$m); $script:SessionFieldWidths[$m[1]] = [int]$m[2]; Write-Host "Width '$($m[1])' = $($m[2])"
}
Register-ILPCommand -Name 'output' -Pattern '^output\s+(\w+)$' -Category 'Session' -Usage 'output <Grid|Table|List>' -Help 'Set display format.' -Handler {
    param($s,$m); $f = $m[1]; if ($f -in @('Grid','Table','List')) { $s.OutputFormat = $f; Write-Host "Output: $f" } else { Write-Host 'Use: Grid, Table, List' }
}

# --- JOURNAL ---
Register-ILPCommand -Name 'note' -Pattern '^note\s+"?(.+?)"?\s*$' -Category 'Journal' -Usage 'note "<text>"' -Help 'Add analyst note to investigation journal.' -Handler {
    param($s,$m); $s.Journal.Add([PSCustomObject]@{ Timestamp=[datetime]::Now; Command=''; Summary=$m[1]; Type='note' })
    Write-Host "Note added: $($m[1])"
}

Register-ILPCommand -Name 'journal' -Pattern '^journal(\s+export\s+(.+))?$' -Category 'Journal' -Usage 'journal [export <path>]' `
    -Help "Show or export investigation journal as markdown." -Handler {
    param($s,$m); $c = $script:C; $ep = $m[2]
    if ($ep) { $ep = $ep.Trim('"',"'"); $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine("# Investigation Journal"); [void]$sb.AppendLine("**Started:** $($s.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))")
        [void]$sb.AppendLine("**Duration:** $([Math]::Round(([datetime]::Now - $s.StartTime).TotalMinutes)) minutes")
        [void]$sb.AppendLine("**Events loaded:** $(Format-Number $s.AllEvents.Count) from $($s.SourceFiles.Count) files"); [void]$sb.AppendLine("`n## Timeline")
        foreach ($j in $s.Journal) { $ts = $j.Timestamp.ToString('HH:mm:ss')
            $line = switch ($j.Type) { 'note' { "- **$ts** [NOTE] $($j.Summary)" } 'bookmark' { "- **$ts** [BOOKMARK] $($j.Summary)" } default { "- **$ts** ``$($j.Command)`` -- $($j.Summary)" } }
            [void]$sb.AppendLine($line) }
        [System.IO.File]::WriteAllText($ep, $sb.ToString()); Write-Host "Journal exported to $ep" }
    else { if ($s.Journal.Count -eq 0) { Write-Host 'Journal is empty.'; return }
        Write-ColorText "$([string][char]0x2500*3) Investigation Journal $([string][char]0x2500*32)" $c.BoldWhite
        Write-Host "  Started: $($s.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))  Duration: $([Math]::Round(([datetime]::Now - $s.StartTime).TotalMinutes))min"
        foreach ($j in $s.Journal) { $icon = switch ($j.Type) { 'note' { "$($c.Yellow)[N]$($c.Reset)" } 'bookmark' { "$($c.Cyan)[B]$($c.Reset)" } default { "$($c.Dim)[C]$($c.Reset)" } }
            Write-Host "  $($c.Dim)$($j.Timestamp.ToString('HH:mm:ss'))$($c.Reset) $icon $(if ($j.Command) { $j.Command } else { $j.Summary })" } }
}

# --- BOOKMARKS ---
Register-ILPCommand -Name 'bookmark' -Pattern '^bookmark\s+(\d+)(\s+"?(.+?)"?)?$' -Category 'Bookmarks' -Usage 'bookmark <N> ["note"]' -Help 'Tag event #N with a note.' -Handler {
    param($s,$m); $idx = [int]$m[1] - 1; $note = if ($m[3]) { $m[3] } else { '' }
    if ($idx -lt 0 -or $idx -ge $s.FilteredEvents.Count) { Write-Host "Out of range (1-$($s.FilteredEvents.Count))"; return }
    $s.Bookmarks.Add([PSCustomObject]@{ EventRef=$s.FilteredEvents[$idx]; Index=[int]$m[1]; Note=$note; Timestamp=[datetime]::Now })
    $s.Journal.Add([PSCustomObject]@{ Timestamp=[datetime]::Now; Command="bookmark $($m[1])"; Summary="Bookmarked event #$($m[1]): $note"; Type='bookmark' })
    Write-Host "Bookmarked event #$($m[1])$(if ($note) { ": $note" })"
}

Register-ILPCommand -Name 'bookmarks' -Pattern '^bookmarks(\s+(.+))?$' -Category 'Bookmarks' -Usage 'bookmarks [show|export <path>|clear]' `
    -Help "List, show, export, or clear bookmarks." -Handler {
    param($s,$m); $c = $script:C; $sub = if ($m[2]) { $m[2].Trim() } else { '' }
    if ($sub -eq 'clear') { $s.Bookmarks = [System.Collections.Generic.List[object]]::new(); Write-Host 'Bookmarks cleared.' }
    elseif ($sub -eq 'show') { foreach ($bm in $s.Bookmarks) { Write-Host ''; & ($script:ILPCommands['show'].Handler) $s @{1="$($bm.Index)"} } }
    elseif ($sub -match '^export\s+(.+)$') { $p = $Matches[1].Trim('"',"'"); $lines = @('Index,Timestamp,Severity,Source,Message,Note')
        foreach ($bm in $s.Bookmarks) { $ev = $bm.EventRef; $lines += "$($bm.Index),`"$($ev.Timestamp)`",`"$($ev.Severity)`",`"$($ev.Source)`",`"$($ev.Message -replace '"','""')`",`"$($bm.Note)`"" }
        [System.IO.File]::WriteAllLines($p, $lines); Write-Host "Exported $($s.Bookmarks.Count) bookmarks to $p" }
    elseif ($sub -eq '' -or $sub -eq 'list') { if ($s.Bookmarks.Count -eq 0) { Write-Host 'No bookmarks.'; return }
        Write-ColorText "$([string][char]0x2500*3) Bookmarks ($($s.Bookmarks.Count)) $([string][char]0x2500*35)" $c.BoldWhite
        foreach ($bm in $s.Bookmarks) { $ev = $bm.EventRef; $ts = if ($ev.Timestamp -ne [datetime]::MinValue) { $ev.Timestamp.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
            Write-Host "  $($c.Cyan)#$($bm.Index)$($c.Reset)  $ts  $($ev.Severity.PadRight(8))  $($ev.Message.Substring(0, [Math]::Min(50, $ev.Message.Length)))$(if ($bm.Note) { "  $($c.Yellow)[$($bm.Note)]$($c.Reset)" })" } }
    else { Write-Host 'Usage: bookmarks [show|export <path>|clear]' }
}

# --- WATCHLIST ---
Register-ILPCommand -Name 'watch' -Pattern '^watch(\s+(.+))?$' -Category 'Watchlist' -Usage 'watch <field> <val,...> | remove | clear' `
    -Help "watch srcip 10.0.1.5,10.0.1.8 -- Add to watchlist`nwatch remove srcip [val] -- Remove`nwatch clear -- Clear all" -Handler {
    param($s,$m); $c = $script:C; $args2 = if ($m[2]) { $m[2].Trim() } else { '' }
    if ($args2 -eq 'clear') { $s.Watchlist = @{}; Write-Host 'Watchlist cleared.' }
    elseif ($args2 -match '^remove\s+([\w-]+)(\s+(.+))?$') { $f = $Matches[1]; $v = $Matches[3]
        if ($v -and $s.Watchlist.ContainsKey($f)) { $s.Watchlist[$f] = @($s.Watchlist[$f] | Where-Object { $_ -ne $v }) } elseif ($s.Watchlist.ContainsKey($f)) { $s.Watchlist.Remove($f) }
        Write-Host "Removed from watchlist." }
    elseif ($args2 -match '^([\w-]+)\s+(.+)$') { $f = $Matches[1]; $vals = ($Matches[2] -split ',') | ForEach-Object { $_.Trim() }
        if (-not $s.Watchlist.ContainsKey($f)) { $s.Watchlist[$f] = @() }; $s.Watchlist[$f] = @($s.Watchlist[$f]) + $vals
        Write-Host "Watching $f`: $($vals -join ', ')" }
    else { if ($s.Watchlist.Count -eq 0) { Write-Host 'Watchlist empty.' } else {
        Write-ColorText "$([string][char]0x2500*3) Watchlist $([string][char]0x2500*44)" $c.BoldWhite
        foreach ($wk in $s.Watchlist.Keys) { Write-Host "  $($c.Cyan)$wk$($c.Reset): $($s.Watchlist[$wk] -join ', ')" } } }
}

# --- VARIABLES ---
Register-ILPCommand -Name 'var-set' -Pattern '^\$(\w+)\s*=\s*select\s+([\w-]+)$' -Category 'Variables' -Usage '$name = select <field>' `
    -Help "Capture unique field values into a named variable." -Handler {
    param($s,$m); $vn = $m[1]; $vf = $m[2]; $vals = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($ev in $s.FilteredEvents) { $v = Get-EventFieldValue -Event $ev -Field $vf; if ($v) { $vals.Add("$v") | Out-Null } }
    $s.Variables[$vn] = @($vals); Write-Host "`$$vn = $($vals.Count) unique $vf values$(if ($vals.Count -le 5) { ": $($vals -join ', ')" } else { " (first 5: $($vals | Select-Object -First 5 | ForEach-Object { $_ }) ...)" })"
}
Register-ILPCommand -Name 'var-show' -Pattern '^\$(\w+)$' -Category 'Variables' -Usage '$name' -Help 'Print variable contents.' -Handler {
    param($s,$m); $vn = $m[1]; if (-not $s.Variables.ContainsKey($vn)) { Write-Host "Variable `$$vn not defined."; return }
    $v = $s.Variables[$vn]; if ($v -is [hashtable]) { Write-Host "`$$vn ($($v.Count) entries)"; foreach ($k in ($v.Keys | Select-Object -First 10)) { Write-Host "  $k = $($v[$k])" } }
    else { Write-Host "`$$vn ($(@($v).Count) values)"; foreach ($val in ($v | Select-Object -First 20)) { Write-Host "  $val" } }
}
Register-ILPCommand -Name 'vars' -Pattern '^vars$' -Category 'Variables' -Usage 'vars' -Help 'List all variables.' -Handler {
    param($s,$m); if ($s.Variables.Count -eq 0) { Write-Host 'No variables.' } else { foreach ($vk in $s.Variables.Keys) { $v = $s.Variables[$vk]; $cnt = if ($v -is [hashtable]) { $v.Count } else { @($v).Count }; Write-Host "  `$$vk ($cnt values)" } }
}

# --- EVIDENCE ---
Register-ILPCommand -Name 'evidence' -Pattern '^evidence(\s+(.+))?$' -Category 'Compliance' -Usage 'evidence start|capture|finish|export|list' `
    -Help "evidence start `"AC-2`" -- Begin collection`nevidence capture `"desc`" -- Snapshot current state`nevidence finish -- Close collection`nevidence export <path> -- Export as HTML`nevidence list -- Show collections" -Handler {
    param($s,$m); $c = $script:C; $args2 = if ($m[2]) { $m[2].Trim() } else { '' }
    if ($args2 -match '^start\s+"?(.+?)"?\s*$') { $s._EvidenceCtx = @{ ControlId=$Matches[1]; StartTime=[datetime]::Now; Captures=[System.Collections.Generic.List[object]]::new() }
        Write-Host "Evidence collection started for: $($Matches[1])" }
    elseif ($args2 -match '^capture\s+"?(.+?)"?\s*$') { if (-not $s._EvidenceCtx) { Write-Host 'No active evidence collection. Use: evidence start "control"'; return }
        $sc = @{Critical=0;High=0;Medium=0;Low=0;Info=0}; foreach ($ev in $s.FilteredEvents) { if ($sc.ContainsKey($ev.Severity)) { $sc[$ev.Severity]++ } }
        $cap = @{ Description=$Matches[1]; Filter=$s.ActiveFilter; EventCount=$s.FilteredEvents.Count; SeverityCounts=$sc; Timestamp=[datetime]::Now
            TimeRange=@{ Min=($s.FilteredEvents | Where-Object { $_.Timestamp -ne [datetime]::MinValue } | ForEach-Object { $_.Timestamp } | Measure-Object -Minimum -ErrorAction SilentlyContinue).Minimum
                         Max=($s.FilteredEvents | Where-Object { $_.Timestamp -ne [datetime]::MinValue } | ForEach-Object { $_.Timestamp } | Measure-Object -Maximum -ErrorAction SilentlyContinue).Maximum }
            SampleEvents=@($s.FilteredEvents | Select-Object -First 10) }
        $s._EvidenceCtx.Captures.Add($cap); Write-Host "Captured: $($Matches[1]) ($($cap.EventCount) events)"
        $s.Journal.Add([PSCustomObject]@{ Timestamp=[datetime]::Now; Command="evidence capture"; Summary="Evidence: $($Matches[1]) ($($cap.EventCount) events)"; Type='command' }) }
    elseif ($args2 -eq 'finish') { if (-not $s._EvidenceCtx) { Write-Host 'No active evidence collection.'; return }
        if (-not $s._EvidenceCollections) { $s | Add-Member -NotePropertyName '_EvidenceCollections' -NotePropertyValue ([System.Collections.Generic.List[object]]::new()) -ErrorAction SilentlyContinue }
        $s._EvidenceCollections.Add($s._EvidenceCtx); Write-Host "Evidence collection '$($s._EvidenceCtx.ControlId)' finished with $($s._EvidenceCtx.Captures.Count) captures."; $s._EvidenceCtx = $null }
    elseif ($args2 -match '^export\s+(.+)$') { $p = $Matches[1].Trim('"',"'"); $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine('<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Evidence Collection</title><style>body{font-family:sans-serif;max-width:800px;margin:auto;padding:20px}h2{color:#0078d4;border-bottom:2px solid #0078d4}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:6px;text-align:left}th{background:#f0f4f8}</style></head><body>')
        $colls = @(); if ($s._EvidenceCtx) { $colls += $s._EvidenceCtx }; if ($s._EvidenceCollections) { $colls += $s._EvidenceCollections }
        foreach ($ec in $colls) { [void]$sb.AppendLine("<h2>Control: $($ec.ControlId)</h2><p>Collected: $($ec.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))</p>")
            $ci = 1; foreach ($cap in $ec.Captures) { [void]$sb.AppendLine("<h3>Capture $ci`: $($cap.Description)</h3><p>Filter: <code>$($cap.Filter)</code><br>Events: $($cap.EventCount)<br>Severity: C:$($cap.SeverityCounts.Critical) H:$($cap.SeverityCounts.High) M:$($cap.SeverityCounts.Medium) L:$($cap.SeverityCounts.Low) I:$($cap.SeverityCounts.Info)</p>")
                if ($cap.SampleEvents.Count -gt 0) { [void]$sb.AppendLine('<table><tr><th>Timestamp</th><th>Severity</th><th>Source</th><th>Message</th></tr>')
                    foreach ($ev in $cap.SampleEvents) { [void]$sb.AppendLine("<tr><td>$($ev.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</td><td>$($ev.Severity)</td><td>$($ev.Source)</td><td>$([System.Web.HttpUtility]::HtmlEncode($ev.Message))</td></tr>") }
                    [void]$sb.AppendLine('</table>') }; $ci++ } }
        [void]$sb.AppendLine('</body></html>'); [System.IO.File]::WriteAllText($p, $sb.ToString()); Write-Host "Evidence exported to $p" }
    elseif ($args2 -eq 'list') { $colls = @(); if ($s._EvidenceCtx) { $colls += $s._EvidenceCtx }; if ($s._EvidenceCollections) { $colls += $s._EvidenceCollections }
        if ($colls.Count -eq 0) { Write-Host 'No evidence collections.' } else { foreach ($ec in $colls) { $st = if ($s._EvidenceCtx -eq $ec) { ' (active)' } else { '' }
            Write-Host "  $($c.Cyan)$($ec.ControlId)$($c.Reset)$st  $($ec.Captures.Count) captures  $($ec.StartTime.ToString('yyyy-MM-dd HH:mm'))" } } }
    else { Write-Host 'Usage: evidence start "control" | capture "desc" | finish | export <path> | list' }
}

# --- PLAYBOOKS ---
Register-ILPCommand -Name 'playbook' -Pattern '^playbook(\s+(.+))?$' -Category 'Compliance' -Usage 'playbook list|run <name>|create <name>' `
    -Help "playbook list -- Show available playbooks`nplaybook run <name> -- Execute playbook`nplaybook create <name> -- Save history as playbook" -Handler {
    param($s,$m); $c = $script:C; $args2 = if ($m[2]) { $m[2].Trim() } else { '' }
    $pbDirs = @($PSScriptRoot, (Join-Path $HOME '.ilp/playbooks'), (Get-Location).Path) | Where-Object { $_ -and (Test-Path $_) }
    if ($args2 -eq 'list' -or $args2 -eq '') { $found = @(); foreach ($d in $pbDirs) { $found += Get-ChildItem $d -Filter '*.ilp-playbook' -ErrorAction SilentlyContinue }
        if ($found.Count -eq 0) { Write-Host 'No playbooks found.' } else { Write-ColorText "$([string][char]0x2500*3) Playbooks $([string][char]0x2500*43)" $c.BoldWhite
            foreach ($f in $found) { $desc = (Get-Content $f.FullName -TotalCount 1) -replace '^#\s*',''; $lines = @(Get-Content $f.FullName | Where-Object { $_ -and -not $_.StartsWith('#') -and $_ -notmatch '^---' }).Count
                Write-Host "  $($c.Cyan)$($f.BaseName)$($c.Reset)  $desc  ($lines commands)" } } }
    elseif ($args2 -match '^run\s+(.+)$') { $name = $Matches[1].Trim('"',"'"); $pbFile = $null
        foreach ($d in $pbDirs) { $p = Join-Path $d "$name.ilp-playbook"; if (Test-Path $p) { $pbFile = $p; break }; $p = Join-Path $d $name; if (Test-Path $p) { $pbFile = $p; break } }
        if (-not $pbFile) { Write-Host "Playbook not found: $name"; return }
        $lines = Get-Content $pbFile; Write-ColorText "$([string][char]0x2500*3) Running: $name $([string][char]0x2500*35)" $c.BoldWhite
        $s.Journal.Add([PSCustomObject]@{ Timestamp=[datetime]::Now; Command="playbook run $name"; Summary="Started playbook: $name"; Type='command' })
        foreach ($line in $lines) { $line = $line.Trim()
            if (-not $line -or $line.StartsWith('#')) { if ($line.StartsWith('#')) { Write-ColorText "  $line" $c.Dim }; continue }
            if ($line -match '^---\s*pause\s*(.*?)\s*---$') { $label = $Matches[1]; if ($label) { Write-ColorText "`n  >> $label" $c.BoldWhite }
                Write-Host '  [Enter] continue | [s] skip | [q] quit: ' -NoNewline; $key = Read-Host
                if ($key -eq 'q') { Write-Host 'Playbook stopped.'; return }; if ($key -eq 's') { $skip = $true; continue }; continue }
            $line = $line -replace '\{date\}', (Get-Date -Format 'yyyy-MM-dd') -replace '\{datetime\}', (Get-Date -Format 'yyyy-MM-dd_HHmmss')
            Write-Host "$($c.Dim)> $line$($c.Reset)"; $s._PlaybookInput = $line; $s._RunPlaybookCmd = $true } }
    elseif ($args2 -match '^create\s+(.+)$') { $name = $Matches[1].Trim('"',"'"); $dir = Join-Path $HOME '.ilp/playbooks'
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $p = Join-Path $dir "$name.ilp-playbook"; $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine("# $name"); [void]$sb.AppendLine("# Created $(Get-Date -Format 'yyyy-MM-dd HH:mm')"); [void]$sb.AppendLine('')
        foreach ($cmd in $s.CommandHistory) { if ($cmd -in @('exit','quit','history','help')) { continue }; [void]$sb.AppendLine($cmd) }
        [System.IO.File]::WriteAllText($p, $sb.ToString()); Write-Host "Playbook saved to $p ($($s.CommandHistory.Count) commands)" }
    else { Write-Host 'Usage: playbook list | run <name> | create <name>' }
}

# --- SESSION PERSISTENCE ---
Register-ILPCommand -Name 'session' -Pattern '^session(\s+(.+))?$' -Category 'Session' -Usage 'session save|restore|list' `
    -Help "session save <path> -- Save session state`nsession restore <path> -- Restore session`nsession list -- List saved sessions" -Handler {
    param($s,$m); $args2 = if ($m[2]) { $m[2].Trim() } else { '' }
    if ($args2 -match '^save\s+(.+)$') { $p = $Matches[1].Trim('"',"'"); $state = @{
        SourceFiles = $s.SourceFiles; ActiveFilter = $s.ActiveFilter; CommandHistory = @($s.CommandHistory)
        Aliases = $s.Aliases; Watchlist = $s.Watchlist; Variables = @{}; DisplayColumns = $s.DisplayColumns
        OutputFormat = $s.OutputFormat; FieldWidths = $s.FieldWidths; Highlight = $s.Highlight
        Bookmarks = @($s.Bookmarks | ForEach-Object { @{ Index=$_.Index; Note=$_.Note } })
        Journal = @($s.Journal | ForEach-Object { @{ Timestamp=$_.Timestamp.ToString('o'); Command=$_.Command; Summary=$_.Summary; Type=$_.Type } }) }
        foreach ($vk in $s.Variables.Keys) { if ($s.Variables[$vk] -is [hashtable]) { $state.Variables[$vk] = $s.Variables[$vk] } else { $state.Variables[$vk] = @($s.Variables[$vk]) } }
        $state | ConvertTo-Json -Depth 5 | Set-Content $p; Write-Host "Session saved to $p" }
    elseif ($args2 -match '^restore\s+(.+)$') { $p = $Matches[1].Trim('"',"'"); if (-not (Test-Path $p)) { Write-Host "Not found: $p"; return }
        try { $state = Get-Content $p -Raw | ConvertFrom-Json
            if ($state.Aliases) { foreach ($prop in $state.Aliases.PSObject.Properties) { $s.Aliases[$prop.Name] = $prop.Value } }
            if ($state.Watchlist) { foreach ($prop in $state.Watchlist.PSObject.Properties) { $s.Watchlist[$prop.Name] = @($prop.Value) } }
            if ($state.DisplayColumns) { $s.DisplayColumns = @($state.DisplayColumns) }
            if ($state.OutputFormat) { $s.OutputFormat = $state.OutputFormat }
            if ($state.Highlight) { $s.Highlight = $state.Highlight }
            if ($state.CommandHistory) { foreach ($cmd in $state.CommandHistory) { $s.CommandHistory.Add($cmd) } }
            Write-Host "Session restored from $p ($(if ($state.Aliases) { $state.Aliases.PSObject.Properties.Count } else { 0 }) aliases, $(if ($state.Watchlist) { $state.Watchlist.PSObject.Properties.Count } else { 0 }) watchlists)" }
        catch { Write-Host "Error restoring: $_" } }
    elseif ($args2 -eq 'list' -or $args2 -eq '') { $dirs = @((Get-Location).Path, (Join-Path $HOME '.ilp/sessions'))
        $files = @(); foreach ($d in $dirs) { if (Test-Path $d) { $files += Get-ChildItem $d -Filter '*.ilp-session' -ErrorAction SilentlyContinue } }
        if ($files.Count -eq 0) { Write-Host 'No saved sessions.' } else { foreach ($f in $files) { Write-Host "  $($f.Name)  $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm'))  $('{0:N0}' -f ($f.Length / 1KB))KB" } } }
    else { Write-Host 'Usage: session save <path> | restore <path> | list' }
}

# --- COPY ---
Register-ILPCommand -Name 'copy' -Pattern '^copy(\s+(\d+))?$' -Category 'Data' -Usage 'copy [N]' -Help 'Copy events or event #N to clipboard.' -Handler {
    param($s,$m); $idx = $m[2]
    if ($idx) { $i = [int]$idx - 1; if ($i -lt 0 -or $i -ge $s.FilteredEvents.Count) { Write-Host "Out of range."; return }
        $ev = $s.FilteredEvents[$i]; $text = "$($ev.Timestamp) $($ev.Severity) $($ev.Source) $($ev.Message)"; Set-Clipboard $text; Write-Host "Event #$idx copied." }
    else { $text = ($s.FilteredEvents | ForEach-Object { "$($_.Timestamp) $($_.Severity) $($_.Source) $($_.Message)" }) -join "`n"
        Set-Clipboard $text; Write-Host "$(Format-Number $s.FilteredEvents.Count) events copied." }
}

# ============================================================================
# Start-InteractiveMode (REPL)
# ============================================================================

function Start-InteractiveMode {
    param([System.Collections.Generic.List[object]]$Events, [string[]]$LoadedFiles, [string[]]$LoadedFormats)
    $c = $script:C
    $script:SessionFieldWidths = @{}

    # --- A4: Load config ---
    $config = Import-ILPConfig

    # --- A2: Session object ---
    $session = [PSCustomObject]@{
        AllEvents       = $Events
        FilteredEvents  = $Events
        ActiveFilter    = ''
        FilterHistory   = [System.Collections.Generic.List[object]]::new()
        PageIndex       = 0
        PinnedEvents    = [System.Collections.Generic.List[object]]::new()
        Bookmarks       = [System.Collections.Generic.List[object]]::new()
        Watchlist       = @{}
        Variables       = @{}
        Journal         = [System.Collections.Generic.List[object]]::new()
        OutputFormat    = 'Grid'
        DisplayColumns  = @()
        FieldWidths     = @{}
        Highlight       = ''
        CommandHistory  = [System.Collections.Generic.List[string]]::new()
        Aliases         = @{}
        SourceFiles     = @($LoadedFiles)
        StartTime       = [datetime]::Now
        Config          = $config
        _Exit           = $false
        _Rerun          = $false
        _RerunInput     = ''
        _EvidenceCtx    = $null
        FieldIndex      = @{}
    }

    # Apply config defaults
    if ($config.defaultOutputFormat) { $session.OutputFormat = $config.defaultOutputFormat }
    if ($config.defaultColumns -and @($config.defaultColumns).Count -gt 0) { $session.DisplayColumns = @($config.defaultColumns) }
    if ($config.aliases) { foreach ($prop in $config.aliases.PSObject.Properties) { $session.Aliases[$prop.Name] = $prop.Value } }
    if ($config.watchlist) { foreach ($prop in $config.watchlist.PSObject.Properties) { $session.Watchlist[$prop.Name] = @($prop.Value) } }

    # --- A3: Build field index ---
    $indexFields = if ($config.autoIndex) { @($config.autoIndex) } else { @('srcip','dstip','user','action','severity') }
    if ($Events.Count -gt 0) { Update-FieldIndex $session $indexFields }

    # --- Banner ---
    Write-ColorText "Invoke-LogParser v$($script:Version)" $c.BoldWhite
    Write-Host "Loaded $(Format-Number $Events.Count) events from $($LoadedFiles.Count) file(s)"
    if ($session.Watchlist.Count -gt 0) { Write-Host "Watchlist active: $($session.Watchlist.Count) field(s)" }
    Write-Host "Type 'help' for commands."
    Write-Host ''

    # --- Main loop ---
    $rerun = $false
    while ($true) {
        if (-not $rerun) {
            # Build prompt
            $pp = @('ILP')
            if ($session.ActiveFilter) { $pp += "($($session.ActiveFilter))" }
            $pp += "[$($session.FilteredEvents.Count)]"
            if ($session.PinnedEvents.Count -gt 0) { $pp += "[pin:$($session.PinnedEvents.Count)]" }
            if ($session.Watchlist.Count -gt 0) { $pp += '[W]' }
            if ($session._EvidenceCtx) { $pp += "[E:$($session._EvidenceCtx.ControlId)]" }
            $hlI = if ($session.Highlight) { ' H' } else { '' }
            Write-Host "$($c.BoldCyan)$($pp -join ' ')$hlI> $($c.Reset)" -NoNewline
            $input2 = Read-Host
            if ([string]::IsNullOrWhiteSpace($input2)) { continue }
            $input2 = $input2.Trim()
            $session.CommandHistory.Add($input2)

            # Alias expansion
            $fw = ($input2 -split '\s+', 2)[0]
            if ($session.Aliases.ContainsKey($fw)) {
                $rest = if ($input2.Length -gt $fw.Length) { $input2.Substring($fw.Length) } else { '' }
                $input2 = $session.Aliases[$fw] + $rest
            }
        }
        $rerun = $false

        # Variable expansion in queries: $varname -> OR expansion
        if ($input2 -match '\$(\w+)' -and $session.Variables.ContainsKey($Matches[1])) {
            $vn = $Matches[1]; $vv = $session.Variables[$vn]
            if ($vv -is [array] -or $vv -is [System.Collections.IEnumerable]) {
                $before = $input2 -replace "\`$$vn", ''
                if ($before -match '([\w-]+):\$') { $fld = $Matches[1]
                    $expanded = ($vv | ForEach-Object { "$fld`:$_" }) -join ' OR '
                    $input2 = $input2 -replace "[^\s]+:\`$$vn", "($expanded)"
                }
            }
        }

        # --- !N / !! history re-execution ---
        if ($input2 -match '^!(\d+)$') {
            $hi = [int]$Matches[1] - 1
            if ($hi -lt 0 -or $hi -ge $session.CommandHistory.Count) { Write-Host "History index out of range (1-$($session.CommandHistory.Count))"; Write-Host ''; continue }
            $input2 = $session.CommandHistory[$hi]; Write-Host "$($c.Dim)>> $input2$($c.Reset)"; $session.CommandHistory.Add($input2); $rerun = $true; continue
        }
        if ($input2 -eq '!!') {
            if ($session.CommandHistory.Count -lt 2) { Write-Host 'No previous command.'; Write-Host ''; continue }
            $input2 = $session.CommandHistory[$session.CommandHistory.Count - 2]; Write-Host "$($c.Dim)>> $input2$($c.Reset)"; $session.CommandHistory.Add($input2); $rerun = $true; continue
        }

        # --- Command chaining (;) ---
        $segments = @($input2)
        if ($input2.Contains(' ; ')) { $segments = $input2 -split ' ; ' }

        foreach ($seg in $segments) {
            $seg = $seg.Trim(); if (-not $seg) { continue }

            # --- Help handler (auto-generated from registry) ---
            if ($seg -eq 'help') {
                $cats = [ordered]@{}
                foreach ($cmd in $script:ILPCommands.Values) { if (-not $cats.ContainsKey($cmd.Category)) { $cats[$cmd.Category] = @() }; $cats[$cmd.Category] += $cmd }
                Write-Host ''
                Write-Host "  $($c.BoldWhite)QUERY SYNTAX$($c.Reset)"
                Write-Host "    field:value  Exact    field:val*  Wildcard    field:>N/<N  Numeric"
                Write-Host "    NOT / AND / OR        | count [by F]  | top N  | sort F  | head/tail N"
                Write-Host ''
                foreach ($cat in $cats.Keys) {
                    Write-Host "  $($c.BoldWhite)$($cat.ToUpper())$($c.Reset)"
                    foreach ($cmd in $cats[$cat]) { Write-Host "    $($cmd.Usage.PadRight(32)) $($cmd.Help.Split("`n")[0])" }
                    Write-Host '' }
                Write-Host "  $($c.BoldWhite)OTHER$($c.Reset)"
                Write-Host "    !N / !!                          Re-run command from history"
                Write-Host "    cmd1 ; cmd2                      Command chaining"
                Write-Host "    `$name = select <field>           Capture values to variable"
                Write-Host "    exit / quit                      Exit interactive mode"
                continue
            }
            if ($seg -match '^help\s+(\S+)$') {
                $hc = $Matches[1]; $found = $false
                foreach ($cmd in $script:ILPCommands.Values) { if ($cmd.Name -eq $hc -or $cmd.Usage -like "$hc*") { Write-Host "`nUsage: $($cmd.Usage)`n$($cmd.Help)"; $found = $true; break } }
                if (-not $found) { Write-Host "No help for '$hc'." }
                continue
            }

            # --- Dispatcher: match against registered commands ---
            $matched = $false
            foreach ($cmd in $script:ILPCommands.Values) {
                if ($seg -match $cmd.Pattern) {
                    try { & $cmd.Handler $session $Matches } catch { Write-Host "Error: $_" }
                    $matched = $true

                    # Auto-journal
                    if ($session.Config.journalAutoLog -and $cmd.Category -notin @('Session','Core')) {
                        $summary = switch -Wildcard ($cmd.Name) {
                            'show' { "Inspected event #$($Matches[1])" }
                            'search' { "$($session.FilteredEvents.Count) events matching '$($Matches[1])'" }
                            'correlate' { "Correlated on $($Matches[1]): $($session.FilteredEvents.Count) events" }
                            default { "$($session.FilteredEvents.Count) events" }
                        }
                        $session.Journal.Add([PSCustomObject]@{ Timestamp=[datetime]::Now; Command=$seg; Summary=$summary; Type='command' })
                    }

                    if ($session._Exit) { return }
                    if ($session._Rerun) { $input2 = $session._RerunInput; $session._Rerun = $false; $rerun = $true }
                    break
                }
            }

            if ($rerun) { break }

            # --- Default: treat as query ---
            if (-not $matched) {
                try {
                    $session.FilterHistory.Add(@{ Filter = $session.ActiveFilter; Events = $session.FilteredEvents })
                    $session.FilteredEvents = Invoke-FilterEvents -Events $session.AllEvents -Query $seg
                    $session.ActiveFilter = $seg; $session.PageIndex = 0
                    if ($session.FilteredEvents.Count -gt 0 -and $session.FilteredEvents[0].PSObject.Properties['_AggCount']) {
                        Format-LogTable -Events $session.FilteredEvents -HighlightPattern $session.Highlight -Max 50
                    } else {
                        Write-Host "$(Format-Number $session.FilteredEvents.Count) events"
                        if ($session.FilteredEvents.Count -gt 0 -and $session.FilteredEvents.Count -le 50) {
                            switch ($session.OutputFormat) {
                                'Table' { Format-LogTable -Events $session.FilteredEvents -HighlightPattern $session.Highlight -FieldList $session.DisplayColumns -Max 50 }
                                'List'  { Format-LogList -Events $session.FilteredEvents -HighlightPattern $session.Highlight -Max 50 }
                                default { Format-LogGrid -Events $session.FilteredEvents -HighlightPattern $session.Highlight -FieldList $session.DisplayColumns -Max 50 }
                            }
                        }
                    }
                    if ($session.Config.journalAutoLog) { $session.Journal.Add([PSCustomObject]@{ Timestamp=[datetime]::Now; Command=$seg; Summary="$($session.FilteredEvents.Count) events"; Type='command' }) }
                } catch {
                    # Fuzzy match suggestion
                    $errMsg = "$_"
                    $cmdNames = @($script:ILPCommands.Keys)
                    $firstWord = ($seg -split '\s+', 2)[0]
                    $suggestion = ''
                    foreach ($cn in $cmdNames) { if ((Get-LevenshteinDistance $firstWord $cn) -le 2) { $suggestion = $cn; break } }
                    Write-Host "Query error: $errMsg"
                    if ($suggestion) { Write-Host "$($c.Dim)Did you mean: $suggestion?$($c.Reset)" }
                }
            }
        }

        if (-not $rerun) { Write-Host '' }
    }
}

# ============================================================================
# SECTION 10: Live Tail Mode
# ============================================================================

function Start-TailMode {
    param(
        [string]$FilePath,
        [string]$Format,
        [string]$FilterQuery = '',
        [string]$HighlightPattern = '',
        [int]$InitialLines = 20
    )
    $c = $script:C
    $fileName = [System.IO.Path]::GetFileName($FilePath)
    $eventCount = 0

    Write-ColorText "$([string][char]0x2500 * 3) Tailing $fileName ($Format) | Ctrl+C to stop $([string][char]0x2500 * 20)" $c.Dim
    try {
        Get-Content -Path $FilePath -Wait -Tail $InitialLines | ForEach-Object {
            $rawLine = $_
            if ([string]::IsNullOrWhiteSpace($rawLine)) { return }

            # Quick parse for display
            $tempFile = [System.IO.Path]::GetTempFileName()
            $events = $null
            try {
                [System.IO.File]::WriteAllText($tempFile, $rawLine)
                $events = Invoke-ParseLogFile -FilePath $tempFile -Format $Format
            } catch {} finally { Remove-Item $tempFile -ErrorAction SilentlyContinue }

            if (-not $events) { return }
            foreach ($e in $events) {
                if (-not $e) { continue }
                if ($FilterQuery) {
                    $filtered = Invoke-FilterEvents -Events ([System.Collections.Generic.List[object]]@($e)) -Query $FilterQuery
                    if (-not $filtered -or $filtered.Count -eq 0) { return }
                }
                $eventCount++
                $ts = if ($e.Timestamp -ne [datetime]::MinValue) { $e.Timestamp.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                $sev = Get-SeverityAbbrev $e.Severity
                $sevC = if ($script:SevColor.ContainsKey($e.Severity)) { $script:SevColor[$e.Severity] } else { '' }
                $msgText = if ($e.Message) { $e.Message -replace "`n", ' ' } else { '' }
                if ($msgText.Length -gt 80) { $msgText = $msgText.Substring(0, 79) + [char]0x2026 }
                if ($HighlightPattern) { $msgText = Add-Highlight $msgText $HighlightPattern }
                $srcText = if ($e.Source) { $e.Source } else { '' }
                Write-Host "$($ts.PadRight(21)) $sevC$($sev.PadRight(6))$($c.Reset) $($srcText.PadRight(16)) $msgText"
            }
            Write-Progress -Activity "Tailing $fileName" -Status "$eventCount events | Ctrl+C to stop"
        }
    } catch {
        if ($_.Exception -isnot [System.Management.Automation.PipelineStoppedException]) { throw }
    }
    Write-Host ''
    Write-ColorText "$([string][char]0x2500 * 3) Tail stopped. $eventCount events captured. $([string][char]0x2500 * 20)" $c.Dim
}

# ============================================================================
# SECTION 11: Output Helpers
# ============================================================================

function Copy-ToClipboard {
    param([string]$Text)
    try { Set-Clipboard $Text; if (-not $script:QuietFlag) { Write-ColorText 'Copied to clipboard.' $script:C.Green } }
    catch { Write-Warning 'Clipboard not available (Set-Clipboard requires Windows PS 5.1+).' }
}

function Send-ReportEmail {
    param([string]$To, [string]$Server, [string]$Subject, [string]$Body)
    $from = "logparser@$($env:COMPUTERNAME)"
    if ($PSVersionTable.PSVersion.Major -ge 7) { Write-Warning 'Send-MailMessage is obsolete in PS 7+. Attempting anyway...' }
    try {
        Send-MailMessage -From $from -To $To -Subject $Subject -Body $Body -BodyAsHtml -SmtpServer $Server
        if (-not $script:QuietFlag) { Write-ColorText "Email sent to $To" $script:C.Green }
    } catch { Write-Warning "Email failed: $_" }
}

function Open-ExportFile {
    param([string]$Path)
    try { Invoke-Item $Path } catch { try { Start-Process $Path } catch { Write-Warning "Could not open: $Path" } }
}

# ============================================================================
# SECTION 12: Zip Extraction
# ============================================================================

function Expand-LogArchive {
    param([string]$ZipPath)
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $tempDir = Join-Path $env:TEMP "Invoke-LogParser-$([Guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    $script:TempDirs.Add($tempDir)

    try { [System.IO.Compression.ZipFile]::ExtractToDirectory($ZipPath, $tempDir) }
    catch { Write-Warning "Failed to extract $ZipPath`: $_"; return @() }

    $skipExts = @('.exe','.dll','.png','.jpg','.jpeg','.gif','.pdf','.msi','.iso','.cab','.bmp')
    $tryExts = @('.log','.txt','.csv','.xml','.json','.conf','.evtx','.evt','')

    $results = [System.Collections.Generic.List[object]]::new()
    $allFiles = Get-ChildItem -Path $tempDir -Recurse -File

    foreach ($f in $allFiles) {
        $ext = $f.Extension.ToLower()
        if ($ext -in $skipExts) { continue }
        if ($ext -eq '.zip') {
            # One level of nested zip
            $nestedResults = Expand-LogArchive $f.FullName
            if ($null -ne $nestedResults -and $nestedResults.Count -gt 0) { $results.AddRange($nestedResults) }
            continue
        }
        if ($ext -notin $tryExts -and $ext -ne '') { continue }
        $fmt = Invoke-DetectLogFormat $f.FullName
        if ($fmt) {
            $results.Add(@{ Path = $f.FullName; Format = $fmt; FileName = $f.Name })
            if (-not $script:QuietFlag) { Write-Host "  $($f.Name.PadRight(35)) $($fmt.PadRight(20))" }
        } else {
            if (-not $script:QuietFlag) { Write-ColorText "  $($f.Name.PadRight(35)) (skipped - unknown format)" $script:C.Dim }
        }
    }
    return $results
}

} # end begin

process {
    if ($InputObject) {
        foreach ($line in $InputObject) { $script:PipedLines.Add($line) }
    }
}

end {
# ============================================================================
# SECTION 13: Main Execution
# ============================================================================
try {
    # Handle list commands
    if ($ListParsers) {
        Write-Host 'Available parsers:'
        Write-Host '  FortiGateConf     FortiGate configuration file (.conf)'
        Write-Host '  FortiGateKV       Fortinet key=value log format (.log)'
        Write-Host '  FortiClientLocal  FortiClient EMS local log (.log, .txt)'
        Write-Host '  FortiSwitchEvent  FortiSwitch event log (.log)'
        Write-Host '  WindowsEvtx       Windows Event Log (.evtx, .xml)'
        return
    }
    if ($ListAnalyzers) {
        Write-Host 'Available analyzers:'
        Write-Host '  FailedLogins   Aggregate failed authentication events'
        Write-Host '  VpnSessions    Track VPN session lifecycle and impossible travel'
        Write-Host '  IpsecTunnel    IPsec tunnel health, flaps, and negotiation failures'
        Write-Host '  Summary        General statistics and top talkers'
        return
    }
    if ($ListReports) {
        Write-Host 'Available reports:'
        Write-Host '  Summary      Parse stats, severity distribution, top talkers'
        Write-Host '  Morning      Multi-source overnight summary'
        Write-Host '  Audit        Privileged activity, failed auth, config changes'
        Write-Host '  Compliance   FFIEC-mapped control evidence'
        Write-Host '  Timeline     Chronological event timeline'
        return
    }

    # Validate input
    $hasPipedInput = $script:PipedLines.Count -gt 0
    if (-not $Path -and -not $hasPipedInput) {
        Write-Warning 'No input specified. Use -Path <file> or pipe content. Use -ListParsers to see supported formats.'
        return
    }

    $allEvents = [System.Collections.Generic.List[object]]::new()
    $loadedFiles = [System.Collections.Generic.List[string]]::new()
    $loadedFormats = [System.Collections.Generic.List[string]]::new()
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    # Pipeline input
    if ($hasPipedInput) {
        if (-not $Format) { Write-Warning 'Pipeline input requires -Format parameter.'; return }
        $tempFile = [System.IO.Path]::GetTempFileName()
        $script:TempDirs.Add($tempFile)
        [System.IO.File]::WriteAllLines($tempFile, $script:PipedLines.ToArray())
        $events = Invoke-ParseLogFile -FilePath $tempFile -Format $Format -SourceFile '(piped)'
        if ($null -ne $events -and $events.Count -gt 0) { $allEvents.AddRange($events) }
        $loadedFiles.Add('(piped)')
        $loadedFormats.Add($Format)
    }

    # File input
    if ($Path) {
        $resolvedPaths = [System.Collections.Generic.List[string]]::new()
        foreach ($p in $Path) {
            if ($p -match '\*|\?') {
                $resolved = Resolve-Path $p -ErrorAction SilentlyContinue
                if ($resolved) { foreach ($r in $resolved) { $resolvedPaths.Add($r.Path) } }
            } else {
                $resolvedPaths.Add($p)
            }
        }

        foreach ($filePath in $resolvedPaths) {
            if (-not (Test-Path -LiteralPath $filePath)) { Write-Warning "File not found: $filePath"; continue }

            if ($filePath -match '\.zip$') {
                if (-not $script:QuietFlag) { Write-Host "Extracting $([System.IO.Path]::GetFileName($filePath))..." }
                $archiveFiles = Expand-LogArchive $filePath
                if ($null -ne $archiveFiles) {
                    foreach ($af in $archiveFiles) {
                        if (-not $script:QuietFlag) {
                            Write-Progress -Activity 'Parsing' -Status "$($af.FileName) ($($af.Format))" -PercentComplete 0
                        }
                        $events = Invoke-ParseLogFile -FilePath $af.Path -Format $af.Format -SourceFile $af.FileName
                        if ($null -ne $events -and $events.Count -gt 0) { $allEvents.AddRange($events) }
                        $loadedFiles.Add($af.FileName)
                        if ($af.Format -notin $loadedFormats) { $loadedFormats.Add($af.Format) }
                    }
                }
            } else {
                $fileFormat = if ($Format) { $Format } else { Invoke-DetectLogFormat $filePath }
                if (-not $fileFormat) { Write-Warning "Could not detect format for: $filePath"; continue }
                $fileName = [System.IO.Path]::GetFileName($filePath)
                if (-not $script:QuietFlag) {
                    Write-Progress -Activity 'Parsing' -Status "$fileName ($fileFormat)" -PercentComplete 0
                }

                # Store raw lines for -Context support
                if ($Context -gt 0) {
                    try { $script:RawFileLines[$fileName] = [System.IO.File]::ReadAllLines($filePath) } catch {}
                }

                $events = Invoke-ParseLogFile -FilePath $filePath -Format $fileFormat -SourceFile $filePath
                if ($null -ne $events -and $events.Count -gt 0) { $allEvents.AddRange($events) }
                $loadedFiles.Add($fileName)
                if ($fileFormat -notin $loadedFormats) { $loadedFormats.Add($fileFormat) }
            }
        }
    }

    if (-not $script:QuietFlag -and -not $script:OutputRedirected) {
        Write-Progress -Activity 'Parsing' -Completed
    }
    $sw.Stop()
    $parseTime = $sw.Elapsed.TotalSeconds

    if ($allEvents.Count -eq 0) { Write-Warning 'No events parsed.'; return }

    # Sort by timestamp
    $sorted = $allEvents | Sort-Object { if ($_.Timestamp -ne [datetime]::MinValue) { $_.Timestamp } else { [datetime]::MaxValue } }
    $allEvents = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $sorted) { $allEvents.AddRange(@($sorted)) }

    # Config diff mode
    if ($DiffPath) {
        $diffFile = $DiffPath[0]
        $diffResult = Compare-Configs -File1 $Path[0] -File2 $diffFile -SectionFilter $Section
        Format-ConfigDiff $diffResult
        if ($ExportPath) {
            $reportData = New-ReportData 'Config Diff' ([System.Collections.Generic.List[object]]::new())
            $html = ConvertTo-HtmlReport -ReportData $reportData -Events $allEvents
            # Inject diff HTML
            $diffHtml = '<h2>DIFFERENCES</h2><div class="code">'
            foreach ($d in $diffResult.Diffs) {
                $cls = if ($d.Type -eq 'Added') { 'diff-add' } else { 'diff-del' }
                $prefix = if ($d.Type -eq 'Added') { '+' } else { '-' }
                $diffHtml += "<div class='$cls'>$prefix $([System.Net.WebUtility]::HtmlEncode($d.Line))</div>"
            }
            $diffHtml += '</div>'
            $html = $html -replace '</body>', "$diffHtml</body>"
            [System.IO.File]::WriteAllText($ExportPath, $html)
            Write-ColorText "Exported diff to $ExportPath" $script:C.Green
            if ($Open) { Open-ExportFile $ExportPath }
        }
        return
    }

    # Config section extraction mode
    if ($Section) {
        $sectionLines = Get-ConfigSection $Path[0] $Section
        if ($sectionLines.Count -eq 0) { Write-Warning "Section '$Section' not found."; return }
        Format-ConfigSection $sectionLines
        if ($Clipboard) {
            $text = $sectionLines -join "`n"
            Copy-ToClipboard $text
        }
        return
    }

    # Tail mode
    if ($Tail) {
        $tailFormat = if ($Format) { $Format } else { Invoke-DetectLogFormat $Path[0] }
        Start-TailMode -FilePath $Path[0] -Format $tailFormat -FilterQuery $Filter -HighlightPattern $Highlight -InitialLines $TailLines
        return
    }

    # StatsOnly mode
    if ($StatsOnly) {
        $stats = Get-LogStatistics $allEvents
        if ($stats.PerFile.Keys.Count -gt 1) {
            Write-QuickDigest $stats
        } else {
            Write-LogStats -Stats $stats -SourceFiles @($loadedFiles) -Formats @($loadedFormats) -ParseTime $parseTime
        }
        if ($Clipboard) {
            $text = "Events: $($stats.Total) | Critical: $($stats.SeverityCounts.Critical) | High: $($stats.SeverityCounts.High) | Medium: $($stats.SeverityCounts.Medium)"
            Copy-ToClipboard $text
        }
        return
    }

    # Apply filters
    $filtered = $allEvents
    if ($Filter) { $filtered = Invoke-FilterEvents -Events $filtered -Query $Filter }
    if ($Regex) {
        $regexObj = [regex]::new($Regex, 'IgnoreCase, Compiled')
        $regexFiltered = [System.Collections.Generic.List[object]]::new()
        foreach ($e in $filtered) {
            $raw = if ($e.RawLine) { $e.RawLine } else { '' }
            if ($regexObj.IsMatch($raw)) { $regexFiltered.Add($e) }
        }
        $filtered = $regexFiltered
    }

    # Surround mode
    if ($Surround -gt 0 -and $filtered.Count -gt 0) {
        $matchTimestamps = @($filtered | Where-Object { $null -ne $_ -and $_.Timestamp -ne [datetime]::MinValue } | ForEach-Object { $_.Timestamp })
        $surroundResult = [System.Collections.Generic.List[object]]::new()
        $surroundSpan = [timespan]::FromSeconds($Surround)
        foreach ($e in $allEvents) {
            if ($e.Timestamp -eq [datetime]::MinValue) { continue }
            foreach ($mt in $matchTimestamps) {
                $diff = [Math]::Abs(($e.Timestamp - $mt).TotalSeconds)
                if ($diff -le $Surround) { $surroundResult.Add($e); break }
            }
        }
        $filtered = $surroundResult
    }

    # MaxResults
    $displayMax = if ($MaxResults -gt 0) { $MaxResults } else { 0 }

    # Run analysis
    if ($Analyze) {
        switch ($Analyze) {
            'FailedLogins' {
                $results = Invoke-AnalyzeFailedLogins $filtered
                if ($results.Count -eq 0) { Write-Host 'No failed login events found.' }
                else {
                    $c = $script:C
                    Write-ColorText "$([string][char]0x2500 * 3) Failed Login Analysis $([string][char]0x2500 * 35)" $c.BoldWhite
                    Write-Host "  $($c.BoldWhite)$('User'.PadRight(30)) $('Count'.PadRight(8)) $('Unique IPs'.PadRight(12)) $('First Seen'.PadRight(20)) $('Last Seen'.PadRight(20)) Sources$($c.Reset)"
                    Write-ColorText "  $([string][char]0x2500 * 110)" $c.Dim
                    foreach ($r in $results) {
                        $color = if ($r.Count -ge 10) { $c.Red } elseif ($r.Count -ge 5) { $c.Yellow } else { '' }
                        $fs = if ($r.FirstSeen -ne [datetime]::MinValue) { $r.FirstSeen.ToString('yyyy-MM-dd HH:mm') } else { '' }
                        $ls = if ($r.LastSeen -ne [datetime]::MinValue) { $r.LastSeen.ToString('yyyy-MM-dd HH:mm') } else { '' }
                        Write-Host "  $color$($r.User.PadRight(30)) $(($r.Count.ToString()).PadRight(8)) $(($r.SourceIPs.Count.ToString()).PadRight(12)) $($fs.PadRight(20)) $($ls.PadRight(20)) $($r.Sources -join ', ')$($c.Reset)"
                    }
                }
            }
            'VpnSessions' {
                $results = Invoke-AnalyzeVpnSessions $filtered
                $c = $script:C
                Write-ColorText "$([string][char]0x2500 * 3) VPN Session Analysis $([string][char]0x2500 * 35)" $c.BoldWhite
                Write-Host "  $($c.BoldWhite)$('User'.PadRight(25)) $('Start'.PadRight(20)) $('End'.PadRight(20)) $('Duration'.PadRight(15)) Remote IP$($c.Reset)"
                foreach ($uk in $results.Sessions.Keys) {
                    foreach ($s in $results.Sessions[$uk]) {
                        $st = if ($s.StartTime -ne [datetime]::MinValue) { $s.StartTime.ToString('yyyy-MM-dd HH:mm') } else { '' }
                        $et = if ($s.EndTime) { $s.EndTime.ToString('yyyy-MM-dd HH:mm') } else { '(active)' }
                        $dur = if ($s.Duration) { $s.Duration.ToString('d\.hh\:mm\:ss') } else { '' }
                        Write-Host "  $($s.User.PadRight(25)) $($st.PadRight(20)) $($et.PadRight(20)) $($dur.PadRight(15)) $($s.RemoteIP)"
                    }
                }
                if ($results.ImpossibleTravel.Count -gt 0) {
                    Write-ColorText "`n  IMPOSSIBLE TRAVEL ($($results.ImpossibleTravel.Count)):" $c.Red
                    foreach ($tf in $results.ImpossibleTravel) {
                        Write-ColorText "    $($tf.User): $($tf.IP1) @ $($tf.Time1.ToString('HH:mm')) -> $($tf.IP2) @ $($tf.Time2.ToString('HH:mm')) ($($tf.MinutesBetween) min)" $c.Yellow
                    }
                }
            }
            'IpsecTunnel' {
                $results = Invoke-AnalyzeIpsecTunnel $filtered
                $c = $script:C
                Write-ColorText "$([string][char]0x2500 * 3) IPsec Tunnel Analysis $([string][char]0x2500 * 35)" $c.BoldWhite
                Write-Host "  Total: $($results.Summary.TotalTunnels) | Up: $($results.Summary.UpCount) | Down: $($results.Summary.DownCount) | Flaps: $($results.Summary.FlapCount)"
                Write-Host "  $($c.BoldWhite)$('Tunnel'.PadRight(25)) $('Status'.PadRight(10)) $('Flaps'.PadRight(8)) Last Failure$($c.Reset)"
                foreach ($tn in $results.Tunnels.Keys) {
                    $t = $results.Tunnels[$tn]
                    $color = if ($t.Status -eq 'Down') { $c.Red } elseif ($t.FlapCount -gt 0) { $c.Yellow } else { $c.Green }
                    Write-Host "  $color$($t.TunnelName.PadRight(25)) $($t.Status.PadRight(10)) $($t.FlapCount.ToString().PadRight(8)) $(if ($t.LastFailureReason) { $t.LastFailureReason } else { '-' })$($c.Reset)"
                }
            }
            'Summary' {
                $stats = Get-LogStatistics $filtered
                Write-LogStats -Stats $stats -SourceFiles @($loadedFiles) -Formats @($loadedFormats) -ParseTime $parseTime
            }
        }
        Write-Host ''
    }

    # Generate report
    $reportData = $null
    if ($Report) {
        $reportData = switch ($Report) {
            'Summary'    { New-SummaryReport $filtered }
            'Morning'    { New-MorningBriefing $filtered }
            'Audit'      { New-AuditReport $filtered }
            'Compliance' { New-ComplianceReport $filtered }
            'Timeline'   { New-TimelineReport $filtered }
        }
        if (-not $script:QuietFlag -and -not $ExportPath) { Render-ReportToConsole $reportData }
    }

    # Field selection
    $fieldList = @()
    if ($Fields) { $fieldList = ($Fields -split ',') | ForEach-Object { $_.Trim() } }

    # Display output (unless report already shown or quiet)
    if (-not $Report -and -not $Analyze -and -not $script:QuietFlag) {
        # Context mode
        if ($Context -gt 0) {
            foreach ($e in $filtered) {
                $rawLines = $null
                if ($e.SourceFile -and $script:RawFileLines.ContainsKey($e.SourceFile)) {
                    $rawLines = $script:RawFileLines[$e.SourceFile]
                }
                Write-ContextBlock -Event $e -ContextLines $Context -AllRawLines $rawLines
            }
        } else {
            switch ($OutputFormat) {
                'Table' { Format-LogTable -Events $filtered -FieldList $fieldList -HighlightPattern $Highlight -Max $displayMax }
                'Grid'  { Format-LogGrid -Events $filtered -FieldList $fieldList -HighlightPattern $Highlight -Max $displayMax }
                'List'  { Format-LogList -Events $filtered -HighlightPattern $Highlight -Max $displayMax }
                'Raw'   { Format-LogRaw -Events $filtered -Max $displayMax }
                'Json'  { Format-LogJson -Events $filtered -Max $displayMax }
                'Csv'   { Format-LogCsv -Events $filtered -Max $displayMax }
            }
        }
    }

    # Export
    if ($ExportPath) {
        $rd = if ($reportData) { $reportData } else { New-SummaryReport $filtered }
        Export-Report -Path $ExportPath -Format $ExportFormat -ReportData $rd -Events $filtered
        if ($Open) { Open-ExportFile $ExportPath }
    }

    # Email
    if ($EmailTo -and $SmtpServer) {
        $rd = if ($reportData) { $reportData } else { New-SummaryReport $filtered }
        $html = ConvertTo-HtmlReport -ReportData $rd -Events $filtered
        $subject = "Invoke-LogParser: $($rd.Title) - $(Get-Date -Format 'yyyy-MM-dd')"
        Send-ReportEmail -To $EmailTo -Server $SmtpServer -Subject $subject -Body $html
    }

    # Clipboard
    if ($Clipboard) {
        $clipText = switch ($OutputFormat) {
            'Json' { (Format-LogJson -Events $filtered) -join "`n" }
            'Csv' { (Format-LogCsv -Events $filtered) -join "`n" }
            default {
                ($filtered | ForEach-Object {
                    "$($_.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))  $($_.Severity)  $($_.Source)  $($_.Message)"
                }) -join "`n"
            }
        }
        Copy-ToClipboard $clipText
    }

    # Interactive mode
    if ($Interactive) {
        Start-InteractiveMode -Events $allEvents -LoadedFiles @($loadedFiles) -LoadedFormats @($loadedFormats)
    }

} finally {
    # Cleanup temp files and directories
    foreach ($dir in $script:TempDirs) {
        if (Test-Path $dir) {
            Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
} # end end
