<#
.SYNOPSIS
    CLI-first bulk connectivity tester with parallel execution, SSL inspection, HTTP health checks, and banner grabbing.

.DESCRIPTION
    Tests connectivity to one or more hosts via ICMP ping, TCP port checks, SSL/TLS
    certificate inspection, HTTP health checks, and service banner grabbing. Hosts
    can be passed positionally, via pipeline, from a file, or as CIDR ranges.
    All tests run in parallel using a runspace pool. Results are exported to CSV
    and an optional HTML report.

.PARAMETER Target
    One or more hostnames, IP addresses, or CIDR ranges (e.g., 10.0.1.0/24).
    Accepts pipeline input. Aliases: Host, ComputerName, IPAddress.

.PARAMETER HostFile
    Path to a plain-text file with one host/IP/CIDR per line. Comments (#) supported.

.PARAMETER TcpPorts
    TCP ports to check on each host. Pass 0 to skip port checks.

.PARAMETER TestSsl
    Enable SSL/TLS certificate inspection. Checks the first open port, or 443.

.PARAMETER TestHttp
    URL path for HTTP health check (must start with /). Constructs URL from host:port.

.PARAMETER GrabBanner
    Read the service banner from each open TCP port.

.PARAMETER PingOnly
    Skip all TCP/SSL/HTTP/banner checks. Ping and DNS only.

.PARAMETER NoPing
    Skip ICMP ping. Useful when ICMP is blocked but TCP works.

.PARAMETER Watch
    Repeat the scan every N seconds. 0 = one-shot (default). Ctrl+C to stop.

.PARAMETER MaxConcurrent
    Maximum parallel workers. Default: 10.

.PARAMETER CertWarnDays
    Flag SSL certificates expiring within this many days. Default: 30.

.PARAMETER ExpectedStatusCode
    Expected HTTP status code for health checks. Default: 200.

.PARAMETER GenerateHtml
    Produce a self-contained HTML report alongside the CSV.

.EXAMPLE
    .\Test-ConnectivityBulk.ps1 server01 server02 server03
    Positional host input with default settings.

.EXAMPLE
    Get-Content servers.txt | .\Test-ConnectivityBulk.ps1 -TcpPorts 22,443,3389
    Pipeline input with multi-port checks.

.EXAMPLE
    .\Test-ConnectivityBulk.ps1 "10.0.1.0/24" -PingOnly
    Ping sweep an entire /24 subnet.

.EXAMPLE
    .\Test-ConnectivityBulk.ps1 web01,web02 -TcpPorts 443 -TestSsl -TestHttp "/health"
    Full check: ping, port 443, SSL cert, and HTTP health endpoint.

.EXAMPLE
    .\Test-ConnectivityBulk.ps1 -HostFile servers.txt -TcpPorts 22 -GrabBanner -GenerateHtml
    Banner grab with HTML report from a host file.

.EXAMPLE
    .\Test-ConnectivityBulk.ps1 gw01,gw02 -Watch 30 -TcpPorts 443
    Monitor two hosts every 30 seconds, showing changes between scans.
#>
#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = "Targets")]
param(
    [Parameter(ParameterSetName = "Targets", Position = 0, ValueFromPipeline,
               ValueFromPipelineByPropertyName,
               HelpMessage = "Hostnames, IPs, or CIDR ranges to test.")]
    [ValidateNotNullOrEmpty()]
    [Alias("Host", "ComputerName", "IPAddress")]
    [string[]]$Target,

    [Parameter(ParameterSetName = "File",
               HelpMessage = "Path to a text file with one host/IP/CIDR per line.")]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [Alias("File")]
    [string]$HostFile,

    [Parameter(HelpMessage = "TCP ports to check. Pass 0 to skip.")]
    [int[]]$TcpPorts,

    [Parameter(HelpMessage = "Enable SSL/TLS certificate inspection.")]
    [switch]$TestSsl,

    [Parameter(HelpMessage = "URL path for HTTP health check (e.g., '/health').")]
    [ValidatePattern('^/')]
    [string]$TestHttp,

    [Parameter(HelpMessage = "Grab service banners from open TCP ports.")]
    [switch]$GrabBanner,

    [Parameter(HelpMessage = "Ping and DNS only — skip all TCP/SSL/HTTP checks.")]
    [switch]$PingOnly,

    [Parameter(HelpMessage = "Skip ICMP ping (useful when ICMP is blocked).")]
    [switch]$NoPing,

    [Parameter(HelpMessage = "Repeat every N seconds. 0 = one-shot.")]
    [ValidateRange(0, 86400)]
    [int]$Watch = 0,

    [Parameter(HelpMessage = "Maximum parallel workers.")]
    [ValidateRange(1, 200)]
    [int]$MaxConcurrent,

    [Parameter(HelpMessage = "Days until SSL cert expiry to flag as warning.")]
    [ValidateRange(1, 365)]
    [int]$CertWarnDays,

    [Parameter(HelpMessage = "Expected HTTP status code for health checks.")]
    [ValidateRange(100, 599)]
    [int]$ExpectedStatusCode,

    [Parameter(HelpMessage = "Generate an HTML report alongside the CSV.")]
    [switch]$GenerateHtml
)

# =============================================================================
# BEGIN — config, logging, parameter overrides
# =============================================================================
begin {

# --- Configuration ---
$Config = @{
    ScriptName = "Test-ConnectivityBulk"
    LogDir     = "$PSScriptRoot\logs"
    OutputDir  = "$PSScriptRoot\output"

    Targets    = @()
    HostFile   = "$PSScriptRoot\hosts.txt"

    PingCount      = 4
    PingTimeout    = 1000
    TcpPorts       = @(443)
    TcpTimeoutMs   = 2000
    MaxConcurrent  = 10
    TracerouteOnFail = $false
    GenerateHtml   = $false
    LossWarnPct    = 0

    CertWarnDays       = 30
    SslPort            = 443
    HttpScheme         = "https"
    ExpectedStatusCode = 200
    HttpTimeoutMs      = 5000
    BannerMaxBytes     = 1024
    BannerTimeoutMs    = 3000
    WatchIntervalSec   = 0
}

# --- Parameter overrides ---
if ($PSBoundParameters.ContainsKey('TcpPorts')) {
    $Config.TcpPorts = if ($TcpPorts.Count -eq 1 -and $TcpPorts[0] -eq 0) { @() } else { $TcpPorts }
}
if ($PSBoundParameters.ContainsKey('HostFile'))           { $Config.HostFile           = $HostFile }
if ($PSBoundParameters.ContainsKey('MaxConcurrent'))      { $Config.MaxConcurrent      = $MaxConcurrent }
if ($PSBoundParameters.ContainsKey('CertWarnDays'))       { $Config.CertWarnDays       = $CertWarnDays }
if ($PSBoundParameters.ContainsKey('ExpectedStatusCode')) { $Config.ExpectedStatusCode = $ExpectedStatusCode }
if ($PSBoundParameters.ContainsKey('Watch'))              { $Config.WatchIntervalSec   = $Watch }
if ($GenerateHtml)                                        { $Config.GenerateHtml       = $true }

# Validate mutually exclusive switches
if ($PingOnly -and $NoPing) {
    throw "-PingOnly and -NoPing cannot be used together."
}

# --- Logging setup ---
$Script:LogFile = $null
if ($Config.LogDir) {
    if (-not (Test-Path $Config.LogDir)) { New-Item -ItemType Directory -Path $Config.LogDir | Out-Null }
    $Script:LogFile = Join-Path $Config.LogDir (
        "{0}_{1}.log" -f $Config.ScriptName, (Get-Date -Format "yyyyMMdd_HHmmss")
    )
}

function Write-Log {
    param([string]$Message, [ValidateSet("INFO","WARNING","ERROR")][string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    switch ($Level) {
        "INFO"    { Write-Host $line -ForegroundColor Cyan }
        "WARNING" { Write-Host $line -ForegroundColor Yellow }
        "ERROR"   { Write-Host $line -ForegroundColor Red }
    }
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $line }
}

function Write-Summary {
    <# Colored console + log file output. #>
    param([string]$Line, [string]$Color = "White")
    Write-Host $Line -ForegroundColor $Color
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $Line }
}

# ── Test functions (defined once, injected into runspaces via ISS) ──────────

function Resolve-HostDns {
    <# Forward and reverse DNS lookup. #>
    param([string]$Target)
    $r = @{ ForwardIP = "N/A"; ReverseDNS = "N/A"; DnsOk = $false }
    try {
        $entry = [System.Net.Dns]::GetHostEntry($Target)
        if ($entry.AddressList.Count -gt 0) {
            $r.ForwardIP = $entry.AddressList[0].ToString()
            $r.DnsOk = $true
        }
        try {
            $rev = [System.Net.Dns]::GetHostEntry($r.ForwardIP)
            if ($rev.HostName -and $rev.HostName -ne $r.ForwardIP) { $r.ReverseDNS = $rev.HostName }
        } catch { }
    } catch { }
    return $r
}

function Test-HostPing {
    <# Pings a target N times, returns reachability and min/avg/max latency. #>
    param([string]$Target, [int]$Count, [int]$Timeout)
    $rts = [System.Collections.Generic.List[long]]::new()
    $ip = "N/A"
    for ($i = 0; $i -lt $Count; $i++) {
        try {
            $p = (New-Object System.Net.NetworkInformation.Ping).Send($Target, $Timeout)
            if ($p.Status -eq "Success") {
                $rts.Add($p.RoundtripTime)
                if ($ip -eq "N/A") { $ip = $p.Address.ToString() }
            }
        } catch { }
    }
    if ($rts.Count -gt 0) {
        return @{ Reachable = $true; IPAddress = $ip; Sent = $Count; Received = $rts.Count
                  MinMs = ($rts | Measure-Object -Minimum).Minimum
                  AvgMs = [math]::Round(($rts | Measure-Object -Average).Average, 1)
                  MaxMs = ($rts | Measure-Object -Maximum).Maximum }
    }
    return @{ Reachable = $false; IPAddress = "N/A"; Sent = $Count; Received = 0; MinMs = -1; AvgMs = -1; MaxMs = -1 }
}

function Test-TcpPort {
    <# Async TCP connect with timeout. Returns $true if port is open. #>
    param([string]$Target, [int]$Port, [int]$TimeoutMs)
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $t = $c.BeginConnect($Target, $Port, $null, $null)
        $w = $t.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($w -and $c.Connected) { $c.EndConnect($t); return $true }
        return $false
    } catch { return $false } finally { $c.Close() }
}

function Get-Traceroute {
    <# Returns the last reachable hop to a target. #>
    param([string]$Target)
    try {
        $out = & tracert -d -w 1000 -h 15 $Target 2>&1
        $hop = ""
        foreach ($line in $out) {
            if ($line -match '^\s*\d+\s+.*\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') { $hop = $Matches[1] }
        }
        return $(if ($hop) { $hop } else { "No hops resolved" })
    } catch { return "Traceroute failed" }
}

function Get-SslCertificate {
    <# Connects via TLS and returns certificate details. #>
    param([string]$Target, [int]$Port, [int]$TimeoutMs = 5000)
    $r = @{ Subject="N/A"; Issuer="N/A"; NotAfter="N/A"; DaysUntilExpiry=-1; Thumbprint="N/A"; SANs="N/A"; SslError=$null }
    $client = $null; $ssl = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $ct = $client.BeginConnect($Target, $Port, $null, $null)
        if (-not $ct.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -or -not $client.Connected) {
            $r.SslError = "TCP connect timeout"; return $r
        }
        $client.EndConnect($ct)
        $ssl = New-Object System.Net.Security.SslStream(
            $client.GetStream(), $false,
            ([System.Net.Security.RemoteCertificateValidationCallback]{ param($s,$c,$ch,$e) $true })
        )
        $ssl.AuthenticateAsClient($Target)
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
        $r.Subject         = $cert.Subject
        $r.Issuer          = $cert.Issuer
        $r.NotAfter        = $cert.NotAfter.ToString("yyyy-MM-dd HH:mm:ss")
        $r.DaysUntilExpiry = [int]($cert.NotAfter - (Get-Date)).TotalDays
        $r.Thumbprint      = $cert.Thumbprint
        $sanExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" }
        if ($sanExt) { $r.SANs = $sanExt.Format($false) }
    } catch { $r.SslError = $_.Exception.InnerException.Message
              if (-not $r.SslError) { $r.SslError = $_.Exception.Message }
    } finally { if ($ssl) { $ssl.Dispose() }; if ($client) { $client.Close() } }
    return $r
}

function Invoke-HttpHealthCheck {
    <# HTTP GET to host:port/path, returns status code and response time. #>
    param([string]$Target, [int]$Port, [string]$Path, [string]$Scheme="https",
          [int]$TimeoutMs=5000, [int]$ExpectedStatusCode=200)
    $url = "${Scheme}://${Target}:${Port}${Path}"
    $r = @{ Url=$url; StatusCode=-1; ResponseTimeMs=-1; IsExpectedStatus=$false; HttpError=$null }
    try {
        $req = [System.Net.HttpWebRequest]::Create($url)
        $req.Method = "GET"; $req.Timeout = $TimeoutMs; $req.AllowAutoRedirect = $false
        $req.UserAgent = "Test-ConnectivityBulk/2.0"
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $resp = $req.GetResponse(); $sw.Stop()
            $r.StatusCode = [int]$resp.StatusCode; $resp.Close()
        } catch [System.Net.WebException] {
            $sw.Stop()
            if ($_.Exception.Response) {
                $r.StatusCode = [int]$_.Exception.Response.StatusCode
                $_.Exception.Response.Close()
            } else { $r.HttpError = $_.Exception.Message }
        }
        $r.ResponseTimeMs = $sw.ElapsedMilliseconds
        $r.IsExpectedStatus = ($r.StatusCode -eq $ExpectedStatusCode)
    } catch { $r.HttpError = $_.Exception.Message }
    return $r
}

function Get-TcpBanner {
    <# Connects to a port and reads the service banner. #>
    param([string]$Target, [int]$Port, [int]$MaxBytes=1024, [int]$TimeoutMs=3000)
    $r = @{ Banner=""; BannerError=$null }
    $c = $null
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $ct = $c.BeginConnect($Target, $Port, $null, $null)
        if (-not $ct.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -or -not $c.Connected) {
            $r.BannerError = "Connect timeout"; return $r
        }
        $c.EndConnect($ct)
        $s = $c.GetStream(); $s.ReadTimeout = $TimeoutMs
        $buf = New-Object byte[] $MaxBytes
        try {
            $n = $s.Read($buf, 0, $MaxBytes)
            if ($n -gt 0) { $r.Banner = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n).Trim() }
        } catch [System.IO.IOException] { $r.BannerError = "No banner (timeout)" }
    } catch { $r.BannerError = $_.Exception.Message
    } finally { if ($c) { $c.Close() } }
    return $r
}

# ── Utility functions (main scope only) ─────────────────────────────────────

function Expand-CidrRange {
    <# Expands a CIDR notation string to individual IP addresses. #>
    param([Parameter(Mandatory)][string]$Cidr)
    $parts = $Cidr -split '/'
    if ($parts.Count -ne 2) { throw "Invalid CIDR: $Cidr" }
    $ip = [System.Net.IPAddress]::Parse($parts[0])
    $prefix = [int]$parts[1]
    if ($prefix -lt 8 -or $prefix -gt 30) { throw "Prefix must be /8 to /30. Got /$prefix" }
    $bytes = $ip.GetAddressBytes(); [Array]::Reverse($bytes)
    $ipInt = [BitConverter]::ToUInt32($bytes, 0)
    $hostBits = 32 - $prefix
    $netInt = [uint32]($ipInt -band ([uint32]::MaxValue -shl $hostBits))
    $bcastInt = [uint32]($netInt -bor (([uint32]1 -shl $hostBits) - 1))
    $results = [System.Collections.Generic.List[string]]::new()
    for ($i = $netInt + 1; $i -lt $bcastInt; $i++) {
        $b = [BitConverter]::GetBytes([uint32]$i); [Array]::Reverse($b)
        $results.Add(([System.Net.IPAddress]::new($b)).ToString())
    }
    return ,$results
}

function Compare-WatchResults {
    <# Diffs previous and current scan results, returns list of changes. #>
    param($Previous, $Current)
    $changes = [System.Collections.Generic.List[PSCustomObject]]::new()
    $prev = @{}; foreach ($r in $Previous) { $prev[$r.Host] = $r }
    foreach ($r in $Current) {
        if ($prev.ContainsKey($r.Host)) {
            $p = $prev[$r.Host]
            if ($p.PingStatus -ne $r.PingStatus) {
                $type = if ($r.PingStatus -eq "Reachable") { "RECOVERED" } else { "NEW FAILURE" }
                $changes.Add([PSCustomObject]@{ Host=$r.Host; Type=$type; Detail="$($p.PingStatus) -> $($r.PingStatus)" })
            }
            foreach ($prop in $r.PSObject.Properties) {
                if ($prop.Name -like "Port_*" -and $p.PSObject.Properties[$prop.Name]) {
                    if ($p.$($prop.Name) -ne $r.$($prop.Name)) {
                        $changes.Add([PSCustomObject]@{ Host=$r.Host; Type="PORT CHANGE"; Detail="$($prop.Name): $($p.$($prop.Name)) -> $($r.$($prop.Name))" })
                    }
                }
            }
        }
    }
    return ,$changes
}

# Pipeline target accumulator
$pipelineTargets = [System.Collections.Generic.List[string]]::new()

} # end begin

# =============================================================================
# PROCESS — collect pipeline input
# =============================================================================
process {
    if ($Target) {
        foreach ($t in $Target) { $pipelineTargets.Add($t.Trim()) }
    }
}

# =============================================================================
# END — build target list, run tests, produce output
# =============================================================================
end {
try {
    Write-Log "Starting $($Config.ScriptName)"

    # ── Build target list ───────────────────────────────────────────────────
    $rawTargets = [System.Collections.Generic.List[string]]::new()

    if ($pipelineTargets.Count -gt 0) {
        $rawTargets.AddRange($pipelineTargets)
        Write-Log "Received $($rawTargets.Count) target(s) from parameters/pipeline"
    } elseif ($PSBoundParameters.ContainsKey('HostFile') -or
              ($Config.Targets.Count -eq 0 -and (Test-Path $Config.HostFile))) {
        $fileTargets = Get-Content $Config.HostFile |
            Where-Object { $_.Trim() -ne '' -and -not $_.StartsWith('#') }
        $rawTargets.AddRange($fileTargets)
        Write-Log "Loaded $($rawTargets.Count) host(s) from $($Config.HostFile)"
    } elseif ($Config.Targets.Count -gt 0) {
        $rawTargets.AddRange($Config.Targets)
        Write-Log "Using inline target list ($($rawTargets.Count) host(s))"
    } else {
        throw "No targets. Pass hostnames, use -HostFile, or set Config.Targets."
    }

    # CIDR expansion
    $targets = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $rawTargets) {
        if ($entry -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$') {
            $expanded = Expand-CidrRange -Cidr $entry
            Write-Log "Expanded CIDR $entry -> $($expanded.Count) host(s)"
            if ($expanded.Count -gt 1024) {
                Write-Log "Large subnet: $($expanded.Count) hosts from $entry" -Level WARNING
            }
            $targets.AddRange($expanded)
        } else {
            $targets.Add($entry.Trim())
        }
    }

    if ($targets.Count -eq 0) { Write-Log "Target list is empty." -Level WARNING; return }

    $checkPorts = (-not $PingOnly) -and $Config.TcpPorts.Count -gt 0
    $doSsl      = (-not $PingOnly) -and $TestSsl
    $doHttp     = (-not $PingOnly) -and $TestHttp
    $doBanner   = (-not $PingOnly) -and $GrabBanner

    if ($checkPorts) { Write-Log "TCP ports: $($Config.TcpPorts -join ', ')" }
    if ($doSsl)      { Write-Log "SSL cert check enabled (warn at $($Config.CertWarnDays) days)" }
    if ($doHttp)     { Write-Log "HTTP health check: $TestHttp (expect $($Config.ExpectedStatusCode))" }
    if ($doBanner)   { Write-Log "Banner grab enabled" }
    Write-Log "Workers: $($Config.MaxConcurrent)  |  Targets: $($targets.Count)"

    # ── Build InitialSessionState with functions ────────────────────────────
    $functionsToInject = @('Resolve-HostDns','Test-HostPing','Test-TcpPort','Get-Traceroute',
                           'Get-SslCertificate','Invoke-HttpHealthCheck','Get-TcpBanner')
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($fname in $functionsToInject) {
        $body = (Get-Command $fname).ScriptBlock.ToString()
        $iss.Commands.Add(
            [System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($fname, $body)
        )
    }

    # Disable cert validation process-wide for HTTP checks (diagnostic tool)
    $originalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    if ($doHttp) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { param($s,$c,$ch,$e) $true }
    }

    # ── Runspace scriptblock ────────────────────────────────────────────────
    $scriptBlock = {
        param([hashtable]$P)
        $dns = Resolve-HostDns -Target $P.Target

        # Ping
        $ping = if (-not $P.NoPing) {
            Test-HostPing -Target $P.Target -Count $P.PingCount -Timeout $P.PingTimeout
        } else {
            @{ Reachable="Skipped"; IPAddress=$dns.ForwardIP; Sent=0; Received=0; MinMs=-1; AvgMs=-1; MaxMs=-1 }
        }

        # TCP ports
        $portResults = @{}; $openPorts = [System.Collections.Generic.List[int]]::new()
        if (-not $P.PingOnly -and $P.TcpPorts.Count -gt 0) {
            foreach ($port in $P.TcpPorts) {
                $open = Test-TcpPort -Target $P.Target -Port $port -TimeoutMs $P.TcpTimeoutMs
                $portResults[$port] = if ($open) { "Open" } else { "Closed/Filtered" }
                if ($open) { $openPorts.Add($port) }
            }
        }

        # Banner
        $bannerResults = @{}
        if (-not $P.PingOnly -and $P.GrabBanner -and $openPorts.Count -gt 0) {
            foreach ($port in $openPorts) {
                $bannerResults[$port] = Get-TcpBanner -Target $P.Target -Port $port `
                    -MaxBytes $P.BannerMaxBytes -TimeoutMs $P.BannerTimeoutMs
            }
        }

        # SSL
        $sslResult = $null
        if (-not $P.PingOnly -and $P.TestSsl) {
            $sslPort = if ($openPorts.Count -gt 0) { $openPorts[0] } else { $P.SslPort }
            $sslResult = Get-SslCertificate -Target $P.Target -Port $sslPort -TimeoutMs $P.TcpTimeoutMs
        }

        # HTTP
        $httpResult = $null
        if (-not $P.PingOnly -and $P.TestHttp) {
            $httpPort = if ($openPorts.Count -gt 0) { $openPorts[0] } else { $P.SslPort }
            $httpResult = Invoke-HttpHealthCheck -Target $P.Target -Port $httpPort `
                -Path $P.TestHttp -Scheme $P.HttpScheme `
                -TimeoutMs $P.HttpTimeoutMs -ExpectedStatusCode $P.ExpectedStatusCode
        }

        # Traceroute
        $lastHop = $null
        if ($P.TracerouteOnFail -and $ping.Reachable -eq $false) {
            $lastHop = Get-Traceroute -Target $P.Target
        }

        return @{
            Target=$P.Target; Dns=$dns; Ping=$ping; PortResults=$portResults
            BannerResults=$bannerResults; SslResult=$sslResult; HttpResult=$httpResult; LastHop=$lastHop
        }
    }

    # ── Watch loop ──────────────────────────────────────────────────────────
    $iteration = 0
    $previousResults = $null
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Config.MaxConcurrent, $iss, $Host)
    $pool.Open()

    do {
        $iteration++
        if ($iteration -gt 1) {
            Write-Log "Next scan in $($Config.WatchIntervalSec)s... (Ctrl+C to stop)"
            Start-Sleep -Seconds $Config.WatchIntervalSec
            Clear-Host
        }
        if ($Config.WatchIntervalSec -gt 0) { Write-Log "Watch iteration $iteration" }

        # Build per-host params hashtable
        $hostParams = @{
            PingCount=$Config.PingCount; PingTimeout=$Config.PingTimeout
            TcpPorts=$Config.TcpPorts; TcpTimeoutMs=$Config.TcpTimeoutMs
            NoPing=[bool]$NoPing; PingOnly=[bool]$PingOnly
            TracerouteOnFail=$Config.TracerouteOnFail
            TestSsl=[bool]$doSsl; SslPort=$Config.SslPort; CertWarnDays=$Config.CertWarnDays
            TestHttp=$(if ($doHttp) { $TestHttp } else { $null })
            HttpScheme=$Config.HttpScheme; HttpTimeoutMs=$Config.HttpTimeoutMs
            ExpectedStatusCode=$Config.ExpectedStatusCode
            GrabBanner=[bool]$doBanner; BannerMaxBytes=$Config.BannerMaxBytes; BannerTimeoutMs=$Config.BannerTimeoutMs
        }

        # Dispatch
        $jobs = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($t in $targets) {
            $p = $hostParams.Clone(); $p.Target = $t
            $ps = [PowerShell]::Create().AddScript($scriptBlock).AddArgument($p)
            $ps.RunspacePool = $pool
            $jobs.Add(@{ PowerShell=$ps; Handle=$ps.BeginInvoke(); Target=$t })
        }
        Write-Log "Dispatched $($jobs.Count) test(s)"

        # Collect
        $results = [System.Collections.Generic.List[PSCustomObject]]::new()
        $done = 0
        foreach ($job in $jobs) {
            try {
                $out = $job.PowerShell.EndInvoke($job.Handle)
                $done++
                if ($out -and $out.Count -gt 0) {
                    $d = $out[0]; $dns = $d.Dns; $ping = $d.Ping

                    $lossPct = if ($ping.Sent -gt 0) {
                        [math]::Round((($ping.Sent - $ping.Received) / $ping.Sent) * 100, 1)
                    } else { 0 }

                    # Determine ping status — handle runspace serialization edge cases
                    $pingReachable = $ping.Reachable
                    $pingStatus = if ("$pingReachable" -eq "Skipped") { "Skipped" }
                                  elseif ($pingReachable -eq $true -or "$pingReachable" -eq "True") { "Reachable" }
                                  else { "Unreachable" }
                    $pingOk = ($pingStatus -eq "Reachable")

                    $row = [ordered]@{
                        Host       = $d.Target
                        ResolvedIP = $dns.ForwardIP
                        ReverseDNS = $dns.ReverseDNS
                        PingStatus = $pingStatus
                        PingSent   = $ping.Sent
                        PingRecv   = $ping.Received
                        PingLossPct = $lossPct
                        PingMinMs  = if ($pingOk) { $ping.MinMs } else { "" }
                        PingAvgMs  = if ($pingOk) { $ping.AvgMs } else { "" }
                        PingMaxMs  = if ($pingOk) { $ping.MaxMs } else { "" }
                    }

                    foreach ($port in $Config.TcpPorts) {
                        $st = if ($d.PortResults.ContainsKey($port)) { $d.PortResults[$port] } else { "N/A" }
                        $row["Port_$port"] = $st
                    }

                    if ($doBanner) {
                        foreach ($port in $Config.TcpPorts) {
                            $b = if ($d.BannerResults.ContainsKey($port)) { $d.BannerResults[$port].Banner } else { "" }
                            $row["Banner_$port"] = $b
                        }
                    }

                    if ($doSsl -and $d.SslResult) {
                        $ssl = $d.SslResult
                        $row["SslSubject"]    = $ssl.Subject
                        $row["SslIssuer"]     = $ssl.Issuer
                        $row["SslExpiry"]     = $ssl.NotAfter
                        $row["SslDaysLeft"]   = $ssl.DaysUntilExpiry
                        $row["SslThumbprint"] = $ssl.Thumbprint
                        $row["SslSANs"]       = $ssl.SANs
                        $row["SslStatus"]     = if ($ssl.SslError) { "ERROR" }
                                                elseif ($ssl.DaysUntilExpiry -lt 0) { "EXPIRED" }
                                                elseif ($ssl.DaysUntilExpiry -le $Config.CertWarnDays) { "WARNING" }
                                                else { "OK" }
                    }

                    if ($doHttp -and $d.HttpResult) {
                        $http = $d.HttpResult
                        $row["HttpUrl"]        = $http.Url
                        $row["HttpStatusCode"] = $http.StatusCode
                        $row["HttpResponseMs"] = $http.ResponseTimeMs
                        $row["HttpStatus"]     = if ($http.HttpError) { "ERROR" }
                                                 elseif ($http.IsExpectedStatus) { "OK" }
                                                 else { "UNEXPECTED" }
                    }

                    if ($Config.TracerouteOnFail) {
                        $row["LastHop"] = if ($d.LastHop) { $d.LastHop } else { "" }
                    }
                    $row["TestedAt"] = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    $results.Add([PSCustomObject]$row)
                }
                if ($done % 25 -eq 0 -or $done -eq $jobs.Count) {
                    Write-Log "Progress: $done/$($jobs.Count)"
                }
            } catch {
                Write-Log "Error collecting $($job.Target): $_" -Level ERROR
            } finally { $job.PowerShell.Dispose() }
        }

        # ── Counts ──────────────────────────────────────────────────────────
        $reachable   = @($results | Where-Object { $_.PingStatus -eq "Reachable" }).Count
        $unreachable = @($results | Where-Object { $_.PingStatus -eq "Unreachable" }).Count
        $skipped     = @($results | Where-Object { $_.PingStatus -eq "Skipped" }).Count
        Write-Log "Done — Reachable: $reachable  Unreachable: $unreachable  Skipped: $skipped"

        # ── Export (first iteration only in watch mode) ─────────────────────
        if ($iteration -eq 1) {
            if (-not (Test-Path $Config.OutputDir)) { New-Item -ItemType Directory -Path $Config.OutputDir | Out-Null }
            $ts = Get-Date -Format "yyyyMMdd_HHmmss"
            $csvFile = Join-Path $Config.OutputDir "ConnectivityReport_$ts.csv"
            $results | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
            Write-Log "CSV: $csvFile"

            if ($Config.GenerateHtml) {
                $htmlFile = Join-Path $Config.OutputDir "ConnectivityReport_$ts.html"
                # ── HTML report ─────────────────────────────────────────────
                $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                $lossHosts = @($results | Where-Object { $_.PingLossPct -gt 0 -and $_.PingStatus -ne "Skipped" }).Count
                $certWarn  = if ($doSsl) { @($results | Where-Object { $_.SslStatus -eq "WARNING" -or $_.SslStatus -eq "EXPIRED" }).Count } else { 0 }
                $httpFail  = if ($doHttp) { @($results | Where-Object { $_.HttpStatus -ne "OK" }).Count } else { 0 }

                $ph = [System.Text.StringBuilder]::new()
                foreach ($p in $Config.TcpPorts) { [void]$ph.Append("<th>Port $p</th>") }
                if ($doBanner) { foreach ($p in $Config.TcpPorts) { [void]$ph.Append("<th>Banner $p</th>") } }
                $sslH = if ($doSsl)  { "<th>SSL Status</th><th>Subject</th><th>Expiry</th><th>Days</th>" } else { "" }
                $httpH = if ($doHttp) { "<th>HTTP</th><th>Code</th><th>ms</th>" } else { "" }
                $trH = if ($Config.TracerouteOnFail) { "<th>Last Hop</th>" } else { "" }

                $trs = [System.Text.StringBuilder]::new()
                foreach ($r in $results) {
                    $pc = if ($r.PingStatus -eq "Reachable") {"pass"} elseif ($r.PingStatus -eq "Skipped") {""} else {"fail"}
                    [void]$trs.Append("<tr><td>$([System.Net.WebUtility]::HtmlEncode($r.Host))</td>")
                    [void]$trs.Append("<td>$($r.ResolvedIP)</td><td>$($r.ReverseDNS)</td>")
                    [void]$trs.Append("<td class=`"$pc`">$($r.PingStatus)</td>")
                    [void]$trs.Append("<td>$($r.PingLossPct)%</td>")
                    [void]$trs.Append("<td>$($r.PingMinMs)</td><td>$($r.PingAvgMs)</td><td>$($r.PingMaxMs)</td>")
                    foreach ($p in $Config.TcpPorts) {
                        $v = $r."Port_$p"; $cls = if ($v -eq "Open"){"pass"} elseif ($v -eq "N/A"){""} else {"fail"}
                        [void]$trs.Append("<td class=`"$cls`">$v</td>")
                    }
                    if ($doBanner) { foreach ($p in $Config.TcpPorts) {
                        $b = $r."Banner_$p"; [void]$trs.Append("<td><code>$([System.Net.WebUtility]::HtmlEncode("$b".Substring(0, [math]::Min(80,"$b".Length))))</code></td>")
                    }}
                    if ($doSsl) {
                        $sc = if ($r.SslStatus -eq "OK"){"pass"} elseif ($r.SslStatus -eq "WARNING"){"warn"} elseif ($r.SslStatus -eq "EXPIRED"){"fail"} else {""}
                        [void]$trs.Append("<td class=`"$sc`">$($r.SslStatus)</td><td>$([System.Net.WebUtility]::HtmlEncode($r.SslSubject))</td><td>$($r.SslExpiry)</td><td>$($r.SslDaysLeft)</td>")
                    }
                    if ($doHttp) {
                        $hc = if ($r.HttpStatus -eq "OK"){"pass"} else {"fail"}
                        [void]$trs.Append("<td class=`"$hc`">$($r.HttpStatus)</td><td>$($r.HttpStatusCode)</td><td>$($r.HttpResponseMs)</td>")
                    }
                    if ($Config.TracerouteOnFail) { [void]$trs.Append("<td>$($r.LastHop)</td>") }
                    [void]$trs.AppendLine("</tr>")
                }

                $extraCards = ""
                if ($lossHosts -gt 0) { $extraCards += "<div class=`"card warn`"><div class=`"count`">$lossHosts</div><div class=`"label`">Packet Loss</div></div>" }
                if ($doSsl -and $certWarn -gt 0) { $extraCards += "<div class=`"card warn`"><div class=`"count`">$certWarn</div><div class=`"label`">Cert Issues</div></div>" }
                if ($doHttp -and $httpFail -gt 0) { $extraCards += "<div class=`"card bad`"><div class=`"count`">$httpFail</div><div class=`"label`">HTTP Failures</div></div>" }

                $html = @"
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connectivity Report</title><style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;color:#1a1a2e;line-height:1.5;padding:2rem}
.wrap{max-width:1800px;margin:0 auto}
.header{background:#1a1a2e;color:#fff;padding:1.5rem 2rem;border-radius:10px 10px 0 0}
.header h1{font-size:1.5rem;margin-bottom:.3rem}.header .meta{opacity:.8;font-size:.85rem}
.cards{display:flex;gap:.75rem;padding:1.25rem 2rem;background:#fff;border-bottom:1px solid #e0e0e0;flex-wrap:wrap}
.card{flex:1;min-width:120px;padding:1rem;border-radius:8px;text-align:center}
.card .count{font-size:2rem;font-weight:700}.card .label{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;margin-top:.25rem}
.card.good{background:#f0fdf4;color:#16a34a}.card.bad{background:#fef2f2;color:#dc2626}
.card.warn{background:#fefce8;color:#ca8a04}.card.neutral{background:#eff6ff;color:#2563eb}
.section{background:#fff;padding:1.5rem 2rem;border-radius:0 0 10px 10px;overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.82rem;white-space:nowrap}
th{text-align:left;padding:.5rem .4rem;border-bottom:2px solid #d1d5db;color:#6b7280;font-weight:600;font-size:.72rem;text-transform:uppercase;letter-spacing:.05em}
td{padding:.5rem .4rem;border-bottom:1px solid #f3f4f6;vertical-align:top}
tr:hover{background:#f9fafb}.pass{background:#f0fdf4;color:#16a34a;font-weight:600}
.fail{background:#fef2f2;color:#dc2626;font-weight:600}.warn{background:#fefce8;color:#ca8a04;font-weight:600}
code{font-size:.78rem;color:#6b7280}
.footer{text-align:center;padding:1rem;color:#9ca3af;font-size:.8rem}
</style></head><body><div class="wrap">
<div class="header"><h1>Connectivity Report</h1><div class="meta">$now &mdash; $($targets.Count) hosts &mdash; ports: $(if($Config.TcpPorts.Count -gt 0){$Config.TcpPorts -join ', '}else{'none'})</div></div>
<div class="cards">
<div class="card neutral"><div class="count">$($targets.Count)</div><div class="label">Total</div></div>
<div class="card good"><div class="count">$reachable</div><div class="label">Reachable</div></div>
<div class="card bad"><div class="count">$unreachable</div><div class="label">Unreachable</div></div>
$extraCards
</div>
<div class="section"><table><thead><tr><th>Host</th><th>IP</th><th>rDNS</th><th>Ping</th><th>Loss</th><th>Min</th><th>Avg</th><th>Max</th>$($ph.ToString())$sslH$httpH$trH</tr></thead><tbody>$($trs.ToString())</tbody></table></div>
</div><div class="footer">Test-ConnectivityBulk &mdash; $now</div></body></html>
"@
                [System.IO.File]::WriteAllText($htmlFile, $html, [System.Text.Encoding]::UTF8)
                Write-Log "HTML: $htmlFile"
            }
        }

        # ── Console summary ─────────────────────────────────────────────────
        $sep = [string]::new([char]0x2550, 76)
        $div = [string]::new([char]0x2500, 76)
        $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $portLbl = if ($checkPorts) { "ports: $($Config.TcpPorts -join ', ')" } else { "no port check" }

        Write-Summary ""
        Write-Summary $sep -Color Yellow
        Write-Summary "  Connectivity Test  —  $now$(if ($Config.WatchIntervalSec -gt 0) { "  [iteration $iteration]" })" -Color Yellow
        Write-Summary "  Targets: $($targets.Count)  |  $portLbl  |  Workers: $($Config.MaxConcurrent)" -Color Yellow
        Write-Summary $sep -Color Yellow
        Write-Summary ""

        # Reachable hosts (shown when mostly unreachable — more useful than listing 200+ dead hosts)
        $rh = @($results | Where-Object { $_.PingStatus -eq "Reachable" })
        $uh = @($results | Where-Object { $_.PingStatus -eq "Unreachable" })

        if ($rh.Count -gt 0 -and $rh.Count -le $uh.Count) {
            Write-Summary "  REACHABLE HOSTS ($($rh.Count) of $($results.Count))" -Color Cyan
            Write-Summary $div -Color Cyan
            foreach ($h in $rh) {
                $line = "  {0,-42} {1}  avg: {2}ms" -f $h.Host, $h.ResolvedIP, $h.PingAvgMs
                Write-Summary $line -Color Green
            }
            Write-Summary ""
        }

        # Unreachable hosts (capped at 20 to avoid flooding the console)
        if ($uh.Count -gt 0) {
            Write-Summary "  UNREACHABLE HOSTS ($($uh.Count))" -Color Cyan
            Write-Summary $div -Color Cyan
            $showCount = [math]::Min($uh.Count, 20)
            for ($idx = 0; $idx -lt $showCount; $idx++) {
                $h = $uh[$idx]
                $line = "  {0,-42} resolved: {1}" -f $h.Host, $h.ResolvedIP
                if ($Config.TracerouteOnFail -and $h.LastHop) { $line += "  hop: $($h.LastHop)" }
                Write-Summary $line -Color Red
            }
            if ($uh.Count -gt 20) {
                Write-Summary "  ... and $($uh.Count - 20) more (see CSV for full list)" -Color DarkGray
            }
            Write-Summary ""
        }

        # Failed ports
        if ($checkPorts) {
            foreach ($port in $Config.TcpPorts) {
                $fp = @($results | Where-Object { $_.PingStatus -ne "Unreachable" -and $_."Port_$port" -eq "Closed/Filtered" })
                if ($fp.Count -gt 0) {
                    Write-Summary "  FAILED PORT $port ($($fp.Count) host(s))" -Color Cyan
                    Write-Summary $div -Color Cyan
                    foreach ($h in $fp) { Write-Summary "  $($h.Host)" -Color Red }
                    Write-Summary ""
                }
            }
        }

        # High latency
        $slow = @($results | Where-Object { $_.PingStatus -eq "Reachable" -and $_.PingAvgMs -gt 100 })
        if ($slow.Count -gt 0) {
            Write-Summary "  HIGH LATENCY (avg > 100ms)" -Color Cyan
            Write-Summary $div -Color Cyan
            foreach ($h in ($slow | Sort-Object PingAvgMs -Descending)) {
                Write-Summary ("  {0,-42} avg: {1}ms  (min:{2} / max:{3})" -f $h.Host,$h.PingAvgMs,$h.PingMinMs,$h.PingMaxMs) -Color Yellow
            }
            Write-Summary ""
        }

        # Packet loss
        $lossHosts = @($results | Where-Object { $_.PingLossPct -gt $Config.LossWarnPct -and $_.PingStatus -eq "Reachable" })
        if ($lossHosts.Count -gt 0) {
            Write-Summary "  PACKET LOSS DETECTED ($($lossHosts.Count) host(s))" -Color Cyan
            Write-Summary $div -Color Cyan
            foreach ($h in ($lossHosts | Sort-Object PingLossPct -Descending)) {
                Write-Summary ("  {0,-42} loss: {1}% ({2}/{3} received)" -f $h.Host,$h.PingLossPct,$h.PingRecv,$h.PingSent) -Color Yellow
            }
            Write-Summary ""
        }

        # SSL certs
        if ($doSsl) {
            $certExpiring = @($results | Where-Object { $_.SslStatus -eq "WARNING" })
            $certExpired  = @($results | Where-Object { $_.SslStatus -eq "EXPIRED" })
            $certError    = @($results | Where-Object { $_.SslStatus -eq "ERROR" })
            if ($certExpired.Count -gt 0) {
                Write-Summary "  SSL CERTIFICATES EXPIRED ($($certExpired.Count))" -Color Cyan
                Write-Summary $div -Color Cyan
                foreach ($h in $certExpired) {
                    Write-Summary ("  {0,-42} {1}  expired: {2}  ({3} days)" -f $h.Host,$h.SslSubject,$h.SslExpiry,$h.SslDaysLeft) -Color Red
                }
                Write-Summary ""
            }
            if ($certExpiring.Count -gt 0) {
                Write-Summary "  SSL CERTIFICATES EXPIRING within $($Config.CertWarnDays) days ($($certExpiring.Count))" -Color Cyan
                Write-Summary $div -Color Cyan
                foreach ($h in ($certExpiring | Sort-Object SslDaysLeft)) {
                    Write-Summary ("  {0,-42} {1}  expires: {2}  ({3} days)" -f $h.Host,$h.SslSubject,$h.SslExpiry,$h.SslDaysLeft) -Color Yellow
                }
                Write-Summary ""
            }
            if ($certError.Count -gt 0) {
                Write-Summary "  SSL ERRORS ($($certError.Count))" -Color Cyan
                Write-Summary $div -Color Cyan
                foreach ($h in $certError) { Write-Summary "  $($h.Host)" -Color Red }
                Write-Summary ""
            }
        }

        # HTTP failures
        if ($doHttp) {
            $httpFails = @($results | Where-Object { $_.HttpStatus -ne "OK" })
            if ($httpFails.Count -gt 0) {
                Write-Summary "  HTTP HEALTH CHECK FAILURES ($($httpFails.Count))" -Color Cyan
                Write-Summary $div -Color Cyan
                foreach ($h in $httpFails) {
                    $detail = if ($h.HttpStatus -eq "ERROR") { "ERROR" } else { "expected $($Config.ExpectedStatusCode) got $($h.HttpStatusCode)" }
                    Write-Summary ("  {0,-42} {1}  ({2}ms)" -f $h.Host, $detail, $h.HttpResponseMs) -Color Red
                }
                Write-Summary ""
            }
        }

        # Banners
        if ($doBanner) {
            foreach ($port in $Config.TcpPorts) {
                $withBanner = @($results | Where-Object { $_."Banner_$port" -ne "" -and $_."Banner_$port" -ne $null })
                if ($withBanner.Count -gt 0) {
                    Write-Summary "  BANNERS — PORT $port ($($withBanner.Count) host(s))" -Color Cyan
                    Write-Summary $div -Color Cyan
                    foreach ($h in $withBanner) {
                        $b = $h."Banner_$port"
                        if ($b.Length -gt 60) { $b = $b.Substring(0, 60) + "..." }
                        Write-Summary ("  {0,-20} {1}" -f $h.Host, $b) -Color White
                    }
                    Write-Summary ""
                }
            }
        }

        # Watch changes
        if ($previousResults -and $Config.WatchIntervalSec -gt 0) {
            $changes = Compare-WatchResults -Previous $previousResults -Current $results
            if ($changes.Count -gt 0) {
                Write-Summary "  CHANGES SINCE LAST SCAN ($($changes.Count))" -Color Magenta
                Write-Summary $div -Color Magenta
                foreach ($ch in $changes) {
                    $clr = if ($ch.Type -eq "RECOVERED") { "Green" } else { "Red" }
                    Write-Summary ("  {0,-14} {1,-30} {2}" -f $ch.Type, $ch.Host, $ch.Detail) -Color $clr
                }
                Write-Summary ""
            } else {
                Write-Summary "  No changes since last scan." -Color Green
                Write-Summary ""
            }
        }

        # Totals
        Write-Summary $sep -Color Cyan
        $tl = "  TOTAL: {0} hosts  |  {1} reachable  |  {2} unreachable" -f $targets.Count, $reachable, $unreachable
        if ($skipped -gt 0) { $tl += "  |  $skipped skipped" }
        if ($checkPorts) {
            foreach ($port in $Config.TcpPorts) {
                $oc = @($results | Where-Object { $_."Port_$port" -eq "Open" }).Count
                $cc = @($results | Where-Object { $_."Port_$port" -eq "Closed/Filtered" }).Count
                $tl += "  |  ${port}: ${oc}/${cc}"
            }
        }
        Write-Summary $tl -Color Cyan
        if ($iteration -eq 1 -and $csvFile)  { Write-Summary "  CSV: $csvFile" -Color Cyan }
        if ($iteration -eq 1 -and $htmlFile) { Write-Summary "  HTML: $htmlFile" -Color Cyan }
        Write-Summary $sep -Color Cyan
        Write-Summary ""

        $previousResults = $results

    } while ($Config.WatchIntervalSec -gt 0)

    $pool.Close(); $pool.Dispose()

    # Restore cert validation callback
    if ($doHttp) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
    }

    Write-Log "Completed $($Config.ScriptName) successfully"
    exit 0
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    if ($pool) { try { $pool.Close(); $pool.Dispose() } catch { } }
    exit 1
}
} # end end
