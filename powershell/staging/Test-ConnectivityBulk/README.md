# Test-ConnectivityBulk

CLI-first bulk connectivity tester. Pings, port scans, grabs service banners, inspects SSL certificates, and checks HTTP health endpoints — all in parallel via a runspace pool. Accepts hosts positionally, via pipeline, from a file, or as CIDR ranges.

## Quick Start

```powershell
# Positional — just list the hosts
.\Test-ConnectivityBulk.ps1 server01 server02 10.0.1.1

# Pipeline — from a file, AD, or any command
Get-Content servers.txt | .\Test-ConnectivityBulk.ps1
Get-ADComputer -Filter * | Select -Expand Name | .\Test-ConnectivityBulk.ps1

# CIDR subnet sweep
.\Test-ConnectivityBulk.ps1 "10.0.1.0/24" -PingOnly

# Full check — ports, SSL cert, HTTP health, HTML report
.\Test-ConnectivityBulk.ps1 web01,web02 -TcpPorts 443 -TestSsl -TestHttp "/health" -GenerateHtml

# Watch mode — monitor every 30 seconds
.\Test-ConnectivityBulk.ps1 gw01,gw02 -TcpPorts 443 -Watch 30
```

## Prerequisites

- PowerShell 5.1+
- No external modules required
- `tracert` in PATH (only if `TracerouteOnFail` is enabled in config)

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Target` | `string[]` | Hostnames, IPs, or CIDR ranges. Position 0. Accepts pipeline. Aliases: `Host`, `ComputerName`, `IPAddress`. |
| `-HostFile` | `string` | Text file with one host/IP/CIDR per line. `#` comments supported. |
| `-TcpPorts` | `int[]` | TCP ports to test. Pass `0` to skip. Default: `443`. |
| `-TestSsl` | `switch` | Inspect the SSL/TLS certificate on the first open port (or 443). |
| `-TestHttp` | `string` | URL path for HTTP health check (must start with `/`). Constructs `https://host:port/path`. |
| `-GrabBanner` | `switch` | Read service banners from open TCP ports (SSH, SMTP, FTP, etc.). |
| `-PingOnly` | `switch` | Skip all TCP/SSL/HTTP/banner checks. Ping and DNS only. |
| `-NoPing` | `switch` | Skip ICMP ping. Useful when ICMP is blocked but TCP works. |
| `-Watch` | `int` | Repeat every N seconds. `0` = one-shot (default). Ctrl+C to stop. |
| `-MaxConcurrent` | `int` | Parallel workers. Range: 1-200. Default: `10`. |
| `-CertWarnDays` | `int` | Flag certs expiring within N days. Range: 1-365. Default: `30`. |
| `-ExpectedStatusCode` | `int` | Expected HTTP status. Range: 100-599. Default: `200`. |
| `-GenerateHtml` | `switch` | Produce a self-contained HTML report alongside the CSV. |

## Host Input Methods

Hosts are accepted from multiple sources (checked in this priority):

1. **Positional/pipeline** — `.\Test-ConnectivityBulk.ps1 host1 host2` or `"host1" | .\Test-ConnectivityBulk.ps1`
2. **`-HostFile`** — text file, one entry per line
3. **`$Config.Targets`** — inline array in the script
4. **`$Config.HostFile`** — fallback file path

All sources support **CIDR notation** (e.g., `10.0.1.0/24`). CIDRs are expanded to individual host addresses before testing. Prefix lengths `/8` through `/30` are supported; a warning is logged for subnets larger than 1024 hosts.

## Test Capabilities

### ICMP Ping (default)

Sends `PingCount` (default 4) ICMP echo requests per host. Reports:
- Reachable/Unreachable status
- Min/Avg/Max roundtrip latency
- Packet loss percentage
- Hosts with loss > `LossWarnPct` are flagged in the summary

Skip with `-NoPing`. Do ping only with `-PingOnly`.

### DNS Resolution (always)

Forward lookup via `[System.Net.Dns]::GetHostEntry()`, then reverse lookup on the resolved IP. Populates `ResolvedIP` and `ReverseDNS` columns.

### TCP Port Check

Tests each port in `-TcpPorts` using async `TcpClient.BeginConnect()` with a configurable timeout. Reports `Open` or `Closed/Filtered` per port.

### Banner Grab (`-GrabBanner`)

After a TCP port is confirmed open, connects again and reads whatever the server sends within the timeout. Many protocols send a banner immediately:
- SSH: `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`
- SMTP: `220 mail.example.com ESMTP Postfix`
- FTP: `220 ProFTPD Server ready`
- MySQL: version string in binary protocol header

Banners are ASCII-decoded and trimmed. Stored as `Banner_<port>` columns.

### SSL Certificate Inspection (`-TestSsl`)

Connects via `SslStream`, accepts all certificates (including expired/self-signed) for inspection, and reports:

| Field | Description |
|-------|-------------|
| `SslSubject` | Certificate subject (CN) |
| `SslIssuer` | Issuer CN |
| `SslExpiry` | Expiration date |
| `SslDaysLeft` | Days until expiry (negative = expired) |
| `SslThumbprint` | SHA-1 thumbprint |
| `SslSANs` | Subject Alternative Names |
| `SslStatus` | `OK`, `WARNING` (within CertWarnDays), `EXPIRED`, or `ERROR` |

Checks the first open port from `-TcpPorts`, or falls back to port 443.

### HTTP Health Check (`-TestHttp "/path"`)

Issues an HTTP GET to `https://host:port/path` using `HttpWebRequest`. Reports:

| Field | Description |
|-------|-------------|
| `HttpUrl` | Full URL tested |
| `HttpStatusCode` | Response status code |
| `HttpResponseMs` | Response time in milliseconds |
| `HttpStatus` | `OK` (matches expected), `UNEXPECTED`, or `ERROR` |

Redirects are not followed — a 301/302 is reported as-is. The expected status code defaults to 200 but can be overridden with `-ExpectedStatusCode`.

## Watch Mode (`-Watch N`)

Repeats the entire scan every N seconds. Between scans, the console clears and shows:
- Full results for the current scan
- **CHANGES SINCE LAST SCAN** section highlighting:
  - `RECOVERED` — host went from unreachable to reachable
  - `NEW FAILURE` — host went from reachable to unreachable
  - `PORT CHANGE` — a port changed state

CSV and HTML are exported on the first iteration only. The log captures every iteration. Press Ctrl+C to stop.

## Output

### CSV

`output\ConnectivityReport_<yyyyMMdd_HHmmss>.csv`

Columns vary based on which switches are enabled:

| Always | With `-GrabBanner` | With `-TestSsl` | With `-TestHttp` |
|--------|--------------------|-----------------|------------------|
| Host, ResolvedIP, ReverseDNS | Banner\_\<port\> | SslSubject, SslIssuer | HttpUrl |
| PingStatus, PingSent, PingRecv, PingLossPct | | SslExpiry, SslDaysLeft | HttpStatusCode |
| PingMinMs, PingAvgMs, PingMaxMs | | SslThumbprint, SslSANs | HttpResponseMs |
| Port\_\<N\> (per port) | | SslStatus | HttpStatus |
| TestedAt | | | |

### HTML Report (`-GenerateHtml`)

`output\ConnectivityReport_<yyyyMMdd_HHmmss>.html`

Self-contained single file with:
- Summary cards (total, reachable, unreachable, plus contextual cards for packet loss, cert issues, HTTP failures)
- Full results table with color-coded cells
- No external dependencies — can be emailed or attached to tickets

### Console Summary

Sections displayed (only those with findings):
1. Unreachable hosts
2. Failed port checks (per port)
3. High latency hosts (avg > 100ms)
4. Packet loss detected
5. SSL certificates expired / expiring
6. HTTP health check failures
7. Service banners (per port)
8. Changes since last scan (watch mode)
9. Totals line

### Log

`logs\Test-ConnectivityBulk_<yyyyMMdd_HHmmss>.log`

## Configuration

Settings in the `$Config` hashtable that don't have dedicated parameters:

| Setting | Default | Description |
|---------|---------|-------------|
| `PingCount` | `4` | ICMP requests per host |
| `PingTimeout` | `1000` | ms per ping attempt |
| `TcpTimeoutMs` | `2000` | TCP connect timeout |
| `TracerouteOnFail` | `$false` | Run tracert on unreachable hosts |
| `LossWarnPct` | `0` | Flag hosts with loss >= this % |
| `SslPort` | `443` | Fallback port for SSL check |
| `HttpScheme` | `"https"` | `http` or `https` |
| `HttpTimeoutMs` | `5000` | HTTP request timeout |
| `BannerMaxBytes` | `1024` | Max bytes to read from banner |
| `BannerTimeoutMs` | `3000` | Wait time for server to send banner |

## Architecture

- **Parallelism**: `System.Management.Automation.Runspaces.RunspacePool` with `InitialSessionState` function injection — test functions are defined once and available in all runspaces
- **Pipeline**: `begin/process/end` structure accumulates targets from pipeline in `process`, runs all tests in `end`
- **Per-host dispatch**: Each runspace receives a single hashtable with all parameters and the target hostname
- **PS 5.1 compatible**: No PS 7 features (no `ForEach-Object -Parallel`, no ternary, no null-coalescing)

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Completed successfully |
| `1` | Fatal error |
