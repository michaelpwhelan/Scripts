# Invoke-LogParser v7.0

Single-file CLI tool for parsing, filtering, analyzing, and reporting on infrastructure log files. One script, zero dependencies, cross-platform.

## Quick Start

```powershell
# Parse and display with auto-detection
.\Invoke-LogParser.ps1 -Path firewall.log

# Filter and display as compact grid
.\Invoke-LogParser.ps1 -Path firewall.log -Filter "action:deny" -OutputFormat Grid

# Quick digest of all logs in a directory
.\Invoke-LogParser.ps1 -Path *.log -StatsOnly

# Multi-file parsing
.\Invoke-LogParser.ps1 -Path firewall.log,switch.log,dc01-security.xml

# Extract and parse a zip archive
.\Invoke-LogParser.ps1 -Path logs-export.zip

# Analyze failed logins across sources
.\Invoke-LogParser.ps1 -Path firewall.log,dc01-security.xml -Analyze FailedLogins

# Generate HTML report
.\Invoke-LogParser.ps1 -Path firewall.log -Report Summary -ExportPath report.html -ExportFormat Html -Open

# Interactive query mode
.\Invoke-LogParser.ps1 -Path firewall.log -Interactive

# Live tail with filtering
.\Invoke-LogParser.ps1 -Path firewall.log -Tail -Filter "action:deny"

# Pipeline integration
Get-Content firewall.log | .\Invoke-LogParser.ps1 -Format FortiGateKV -OutputFormat Raw | Where-Object { $_.dstport -eq '3389' }

# Regex search with context lines
.\Invoke-LogParser.ps1 -Path firewall.log -Regex "tunnel.*down" -Context 5

# Temporal surround — show everything within 30s of critical events
.\Invoke-LogParser.ps1 -Path firewall.log,switch.log -Filter "severity:Critical" -Surround 30

# Highlight without filtering
.\Invoke-LogParser.ps1 -Path firewall.log -Highlight "10\.12\.1\.50" -OutputFormat Grid

# FortiGate config section extraction
.\Invoke-LogParser.ps1 -Path config.conf -Section "firewall policy"

# Copy results to clipboard
.\Invoke-LogParser.ps1 -Path firewall.log -Filter "severity:High" -Clipboard
```

## Requirements

- **PowerShell 5.1+** (Windows PowerShell or pwsh 7+)
- **No external modules** — pure PowerShell + .NET Framework
- **Single file** — just `Invoke-LogParser.ps1`, no helper files needed

## Supported Formats

| Parser | Description | Auto-Detect |
|---|---|---|
| `FortiGateConf` | FortiGate configuration file (`.conf`) | `#config-version=FG` or `config system global` |
| `FortiGateKV` | Fortinet key=value syslog (FortiGate, FortiClient EMS, FortiAP) | `logid=` + `type=` + `devname=`/`devid=` |
| `FortiClientLocal` | FortiClient local log (tab-delimited debug + structured events) | Tab-delimited timestamp pattern, `fctver=`, `devid=FCT`, or legacy `[timestamp] [level] [module]` |
| `FortiSwitchEvent` | FortiSwitch event log (port, STP, MAC, 802.1X) | `devid=FS` or `devtype="FortiSwitch"` |
| `WindowsEvtx` | Windows Event Log (binary `.evtx` or XML export) | `.evtx` extension or `<Event xmlns=` |

Compressed `.zip` archives are automatically extracted and parsed. Format is auto-detected from file content — use `-Format` to override.

### FortiClient Local Log Format

FortiClient local logs (exported from `C:\Program Files\Fortinet\FortiClient\logs\`) contain two interleaved line types:

- **Debug lines** — `TIMESTAMP<TAB>LEVEL<TAB>CATEGORY<TAB>MESSAGE` with internal diagnostic messages. Parsed with `LogType=Debug`.
- **Structured events** — same tab-delimited layout, but the message field contains a full Fortinet key=value payload (`date=... time=... type=... msg="..."`). All key=value pairs are expanded into properties. Parsed with `LogType=Event`.

Filter structured events with `-Filter "LogType:Event"` to skip debug noise.

The legacy bracket format (`[YYYY-MM-DD HH:MM:SS] [level] [module] message`) from older FortiClient versions is also supported.

```powershell
.\Invoke-LogParser.ps1 -ListParsers    # show all parsers
```

## Output Formats

| Format | Flag | Description |
|---|---|---|
| **Table** | `-OutputFormat Table` | Box-drawing bordered table (default) |
| **Grid** | `-OutputFormat Grid` | Compact space-padded columns |
| **List** | `-OutputFormat List` | Detailed field-per-line for each event |
| **Raw** | `-OutputFormat Raw` | PSObjects for pipeline (`Where-Object`, `Export-Csv`, etc.) |
| **Json** | `-OutputFormat Json` | JSON Lines (one object per line) |
| **Csv** | `-OutputFormat Csv` | CSV with auto-discovered headers |

All output formats respect the `-Fields` parameter to select specific columns.

When output is piped, auto-switches to Raw format with color disabled.

## Query Syntax

Used with `-Filter` and in interactive mode. Supports hyphenated field names (e.g., `ips-sensor:default`, `utm-status:enable`):

```
# Field matching
action:deny                         # exact match
srcip:10.12.*                       # wildcard
dstport:>1024                       # numeric comparison
NOT action:accept                   # negation
action:deny AND srcip:10.*          # boolean AND
severity:High OR severity:Critical  # boolean OR

# Pipeline operators
action:deny | count                 # count results
action:deny | count by dstport      # group and count
action:deny | top 10                # top N results
severity:* | sort Timestamp desc    # sort by field
| head 50                           # first N
| tail 20                           # last N
| timeline 1h                       # time-bucketed histogram
| table srcip,dstip,action          # select columns
```

## Analysis Engines

```powershell
.\Invoke-LogParser.ps1 -Path <files> -Analyze <engine>
.\Invoke-LogParser.ps1 -ListAnalyzers   # show all engines
```

| Engine | Description |
|---|---|
| `FailedLogins` | Cross-source failed auth aggregation (Windows 4625/4771/6273, NPS, FortiGate) with brute-force flagging |
| `VpnSessions` | VPN session lifecycle tracking with impossible travel detection (public IPs only) |
| `IpsecTunnel` | Per-tunnel health: flap detection, negotiation success rate, DPD timeouts, uptime percentage |
| `Summary` | General statistics: severity distribution, top sources/IPs, events per hour |

## Reports

```powershell
.\Invoke-LogParser.ps1 -Path <files> -Report <type> [-ExportPath report.html -ExportFormat Html]
.\Invoke-LogParser.ps1 -ListReports     # show all report types
```

| Report | Description |
|---|---|
| `Summary` | Parse stats, severity distribution, top source IPs, top event IDs |
| `Morning` | Detailed summary with tunnel status, failed logins, security alerts |
| `Audit` | Privileged activity (4672, 4648), account changes (4720-4767), failed auth |
| `Compliance` | FFIEC/NCUA control mapping with evidence counts and coverage assessment |
| `Timeline` | Chronological cross-source event timeline |

Reports render to console by default. Export to HTML with `-ExportPath` for a self-contained, print-friendly monospace document.

## FortiGate Config Tools

```powershell
# Extract a config section
.\Invoke-LogParser.ps1 -Path config.conf -Section "firewall policy"
.\Invoke-LogParser.ps1 -Path config.conf -Section "system interface"
.\Invoke-LogParser.ps1 -Path config.conf -Section "firewall*"          # wildcard
```

The config parser flags security issues: `INSECURE-MGMT` (HTTP/Telnet management), `NO-IPS`, `NO-UTM`, `NO-LOGGING`, `PERMISSIVE` (all/all/ALL rules), `WEAK-PASSWD-POLICY`, `WEAK-SSL-INSPECT`.

For config diffing, use the dedicated `Compare-FortiGateConfigs.ps1` script in this repo.

## Interactive Mode

```
.\Invoke-LogParser.ps1 -Path firewall.log -Interactive

Invoke-LogParser v7.0
Loaded 14,892 events from 1 file(s)
Type 'help' for commands.

ILP [14892]> action:deny AND severity:High
87 events
ILP (action:deny AND severity:High) [87]> whois srcip
ILP (...) [87]> correlate srcip
Correlated on 3 unique srcip values: 1,247 events
ILP (correlate:srcip) [1247]> columns srcip,dstip,action,Message
ILP (correlate:srcip) [1247]> exclude severity:Info
892 events (excluded severity=Info)
ILP (exclude severity:Info) [892]> unique srcip
3 unique srcip values (from 892 events)
ILP (unique:srcip) [3]> show 1
ILP> report summary --export report.html
ILP> exit
```

Type `help` for all commands or `help <command>` for details. See the Interactive Guide for the full command reference and investigation workflows.

## Live Tail Mode

```powershell
.\Invoke-LogParser.ps1 -Path firewall.log -Tail
.\Invoke-LogParser.ps1 -Path firewall.log -Tail -TailLines 50
.\Invoke-LogParser.ps1 -Path firewall.log -Tail -Filter "action:deny"
.\Invoke-LogParser.ps1 -Path firewall.log -Tail -Highlight "10\.12\.1\.50"
```

Real-time parsed and color-coded output using `Get-Content -Wait`. Ctrl+C to stop.

## Enrichment Data

Embedded in the script — no external data files needed:

- **Windows Event IDs** — 100+ annotated IDs (security, AD, NPS, Hyper-V, DHCP, Defender)
- **NPS/RADIUS reason codes** — 40+ translations
- **FortiGate mappings** — type/subtype descriptions, log ID ranges, FortiClient module names
- **Severity normalization** — maps vendor-specific levels to: Critical, High, Medium, Low, Info

## Parameters

| Parameter | Description |
|---|---|
| `-Path` | Log file(s), glob patterns, or `.zip` archives |
| `-Format` | Force parser: `FortiGateConf`, `FortiGateKV`, `FortiClientLocal`, `FortiSwitchEvent`, `WindowsEvtx` |
| `-Filter` | Query string (`field:value`, boolean, pipeline ops) |
| `-Regex` | Regex filter against raw log lines |
| `-Analyze` | Run analysis: `FailedLogins`, `VpnSessions`, `IpsecTunnel`, `Summary` |
| `-Report` | Generate report: `Summary`, `Morning`, `Audit`, `Compliance`, `Timeline` |
| `-OutputFormat` | Display format: `Table`, `Grid`, `List`, `Raw`, `Json`, `Csv` |
| `-ExportPath` | File path to write report |
| `-ExportFormat` | Export format: `Html`, `Csv`, `Json` |
| `-Fields` | Comma-separated fields to display (works with all output formats) |
| `-MaxResults` | Limit displayed events |
| `-StatsOnly` | Show only statistics / quick digest |
| `-Interactive` | Launch REPL |
| `-Tail` | Live file monitoring |
| `-TailLines` | Initial lines to show before tailing (default: 20) |
| `-Highlight` | Color-highlight matching text without filtering |
| `-Context` | Show N raw lines before/after matches |
| `-Surround` | Show all events within N seconds of matches |
| `-Section` | Extract FortiGate config section |
| `-Clipboard` | Copy output to clipboard |
| `-Open` | Auto-open exported file |
| `-NoColor` | Disable colored output |
| `-Quiet` | Suppress console output |
| `-InputObject` | Accept piped input (requires `-Format`) |
| `-ListParsers` | List available parsers |
| `-ListAnalyzers` | List available analysis engines |
| `-ListReports` | List available report types |

## Architecture

Single file (`Invoke-LogParser.ps1`, ~2,900 lines) organized into 13 sections:

```
 1. Parameters & Configuration     — CmdletBinding, color system
 2. Enrichment Data                — FortiGate mappings, Event IDs, NPS codes
 3. Parsers                        — 5 parsers + auto-detect + dispatcher
 4. Filter Engine                  — Query parser, field matching, pipeline ops
 5. Analysis Engines               — Failed logins, VPN sessions, IPsec tunnels
 6. Output Formatter               — Table, Grid, List, Raw, Json, Csv + analysis renderers
 7. Config Tools                   — Section extraction, syntax highlighting
 8. Report Engine                  — Report types + HTML renderer
 9. Interactive Mode               — REPL with query, analyze, export
10. Live Tail Mode                 — Real-time parsed output
11. Output Helpers                 — Clipboard, file open
12. Zip Extraction                 — Archive handling with format discovery
13. Main Execution                 — Orchestration, pipeline support, cleanup
```

## License

Internal tool. Not licensed for external distribution.
