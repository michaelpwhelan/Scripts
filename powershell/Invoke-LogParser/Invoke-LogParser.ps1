<#
.SYNOPSIS
    Universal Log Parser v5.0 — parses, filters, and investigates log files across 32 formats.
    Supports both WinForms GUI (Windows) and console mode (cross-platform).

.DESCRIPTION
    A sysadmin-grade universal log parser with dual-mode architecture: a full WinForms GUI on
    Windows and a color-coded console mode for Linux/macOS/pwsh. Ships with pre-built parsers
    for FortiGate key=value, FortiGate config files, FortiClient local logs, Windows EVTX,
    Syslog (RFC 3164/5424), IIS W3C, Apache/Nginx CLF, NPS/RADIUS XML, CSV, JSON/NDJSON,
    PowerShell transcripts, user-defined regex, plain text, Windows DHCP server, Windows DNS
    debug, Entra ID sign-in, and Veeam backup job logs. Features include severity color coding,
    text/regex filtering, date range filtering, bookmarks, live tail mode, six themes, CSV/HTML
    export, saved filter profiles, MITRE ATT&CK enrichment, investigation templates, IOC
    matching, cross-log failed login aggregation, VPN session analysis with impossible travel
    detection, FFIEC/NCUA compliance audit reports, and statistical summaries.

.PARAMETER FilePath
    Path to one or more log files. Accepts comma-separated paths or a directory path.

.PARAMETER Theme
    Visual theme: Dark (default), Light, HighContrast, SolarizedDark, Nord, or Monokai.

.PARAMETER ConsoleMode
    Force console output mode. Auto-detected on Linux/macOS.

.PARAMETER Filter
    Text filter for console mode (case-insensitive substring match).

.PARAMETER FilterRegex
    Regex filter for console mode.

.PARAMETER Level
    Severity level filter: ALL, CRITICAL, ERROR, WARNING, INFO, DEBUG, TRACE.

.PARAMETER Source
    Source filter for console mode (case-insensitive substring match).

.PARAMETER ExportCsv
    Export filtered entries to CSV at the specified path.

.PARAMETER ExportHtml
    Export filtered entries to HTML report at the specified path.

.PARAMETER Format
    Force a specific parser format instead of auto-detection.

.PARAMETER Head
    Limit console output to first N entries (0 = all).

.PARAMETER Tail
    Show only the last N entries (0 = all).

.PARAMETER OutputObject
    Console mode emits PSCustomObject entries to the pipeline for piping to other cmdlets.

.PARAMETER Template
    Apply an investigation template by name (e.g., failed-logins-24h, firewall-denies).

.PARAMETER IocFile
    Path to a CSV file containing indicators of compromise for matching against log entries.

.PARAMETER AuditReport
    Generate an FFIEC/NCUA compliance audit report HTML file at the specified path.

.PARAMETER DateFrom
    Start date filter for entries and reports.

.PARAMETER DateTo
    End date filter for entries and reports.

.PARAMETER Stats
    Show statistical summary (console mode).

.PARAMETER Aggregate
    Run aggregation: FailedLogins or VpnSessions.

.PARAMETER Recurse
    When FilePath is a directory, recurse into subdirectories.

.NOTES
    Author:       Michael Whelan
    Created:      2026-03-18
    Version:      5.0.0
    Dependencies: PowerShell 5.1+ (GUI requires Windows + .NET WinForms)

.EXAMPLE
    .\Invoke-LogParser.ps1
    Opens the GUI with no file loaded (Windows only).

.EXAMPLE
    .\Invoke-LogParser.ps1 -FilePath "C:\Logs\firewall.log"
    Opens the GUI and immediately parses the specified file.

.EXAMPLE
    .\Invoke-LogParser.ps1 -ConsoleMode -FilePath ./firewall.log -Level ERROR
    Parses in console mode showing only ERROR entries.

.EXAMPLE
    .\Invoke-LogParser.ps1 -ConsoleMode -FilePath ./fw.log -OutputObject | Group-Object Level
    Parses and emits objects to the pipeline for further processing.

.EXAMPLE
    .\Invoke-LogParser.ps1 -ConsoleMode -FilePath ./security.evtx -Template failed-logins-24h
    Applies the "Failed Logins (24h)" investigation template.

.EXAMPLE
    .\Invoke-LogParser.ps1 -ConsoleMode -FilePath ./fw.log -IocFile ./bad-ips.csv
    Matches log entries against an IOC list.

.EXAMPLE
    .\Invoke-LogParser.ps1 -ConsoleMode -FilePath ./fw.log,./security.evtx -AuditReport ./audit.html
    Generates an FFIEC/NCUA compliance audit report from multiple log sources.
#>
#Requires -Version 5.1

param(
    [string[]]$FilePath,
    [ValidateSet("Dark", "Light", "HighContrast", "SolarizedDark", "Nord", "Monokai")]
    [string]$Theme = "Dark",
    [switch]$ConsoleMode,
    [string]$Filter,
    [string]$FilterRegex,
    [ValidateSet("ALL", "CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "TRACE")]
    [string]$Level = "ALL",
    [string]$Source,
    [string]$ExportCsv,
    [string]$ExportHtml,
    [string]$Format = "auto",
    [int]$Head = 0,
    [int]$Tail = 0,
    [switch]$OutputObject,
    [string]$Template,
    [string]$IocFile,
    [string]$AuditReport,
    [Parameter(Mandatory=$false)][Nullable[datetime]]$DateFrom,
    [Parameter(Mandatory=$false)][Nullable[datetime]]$DateTo,
    [switch]$Stats,
    [string]$Aggregate,
    [switch]$Recurse,
    [string]$MorningBriefing,
    [string]$SiteHealthReport,
    [string]$IncidentTimeline,
    [string]$FfiecReport,
    [string]$VulnerabilityReport,
    [string]$ExportJson,
    [string]$Query,
    [string]$BaselineBuild,
    [string]$BaselineCompare,
    [string]$TriageReport
)

# Store param values in Script scope for use by dot-sourced files
$Script:UseConsoleParam = $ConsoleMode.IsPresent
$Script:ThemeParam = $Theme
$Script:FilterParam = $Filter
$Script:FilterRegexParam = $FilterRegex
$Script:LevelParam = $Level
$Script:SourceParam = $Source
$Script:FormatParam = $Format

# ── Dot-source core libraries ──────────────────────────────────────────────────
$ScriptRoot = $PSScriptRoot
. "$ScriptRoot\lib\Platform.ps1"
. "$ScriptRoot\lib\Config.ps1"
. "$ScriptRoot\lib\Logging.ps1"
. "$ScriptRoot\lib\State.ps1"
. "$ScriptRoot\lib\Helpers.ps1"
. "$ScriptRoot\lib\ParserEngine.ps1"
. "$ScriptRoot\lib\FilterEngine.ps1"
. "$ScriptRoot\lib\StatsEngine.ps1"
. "$ScriptRoot\lib\Bookmarks.ps1"
. "$ScriptRoot\lib\Export.ps1"
. "$ScriptRoot\lib\TailMode.ps1"
. "$ScriptRoot\lib\MultiSourceLoader.ps1"
. "$ScriptRoot\lib\QueryLanguage.ps1"
. "$ScriptRoot\lib\BaselineEngine.ps1"
. "$ScriptRoot\lib\TopologyEngine.ps1"
. "$ScriptRoot\lib\AssetEngine.ps1"
. "$ScriptRoot\lib\DiffEngine.ps1"
. "$ScriptRoot\lib\TriageEngine.ps1"
. "$ScriptRoot\lib\IndexEngine.ps1"
. "$ScriptRoot\lib\CacheManager.ps1"
. "$ScriptRoot\lib\Persistence.ps1"
. "$ScriptRoot\lib\ThemeEngine.ps1"

# ── Dot-source enrichment data ─────────────────────────────────────────────────
. "$ScriptRoot\enrichment\EventIds.ps1"
. "$ScriptRoot\enrichment\NpsReasonCodes.ps1"
. "$ScriptRoot\enrichment\FortiGateMappings.ps1"
. "$ScriptRoot\enrichment\MitreAttack.ps1"
. "$ScriptRoot\enrichment\FortiManagerMappings.ps1"
. "$ScriptRoot\enrichment\IpsecErrorCodes.ps1"
. "$ScriptRoot\enrichment\BgpStateCodes.ps1"
. "$ScriptRoot\enrichment\VeeamErrorCodes.ps1"
. "$ScriptRoot\enrichment\HyperVEventIds.ps1"
. "$ScriptRoot\enrichment\FfiecControlMap.ps1"
. "$ScriptRoot\enrichment\FortiSwitchEventIds.ps1"
. "$ScriptRoot\enrichment\CertificateEventIds.ps1"

# ── Dot-source connectors ────────────────────────────────────────────────────
foreach ($connectorFile in (Get-ChildItem "$ScriptRoot\connectors\*.ps1" -ErrorAction SilentlyContinue)) {
    . $connectorFile.FullName
}

# ── Auto-discover and load parsers ─────────────────────────────────────────────
foreach ($parserFile in (Get-ChildItem "$ScriptRoot\parsers\*.ps1" -ErrorAction SilentlyContinue)) {
    . $parserFile.FullName
}

# ── Dot-source analysis and reports ────────────────────────────────────────────
. "$ScriptRoot\analysis\TimelineMerge.ps1"
. "$ScriptRoot\analysis\InvestigationTemplates.ps1"
. "$ScriptRoot\analysis\IocMatcher.ps1"
. "$ScriptRoot\analysis\FailedLoginAggregator.ps1"
. "$ScriptRoot\analysis\VpnSessionAnalyzer.ps1"
. "$ScriptRoot\analysis\CorrelationEngine.ps1"
. "$ScriptRoot\analysis\BgpRouteAnalyzer.ps1"
. "$ScriptRoot\analysis\IpsecTunnelAnalyzer.ps1"
. "$ScriptRoot\analysis\NpsSessionAnalyzer.ps1"
. "$ScriptRoot\analysis\CertExpiryTracker.ps1"
. "$ScriptRoot\analysis\ChangeAuditAnalyzer.ps1"
. "$ScriptRoot\analysis\ThreatCorrelator.ps1"
. "$ScriptRoot\analysis\ComplianceAnalyzer.ps1"
. "$ScriptRoot\analysis\AnomalyDetector.ps1"
. "$ScriptRoot\reports\AuditReport.ps1"
. "$ScriptRoot\reports\StatisticalSummary.ps1"
. "$ScriptRoot\reports\MorningBriefing.ps1"
. "$ScriptRoot\reports\SiteHealthReport.ps1"
. "$ScriptRoot\reports\IncidentTimeline.ps1"
. "$ScriptRoot\reports\FfiecReport.ps1"
. "$ScriptRoot\reports\VulnerabilityReport.ps1"

# ── Dot-source GUI or Console mode ─────────────────────────────────────────────
if ($Script:UseConsole) {
    . "$ScriptRoot\console\ConsoleMode.ps1"
} else {
    . "$ScriptRoot\gui\MainForm.ps1"
    . "$ScriptRoot\gui\EventHandlers.ps1"
    . "$ScriptRoot\gui\ContextMenu.ps1"
    . "$ScriptRoot\gui\Widgets.ps1"
    . "$ScriptRoot\gui\DashboardPanel.ps1"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if ($Script:UseConsole) {
    # Console mode
    try {
        $consoleArgs = @{
            InputPath = $FilePath
        }
        if ($OutputObject)  { $consoleArgs['OutputObject'] = $true }
        if ($Template)      { $consoleArgs['Template'] = $Template }
        if ($IocFile)       { $consoleArgs['IocFile'] = $IocFile }
        if ($AuditReport)   { $consoleArgs['AuditReport'] = $AuditReport }
        if ($Stats)         { $consoleArgs['Stats'] = $true }
        if ($Aggregate)     { $consoleArgs['Aggregate'] = $Aggregate }
        if ($null -ne $DateFrom) { $consoleArgs['DateFrom'] = $DateFrom }
        if ($null -ne $DateTo)  { $consoleArgs['DateTo'] = $DateTo }
        if ($Recurse)       { $consoleArgs['Recurse'] = $true }
        if ($MorningBriefing)    { $consoleArgs['MorningBriefing'] = $MorningBriefing }
        if ($SiteHealthReport)   { $consoleArgs['SiteHealthReport'] = $SiteHealthReport }
        if ($IncidentTimeline)   { $consoleArgs['IncidentTimeline'] = $IncidentTimeline }
        if ($FfiecReport)        { $consoleArgs['FfiecReport'] = $FfiecReport }
        if ($VulnerabilityReport) { $consoleArgs['VulnerabilityReport'] = $VulnerabilityReport }
        if ($ExportJson)         { $consoleArgs['ExportJson'] = $ExportJson }
        if ($Query)            { $consoleArgs['Query'] = $Query }
        if ($BaselineBuild)    { $consoleArgs['BaselineBuild'] = $BaselineBuild }
        if ($BaselineCompare)  { $consoleArgs['BaselineCompare'] = $BaselineCompare }
        if ($TriageReport)     { $consoleArgs['TriageReport'] = $TriageReport }

        Invoke-ConsoleMode @consoleArgs
    } catch {
        Write-Host "Fatal error: $_" -ForegroundColor Red
        exit 1
    }
} else {
    # GUI mode
    try {
        Write-Log "Starting $($Config.ScriptName) v$($Config.Version)"

        # Build GUI
        $form = New-MainForm

        # Load persisted settings (theme, recent files, window state)
        Load-Settings
        Set-Theme $Script:State.ActiveTheme
        Update-RecentFilesMenu

        # Initialize investigation templates menu
        Initialize-InvestigationMenu

        # Initialize v5.0 subsystems
        Initialize-QueryFieldMappings
        Initialize-Topology
        Initialize-TriageRules
        Initialize-AssetEngine
        Load-PresetFilterProfiles

        # If files were passed as parameters, open them
        if ($FilePath -and $FilePath.Count -gt 0) {
            if ($FilePath.Count -eq 1 -and (Test-Path $FilePath[0])) {
                Open-LogFile $FilePath[0]
            } elseif ($FilePath.Count -gt 1) {
                $validPaths = $FilePath | Where-Object { Test-Path $_ }
                if ($validPaths) { Invoke-TimelineMerge -FilePaths $validPaths }
            }
        }

        # Run the application
        [System.Windows.Forms.Application]::Run($form)

        Write-Log "Completed $($Config.ScriptName) successfully"
        exit 0
    } catch {
        Write-Log "Fatal error: $_" -Level ERROR
        try {
            [System.Windows.Forms.MessageBox]::Show(
                "Fatal error: $_`n`nThe application will exit.",
                "Error",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error
            ) | Out-Null
        } catch { }
        exit 1
    }
}
