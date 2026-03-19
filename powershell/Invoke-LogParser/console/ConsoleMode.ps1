# ===============================================================================
# CONSOLE MODE FUNCTIONS
# ===============================================================================

function Write-ConsoleUsage {
    $r = $Script:ANSIReset
    $ct = $Script:ConsoleThemes[$Theme]
    Write-Host ""
    Write-Host "$($ct.Title) Universal Log Parser v$($Config.Version) $([char]0x2014) Console Mode$r"
    Write-Host ""
    Write-Host "$($ct.Header)Usage:$r"
    Write-Host "  pwsh -File Invoke-LogParser.ps1 -FilePath <path> [options]"
    Write-Host ""
    Write-Host "$($ct.Header)Options:$r"
    Write-Host "  -ConsoleMode         Force console mode (auto-detected on Linux)"
    Write-Host "  -Theme <name>        Theme: Dark, Light, HighContrast, SolarizedDark, Nord, Monokai"
    Write-Host "  -Filter <text>       Text filter (case-insensitive)"
    Write-Host "  -FilterRegex <rx>    Regex filter"
    Write-Host "  -Level <level>       ALL, CRITICAL, ERROR, WARNING, INFO, DEBUG, TRACE"
    Write-Host "  -Source <text>       Source filter (case-insensitive)"
    Write-Host "  -Format <id>         Force parser: fortigate-kv, fortigate-conf, forticlient-local,"
    Write-Host "                       nps-radius, windows-evtx, iis-w3c, apache-combined,"
    Write-Host "                       syslog-rfc3164, syslog-rfc5424, csv-auto, json-ndjson,"
    Write-Host "                       powershell-transcript, generic-regex, plaintext"
    Write-Host "  -ExportCsv <path>    Export to CSV"
    Write-Host "  -ExportHtml <path>   Export to HTML report"
    Write-Host "  -Head <n>            Show first N entries"
    Write-Host "  -Tail <n>            Show last N entries"
    Write-Host "  -OutputObject        Emit objects to pipeline (for piping to other cmdlets)"
    Write-Host "  -Template <name>     Apply investigation template"
    Write-Host "  -IocFile <path>      Import IOC list for matching"
    Write-Host "  -AuditReport <path>  Generate FFIEC/NCUA audit report"
    Write-Host "  -MorningBriefing <path>  Generate daily morning briefing report"
    Write-Host "  -SiteHealthReport <path> Generate site health report"
    Write-Host "  -IncidentTimeline <path> Generate incident timeline report"
    Write-Host "  -FfiecReport <path>      Generate FFIEC compliance report"
    Write-Host "  -VulnerabilityReport <path> Generate vulnerability report"
    Write-Host "  -ExportJson <path>       Export to JSON"
    Write-Host "  -Query <sql>         Execute SQL query against loaded data"
    Write-Host "  -BaselineBuild <name> Build behavioral baseline from loaded data"
    Write-Host "  -BaselineCompare <name> Compare data against baseline, detect anomalies"
    Write-Host "  -TriageReport <path> Run triage rules and generate report"
    Write-Host "  -Stats               Show statistical summary"
    Write-Host "  -Aggregate <type>    Aggregate: FailedLogins, VpnSessions, BgpRoutes, IpsecTunnels,"
    Write-Host "                       NpsSessions, CertExpiry, ChangeAudit, Threats, Correlation, Compliance,"
    Write-Host "                       Anomaly, Triage"
    Write-Host "  -DateFrom <date>     Start date filter"
    Write-Host "  -DateTo <date>       End date filter"
    Write-Host "  -Recurse             Recurse into directory for files"
    Write-Host ""
    Write-Host "$($ct.Header)Supported formats ($($Script:Parsers.Count)):$r"
    foreach ($pid2 in $Script:Parsers.Keys) {
        Write-Host "  $($ct.Dim)$pid2$r  $($Script:Parsers[$pid2].Name)"
    }
    Write-Host ""
}

function Write-ConsoleSummary {
    param($entries, $totalCount, $parserName, $filePath)
    $r = $Script:ANSIReset
    $ct = $Script:ConsoleThemes[$Theme]
    $counts = @{ CRITICAL = 0; ERROR = 0; WARNING = 0; INFO = 0; DEBUG = 0; TRACE = 0; UNKNOWN = 0 }
    foreach ($e in $entries) {
        if ($counts.ContainsKey($e.Level)) { $counts[$e.Level]++ } else { $counts['UNKNOWN']++ }
    }
    Write-Host ""
    Write-Host "$($ct.Title) Universal Log Parser v$($Config.Version) $([char]0x2014) Console Mode$r"
    Write-Host " $($ct.Dim)File:$r    $(Split-Path $filePath -Leaf)"
    Write-Host " $($ct.Dim)Format:$r  $parserName ($(if ($Format -eq 'auto') { 'auto-detected' } else { 'forced' }))"
    Write-Host " $($ct.Dim)Entries:$r $($ct.Count)$($totalCount.ToString('N0'))$r$(if ($entries.Count -ne $totalCount) { " (showing $($entries.Count.ToString('N0')) after filters)" })"
    Write-Host ""
    $sevLine = " "
    if ($counts['CRITICAL'] -gt 0) { $sevLine += "$($ct.CRITICAL)CRITICAL: $($counts['CRITICAL'])$r  " }
    if ($counts['ERROR'] -gt 0) { $sevLine += "$($ct.ERROR)ERROR: $($counts['ERROR'])$r  " }
    if ($counts['WARNING'] -gt 0) { $sevLine += "$($ct.WARNING)WARNING: $($counts['WARNING'])$r  " }
    $sevLine += "$($ct.INFO)INFO: $($counts['INFO'])$r  "
    if ($counts['DEBUG'] -gt 0) { $sevLine += "$($ct.DEBUG)DEBUG: $($counts['DEBUG'])$r  " }
    Write-Host $sevLine
    Write-Host ""
}

function Write-ConsoleTable {
    param($entries)
    $r = $Script:ANSIReset
    $ct = $Script:ConsoleThemes[$Theme]

    # Header
    $hdr = "$($ct.Header){0,-6} {1,-20} {2,-9} {3,-16} {4}$r" -f "#", "Timestamp", "Level", "Source", "Message"
    Write-Host $hdr
    $border = "$($ct.Border)$([string][char]0x2500 * 6) $([string][char]0x2500 * 20) $([string][char]0x2500 * 9) $([string][char]0x2500 * 16) $([string][char]0x2500 * 50)$r"
    Write-Host $border

    foreach ($e in $entries) {
        $tsStr = if ($e.Timestamp -ne [datetime]::MinValue) { $e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
        $lvlColor = if ($ct.ContainsKey($e.Level)) { $ct[$e.Level] } else { $ct.UNKNOWN }
        $msgLine = ($e.Message -split "`n")[0]
        $termWidth = try { $Host.UI.RawUI.WindowSize.Width } catch { 120 }
        $maxMsg = [Math]::Max(10, $termWidth - 55)
        if ($msgLine.Length -gt $maxMsg) { $msgLine = $msgLine.Substring(0, $maxMsg - 3) + "..." }
        $src = if ($e.Source.Length -gt 16) { $e.Source.Substring(0, 13) + "..." } else { $e.Source }
        $line = "$lvlColor{0,-6} {1,-20} {2,-9} {3,-16} {4}$r" -f $e.Index, $tsStr, $e.Level, $src, $msgLine
        Write-Host $line
    }
}

function Export-ToCsvFile {
    param([string]$OutputPath, [System.Collections.Generic.List[object]]$Entries)
    $sw = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.Encoding]::UTF8)
    $extraKeys = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($e in $Entries) {
        if ($e.Extra) { foreach ($k in $e.Extra.Keys) { $extraKeys.Add($k) | Out-Null } }
    }
    $extraKeyList = $extraKeys | Sort-Object
    $headers = @("Index", "Timestamp", "Level", "Source", "Host", "Message") + $extraKeyList
    $sw.WriteLine(($headers | ForEach-Object { "`"$_`"" }) -join ",")
    foreach ($e in $Entries) {
        $row = @(
            $e.Index
            $(if ($e.Timestamp -ne [datetime]::MinValue) { $e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss") } else { "" })
            $e.Level
            $e.Source
            $e.Host
            $e.Message -replace '"', '""'
        )
        foreach ($k in $extraKeyList) {
            $val = if ($e.Extra -and $e.Extra.ContainsKey($k)) { [string]$e.Extra[$k] -replace '"', '""' } else { "" }
            $row += $val
        }
        $sw.WriteLine(($row | ForEach-Object { "`"$_`"" }) -join ",")
    }
    $sw.Close()
}

function Export-ToHtmlFile {
    param([string]$OutputPath, [System.Collections.Generic.List[object]]$Entries, [int]$TotalCount, [string]$SourcePath)
    $sw = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.Encoding]::UTF8)
    $counts = @{ CRITICAL = 0; ERROR = 0; WARNING = 0; INFO = 0; DEBUG = 0 }
    foreach ($e in $Entries) { if ($counts.ContainsKey($e.Level)) { $counts[$e.Level]++ } }
    $colorMap = @{
        CRITICAL = "background:#8b0000;color:#fff"; ERROR = "background:#ff4444;color:#fff"
        WARNING = "background:#ff8c00;color:#000"; INFO = "background:#f5f5f5;color:#000"
        DEBUG = "background:#808080;color:#fff"; TRACE = "background:#a9a9a9;color:#fff"; UNKNOWN = "background:#f5f5f5;color:#000"
    }
    $sw.WriteLine(@"
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Log Analysis Report</title>
<style>
  body { font-family: Segoe UI, Tahoma, sans-serif; margin: 20px; background: #fff; color: #333; }
  h1 { border-bottom: 2px solid #0078d4; padding-bottom: 8px; }
  .summary { display: flex; gap: 20px; margin: 15px 0; flex-wrap: wrap; }
  .summary .card { background: #f0f0f0; border-radius: 6px; padding: 12px 20px; min-width: 120px; }
  .summary .card h3 { margin: 0 0 4px 0; font-size: 13px; color: #666; }
  .summary .card .val { font-size: 24px; font-weight: bold; }
  .crit .val { color: #8b0000; } .err .val { color: #ff4444; } .warn .val { color: #ff8c00; }
  table { border-collapse: collapse; width: 100%; margin-top: 20px; font-size: 13px; }
  th { background: #0078d4; color: #fff; padding: 8px 10px; text-align: left; position: sticky; top: 0; }
  td { padding: 6px 10px; border-bottom: 1px solid #ddd; max-width: 600px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  tr:hover td { background: #e8f0fe !important; }
  .meta { color: #888; font-size: 12px; margin-top: 20px; }
</style></head><body>
<h1>Log Analysis Report</h1>
<p><strong>Source:</strong> $(Invoke-HtmlEncode $SourcePath)<br>
<strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
<strong>Entries shown:</strong> $($Entries.Count) of $TotalCount</p>
<div class="summary">
  <div class="card crit"><h3>Critical</h3><div class="val">$($counts['CRITICAL'])</div></div>
  <div class="card err"><h3>Errors</h3><div class="val">$($counts['ERROR'])</div></div>
  <div class="card warn"><h3>Warnings</h3><div class="val">$($counts['WARNING'])</div></div>
  <div class="card"><h3>Info</h3><div class="val">$($counts['INFO'])</div></div>
  <div class="card"><h3>Debug</h3><div class="val">$($counts['DEBUG'])</div></div>
  <div class="card"><h3>Total</h3><div class="val">$($Entries.Count)</div></div>
</div>
<table><tr><th>#</th><th>Timestamp</th><th>Level</th><th>Source</th><th>Message</th></tr>
"@)
    $maxRows = [Math]::Min($Entries.Count, 5000)
    for ($i = 0; $i -lt $maxRows; $i++) {
        $e = $Entries[$i]
        $style = if ($colorMap.ContainsKey($e.Level)) { $colorMap[$e.Level] } else { "" }
        $tsStr = if ($e.Timestamp -ne [datetime]::MinValue) { $e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
        $msgHtml = Invoke-HtmlEncode($e.Message.Substring(0, [Math]::Min(300, $e.Message.Length)))
        $sw.WriteLine("<tr style=`"$style`"><td>$($e.Index)</td><td>$tsStr</td><td>$($e.Level)</td><td>$(Invoke-HtmlEncode $e.Source)</td><td title=`"$(Invoke-HtmlEncode $e.Message)`">$msgHtml</td></tr>")
    }
    if ($Entries.Count -gt $maxRows) {
        $sw.WriteLine("<tr><td colspan='5' style='text-align:center;color:#888;'>... $($Entries.Count - $maxRows) more entries truncated ...</td></tr>")
    }
    $sw.WriteLine("</table><p class='meta'>Generated by Universal Log Parser v$($Config.Version)</p></body></html>")
    $sw.Close()
}

function Invoke-ConsoleMode {
    param(
        [string[]]$InputPath,
        [switch]$OutputObject,
        [string]$Template,
        [string]$IocFile,
        [string]$AuditReport,
        [switch]$Stats,
        [string]$Aggregate,
        [Nullable[datetime]]$DateFrom,
        [Nullable[datetime]]$DateTo,
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

    if (-not $InputPath) {
        Write-ConsoleUsage
        return
    }

    # Resolve file list
    $filePaths = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $InputPath) {
        if (Test-Path $p -PathType Container) {
            if ($Recurse) {
                Get-ChildItem $p -Recurse -File | ForEach-Object { $filePaths.Add($_.FullName) }
            } else {
                Get-ChildItem $p -File | ForEach-Object { $filePaths.Add($_.FullName) }
            }
        } elseif (Test-Path $p) {
            $filePaths.Add((Resolve-Path $p).Path)
        } else {
            Write-Host "Error: File not found: $p" -ForegroundColor Red
            exit 1
        }
    }
    if ($filePaths.Count -eq 0) {
        Write-Host "Error: No files found." -ForegroundColor Red
        exit 1
    }

    # Apply investigation template if specified
    if ($Template) {
        $tmpl = Get-InvestigationTemplate -Name $Template
        if ($tmpl) {
            if ($tmpl.regex -and -not $FilterRegex) { $Script:FilterRegexParam = $tmpl.regex }
            if ($tmpl.levels) { $Script:LevelParam = $tmpl.levels }
            if ($tmpl.dateRelative) {
                $now = Get-Date
                if ($tmpl.dateRelative -match '^-(\d+)([hdm])$') {
                    $val = [int]$Matches[1]
                    $DateFrom = switch ($Matches[2]) {
                        'h' { $now.AddHours(-$val) }
                        'd' { $now.AddDays(-$val) }
                        'm' { $now.AddMonths(-$val) }
                    }
                }
            }
        } else {
            Write-Host "Warning: Template '$Template' not found." -ForegroundColor Yellow
        }
    }

    # Import IOC file if specified
    if ($IocFile) {
        Import-IocFile -FilePath $IocFile
    }

    # Process each file and collect all entries
    $allEntries = [System.Collections.Generic.List[object]]::new()
    $parserName = ""
    $cleanupPaths = [System.Collections.Generic.List[string]]::new()

    foreach ($fp in $filePaths) {
        # Handle compressed files
        $actualPath = $fp
        $ext = [System.IO.Path]::GetExtension($fp).ToLower()
        if ($ext -eq '.gz' -or $ext -eq '.zip') {
            Write-Host "Decompressing..." -ForegroundColor Cyan
            $actualPath = Expand-CompressedFile $fp
            if (-not $actualPath) { Write-Host "Decompression failed." -ForegroundColor Red; exit 1 }
            $cleanupPaths.Add($actualPath)
        }

        # Detect format
        $parserId = $Format
        if ($parserId -eq "auto") {
            $parserId = Invoke-AutoDetect $actualPath
            if (-not $parserId) { Write-Host "Could not detect log format for: $fp" -ForegroundColor Red; continue }
        }

        $parser = $Script:Parsers[$parserId]
        $parserName = $parser.Name
        Write-Host "Parsing with $parserName..." -ForegroundColor Cyan

        # Parse using unified engine
        $fileEntries = Invoke-ParserForFile -ParserId $parserId -FilePath $actualPath -Encoding "UTF-8"
        if ($fileEntries) {
            foreach ($entry in $fileEntries) { $allEntries.Add($entry) }
        }
    }

    if (-not $allEntries -or $allEntries.Count -eq 0) {
        $allEntries = [System.Collections.Generic.List[object]]::new()
    }
    $totalCount = $allEntries.Count

    # Run IOC matching if IOCs were imported
    if ($Script:State.IocSet) {
        Invoke-IocMatch -Entries $allEntries
    }

    # Apply filters
    $filtered = [System.Collections.Generic.List[object]]::new()
    $hasFilter = -not [string]::IsNullOrWhiteSpace($Filter)
    $hasFilterRegex = -not [string]::IsNullOrWhiteSpace($FilterRegex)
    $hasSource = -not [string]::IsNullOrWhiteSpace($Source)
    $filterLevel = $Level.ToUpper()

    $regex = $null
    if ($hasFilterRegex) {
        try { $regex = [regex]::new($FilterRegex, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) }
        catch { Write-Host "Invalid regex: $FilterRegex" -ForegroundColor Red; exit 1 }
    }

    foreach ($entry in $allEntries) {
        if ($filterLevel -ne "ALL" -and $entry.Level -ne $filterLevel) { continue }
        if ($hasSource -and (-not $entry.Source -or $entry.Source.IndexOf($Source, [System.StringComparison]::OrdinalIgnoreCase) -lt 0)) { continue }
        if ($hasFilter) {
            $filterUpper = $Filter.ToUpper()
            if (-not ($entry.Message.ToUpper().Contains($filterUpper) -or $entry.RawLine.ToUpper().Contains($filterUpper) -or $entry.Source.ToUpper().Contains($filterUpper))) { continue }
        }
        if ($hasFilterRegex -and $regex) {
            if (-not ($regex.IsMatch($entry.Message) -or $regex.IsMatch($entry.RawLine))) { continue }
        }
        # Date range filters
        if ($DateFrom -and $entry.Timestamp -ne [datetime]::MinValue -and $entry.Timestamp -lt $DateFrom) { continue }
        if ($DateTo -and $entry.Timestamp -ne [datetime]::MinValue -and $entry.Timestamp -gt $DateTo) { continue }
        $filtered.Add($entry)
    }

    # v5.0: SQL Query mode
    if ($Query) {
        $queryResult = Invoke-QueryFilter -QueryString $Query -Entries $filtered
        if ($queryResult -is [System.Collections.Generic.List[object]] -or $queryResult -is [array]) {
            $filtered = [System.Collections.Generic.List[object]]::new()
            foreach ($e in $queryResult) { $filtered.Add($e) }
        } else {
            # Aggregation result
            Write-Host (Format-QueryResults $queryResult)
            return
        }
    }

    # Apply Head/Tail limits
    $display = $filtered
    if ($Tail -gt 0 -and $filtered.Count -gt $Tail) {
        $display = [System.Collections.Generic.List[object]]::new()
        $start = $filtered.Count - $Tail
        for ($i = $start; $i -lt $filtered.Count; $i++) { $display.Add($filtered[$i]) }
    }
    if ($Head -gt 0 -and $display.Count -gt $Head) {
        $trimmed = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt $Head; $i++) { $trimmed.Add($display[$i]) }
        $display = $trimmed
    }

    # -OutputObject: emit objects to pipeline instead of rendering table
    if ($OutputObject) {
        foreach ($e in $display) {
            [PSCustomObject]@{
                Index     = $e.Index
                Timestamp = $e.Timestamp
                Level     = $e.Level
                Source    = $e.Source
                Host      = $e.Host
                Message   = $e.Message
                Extra     = $e.Extra
            }
        }
        return
    }

    # Output
    $displayFilePath = if ($filePaths.Count -eq 1) { $filePaths[0] } else { "$($filePaths.Count) files" }
    Write-ConsoleSummary -entries $display -totalCount $totalCount -parserName $parserName -filePath $displayFilePath
    Write-ConsoleTable -entries $display

    # -Stats: show statistical summary after table output
    if ($Stats) {
        Write-StatisticalSummary -Entries $filtered
    }

    # -AuditReport: generate the report
    if ($AuditReport) {
        New-AuditReport -OutputPath $AuditReport -Entries $filtered -DateFrom $DateFrom -DateTo $DateTo
        Write-Host "`nAudit report generated: $AuditReport" -ForegroundColor Green
    }

    if ($MorningBriefing) {
        New-MorningBriefing -OutputPath $MorningBriefing -Entries $filtered -DateFrom $DateFrom -DateTo $DateTo
        Write-Host "`nMorning briefing generated: $MorningBriefing" -ForegroundColor Green
    }
    if ($SiteHealthReport) {
        New-SiteHealthReport -OutputPath $SiteHealthReport -Entries $filtered -DateFrom $DateFrom -DateTo $DateTo
        Write-Host "`nSite health report generated: $SiteHealthReport" -ForegroundColor Green
    }
    if ($IncidentTimeline) {
        New-IncidentTimeline -OutputPath $IncidentTimeline -Entries $filtered -DateFrom $DateFrom -DateTo $DateTo
        Write-Host "`nIncident timeline generated: $IncidentTimeline" -ForegroundColor Green
    }
    if ($FfiecReport) {
        New-FfiecComplianceReport -OutputPath $FfiecReport -Entries $filtered -DateFrom $DateFrom -DateTo $DateTo
        Write-Host "`nFFIEC compliance report generated: $FfiecReport" -ForegroundColor Green
    }
    if ($VulnerabilityReport) {
        New-VulnerabilityReport -OutputPath $VulnerabilityReport -Entries $filtered -DateFrom $DateFrom -DateTo $DateTo
        Write-Host "`nVulnerability report generated: $VulnerabilityReport" -ForegroundColor Green
    }

    # v5.0: Baseline operations
    if ($BaselineBuild) {
        Build-Baseline -Entries $filtered -Name $BaselineBuild
        Write-Host "`nBaseline '$BaselineBuild' built from $($filtered.Count) entries" -ForegroundColor Green
    }
    if ($BaselineCompare) {
        $anomalies = Get-AnomalyDetection -Entries $filtered -BaselineName $BaselineCompare
        Write-AnomalyTable -Results $anomalies
    }
    if ($TriageReport) {
        $triageResults = Invoke-TriageCheck -Entries $filtered
        New-TriageReport -OutputPath $TriageReport -TriageResults $triageResults
        Write-Host "`nTriage report generated: $TriageReport" -ForegroundColor Green
    }

    # -Aggregate: run aggregation
    if ($Aggregate) {
        switch ($Aggregate.ToLower()) {
            'failedlogins' {
                $results = Get-FailedLoginAggregation -Entries $filtered
                Write-FailedLoginTable -Results $results
            }
            'vpnsessions' {
                $results = Get-VpnSessionAnalysis -Entries $filtered
                Write-VpnSessionTable -Results $results
            }
            'bgproutes' {
                $results = Get-BgpRouteAnalysis -Entries $filtered
                Write-BgpRouteTable -Results $results
            }
            'ipsectunnels' {
                $results = Get-IpsecTunnelAnalysis -Entries $filtered
                Write-IpsecTunnelTable -Results $results
            }
            'npssessions' {
                $results = Get-NpsSessionAnalysis -Entries $filtered
                Write-NpsSessionTable -Results $results
            }
            'certexpiry' {
                $results = Get-CertExpiryAnalysis -Entries $filtered
                Write-CertExpiryTable -Results $results
            }
            'changeaudit' {
                $results = Get-ChangeAuditAnalysis -Entries $filtered
                Write-ChangeAuditTable -Results $results
            }
            'threats' {
                $results = Get-ThreatCorrelation -Entries $filtered
                Write-ThreatCorrelationTable -Results $results
            }
            'correlation' {
                $results = Invoke-CrossSourceCorrelation -Entries $filtered
                Write-CorrelationTable -Results $results
            }
            'compliance' {
                $results = Get-ComplianceAnalysis -Entries $filtered
                Write-ComplianceTable -Results $results
            }
            'anomaly' {
                $results = Get-AnomalyDetection -Entries $filtered
                Write-AnomalyTable -Results $results
            }
            'triage' {
                $results = Invoke-TriageCheck -Entries $filtered
                Write-TriageTable -Results $results
            }
            default { Write-Host "Unknown aggregate type: $Aggregate" -ForegroundColor Yellow }
        }
    }

    # Exports
    if ($ExportCsv) {
        Export-ToCsvFile -OutputPath $ExportCsv -Entries $filtered
        Write-Host "`nExported $($filtered.Count) entries to CSV: $ExportCsv" -ForegroundColor Green
    }
    if ($ExportHtml) {
        Export-ToHtmlFile -OutputPath $ExportHtml -Entries $filtered -TotalCount $totalCount -SourcePath $displayFilePath
        Write-Host "`nExported HTML report: $ExportHtml" -ForegroundColor Green
    }
    if ($ExportJson) {
        Export-ToJsonFile -OutputPath $ExportJson -Entries $filtered
        Write-Host "`nExported $($filtered.Count) entries to JSON: $ExportJson" -ForegroundColor Green
    }

    # Cleanup temp
    foreach ($cp in $cleanupPaths) {
        $cpDir = Split-Path $cp -Parent
        if ($cpDir -and (Test-Path $cpDir)) {
            try { Remove-Item $cpDir -Recurse -Force -ErrorAction SilentlyContinue } catch { }
        }
    }
    if ($filePaths.Count -eq 1 -and $filePaths[0] -ne $InputPath[0] -and (Test-Path $Config.TempDir)) {
        try { Remove-Item $Config.TempDir -Recurse -Force -ErrorAction SilentlyContinue } catch { }
    }
}
