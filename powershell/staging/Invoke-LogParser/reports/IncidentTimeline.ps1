function New-IncidentTimeline {
    param(
        [string]$OutputPath,
        [System.Collections.Generic.List[object]]$Entries,
        [Nullable[datetime]]$DateFrom,
        [Nullable[datetime]]$DateTo
    )

    if (-not $Entries -or $Entries.Count -eq 0) {
        Write-Log "No entries for incident timeline" -Level WARNING
        return
    }

    # Filter by date range if specified
    $filtered = if ($DateFrom -or $DateTo) {
        $Entries | Where-Object {
            ($_.Timestamp -ne [datetime]::MinValue) -and
            (-not $DateFrom -or $_.Timestamp -ge $DateFrom) -and
            (-not $DateTo -or $_.Timestamp -le $DateTo)
        }
    } else { $Entries }
    $filtered = @($filtered)

    if ($filtered.Count -eq 0) {
        Write-Log "No entries match date range for incident timeline" -Level WARNING
        return
    }

    # Severity counts
    $counts = @{ CRITICAL = 0; ERROR = 0; WARNING = 0; INFO = 0; DEBUG = 0; TRACE = 0; UNKNOWN = 0 }
    foreach ($e in $filtered) { if ($counts.ContainsKey($e.Level)) { $counts[$e.Level]++ } else { $counts['UNKNOWN']++ } }

    # Date range determination
    $timestamps = $filtered | Where-Object { $_.Timestamp -ne [datetime]::MinValue } | ForEach-Object { $_.Timestamp }
    $minDate = if ($DateFrom) { $DateFrom } elseif ($timestamps) { ($timestamps | Measure-Object -Minimum).Minimum } else { Get-Date }
    $maxDate = if ($DateTo) { $DateTo } elseif ($timestamps) { ($timestamps | Measure-Object -Maximum).Maximum } else { Get-Date }

    # Source files involved
    $sourceFiles = @($filtered | ForEach-Object { if ($_.Extra -and $_.Extra['SourceFile']) { $_.Extra['SourceFile'] } } | Where-Object { $_ } | Select-Object -Unique)
    if ($sourceFiles.Count -eq 0) { $sourceFiles = @($Script:State.LoadedFiles | ForEach-Object { [System.IO.Path]::GetFileName($_) }) }

    # --- MITRE ATT&CK Observed ---
    $mitreData = @{}
    foreach ($e in $filtered) {
        if ($e.Extra) {
            $techId = $e.Extra['MitreTechniqueId']
            $techName = $e.Extra['MitreTechniqueName']
            $tactic = $e.Extra['MitreTactic']
            if ($techId) {
                if (-not $mitreData.ContainsKey($techId)) {
                    $mitreData[$techId] = @{
                        TechniqueId   = $techId
                        TechniqueName = if ($techName) { $techName } else { '(unknown)' }
                        Tactic        = if ($tactic) { $tactic } else { '(unknown)' }
                        Count         = 0
                    }
                }
                $mitreData[$techId].Count++
            }
        }
    }
    # Also check the script-level MITRE map for EventID-based lookups
    if ($Script:MitreEventIdMap) {
        foreach ($e in $filtered) {
            if ($e.Extra -and $e.Extra['EventID'] -and -not $e.Extra['MitreTechniqueId']) {
                $eid = [int]$e.Extra['EventID']
                if ($Script:MitreEventIdMap.ContainsKey($eid)) {
                    $mitre = $Script:MitreEventIdMap[$eid]
                    $key = $mitre.TechniqueId
                    if (-not $mitreData.ContainsKey($key)) {
                        $mitreData[$key] = @{
                            TechniqueId   = $key
                            TechniqueName = $mitre.TechniqueName
                            Tactic        = $mitre.Tactic
                            Count         = 0
                        }
                    }
                    $mitreData[$key].Count++
                }
            }
        }
    }

    # --- Key Indicators ---
    $uniqueIPs = @{}
    $uniqueUsers = @{}
    foreach ($e in $filtered) {
        if (-not $e.Extra) { continue }
        # IPs
        foreach ($ipField in @('srcip', 'dstip', 'IPAddress', 'IpAddress', 'Calling-Station-Id', 'remip', 'locip')) {
            $ipVal = $e.Extra[$ipField]
            if ($ipVal -and $ipVal -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                if (-not $uniqueIPs.ContainsKey($ipVal)) { $uniqueIPs[$ipVal] = @{ IP = $ipVal; Field = $ipField; Count = 0 } }
                $uniqueIPs[$ipVal].Count++
            }
        }
        # Users
        foreach ($userField in @('user', 'User-Name', 'TargetUserName', 'UserPrincipalName', 'SubjectUserName', 'dstuser', 'srcuser')) {
            $userVal = $e.Extra[$userField]
            if ($userVal -and $userVal -ne '-' -and $userVal -ne 'SYSTEM' -and $userVal -ne 'N/A') {
                if (-not $uniqueUsers.ContainsKey($userVal)) { $uniqueUsers[$userVal] = @{ User = $userVal; Field = $userField; Count = 0 } }
                $uniqueUsers[$userVal].Count++
            }
        }
    }

    $sw = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.Encoding]::UTF8)

    $sw.WriteLine(@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Incident Timeline Report</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: 'Courier New', monospace; margin: 30px; color: #000; background: #fff; max-width: 1200px; margin: 0 auto; padding: 30px; }
  h1 { border-bottom: 2px solid #000; padding-bottom: 8px; }
  h2 { border-left: 4px solid #666; background: #f0f0f0; padding: 6px 12px; margin-top: 25px; }
  .section { margin-bottom: 20px; page-break-inside: avoid; }
  table { border-collapse: collapse; width: 100%; font-size: 12px; }
  th { background: #333; color: #fff; padding: 6px 10px; text-align: left; }
  td { padding: 5px 10px; border: 1px solid #ccc; }
  tr:nth-child(even) td { background: #f8f8f8; }
  tr.sev-critical td { background: #ffe0e0; }
  tr.sev-error td { background: #fff0f0; }
  tr.sev-warning td { background: #fffff0; }
  code { background: #f0f0f0; border: 1px solid #ddd; padding: 2px 6px; font-family: 'Courier New', monospace; }
  .card { background: #f8f8f8; border: 1px solid #ddd; padding: 12px; display: inline-block; margin: 5px; min-width: 120px; text-align: center; }
  .card h3 { margin: 0 0 4px 0; font-size: 11px; text-transform: uppercase; color: #666; }
  .card .val { font-size: 22px; font-weight: bold; }
  .flag-ok { color: #228B22; font-weight: bold; }
  .flag-warn { color: #DAA520; font-weight: bold; }
  .flag-crit { color: #8B0000; font-weight: bold; }
  .meta { color: #888; font-size: 11px; margin-top: 30px; border-top: 1px solid #ddd; padding-top: 8px; }
  @media print { h2 { background: #eee !important; } th { background: #333 !important; -webkit-print-color-adjust: exact; } tr.sev-critical td { background: #ffe0e0 !important; } tr.sev-error td { background: #fff0f0 !important; } tr.sev-warning td { background: #fffff0 !important; } }
</style></head><body>
<h1>Incident Timeline Report</h1>
<p><strong>Date Range:</strong> $(Invoke-HtmlEncode $minDate.ToString("yyyy-MM-dd HH:mm:ss")) to $(Invoke-HtmlEncode $maxDate.ToString("yyyy-MM-dd HH:mm:ss"))<br>
<strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
"@)

    # --- 1. Incident Summary ---
    $sw.WriteLine(@"
<div class="section"><h2>1. Incident Summary</h2>
<div class="card"><h3>Total Events</h3><div class="val">$($filtered.Count.ToString('N0'))</div></div>
<div class="card"><h3>Critical</h3><div class="val flag-crit">$($counts['CRITICAL'])</div></div>
<div class="card"><h3>Error</h3><div class="val flag-crit">$($counts['ERROR'])</div></div>
<div class="card"><h3>Warning</h3><div class="val flag-warn">$($counts['WARNING'])</div></div>
<div class="card"><h3>Info</h3><div class="val">$($counts['INFO'])</div></div>
<div class="card"><h3>Source Files</h3><div class="val">$($sourceFiles.Count)</div></div>
<p><strong>Sources:</strong> $(Invoke-HtmlEncode ($sourceFiles -join ', '))</p>
</div>
"@)

    # --- 2. Timeline ---
    $sortedEvents = $filtered | Sort-Object Timestamp | Select-Object -First 10000
    $timelineHtml = [System.Text.StringBuilder]::new()
    [void]$timelineHtml.Append("<table><tr><th>Time</th><th>Source File</th><th>Parser</th><th>Level</th><th>Source</th><th>Host</th><th>Message</th></tr>")
    foreach ($e in $sortedEvents) {
        $rowClass = switch ($e.Level) {
            'CRITICAL' { ' class="sev-critical"' }
            'ERROR'    { ' class="sev-error"' }
            'WARNING'  { ' class="sev-warning"' }
            default    { '' }
        }
        $sourceFile = if ($e.Extra -and $e.Extra['SourceFile']) { [System.IO.Path]::GetFileName($e.Extra['SourceFile']) } else { '' }
        $parser = if ($e.Extra -and $e.Extra['SourceFormat']) { $e.Extra['SourceFormat'] } else { '' }
        $host_ = if ($e.Extra -and $e.Extra['devname']) { $e.Extra['devname'] }
                 elseif ($e.Extra -and $e.Extra['ComputerName']) { $e.Extra['ComputerName'] }
                 elseif ($e.Extra -and $e.Extra['Host']) { $e.Extra['Host'] }
                 else { '' }
        $msgTrunc = if ($e.Message.Length -gt 200) { $e.Message.Substring(0, 197) + '...' } else { $e.Message }
        [void]$timelineHtml.Append("<tr$rowClass><td>$($e.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</td><td>$(Invoke-HtmlEncode $sourceFile)</td><td>$(Invoke-HtmlEncode $parser)</td><td>$($e.Level)</td><td>$(Invoke-HtmlEncode $e.Source)</td><td>$(Invoke-HtmlEncode $host_)</td><td>$(Invoke-HtmlEncode $msgTrunc)</td></tr>")
    }
    [void]$timelineHtml.Append("</table>")
    if ($filtered.Count -gt 10000) {
        [void]$timelineHtml.Append("<p><em>Showing first 10,000 of $($filtered.Count.ToString('N0')) events.</em></p>")
    }
    $sw.WriteLine("<div class='section'><h2>2. Timeline</h2>")
    $sw.WriteLine($timelineHtml.ToString())
    $sw.WriteLine("</div>")

    # --- 3. MITRE ATT&CK Observed ---
    $mitreHtml = ""
    if ($mitreData.Count -gt 0) {
        $mitreHtml = "<table><tr><th>Technique ID</th><th>Name</th><th>Tactic</th><th>Count</th></tr>"
        foreach ($key in ($mitreData.Keys | Sort-Object)) {
            $m = $mitreData[$key]
            $mitreHtml += "<tr><td>$(Invoke-HtmlEncode $m.TechniqueId)</td><td>$(Invoke-HtmlEncode $m.TechniqueName)</td><td>$(Invoke-HtmlEncode $m.Tactic)</td><td>$($m.Count)</td></tr>"
        }
        $mitreHtml += "</table>"
    } else {
        $mitreHtml = "<p>No MITRE ATT&amp;CK techniques observed in the event data.</p>"
    }
    $sw.WriteLine("<div class='section'><h2>3. MITRE ATT&amp;CK Observed</h2>$mitreHtml</div>")

    # --- 4. Key Indicators ---
    $sw.WriteLine("<div class='section'><h2>4. Key Indicators</h2>")

    # Unique IPs
    $sw.WriteLine("<h3>IP Addresses ($($uniqueIPs.Count) unique)</h3>")
    if ($uniqueIPs.Count -gt 0) {
        $sw.WriteLine("<table><tr><th>IP Address</th><th>Field</th><th>Occurrences</th></tr>")
        foreach ($ip in ($uniqueIPs.Values | Sort-Object { $_.Count } -Descending | Select-Object -First 50)) {
            $sw.WriteLine("<tr><td><code>$(Invoke-HtmlEncode $ip.IP)</code></td><td>$(Invoke-HtmlEncode $ip.Field)</td><td>$($ip.Count)</td></tr>")
        }
        $sw.WriteLine("</table>")
    } else {
        $sw.WriteLine("<p>No IP addresses extracted.</p>")
    }

    # Unique Users
    $sw.WriteLine("<h3>User Accounts ($($uniqueUsers.Count) unique)</h3>")
    if ($uniqueUsers.Count -gt 0) {
        $sw.WriteLine("<table><tr><th>User</th><th>Field</th><th>Occurrences</th></tr>")
        foreach ($u in ($uniqueUsers.Values | Sort-Object { $_.Count } -Descending | Select-Object -First 50)) {
            $sw.WriteLine("<tr><td><code>$(Invoke-HtmlEncode $u.User)</code></td><td>$(Invoke-HtmlEncode $u.Field)</td><td>$($u.Count)</td></tr>")
        }
        $sw.WriteLine("</table>")
    } else {
        $sw.WriteLine("<p>No user accounts extracted.</p>")
    }

    $sw.WriteLine("</div>")

    $sw.WriteLine("<p class='meta'>Generated by Invoke-LogParser | Incident Timeline Report</p></body></html>")
    $sw.Close()

    Write-Log "Incident timeline generated: $OutputPath"
}
