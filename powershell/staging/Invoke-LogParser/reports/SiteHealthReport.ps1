function New-SiteHealthReport {
    param(
        [string]$OutputPath,
        [System.Collections.Generic.List[object]]$Entries,
        [Nullable[datetime]]$DateFrom,
        [Nullable[datetime]]$DateTo
    )

    if (-not $Entries -or $Entries.Count -eq 0) {
        Write-Log "No entries for site health report" -Level WARNING
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
        Write-Log "No entries match date range for site health report" -Level WARNING
        return
    }

    # Severity counts
    $counts = @{ CRITICAL = 0; ERROR = 0; WARNING = 0; INFO = 0; DEBUG = 0; TRACE = 0; UNKNOWN = 0 }
    foreach ($e in $filtered) { if ($counts.ContainsKey($e.Level)) { $counts[$e.Level]++ } else { $counts['UNKNOWN']++ } }

    # Date range determination
    $timestamps = $filtered | Where-Object { $_.Timestamp -ne [datetime]::MinValue } | ForEach-Object { $_.Timestamp }
    $minDate = if ($DateFrom) { $DateFrom } elseif ($timestamps) { ($timestamps | Measure-Object -Minimum).Minimum } else { Get-Date }
    $maxDate = if ($DateTo) { $DateTo } elseif ($timestamps) { ($timestamps | Measure-Object -Maximum).Maximum } else { Get-Date }

    # Collect source files
    $sourceFiles = @($filtered | ForEach-Object { if ($_.Extra -and $_.Extra['SourceFile']) { $_.Extra['SourceFile'] } } | Where-Object { $_ } | Select-Object -Unique)
    if ($sourceFiles.Count -eq 0) { $sourceFiles = @($Script:State.LoadedFiles | ForEach-Object { [System.IO.Path]::GetFileName($_) }) }

    # --- Per-Device Summary ---
    $deviceGroups = $filtered | Where-Object { $_.Source } | Group-Object Source
    $deviceSummary = foreach ($dg in ($deviceGroups | Sort-Object Count -Descending)) {
        $devCounts = @{ CRITICAL = 0; ERROR = 0; WARNING = 0; INFO = 0 }
        foreach ($de in $dg.Group) {
            if ($devCounts.ContainsKey($de.Level)) { $devCounts[$de.Level]++ }
        }
        $health = if ($devCounts['CRITICAL'] -gt 0) { 'CRITICAL' }
                  elseif ($devCounts['ERROR'] -gt 0) { 'DEGRADED' }
                  elseif ($devCounts['WARNING'] -gt 0) { 'WARNING' }
                  else { 'HEALTHY' }
        [PSCustomObject]@{
            Device   = $dg.Name
            Total    = $dg.Count
            Critical = $devCounts['CRITICAL']
            Error    = $devCounts['ERROR']
            Warning  = $devCounts['WARNING']
            Info     = $devCounts['INFO']
            Health   = $health
        }
    }

    # --- Tunnel Health ---
    $tunnelEvents = @($filtered | Where-Object {
        $_.Extra -and (
            ($_.Extra['subtype'] -match 'vpn|ipsec') -or
            ($_.Extra['action'] -match 'tunnel-up|tunnel-down')
        )
    })
    $tunnelsByName = @{}
    foreach ($te in $tunnelEvents) {
        $tName = if ($te.Extra['tunnelid']) { $te.Extra['tunnelid'] }
                 elseif ($te.Extra['tunnel_id']) { $te.Extra['tunnel_id'] }
                 elseif ($te.Extra['remip']) { $te.Extra['remip'] }
                 elseif ($te.Extra['peerip']) { $te.Extra['peerip'] }
                 else { $te.Source }
        if (-not $tunnelsByName.ContainsKey($tName)) {
            $tunnelsByName[$tName] = @{ Name = $tName; Up = 0; Down = 0; Events = [System.Collections.Generic.List[object]]::new() }
        }
        $tunnelsByName[$tName].Events.Add($te)
        if ($te.Extra['action'] -match 'tunnel-up') { $tunnelsByName[$tName].Up++ }
        elseif ($te.Extra['action'] -match 'tunnel-down') { $tunnelsByName[$tName].Down++ }
    }

    # --- Authentication Health ---
    $authEvents = @($filtered | Where-Object {
        $_.Extra -and (
            ($_.Extra['PacketTypeName']) -or
            ($_.Extra['EventID'] -and [int]$_.Extra['EventID'] -in @(4624, 4625, 4771, 4768, 4769, 6273, 6274, 6278))
        )
    })
    $authAccept = @($authEvents | Where-Object {
        ($_.Extra['PacketTypeName'] -eq 'Access-Accept') -or
        ($_.Extra['EventID'] -and [int]$_.Extra['EventID'] -in @(4624, 4768, 6278))
    }).Count
    $authReject = @($authEvents | Where-Object {
        ($_.Extra['PacketTypeName'] -eq 'Access-Reject') -or
        ($_.Extra['EventID'] -and [int]$_.Extra['EventID'] -in @(4625, 4771, 6273))
    }).Count
    $authTotal = [Math]::Max(1, $authAccept + $authReject)
    $acceptRate = [Math]::Round(($authAccept / $authTotal) * 100, 1)
    $rejectRate = [Math]::Round(($authReject / $authTotal) * 100, 1)

    # --- Backup Health ---
    $backupEvents = @($filtered | Where-Object {
        $_.Extra -and ($_.Extra['SourceFormat'] -eq 'veeam-job' -or $_.Extra['SourceFormat'] -eq 'veeam-session')
    })
    $backupJobs = $backupEvents | Group-Object {
        if ($_.Extra['JobName']) { $_.Extra['JobName'] }
        elseif ($_.Extra['Name']) { $_.Extra['Name'] }
        else { '(unknown)' }
    }

    # --- Top Issues ---
    $topIssues = @($filtered | Where-Object { $_.Level -in @('ERROR', 'CRITICAL') } | Sort-Object Timestamp -Descending | Select-Object -First 20)

    $sw = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.Encoding]::UTF8)

    $sw.WriteLine(@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Site Health Report</title>
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
  code { background: #f0f0f0; border: 1px solid #ddd; padding: 2px 6px; font-family: 'Courier New', monospace; }
  .card { background: #f8f8f8; border: 1px solid #ddd; padding: 12px; display: inline-block; margin: 5px; min-width: 120px; text-align: center; }
  .card h3 { margin: 0 0 4px 0; font-size: 11px; text-transform: uppercase; color: #666; }
  .card .val { font-size: 22px; font-weight: bold; }
  .flag-ok { color: #228B22; font-weight: bold; }
  .flag-warn { color: #DAA520; font-weight: bold; }
  .flag-crit { color: #8B0000; font-weight: bold; }
  .meta { color: #888; font-size: 11px; margin-top: 30px; border-top: 1px solid #ddd; padding-top: 8px; }
  @media print { h2 { background: #eee !important; } th { background: #333 !important; -webkit-print-color-adjust: exact; } }
</style></head><body>
<h1>Site Health Report</h1>
<p><strong>Date Range:</strong> $(Invoke-HtmlEncode $minDate.ToString("yyyy-MM-dd HH:mm")) to $(Invoke-HtmlEncode $maxDate.ToString("yyyy-MM-dd HH:mm"))<br>
<strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
"@)

    # --- 1. Overview ---
    $sw.WriteLine(@"
<div class="section"><h2>1. Overview</h2>
<div class="card"><h3>Total Events</h3><div class="val">$($filtered.Count.ToString('N0'))</div></div>
<div class="card"><h3>Source Files</h3><div class="val">$($sourceFiles.Count)</div></div>
<div class="card"><h3>Date Span</h3><div class="val">$(([Math]::Max(1, ($maxDate - $minDate).Days))) days</div></div>
<div class="card"><h3>Critical</h3><div class="val flag-crit">$($counts['CRITICAL'])</div></div>
<div class="card"><h3>Error</h3><div class="val flag-crit">$($counts['ERROR'])</div></div>
<div class="card"><h3>Warning</h3><div class="val flag-warn">$($counts['WARNING'])</div></div>
</div>
"@)

    # --- 2. Per-Device Summary ---
    $devHtml = "<table><tr><th>Device</th><th>Total</th><th>Critical</th><th>Error</th><th>Warning</th><th>Info</th><th>Health</th></tr>"
    foreach ($d in $deviceSummary) {
        $healthClass = switch ($d.Health) { 'CRITICAL' { 'flag-crit' } 'DEGRADED' { 'flag-crit' } 'WARNING' { 'flag-warn' } default { 'flag-ok' } }
        $devHtml += "<tr><td>$(Invoke-HtmlEncode $d.Device)</td><td>$($d.Total)</td><td>$($d.Critical)</td><td>$($d.Error)</td><td>$($d.Warning)</td><td>$($d.Info)</td><td class='$healthClass'>$($d.Health)</td></tr>"
    }
    $devHtml += "</table>"
    $sw.WriteLine("<div class='section'><h2>2. Per-Device Summary</h2>$devHtml</div>")

    # --- 3. Tunnel Health ---
    $tunHtml = ""
    if ($tunnelsByName.Count -gt 0) {
        $tunHtml = "<table><tr><th>Tunnel</th><th>Up Events</th><th>Down Events</th><th>Flap Count</th><th>Uptime%</th></tr>"
        foreach ($tk in ($tunnelsByName.Keys | Sort-Object)) {
            $t = $tunnelsByName[$tk]
            $flapCount = [Math]::Min($t.Up, $t.Down)
            $totalTransitions = $t.Up + $t.Down
            $uptimePct = if ($totalTransitions -gt 0) { [Math]::Round(($t.Up / $totalTransitions) * 100, 1) } else { 100.0 }
            $uptimeClass = if ($uptimePct -ge 95) { 'flag-ok' } elseif ($uptimePct -ge 80) { 'flag-warn' } else { 'flag-crit' }
            $tunHtml += "<tr><td>$(Invoke-HtmlEncode $t.Name)</td><td>$($t.Up)</td><td>$($t.Down)</td><td>$flapCount</td><td class='$uptimeClass'>$uptimePct%</td></tr>"
        }
        $tunHtml += "</table>"
    } else {
        $tunHtml = "<p>No VPN/IPsec tunnel events found.</p>"
    }
    $sw.WriteLine("<div class='section'><h2>3. Tunnel Health</h2>$tunHtml</div>")

    # --- 4. Authentication Health ---
    $sw.WriteLine(@"
<div class="section"><h2>4. Authentication Health</h2>
<div class="card"><h3>Total Auth</h3><div class="val">$($authAccept + $authReject)</div></div>
<div class="card"><h3>Accept Rate</h3><div class="val flag-ok">$acceptRate%</div></div>
<div class="card"><h3>Reject Rate</h3><div class="val$(if ($rejectRate -gt 10) { ' flag-crit' } elseif ($rejectRate -gt 5) { ' flag-warn' } else { '' })">$rejectRate%</div></div>
</div>
"@)

    # --- 5. Backup Health ---
    $bkpHtml = ""
    if ($backupJobs -and @($backupJobs).Count -gt 0) {
        $bkpHtml = "<table><tr><th>Job</th><th>Status</th><th>Last Run</th><th>Duration</th></tr>"
        foreach ($bj in $backupJobs) {
            $lastEvent = $bj.Group | Sort-Object Timestamp -Descending | Select-Object -First 1
            $status = if ($lastEvent.Level -in @('ERROR', 'CRITICAL')) { 'Failed' }
                      elseif ($lastEvent.Level -eq 'WARNING') { 'Warning' }
                      else { 'Success' }
            $statusClass = switch ($status) { 'Failed' { 'flag-crit' } 'Warning' { 'flag-warn' } default { 'flag-ok' } }
            $duration = if ($lastEvent.Extra -and $lastEvent.Extra['Duration']) { $lastEvent.Extra['Duration'] } else { '-' }
            $bkpHtml += "<tr><td>$(Invoke-HtmlEncode $bj.Name)</td><td class='$statusClass'>$status</td><td>$($lastEvent.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</td><td>$(Invoke-HtmlEncode $duration)</td></tr>"
        }
        $bkpHtml += "</table>"
    } else {
        $bkpHtml = "<p>No Veeam backup events found.</p>"
    }
    $sw.WriteLine("<div class='section'><h2>5. Backup Health</h2>$bkpHtml</div>")

    # --- 6. Top Issues ---
    $issueHtml = ""
    if ($topIssues.Count -gt 0) {
        $issueHtml = "<table><tr><th>Time</th><th>Source</th><th>Message</th></tr>"
        foreach ($i in $topIssues) {
            $msgTrunc = if ($i.Message.Length -gt 150) { $i.Message.Substring(0, 147) + '...' } else { $i.Message }
            $issueHtml += "<tr><td>$($i.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</td><td>$(Invoke-HtmlEncode $i.Source)</td><td>$(Invoke-HtmlEncode $msgTrunc)</td></tr>"
        }
        $issueHtml += "</table>"
    } else {
        $issueHtml = "<p class='flag-ok'>No error or critical events found.</p>"
    }
    $sw.WriteLine("<div class='section'><h2>6. Top Issues</h2>$issueHtml</div>")

    $sw.WriteLine("<p class='meta'>Generated by Invoke-LogParser | Site Health Report</p></body></html>")
    $sw.Close()

    Write-Log "Site health report generated: $OutputPath"
}
