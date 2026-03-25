function New-MorningBriefing {
    param(
        [string]$OutputPath,
        [System.Collections.Generic.List[object]]$Entries,
        [Nullable[datetime]]$DateFrom,
        [Nullable[datetime]]$DateTo
    )

    if (-not $Entries -or $Entries.Count -eq 0) {
        Write-Log "No entries for morning briefing" -Level WARNING
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
        Write-Log "No entries match date range for morning briefing" -Level WARNING
        return
    }

    # Severity counts
    $counts = @{ CRITICAL = 0; ERROR = 0; WARNING = 0; INFO = 0; DEBUG = 0; TRACE = 0; UNKNOWN = 0 }
    foreach ($e in $filtered) { if ($counts.ContainsKey($e.Level)) { $counts[$e.Level]++ } else { $counts['UNKNOWN']++ } }

    # Date range determination
    $timestamps = $filtered | Where-Object { $_.Timestamp -ne [datetime]::MinValue } | ForEach-Object { $_.Timestamp }
    $minDate = if ($DateFrom) { $DateFrom } elseif ($timestamps) { ($timestamps | Measure-Object -Minimum).Minimum } else { Get-Date }
    $maxDate = if ($DateTo) { $DateTo } elseif ($timestamps) { ($timestamps | Measure-Object -Maximum).Maximum } else { Get-Date }

    # --- Data collection ---

    # Tunnel status: IPsec tunnel up/down events from last 24h
    $last24h = (Get-Date).AddHours(-24)
    $tunnelEvents = @($filtered | Where-Object {
        $_.Timestamp -ge $last24h -and $_.Extra -and
        (($_.Extra['subtype'] -match 'vpn|ipsec') -or ($_.Extra['action'] -match 'tunnel-up|tunnel-down'))
    })
    $tunnelsByName = @{}
    foreach ($te in $tunnelEvents) {
        $tunnelName = if ($te.Extra['tunnelid']) { $te.Extra['tunnelid'] }
                      elseif ($te.Extra['tunnel_id']) { $te.Extra['tunnel_id'] }
                      elseif ($te.Extra['remip']) { $te.Extra['remip'] }
                      elseif ($te.Extra['peerip']) { $te.Extra['peerip'] }
                      else { $te.Source }
        if (-not $tunnelsByName.ContainsKey($tunnelName)) {
            $tunnelsByName[$tunnelName] = @{ Name = $tunnelName; Status = 'Unknown'; LastChange = $te.Timestamp }
        }
        if ($te.Timestamp -gt $tunnelsByName[$tunnelName].LastChange) {
            $tunnelsByName[$tunnelName].LastChange = $te.Timestamp
        }
        if ($te.Extra['action'] -match 'tunnel-up') { $tunnelsByName[$tunnelName].Status = 'UP' }
        elseif ($te.Extra['action'] -match 'tunnel-down') { $tunnelsByName[$tunnelName].Status = 'DOWN' }
    }

    # Backup results (Veeam)
    $backupEvents = @($filtered | Where-Object {
        $_.Extra -and ($_.Extra['SourceFormat'] -eq 'veeam-job' -or $_.Extra['SourceFormat'] -eq 'veeam-session')
    })
    $backupSuccess = @($backupEvents | Where-Object { $_.Level -eq 'INFO' -or ($_.Extra -and $_.Extra['Status'] -match 'Success') }).Count
    $backupWarning = @($backupEvents | Where-Object { $_.Level -eq 'WARNING' }).Count
    $backupFail = @($backupEvents | Where-Object { $_.Level -in @('ERROR', 'CRITICAL') }).Count

    # Failed login summary
    $failedLogins = @($filtered | Where-Object {
        $_.Extra -and (
            ($_.Extra['EventID'] -and [int]$_.Extra['EventID'] -in @(4625, 4771)) -or
            ($_.Extra['PacketTypeName'] -eq 'Access-Reject')
        )
    })
    $failedByUser = $failedLogins | Group-Object {
        if ($_.Extra['TargetUserName']) { $_.Extra['TargetUserName'] }
        elseif ($_.Extra['User-Name']) { $_.Extra['User-Name'] }
        elseif ($_.Extra['user']) { $_.Extra['user'] }
        else { '(unknown)' }
    } | Sort-Object Count -Descending | Select-Object -First 10

    # Certificate warnings (expiring within 90 days)
    $certWarnings = @($filtered | Where-Object {
        $_.Extra -and $_.Extra['DaysToExpiry'] -and [int]$_.Extra['DaysToExpiry'] -le 90
    })

    # Security alerts: Defender alerts + FortiGate UTM denies + IPS events
    $securityAlerts = @($filtered | Where-Object {
        ($_.Level -in @('CRITICAL', 'ERROR')) -and $_.Extra -and (
            ($_.Extra['SourceFormat'] -match 'defender') -or
            ($_.Extra['type'] -eq 'utm') -or
            ($_.Extra['subtype'] -eq 'ips') -or
            ($_.Extra['action'] -match 'block|deny|quarantine|alert')
        )
    } | Sort-Object Timestamp -Descending | Select-Object -First 20)

    # Site health determination
    $healthStatus = if ($counts['CRITICAL'] -gt 0) { 'RED' }
                    elseif ($counts['ERROR'] -gt 5 -or $counts['WARNING'] -gt 20) { 'YELLOW' }
                    else { 'GREEN' }

    $sw = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.Encoding]::UTF8)

    $sw.WriteLine(@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Morning Briefing - $(Get-Date -Format "yyyy-MM-dd")</title>
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
<h1>Morning Briefing &mdash; $(Invoke-HtmlEncode (Get-Date -Format "dddd, MMMM d, yyyy"))</h1>
<p><strong>Report Period:</strong> $(Invoke-HtmlEncode $minDate.ToString("yyyy-MM-dd HH:mm")) to $(Invoke-HtmlEncode $maxDate.ToString("yyyy-MM-dd HH:mm"))<br>
<strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
<strong>Total Events:</strong> $($filtered.Count.ToString('N0'))</p>
"@)

    # --- 1. Executive Summary ---
    $sw.WriteLine(@"
<div class="section"><h2>1. Executive Summary</h2>
<div class="card"><h3>Total</h3><div class="val">$($filtered.Count.ToString('N0'))</div></div>
<div class="card"><h3>Critical</h3><div class="val flag-crit">$($counts['CRITICAL'])</div></div>
<div class="card"><h3>Error</h3><div class="val flag-crit">$($counts['ERROR'])</div></div>
<div class="card"><h3>Warning</h3><div class="val flag-warn">$($counts['WARNING'])</div></div>
</div>
"@)

    # --- 2. Tunnel Status ---
    $tunnelHtml = ""
    if ($tunnelsByName.Count -gt 0) {
        $tunnelHtml = "<table><tr><th>Tunnel</th><th>Status</th><th>Last Change Time</th></tr>"
        foreach ($t in ($tunnelsByName.Values | Sort-Object { $_.Status })) {
            $statusClass = if ($t.Status -eq 'UP') { 'flag-ok' } elseif ($t.Status -eq 'DOWN') { 'flag-crit' } else { 'flag-warn' }
            $tunnelHtml += "<tr><td>$(Invoke-HtmlEncode $t.Name)</td><td><span class='$statusClass'>$($t.Status)</span></td><td>$($t.LastChange.ToString('yyyy-MM-dd HH:mm:ss'))</td></tr>"
        }
        $tunnelHtml += "</table>"
    } else {
        $tunnelHtml = "<p>No tunnel events found in the last 24 hours.</p>"
    }
    $sw.WriteLine("<div class='section'><h2>2. Tunnel Status</h2>$tunnelHtml</div>")

    # --- 3. Backup Results ---
    $sw.WriteLine(@"
<div class="section"><h2>3. Backup Results</h2>
<div class="card"><h3>Success</h3><div class="val flag-ok">$backupSuccess</div></div>
<div class="card"><h3>Warning</h3><div class="val flag-warn">$backupWarning</div></div>
<div class="card"><h3>Failed</h3><div class="val flag-crit">$backupFail</div></div>
</div>
"@)

    # --- 4. Failed Login Summary ---
    $loginHtml = ""
    if ($failedByUser -and $failedByUser.Count -gt 0) {
        $loginHtml = "<p>Total failed login events: <strong>$($failedLogins.Count)</strong></p>"
        $loginHtml += "<table><tr><th>User</th><th>Count</th><th>Source IPs</th></tr>"
        foreach ($g in $failedByUser) {
            $sourceIps = @($g.Group | ForEach-Object {
                if ($_.Extra['IPAddress']) { $_.Extra['IPAddress'] }
                elseif ($_.Extra['srcip']) { $_.Extra['srcip'] }
                elseif ($_.Extra['Calling-Station-Id']) { $_.Extra['Calling-Station-Id'] }
                elseif ($_.Extra['IpAddress']) { $_.Extra['IpAddress'] }
            } | Where-Object { $_ } | Select-Object -Unique | Select-Object -First 5) -join ', '
            $loginHtml += "<tr><td>$(Invoke-HtmlEncode $g.Name)</td><td>$($g.Count)</td><td>$(Invoke-HtmlEncode $sourceIps)</td></tr>"
        }
        $loginHtml += "</table>"
    } else {
        $loginHtml = "<p class='flag-ok'>No failed login events detected.</p>"
    }
    $sw.WriteLine("<div class='section'><h2>4. Failed Login Summary</h2>$loginHtml</div>")

    # --- 5. Certificate Warnings ---
    $certHtml = ""
    if ($certWarnings.Count -gt 0) {
        $certHtml = "<table><tr><th>Subject</th><th>Expires</th><th>Days Left</th></tr>"
        foreach ($c in ($certWarnings | Sort-Object { [int]$_.Extra['DaysToExpiry'] })) {
            $daysLeft = [int]$c.Extra['DaysToExpiry']
            $daysClass = if ($daysLeft -le 14) { 'flag-crit' } elseif ($daysLeft -le 30) { 'flag-warn' } else { '' }
            $subject = if ($c.Extra['Subject']) { $c.Extra['Subject'] } elseif ($c.Extra['CommonName']) { $c.Extra['CommonName'] } else { $c.Message }
            $expires = if ($c.Extra['NotAfter']) { $c.Extra['NotAfter'] } elseif ($c.Extra['ExpiryDate']) { $c.Extra['ExpiryDate'] } else { '' }
            $certHtml += "<tr><td>$(Invoke-HtmlEncode $subject)</td><td>$(Invoke-HtmlEncode $expires)</td><td class='$daysClass'>$daysLeft</td></tr>"
        }
        $certHtml += "</table>"
    } else {
        $certHtml = "<p class='flag-ok'>No certificates expiring within 90 days.</p>"
    }
    $sw.WriteLine("<div class='section'><h2>5. Certificate Warnings</h2>$certHtml</div>")

    # --- 6. Security Alerts ---
    $alertHtml = ""
    if ($securityAlerts.Count -gt 0) {
        $alertHtml = "<table><tr><th>Time</th><th>Source</th><th>Severity</th><th>Message</th></tr>"
        foreach ($a in $securityAlerts) {
            $sevClass = if ($a.Level -eq 'CRITICAL') { 'flag-crit' } else { 'flag-warn' }
            $msgTrunc = if ($a.Message.Length -gt 120) { $a.Message.Substring(0, 117) + '...' } else { $a.Message }
            $alertHtml += "<tr><td>$($a.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</td><td>$(Invoke-HtmlEncode $a.Source)</td><td class='$sevClass'>$($a.Level)</td><td>$(Invoke-HtmlEncode $msgTrunc)</td></tr>"
        }
        $alertHtml += "</table>"
    } else {
        $alertHtml = "<p class='flag-ok'>No security alerts detected.</p>"
    }
    $sw.WriteLine("<div class='section'><h2>6. Security Alerts</h2>$alertHtml</div>")

    # --- 7. Site Health ---
    $healthClass = if ($healthStatus -eq 'GREEN') { 'flag-ok' } elseif ($healthStatus -eq 'YELLOW') { 'flag-warn' } else { 'flag-crit' }
    $healthDesc = if ($healthStatus -eq 'GREEN') { 'All systems nominal. No critical or excessive error events detected.' }
                  elseif ($healthStatus -eq 'YELLOW') { 'Warnings present. Review items above for potential issues.' }
                  else { 'Critical issues detected. Immediate attention required.' }
    $sw.WriteLine(@"
<div class="section"><h2>7. Site Health</h2>
<div class="card"><h3>Overall Status</h3><div class="val $healthClass">$healthStatus</div></div>
<p>$healthDesc</p>
<ul>
<li>Critical events: $($counts['CRITICAL'])</li>
<li>Error events: $($counts['ERROR'])</li>
<li>Warning events: $($counts['WARNING'])</li>
<li>Tunnel issues: $(@($tunnelsByName.Values | Where-Object { $_.Status -eq 'DOWN' }).Count) down</li>
<li>Backup failures: $backupFail</li>
<li>Failed logins: $($failedLogins.Count)</li>
</ul>
</div>
"@)

    $sw.WriteLine("<p class='meta'>Generated by Invoke-LogParser | Morning Briefing Report</p></body></html>")
    $sw.Close()

    Write-Log "Morning briefing generated: $OutputPath"
}
