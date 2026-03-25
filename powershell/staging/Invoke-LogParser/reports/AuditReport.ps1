function New-AuditReport {
    param(
        [string]$OutputPath,
        [System.Collections.Generic.List[object]]$Entries,
        [Nullable[datetime]]$DateFrom,
        [Nullable[datetime]]$DateTo
    )

    if (-not $Entries -or $Entries.Count -eq 0) {
        Write-Log "No entries for audit report" -Level WARNING
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

    $counts = @{ CRITICAL = 0; ERROR = 0; WARNING = 0; INFO = 0; DEBUG = 0; TRACE = 0; UNKNOWN = 0 }
    foreach ($e in $filtered) { if ($counts.ContainsKey($e.Level)) { $counts[$e.Level]++ } else { $counts['UNKNOWN']++ } }

    # Date range determination
    $timestamps = $filtered | Where-Object { $_.Timestamp -ne [datetime]::MinValue } | ForEach-Object { $_.Timestamp }
    $minDate = if ($DateFrom) { $DateFrom } elseif ($timestamps) { ($timestamps | Measure-Object -Minimum).Minimum } else { Get-Date }
    $maxDate = if ($DateTo) { $DateTo } elseif ($timestamps) { ($timestamps | Measure-Object -Maximum).Maximum } else { Get-Date }

    # Collect source files
    $sourceFiles = $filtered | ForEach-Object { if ($_.Extra -and $_.Extra['SourceFile']) { $_.Extra['SourceFile'] } } | Select-Object -Unique
    if (-not $sourceFiles) { $sourceFiles = @($Script:State.LoadedFiles | ForEach-Object { [System.IO.Path]::GetFileName($_) }) }

    $sw = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.Encoding]::UTF8)

    # --- Section helpers ---
    function Write-Section { param([string]$Title, [string]$Content) $sw.WriteLine("<div class='section'><h2>$Title</h2>$Content</div>") }

    # --- Access Control Review ---
    $failedLogins = @($filtered | Where-Object { $_.Extra -and $_.Extra['EventID'] -and ([int]$_.Extra['EventID'] -in @(4625, 4771, 6273)) })
    $lockouts = @($filtered | Where-Object { $_.Extra -and $_.Extra['EventID'] -and [int]$_.Extra['EventID'] -eq 4740 })
    $privEsc = @($filtered | Where-Object { $_.Extra -and $_.Extra['EventID'] -and ([int]$_.Extra['EventID'] -in @(4672, 4648, 4728, 4732, 4756)) })
    $newAccounts = @($filtered | Where-Object { $_.Extra -and $_.Extra['EventID'] -and [int]$_.Extra['EventID'] -eq 4720 })
    $groupChanges = @($filtered | Where-Object { $_.Extra -and $_.Extra['EventID'] -and ([int]$_.Extra['EventID'] -in @(4728, 4732, 4756, 4729, 4733, 4757)) })

    # --- Audit Trail Integrity ---
    $logCleared = @($filtered | Where-Object { $_.Extra -and $_.Extra['EventID'] -and [int]$_.Extra['EventID'] -eq 1102 })
    $auditPolicyChanged = @($filtered | Where-Object { $_.Extra -and $_.Extra['EventID'] -and [int]$_.Extra['EventID'] -eq 4719 })

    # --- Network Security ---
    $fwDenies = @($filtered | Where-Object { $_.Extra -and ($_.Extra['action'] -match 'deny|block|dropped') })
    $utmEvents = @($filtered | Where-Object { $_.Extra -and $_.Extra['type'] -eq 'utm' })

    # --- VPN ---
    $vpnEvents = @($filtered | Where-Object { $_.Extra -and (($_.Extra['subtype'] -eq 'vpn') -or ($_.Message -match 'tunnel-up|tunnel-down|sslvpn')) })

    # --- Backup ---
    $backupEvents = @($filtered | Where-Object { $_.Extra -and $_.Extra['SourceFormat'] -eq 'veeam-job' })
    $backupErrors = @($backupEvents | Where-Object { $_.Level -in @('ERROR', 'CRITICAL') })

    # --- MITRE ---
    $mitreHits = @{}
    if ($Script:MitreEventIdMap) {
        foreach ($e in $filtered) {
            if ($e.Extra -and $e.Extra['EventID']) {
                $eid = [int]$e.Extra['EventID']
                if ($Script:MitreEventIdMap.ContainsKey($eid)) {
                    $mitre = $Script:MitreEventIdMap[$eid]
                    $key = $mitre.TechniqueId
                    if (-not $mitreHits.ContainsKey($key)) { $mitreHits[$key] = @{ Info = $mitre; Count = 0 } }
                    $mitreHits[$key].Count++
                }
            }
        }
    }

    $sw.WriteLine(@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>FFIEC/NCUA Compliance Audit Report</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 0; padding: 30px; color: #333; background: #fff; max-width: 1200px; margin: 0 auto; }
  h1 { color: #1a365d; border-bottom: 3px solid #1a365d; padding-bottom: 10px; }
  h2 { color: #2d4a7a; border-bottom: 1px solid #ccc; padding-bottom: 6px; margin-top: 30px; }
  .section { margin-bottom: 25px; page-break-inside: avoid; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
  .card { background: #f8f9fa; border-radius: 8px; padding: 15px; border-left: 4px solid #ccc; }
  .card h3 { margin: 0 0 5px 0; font-size: 12px; color: #666; text-transform: uppercase; }
  .card .val { font-size: 28px; font-weight: bold; }
  .card.crit { border-color: #8b0000; } .card.crit .val { color: #8b0000; }
  .card.err { border-color: #dc3545; } .card.err .val { color: #dc3545; }
  .card.warn { border-color: #ffc107; } .card.warn .val { color: #856404; }
  .card.ok { border-color: #28a745; } .card.ok .val { color: #28a745; }
  table { border-collapse: collapse; width: 100%; margin: 10px 0; font-size: 13px; }
  th { background: #2d4a7a; color: #fff; padding: 8px 12px; text-align: left; }
  td { padding: 6px 12px; border-bottom: 1px solid #e0e0e0; }
  tr:nth-child(even) td { background: #f8f9fa; }
  .flag { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; }
  .flag-crit { background: #8b0000; color: #fff; }
  .flag-warn { background: #ffc107; color: #333; }
  .flag-ok { background: #28a745; color: #fff; }
  .meta { color: #888; font-size: 12px; margin-top: 30px; border-top: 1px solid #ddd; padding-top: 10px; }
  @media print {
    body { padding: 15px; }
    .section { page-break-inside: avoid; }
    th { background: #333 !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  }
</style></head><body>
<h1>FFIEC/NCUA Compliance Audit Report</h1>
<p><strong>Date Range:</strong> $(Invoke-HtmlEncode($minDate.ToString("yyyy-MM-dd"))) to $(Invoke-HtmlEncode($maxDate.ToString("yyyy-MM-dd")))<br>
<strong>Systems Analyzed:</strong> $(Invoke-HtmlEncode(($sourceFiles -join ', ')))<br>
<strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
<strong>Total Events:</strong> $($filtered.Count.ToString('N0'))</p>
"@)

    # Executive Summary
    $sw.WriteLine(@"
<div class="section"><h2>1. Executive Summary</h2>
<div class="summary-grid">
  <div class="card"><h3>Total Events</h3><div class="val">$($filtered.Count.ToString('N0'))</div></div>
  <div class="card crit"><h3>Critical</h3><div class="val">$($counts['CRITICAL'])</div></div>
  <div class="card err"><h3>Errors</h3><div class="val">$($counts['ERROR'])</div></div>
  <div class="card warn"><h3>Warnings</h3><div class="val">$($counts['WARNING'])</div></div>
  <div class="card"><h3>Failed Logins</h3><div class="val">$($failedLogins.Count)</div></div>
  <div class="card"><h3>Account Lockouts</h3><div class="val">$($lockouts.Count)</div></div>
</div></div>
"@)

    # Access Control Review
    $acHtml = "<p>Failed logins: <strong>$($failedLogins.Count)</strong>, Lockouts: <strong>$($lockouts.Count)</strong>, Privilege escalation events: <strong>$($privEsc.Count)</strong>, New accounts: <strong>$($newAccounts.Count)</strong>, Group changes: <strong>$($groupChanges.Count)</strong></p>"
    if ($failedLogins.Count -gt 0) {
        $topFailed = $failedLogins | Group-Object { if ($_.Extra['TargetUserName']) { $_.Extra['TargetUserName'] } elseif ($_.Extra['User-Name']) { $_.Extra['User-Name'] } else { '(unknown)' } } | Sort-Object Count -Descending | Select-Object -First 10
        $acHtml += "<table><tr><th>User</th><th>Failed Attempts</th></tr>"
        foreach ($g in $topFailed) { $acHtml += "<tr><td>$(Invoke-HtmlEncode $g.Name)</td><td>$($g.Count)</td></tr>" }
        $acHtml += "</table>"
    }
    $sw.WriteLine("<div class='section'><h2>2. Access Control Review (FFIEC InTREx)</h2>$acHtml</div>")

    # Audit Trail Integrity
    $auditFlag = if ($logCleared.Count -gt 0) { "<span class='flag flag-crit'>LOGS CLEARED</span>" } else { "<span class='flag flag-ok'>OK</span>" }
    $auditHtml = "<p>Log cleared events: $auditFlag <strong>$($logCleared.Count)</strong><br>Audit policy changes: <strong>$($auditPolicyChanged.Count)</strong></p>"
    $sw.WriteLine("<div class='section'><h2>3. Audit Trail Integrity</h2>$auditHtml</div>")

    # Network Security
    $netHtml = "<p>Firewall denies: <strong>$($fwDenies.Count)</strong>, UTM events: <strong>$($utmEvents.Count)</strong></p>"
    if ($fwDenies.Count -gt 0) {
        $topSrc = $fwDenies | Group-Object { if ($_.Extra['srcip']) { $_.Extra['srcip'] } else { $_.Source } } | Sort-Object Count -Descending | Select-Object -First 10
        $netHtml += "<table><tr><th>Source</th><th>Denies</th></tr>"
        foreach ($g in $topSrc) { $netHtml += "<tr><td>$(Invoke-HtmlEncode $g.Name)</td><td>$($g.Count)</td></tr>" }
        $netHtml += "</table>"
    }
    $sw.WriteLine("<div class='section'><h2>4. Network Security</h2>$netHtml</div>")

    # VPN Access
    $vpnHtml = "<p>VPN events: <strong>$($vpnEvents.Count)</strong></p>"
    $sw.WriteLine("<div class='section'><h2>5. VPN Access</h2>$vpnHtml</div>")

    # Backup Status
    $backupHtml = "<p>Backup events: <strong>$($backupEvents.Count)</strong>, Errors: <strong>$($backupErrors.Count)</strong></p>"
    if ($backupErrors.Count -gt 0) {
        $backupHtml += "<p><span class='flag flag-warn'>$($backupErrors.Count) backup errors detected</span></p>"
    } elseif ($backupEvents.Count -gt 0) {
        $backupHtml += "<p><span class='flag flag-ok'>No backup errors</span></p>"
    }
    $sw.WriteLine("<div class='section'><h2>6. Backup Status</h2>$backupHtml</div>")

    # MITRE ATT&CK Coverage
    if ($mitreHits.Count -gt 0) {
        $mitreHtml = "<table><tr><th>Technique</th><th>Name</th><th>Tactic</th><th>Count</th></tr>"
        foreach ($key in ($mitreHits.Keys | Sort-Object)) {
            $h = $mitreHits[$key]
            $mitreHtml += "<tr><td>$($h.Info.TechniqueId)</td><td>$(Invoke-HtmlEncode $h.Info.TechniqueName)</td><td>$(Invoke-HtmlEncode $h.Info.Tactic)</td><td>$($h.Count)</td></tr>"
        }
        $mitreHtml += "</table>"
    } else {
        $mitreHtml = "<p>No MITRE ATT&CK techniques observed in loaded logs.</p>"
    }
    $sw.WriteLine("<div class='section'><h2>7. MITRE ATT&CK Coverage</h2>$mitreHtml</div>")

    $sw.WriteLine("<p class='meta'>Generated by Universal Log Parser v$($Config.Version) | FFIEC/NCUA Compliance Audit Report</p></body></html>")
    $sw.Close()

    Write-Log "Audit report generated: $OutputPath"
}
