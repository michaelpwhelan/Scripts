function New-FfiecComplianceReport {
    param(
        [string]$OutputPath,
        [System.Collections.Generic.List[object]]$Entries,
        [Nullable[datetime]]$DateFrom,
        [Nullable[datetime]]$DateTo
    )

    if (-not $Entries -or $Entries.Count -eq 0) {
        Write-Log "No entries for FFIEC compliance report" -Level WARNING
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
        Write-Log "No entries match date range for FFIEC compliance report" -Level WARNING
        return
    }

    # Guard: use $Script:FfiecControlMap if available, otherwise define a basic structure
    $controlMap = if ($Script:FfiecControlMap) { $Script:FfiecControlMap } else {
        @{
            "IS.WP.AC" = @{ Name = "Access Controls and User Management"; Handbook = "Information Security"; EventPatterns = @( @{ Field = "EventID"; Values = @(4624,4625,4634,4647,4648,4672,4720,4722,4725,4726,4740) } ) }
            "IS.WP.AL" = @{ Name = "Audit and Logging"; Handbook = "Information Security"; EventPatterns = @( @{ Field = "EventID"; Values = @(1102,4719,4904,4905,4906,4907,4912) } ) }
            "IS.WP.CM" = @{ Name = "Change Management"; Handbook = "Information Security"; EventPatterns = @( @{ Field = "EventID"; Values = @(4657,4670,4697,4698,4699,4700,4701,4702,5136,7045) } ) }
            "IS.WP.ID" = @{ Name = "Incident Detection and Response"; Handbook = "Information Security"; EventPatterns = @( @{ Field = "EventID"; Values = @(1116,1117,4625,4648,4719,4740,4768,4769,4771,5038) } ) }
            "IS.WP.BC" = @{ Name = "Business Continuity Planning"; Handbook = "Information Security"; EventPatterns = @( @{ Field = "EventID"; Values = @(41,6005,6006,6008,7034,7036,18512,18514,18516) } ) }
            "IS.WP.NS" = @{ Name = "Network Security"; Handbook = "Information Security"; EventPatterns = @( @{ Field = "EventID"; Values = @(4946,4947,4948,4950,5152,5156,5157) } ) }
            "IS.WP.AM" = @{ Name = "Account Management and Authentication"; Handbook = "Information Security"; EventPatterns = @( @{ Field = "EventID"; Values = @(4720,4722,4723,4724,4725,4726,4738,4741,4742,4743,4767) } ) }
            "IS.WP.RM" = @{ Name = "Remote Access Management"; Handbook = "Information Security"; EventPatterns = @( @{ Field = "EventID"; Values = @(4624,4625,4648,4778,4779) } ) }
            "IS.WP.PM" = @{ Name = "Privilege Management"; Handbook = "Information Security"; EventPatterns = @( @{ Field = "EventID"; Values = @(4672,4673,4728,4732,4756,4757) } ) }
            "IS.WP.MV" = @{ Name = "Malware and Vulnerability Management"; Handbook = "Information Security"; EventPatterns = @( @{ Field = "EventID"; Values = @(1006,1007,1008,1116,1117,5001,5010,5012) } ) }
        }
    }

    # Date range determination
    $timestamps = $filtered | Where-Object { $_.Timestamp -ne [datetime]::MinValue } | ForEach-Object { $_.Timestamp }
    $minDate = if ($DateFrom) { $DateFrom } elseif ($timestamps) { ($timestamps | Measure-Object -Minimum).Minimum } else { Get-Date }
    $maxDate = if ($DateTo) { $DateTo } elseif ($timestamps) { ($timestamps | Measure-Object -Maximum).Maximum } else { Get-Date }

    # Source files
    $sourceFiles = @($filtered | ForEach-Object { if ($_.Extra -and $_.Extra['SourceFile']) { $_.Extra['SourceFile'] } } | Where-Object { $_ } | Select-Object -Unique)
    if ($sourceFiles.Count -eq 0) { $sourceFiles = @($Script:State.LoadedFiles | ForEach-Object { [System.IO.Path]::GetFileName($_) }) }

    # --- Assess each control ---
    $controlResults = @{}
    foreach ($controlId in ($controlMap.Keys | Sort-Object)) {
        $control = $controlMap[$controlId]
        $matchedEvents = [System.Collections.Generic.List[object]]::new()

        foreach ($e in $filtered) {
            if (-not $e.Extra) { continue }
            $matched = $false

            foreach ($pattern in $control.EventPatterns) {
                $fieldValue = $e.Extra[$pattern.Field]
                if ($null -eq $fieldValue) { continue }

                if ($pattern.ContainsKey('Values')) {
                    if ($fieldValue -in $pattern.Values) { $matched = $true; break }
                }
                if ($pattern.ContainsKey('Pattern')) {
                    if ($fieldValue -match $pattern.Pattern) { $matched = $true; break }
                }
            }

            if ($matched) { $matchedEvents.Add($e) }
        }

        $controlResults[$controlId] = @{
            Id       = $controlId
            Name     = $control.Name
            Handbook = $control.Handbook
            Events   = $matchedEvents
            Count    = $matchedEvents.Count
            Status   = if ($matchedEvents.Count -gt 0) { 'Evidence Found' } else { 'Insufficient Evidence' }
        }
    }

    $controlsAssessed = $controlResults.Count
    $controlsWithEvidence = @($controlResults.Values | Where-Object { $_.Count -gt 0 }).Count
    $coveragePct = if ($controlsAssessed -gt 0) { [Math]::Round(($controlsWithEvidence / $controlsAssessed) * 100, 1) } else { 0 }

    # --- Privileged Access Review ---
    $privEvents = @($filtered | Where-Object {
        $_.Extra -and $_.Extra['EventID'] -and ([int]$_.Extra['EventID'] -in @(4672, 4648))
    })
    $topPrivUsers = $privEvents | Group-Object {
        if ($_.Extra['SubjectUserName']) { $_.Extra['SubjectUserName'] }
        elseif ($_.Extra['TargetUserName']) { $_.Extra['TargetUserName'] }
        elseif ($_.Extra['user']) { $_.Extra['user'] }
        else { '(unknown)' }
    } | Sort-Object Count -Descending | Select-Object -First 15

    # --- Log Retention Assessment ---
    $earliestTs = if ($timestamps) { ($timestamps | Measure-Object -Minimum).Minimum } else { $null }
    $latestTs = if ($timestamps) { ($timestamps | Measure-Object -Maximum).Maximum } else { $null }
    $daysCovered = if ($earliestTs -and $latestTs) { [Math]::Max(1, ($latestTs - $earliestTs).Days) } else { 0 }

    # --- Audit Trail Integrity ---
    $logCleared = @($filtered | Where-Object { $_.Extra -and $_.Extra['EventID'] -and [int]$_.Extra['EventID'] -eq 1102 })
    $auditPolicyChanged = @($filtered | Where-Object { $_.Extra -and $_.Extra['EventID'] -and [int]$_.Extra['EventID'] -eq 4719 })

    $sw = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.Encoding]::UTF8)

    $sw.WriteLine(@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>FFIEC IT Examination Compliance Evidence Report</title>
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
  .control-block { border: 1px solid #ccc; margin: 15px 0; padding: 15px; page-break-inside: avoid; }
  .control-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
  .control-header h3 { margin: 0; }
  .evidence-found { background: #f0fff0; border-left: 4px solid #228B22; }
  .evidence-missing { background: #fff0f0; border-left: 4px solid #8B0000; }
  .meta { color: #888; font-size: 11px; margin-top: 30px; border-top: 1px solid #ddd; padding-top: 8px; }
  @media print { h2 { background: #eee !important; } th { background: #333 !important; -webkit-print-color-adjust: exact; } .evidence-found { background: #f0fff0 !important; } .evidence-missing { background: #fff0f0 !important; } }
</style></head><body>
"@)

    # --- 1. Cover Page ---
    $sw.WriteLine(@"
<div class="section" style="text-align: center; padding: 60px 0 40px 0;">
<h1 style="font-size: 24px; border-bottom: 3px solid #000;">FFIEC IT Examination<br>Compliance Evidence Report</h1>
<p style="font-size: 14px; margin-top: 30px;">
<strong>Report Period:</strong> $(Invoke-HtmlEncode $minDate.ToString("yyyy-MM-dd")) to $(Invoke-HtmlEncode $maxDate.ToString("yyyy-MM-dd"))<br><br>
<strong>Systems Analyzed:</strong><br>$(Invoke-HtmlEncode ($sourceFiles -join ', '))<br><br>
<strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
<strong>Total Events Analyzed:</strong> $($filtered.Count.ToString('N0'))
</p>
</div>
"@)

    # --- 2. Executive Summary ---
    $sw.WriteLine(@"
<div class="section"><h2>2. Executive Summary</h2>
<div class="card"><h3>Events Analyzed</h3><div class="val">$($filtered.Count.ToString('N0'))</div></div>
<div class="card"><h3>Controls Assessed</h3><div class="val">$controlsAssessed</div></div>
<div class="card"><h3>Evidence Coverage</h3><div class="val$(if ($coveragePct -ge 80) { ' flag-ok' } elseif ($coveragePct -ge 50) { ' flag-warn' } else { ' flag-crit' })">$coveragePct%</div></div>
<div class="card"><h3>Controls w/ Evidence</h3><div class="val flag-ok">$controlsWithEvidence</div></div>
<div class="card"><h3>Gaps</h3><div class="val$(if (($controlsAssessed - $controlsWithEvidence) -gt 0) { ' flag-crit' } else { '' })">$($controlsAssessed - $controlsWithEvidence)</div></div>
</div>
"@)

    # --- 3. Per-Control Assessment ---
    $sw.WriteLine("<div class='section'><h2>3. Per-Control Assessment</h2>")
    foreach ($controlId in ($controlResults.Keys | Sort-Object)) {
        $cr = $controlResults[$controlId]
        $blockClass = if ($cr.Count -gt 0) { 'evidence-found' } else { 'evidence-missing' }
        $statusClass = if ($cr.Count -gt 0) { 'flag-ok' } else { 'flag-crit' }

        $sw.WriteLine("<div class='control-block $blockClass'>")
        $sw.WriteLine("<div class='control-header'><h3>$(Invoke-HtmlEncode $cr.Id) &mdash; $(Invoke-HtmlEncode $cr.Name)</h3><span class='$statusClass'>$($cr.Status)</span></div>")
        $sw.WriteLine("<p><strong>Handbook:</strong> $(Invoke-HtmlEncode $cr.Handbook) | <strong>Evidence Count:</strong> $($cr.Count.ToString('N0'))</p>")

        if ($cr.Count -gt 0) {
            $sampleEvents = $cr.Events | Sort-Object Timestamp -Descending | Select-Object -First 5
            $sw.WriteLine("<table><tr><th>Timestamp</th><th>Source</th><th>Message</th></tr>")
            foreach ($se in $sampleEvents) {
                $msgTrunc = if ($se.Message.Length -gt 120) { $se.Message.Substring(0, 117) + '...' } else { $se.Message }
                $sw.WriteLine("<tr><td>$($se.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</td><td>$(Invoke-HtmlEncode $se.Source)</td><td>$(Invoke-HtmlEncode $msgTrunc)</td></tr>")
            }
            $sw.WriteLine("</table>")
        }
        $sw.WriteLine("</div>")
    }
    $sw.WriteLine("</div>")

    # --- 4. Privileged Access Review ---
    $privHtml = "<p>Total privilege-related events (4672/4648): <strong>$($privEvents.Count.ToString('N0'))</strong></p>"
    if ($topPrivUsers -and @($topPrivUsers).Count -gt 0) {
        $privHtml += "<table><tr><th>User</th><th>Privilege Events</th></tr>"
        foreach ($pu in $topPrivUsers) {
            $privHtml += "<tr><td>$(Invoke-HtmlEncode $pu.Name)</td><td>$($pu.Count)</td></tr>"
        }
        $privHtml += "</table>"
    }
    $sw.WriteLine("<div class='section'><h2>4. Privileged Access Review</h2>$privHtml</div>")

    # --- 5. Log Retention Assessment ---
    $retentionHtml = "<table><tr><th>Metric</th><th>Value</th></tr>"
    $retentionHtml += "<tr><td>Earliest Timestamp</td><td>$(if ($earliestTs) { $earliestTs.ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' })</td></tr>"
    $retentionHtml += "<tr><td>Latest Timestamp</td><td>$(if ($latestTs) { $latestTs.ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' })</td></tr>"
    $retentionHtml += "<tr><td>Total Days of Coverage</td><td><strong>$daysCovered</strong> days</td></tr>"
    $retentionHtml += "</table>"
    $retentionFlag = if ($daysCovered -ge 90) { "<p class='flag-ok'>Log retention meets minimum 90-day FFIEC recommendation.</p>" }
                     elseif ($daysCovered -ge 30) { "<p class='flag-warn'>Log retention is below 90-day recommendation ($daysCovered days available).</p>" }
                     else { "<p class='flag-crit'>Log retention is critically below recommendation ($daysCovered days available). FFIEC recommends 90+ days.</p>" }
    $sw.WriteLine("<div class='section'><h2>5. Log Retention Assessment</h2>$retentionHtml$retentionFlag</div>")

    # --- 6. Audit Trail Integrity ---
    $auditIntHtml = "<table><tr><th>Event</th><th>Count</th><th>Status</th></tr>"
    $logClearedFlag = if ($logCleared.Count -gt 0) { "<span class='flag-crit'>ALERT</span>" } else { "<span class='flag-ok'>OK</span>" }
    $auditIntHtml += "<tr><td>Log Cleared Events (1102)</td><td>$($logCleared.Count)</td><td>$logClearedFlag</td></tr>"
    $policyFlag = if ($auditPolicyChanged.Count -gt 0) { "<span class='flag-warn'>REVIEW</span>" } else { "<span class='flag-ok'>OK</span>" }
    $auditIntHtml += "<tr><td>Audit Policy Changes (4719)</td><td>$($auditPolicyChanged.Count)</td><td>$policyFlag</td></tr>"
    $auditIntHtml += "</table>"

    if ($logCleared.Count -gt 0) {
        $auditIntHtml += "<h3>Log Cleared Events Detail</h3><table><tr><th>Time</th><th>Source</th><th>Message</th></tr>"
        foreach ($lc in ($logCleared | Sort-Object Timestamp | Select-Object -First 10)) {
            $msgTrunc = if ($lc.Message.Length -gt 120) { $lc.Message.Substring(0, 117) + '...' } else { $lc.Message }
            $auditIntHtml += "<tr><td>$($lc.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</td><td>$(Invoke-HtmlEncode $lc.Source)</td><td>$(Invoke-HtmlEncode $msgTrunc)</td></tr>"
        }
        $auditIntHtml += "</table>"
    }

    if ($auditPolicyChanged.Count -gt 0) {
        $auditIntHtml += "<h3>Audit Policy Change Events Detail</h3><table><tr><th>Time</th><th>Source</th><th>Message</th></tr>"
        foreach ($ap in ($auditPolicyChanged | Sort-Object Timestamp | Select-Object -First 10)) {
            $msgTrunc = if ($ap.Message.Length -gt 120) { $ap.Message.Substring(0, 117) + '...' } else { $ap.Message }
            $auditIntHtml += "<tr><td>$($ap.Timestamp.ToString('yyyy-MM-dd HH:mm:ss'))</td><td>$(Invoke-HtmlEncode $ap.Source)</td><td>$(Invoke-HtmlEncode $msgTrunc)</td></tr>"
        }
        $auditIntHtml += "</table>"
    }

    $sw.WriteLine("<div class='section'><h2>6. Audit Trail Integrity</h2>$auditIntHtml</div>")

    $sw.WriteLine("<p class='meta'>Generated by Invoke-LogParser | FFIEC IT Examination Compliance Evidence Report</p></body></html>")
    $sw.Close()

    Write-Log "FFIEC compliance report generated: $OutputPath"
}
