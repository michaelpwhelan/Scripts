function Write-StatisticalSummary {
    param([System.Collections.Generic.List[object]]$Entries)

    $r = $Script:ANSIReset
    $ct = $Script:ConsoleThemes[$Script:State.ActiveTheme]

    Write-Host "`n$($ct.Title)Statistical Summary$r"
    Write-Host "$($ct.Border)$([string][char]0x2500 * 60)$r"

    # Severity breakdown
    $counts = Get-SeverityCounts -Entries $Entries
    Write-Host "$($ct.Header)Severity Distribution:$r"
    foreach ($level in @('CRITICAL','ERROR','WARNING','INFO','DEBUG','TRACE','UNKNOWN')) {
        if ($counts[$level] -gt 0) {
            $pct = [Math]::Round(($counts[$level] / [Math]::Max(1, $Entries.Count)) * 100, 1)
            $barLen = [Math]::Min(40, [Math]::Round($pct / 2.5))
            $bar = [string][char]0x2588 * $barLen
            $color = if ($ct.ContainsKey($level)) { $ct[$level] } else { $ct.INFO }
            $line = "  $color{0,-10} {1,6} ({2,5}%) {3}$r" -f $level, $counts[$level], $pct, $bar
            Write-Host $line
        }
    }

    # Event frequency by hour of day
    $byHour = @{}
    foreach ($e in $Entries) {
        if ($e.Timestamp -ne [datetime]::MinValue) {
            $hour = $e.Timestamp.Hour
            if (-not $byHour.ContainsKey($hour)) { $byHour[$hour] = 0 }
            $byHour[$hour]++
        }
    }
    if ($byHour.Count -gt 0) {
        Write-Host "`n$($ct.Header)Events by Hour of Day:$r"
        $maxHourCount = ($byHour.Values | Measure-Object -Maximum).Maximum
        for ($h = 0; $h -lt 24; $h++) {
            $count = if ($byHour.ContainsKey($h)) { $byHour[$h] } else { 0 }
            $barLen = if ($maxHourCount -gt 0) { [Math]::Min(40, [Math]::Round(($count / $maxHourCount) * 40)) } else { 0 }
            $bar = [string][char]0x2588 * $barLen
            # Highlight after-hours (before 7am, after 6pm)
            $color = if ($h -lt 7 -or $h -ge 18) { $ct.WARNING } else { $ct.INFO }
            $line = "  $color{0:D2}:00  {1,6}  {2}$r" -f $h, $count, $bar
            Write-Host $line
        }
    }

    # Event frequency by day of week
    $byDay = @{}
    foreach ($e in $Entries) {
        if ($e.Timestamp -ne [datetime]::MinValue) {
            $day = $e.Timestamp.DayOfWeek.ToString()
            if (-not $byDay.ContainsKey($day)) { $byDay[$day] = 0 }
            $byDay[$day]++
        }
    }
    if ($byDay.Count -gt 0) {
        Write-Host "`n$($ct.Header)Events by Day of Week:$r"
        $dayOrder = @('Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday')
        $maxDayCount = ($byDay.Values | Measure-Object -Maximum).Maximum
        foreach ($day in $dayOrder) {
            $count = if ($byDay.ContainsKey($day)) { $byDay[$day] } else { 0 }
            $barLen = if ($maxDayCount -gt 0) { [Math]::Min(40, [Math]::Round(($count / $maxDayCount) * 40)) } else { 0 }
            $bar = [string][char]0x2588 * $barLen
            $color = if ($day -in @('Saturday','Sunday')) { $ct.WARNING } else { $ct.INFO }
            $line = "  $color{0,-10} {1,6}  {2}$r" -f $day, $count, $bar
            Write-Host $line
        }
    }

    # Top 20 sources
    $topSources = $Entries | Where-Object { $_.Source } | Group-Object Source | Sort-Object Count -Descending | Select-Object -First 20
    if ($topSources) {
        Write-Host "`n$($ct.Header)Top 20 Sources:$r"
        foreach ($s in $topSources) {
            $line = "  $($ct.INFO){0,-40} {1,6}$r" -f $(if ($s.Name.Length -gt 40) { $s.Name.Substring(0,37) + "..." } else { $s.Name }), $s.Count
            Write-Host $line
        }
    }

    # Top 20 Event IDs (with annotations)
    $eventIdEntries = $Entries | Where-Object { $_.Extra -and $_.Extra['EventID'] }
    if ($eventIdEntries) {
        $topIds = $eventIdEntries | Group-Object { $_.Extra['EventID'] } | Sort-Object Count -Descending | Select-Object -First 20
        Write-Host "`n$($ct.Header)Top 20 Event IDs:$r"
        foreach ($id in $topIds) {
            $eid = [int]$id.Name
            $annotation = if ($Script:State.EventIdLookup.ContainsKey($eid)) { $Script:State.EventIdLookup[$eid] } else { "" }
            $annStr = if ($annotation) { " -- $annotation" } else { "" }
            if ($annStr.Length -gt 50) { $annStr = $annStr.Substring(0, 47) + "..." }
            $line = "  $($ct.INFO){0,-8} {1,6}  {2}$r" -f $id.Name, $id.Count, $annStr
            Write-Host $line
        }
    }

    # Burst detection: minutes with >3x average event rate
    $byMinute = @{}
    foreach ($e in $Entries) {
        if ($e.Timestamp -ne [datetime]::MinValue) {
            $minute = $e.Timestamp.ToString("yyyy-MM-dd HH:mm")
            if (-not $byMinute.ContainsKey($minute)) { $byMinute[$minute] = 0 }
            $byMinute[$minute]++
        }
    }
    if ($byMinute.Count -gt 1) {
        $avgRate = ($byMinute.Values | Measure-Object -Average).Average
        $threshold = $avgRate * 3
        $bursts = $byMinute.GetEnumerator() | Where-Object { $_.Value -gt $threshold } | Sort-Object Value -Descending | Select-Object -First 10
        if ($bursts) {
            Write-Host "`n$($ct.ERROR)Burst Detection (>3x avg rate of $([Math]::Round($avgRate, 1))/min):$r"
            foreach ($b in $bursts) {
                $line = "  $($ct.WARNING){0}  {1} events ({2}x avg)$r" -f $b.Key, $b.Value, [Math]::Round($b.Value / [Math]::Max(1, $avgRate), 1)
                Write-Host $line
            }
        }
    }

    Write-Host ""
}

function Show-StatisticsDialog {
    param([System.Collections.Generic.List[object]]$Entries)

    if ($Script:UseConsole) {
        Write-StatisticalSummary -Entries $Entries
        return
    }

    $dlg = [System.Windows.Forms.Form]::new()
    $dlg.Text = "Statistics"; $dlg.Size = [System.Drawing.Size]::new(700, 600); $dlg.StartPosition = "CenterParent"
    $t = $Script:Themes[$Script:State.ActiveTheme]
    $dlg.BackColor = $t.FormBack; $dlg.ForeColor = $t.FormFore

    $rtb = [System.Windows.Forms.RichTextBox]::new()
    $rtb.Dock = "Fill"; $rtb.ReadOnly = $true
    $rtb.Font = [System.Drawing.Font]::new("Consolas", 9.5)
    $rtb.BackColor = $t.DetailBack; $rtb.ForeColor = $t.DetailFore

    $counts = Get-SeverityCounts -Entries $Entries
    $text = [System.Text.StringBuilder]::new()
    $text.AppendLine("STATISTICAL SUMMARY") | Out-Null
    $text.AppendLine("$([string][char]0x2500 * 50)") | Out-Null
    $text.AppendLine("") | Out-Null
    $text.AppendLine("Severity Distribution:") | Out-Null
    foreach ($level in @('CRITICAL','ERROR','WARNING','INFO','DEBUG','TRACE')) {
        if ($counts[$level] -gt 0) {
            $pct = [Math]::Round(($counts[$level] / [Math]::Max(1, $Entries.Count)) * 100, 1)
            $bar = [string][char]0x2588 * [Math]::Min(30, [Math]::Round($pct / 3.3))
            $text.AppendLine("  {0,-10} {1,6} ({2,5}%) {3}" -f $level, $counts[$level], $pct, $bar) | Out-Null
        }
    }

    # Hour distribution
    $byHour = @{}
    foreach ($e in $Entries) {
        if ($e.Timestamp -ne [datetime]::MinValue) {
            $h = $e.Timestamp.Hour
            if (-not $byHour.ContainsKey($h)) { $byHour[$h] = 0 }
            $byHour[$h]++
        }
    }
    if ($byHour.Count -gt 0) {
        $maxH = ($byHour.Values | Measure-Object -Maximum).Maximum
        $text.AppendLine("") | Out-Null
        $text.AppendLine("Events by Hour of Day:") | Out-Null
        for ($h = 0; $h -lt 24; $h++) {
            $c = if ($byHour.ContainsKey($h)) { $byHour[$h] } else { 0 }
            $barLen = if ($maxH -gt 0) { [Math]::Min(30, [Math]::Round(($c / $maxH) * 30)) } else { 0 }
            $bar = [string][char]0x2588 * $barLen
            $marker = if ($h -lt 7 -or $h -ge 18) { "*" } else { " " }
            $text.AppendLine("  {0:D2}:00 {1}{2,6}  {3}" -f $h, $marker, $c, $bar) | Out-Null
        }
        $text.AppendLine("  (* = after hours)") | Out-Null
    }

    # Top sources
    $topSources = $Entries | Where-Object { $_.Source } | Group-Object Source | Sort-Object Count -Descending | Select-Object -First 20
    if ($topSources) {
        $text.AppendLine("") | Out-Null
        $text.AppendLine("Top 20 Sources:") | Out-Null
        foreach ($s in $topSources) {
            $name = if ($s.Name.Length -gt 35) { $s.Name.Substring(0,32) + "..." } else { $s.Name }
            $text.AppendLine("  {0,-35} {1,6}" -f $name, $s.Count) | Out-Null
        }
    }

    $rtb.Text = $text.ToString()
    $dlg.Controls.Add($rtb)
    $dlg.ShowDialog($Script:UI.Form) | Out-Null
    $dlg.Dispose()
}
