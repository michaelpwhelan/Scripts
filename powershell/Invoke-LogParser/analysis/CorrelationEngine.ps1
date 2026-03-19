function Invoke-CrossSourceCorrelation {
    param([System.Collections.Generic.List[object]]$Entries)

    $rules = @()
    $rulesPath = Join-Path $Config.ScriptRoot "data" "correlation-rules.json"
    if (Test-Path $rulesPath) {
        try {
            $rules = Get-Content -Path $rulesPath -Raw | ConvertFrom-Json
        } catch {
            Write-Log "Failed to load correlation rules: $_" -Level WARNING
        }
    }

    if ($rules.Count -eq 0) {
        $rules = @(
            @{
                RuleName = "VPN + Failed Login"
                SourceTypes = @("fortigate-traffic", "evtx")
                CorrelateField = "username"
                TimeWindowMinutes = 30
                Severity = "HIGH"
            },
            @{
                RuleName = "Multi-Source Auth Failure"
                SourceTypes = @("evtx", "nps-radius", "fortigate-traffic")
                CorrelateField = "username"
                TimeWindowMinutes = 15
                Severity = "HIGH"
            },
            @{
                RuleName = "Cross-Source IP Activity"
                SourceTypes = @("fortigate-traffic", "evtx", "nps-radius")
                CorrelateField = "ip"
                TimeWindowMinutes = 60
                Severity = "MEDIUM"
            },
            @{
                RuleName = "Auth Then Config Change"
                SourceTypes = @("fortigate-traffic", "fortimanager-audit", "entra-audit")
                CorrelateField = "username"
                TimeWindowMinutes = 30
                Severity = "CRITICAL"
            }
        )
    }

    $correlationResults = [System.Collections.Generic.List[object]]::new()

    foreach ($rule in $rules) {
        $ruleName = if ($rule -is [PSCustomObject]) { $rule.RuleName } else { $rule['RuleName'] }
        $sourceTypes = if ($rule -is [PSCustomObject]) { @($rule.SourceTypes) } else { @($rule['SourceTypes']) }
        $correlateField = if ($rule -is [PSCustomObject]) { $rule.CorrelateField } else { $rule['CorrelateField'] }
        $timeWindow = if ($rule -is [PSCustomObject]) { $rule.TimeWindowMinutes } else { $rule['TimeWindowMinutes'] }
        $severity = if ($rule -is [PSCustomObject]) { $rule.Severity } else { $rule['Severity'] }
        if (-not $timeWindow) { $timeWindow = 30 }
        if (-not $severity) { $severity = "MEDIUM" }

        # Filter entries matching any of the rule's source types
        $matchingEntries = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $Entries) {
            if (-not $entry.Extra) { continue }
            $srcFormat = $entry.Extra['SourceFormat']
            if (-not $srcFormat) { continue }
            foreach ($st in $sourceTypes) {
                if ($srcFormat -eq $st) {
                    $matchingEntries.Add($entry)
                    break
                }
            }
        }

        if ($matchingEntries.Count -lt 2) { continue }

        # Extract correlation key values
        $grouped = @{}
        foreach ($entry in $matchingEntries) {
            $keyValue = $null
            if ($correlateField -eq 'username') {
                $keyValue = $entry.Extra['user']
                if (-not $keyValue) { $keyValue = $entry.Extra['User-Name'] }
                if (-not $keyValue) { $keyValue = $entry.Extra['TargetUserName'] }
                if (-not $keyValue) { $keyValue = $entry.Extra['UserPrincipalName'] }
                if (-not $keyValue) { $keyValue = $entry.Extra['SubjectUserName'] }
            } elseif ($correlateField -eq 'ip') {
                $keyValue = $entry.Extra['srcip']
                if (-not $keyValue) { $keyValue = $entry.Extra['IPAddress'] }
                if (-not $keyValue) { $keyValue = $entry.Extra['IpAddress'] }
                if (-not $keyValue) { $keyValue = $entry.Extra['Calling-Station-Id'] }
            }
            if (-not $keyValue) { continue }

            $normalizedKey = $keyValue.ToLower()
            if (-not $grouped.ContainsKey($normalizedKey)) {
                $grouped[$normalizedKey] = [System.Collections.Generic.List[object]]::new()
            }
            $grouped[$normalizedKey].Add($entry)
        }

        # For each key value, check if events from multiple source types exist within the time window
        foreach ($kvp in $grouped.GetEnumerator()) {
            $events = $kvp.Value | Sort-Object { $_.Timestamp }
            $distinctSources = ($events | ForEach-Object { $_.Extra['SourceFormat'] } | Select-Object -Unique)
            if (@($distinctSources).Count -lt 2) { continue }

            # Check time window
            $validTimes = $events | Where-Object { $_.Timestamp -ne [datetime]::MinValue }
            if (@($validTimes).Count -lt 2) { continue }

            $earliest = ($validTimes | Select-Object -First 1).Timestamp
            $latest = ($validTimes | Select-Object -Last 1).Timestamp
            $span = $latest - $earliest

            if ($span.TotalMinutes -le $timeWindow) {
                $correlationResults.Add(@{
                    RuleName       = $ruleName
                    CorrelationKey = $correlateField
                    KeyValue       = $kvp.Key
                    Events         = @($events)
                    TimeSpan       = $span.ToString('d\.hh\:mm\:ss')
                    Severity       = $severity
                    EventCount     = $events.Count
                    Sources        = @($distinctSources) -join ", "
                })
            }
        }
    }

    # Sort by severity then event count descending
    $severityOrder = @{ 'CRITICAL' = 0; 'HIGH' = 1; 'MEDIUM' = 2; 'LOW' = 3 }
    $sorted = $correlationResults | Sort-Object {
        $so = $severityOrder[$_.Severity]
        if ($null -eq $so) { $so = 99 }
        $so
    }, { $_.EventCount } -Descending

    return @($sorted)
}

function Show-CorrelationDialog {
    param($Results)
    if (-not $Results -or @($Results).Count -eq 0) {
        if (-not $Script:UseConsole) {
            [System.Windows.Forms.MessageBox]::Show("No cross-source correlations found.", "Correlation Engine")
        }
        return
    }

    if ($Script:UseConsole) {
        Write-CorrelationTable -Results $Results
        return
    }

    $dlg = [System.Windows.Forms.Form]::new()
    $dlg.Text = "Cross-Source Correlation Results"; $dlg.Size = [System.Drawing.Size]::new(950, 600); $dlg.StartPosition = "CenterParent"
    $t = $Script:Themes[$Script:State.ActiveTheme]
    $dlg.BackColor = $t.FormBack; $dlg.ForeColor = $t.FormFore

    $grid = [System.Windows.Forms.DataGridView]::new()
    $grid.Dock = "Fill"; $grid.ReadOnly = $true; $grid.AllowUserToAddRows = $false
    $grid.BackgroundColor = $t.GridBack; $grid.DefaultCellStyle.BackColor = $t.GridBack; $grid.DefaultCellStyle.ForeColor = $t.FormFore
    $grid.ColumnHeadersDefaultCellStyle.BackColor = $t.GridBack; $grid.ColumnHeadersDefaultCellStyle.ForeColor = $t.FormFore
    $grid.EnableHeadersVisualStyles = $false
    $grid.Columns.Add("Rule", "Rule") | Out-Null
    $grid.Columns.Add("Key", "Key") | Out-Null
    $grid.Columns.Add("Value", "Value") | Out-Null
    $grid.Columns.Add("Events", "Events") | Out-Null
    $grid.Columns.Add("TimeSpan", "Time Span") | Out-Null
    $grid.Columns.Add("Severity", "Severity") | Out-Null
    $grid.Columns.Add("Sources", "Sources") | Out-Null

    foreach ($r in $Results) {
        $rowIdx = $grid.Rows.Add($r.RuleName, $r.CorrelationKey, $r.KeyValue, $r.EventCount, $r.TimeSpan, $r.Severity, $r.Sources)
        if ($r.Severity -eq 'CRITICAL') {
            $grid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Red
        } elseif ($r.Severity -eq 'HIGH') {
            $grid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::OrangeRed
        }
    }
    $grid.AutoResizeColumns()

    $dlg.Controls.Add($grid)
    $dlg.ShowDialog($Script:UI.Form) | Out-Null
    $dlg.Dispose()
}

function Write-CorrelationTable {
    param($Results)
    $r = $Script:ANSIReset
    $ct = $Script:ConsoleThemes[$Script:State.ActiveTheme]

    Write-Host "`n$($ct.Title)Cross-Source Correlation Results$r"
    Write-Host "$($ct.Header){0,-25} {1,-12} {2,-25} {3,-8} {4,-15} {5,-10} {6}$r" -f "Rule", "Key", "Value", "Events", "Time Span", "Severity", "Sources"
    Write-Host "$($ct.Border)$([string][char]0x2500 * 120)$r"

    foreach ($res in $Results) {
        $color = switch ($res.Severity) {
            'CRITICAL' { $ct.ERROR }
            'HIGH'     { $ct.WARNING }
            'MEDIUM'   { $ct.INFO }
            default    { $ct.INFO }
        }
        Write-Host "$color{0,-25} {1,-12} {2,-25} {3,-8} {4,-15} {5,-10} {6}$r" -f $res.RuleName, $res.CorrelationKey, $res.KeyValue, $res.EventCount, $res.TimeSpan, $res.Severity, $res.Sources
    }
    Write-Host ""
}
