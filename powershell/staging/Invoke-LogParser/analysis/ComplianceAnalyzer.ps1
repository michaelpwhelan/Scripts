function Get-ComplianceAnalysis {
    param([System.Collections.Generic.List[object]]$Entries)

    $controls = [System.Collections.Generic.List[object]]::new()
    $privilegedActivity = [System.Collections.Generic.List[object]]::new()
    $earliestTimestamp = [datetime]::MaxValue
    $latestTimestamp = [datetime]::MinValue

    # Determine log retention span
    foreach ($entry in $Entries) {
        if ($entry.Timestamp -ne [datetime]::MinValue) {
            if ($entry.Timestamp -lt $earliestTimestamp) { $earliestTimestamp = $entry.Timestamp }
            if ($entry.Timestamp -gt $latestTimestamp) { $latestTimestamp = $entry.Timestamp }
        }
    }

    $logRetention = @{
        From = if ($earliestTimestamp -ne [datetime]::MaxValue) { $earliestTimestamp } else { $null }
        To   = if ($latestTimestamp -ne [datetime]::MinValue) { $latestTimestamp } else { $null }
        Days = if ($earliestTimestamp -ne [datetime]::MaxValue -and $latestTimestamp -ne [datetime]::MinValue) {
            [Math]::Ceiling(($latestTimestamp - $earliestTimestamp).TotalDays)
        } else { 0 }
    }

    # Extract privileged account activity (EventID 4672 = special privileges assigned, 4648 = logon using explicit credentials)
    foreach ($entry in $Entries) {
        if (-not $entry.Extra) { continue }
        $eventId = $entry.Extra['EventID'] -as [int]
        if ($eventId -eq 4672 -or $eventId -eq 4648) {
            $user = $entry.Extra['SubjectUserName']
            if (-not $user) { $user = $entry.Extra['TargetUserName'] }
            if (-not $user) { continue }

            $privilegedActivity.Add(@{
                Timestamp = $entry.Timestamp
                EventID   = $eventId
                User      = $user
                Type      = if ($eventId -eq 4672) { "Special Privileges" } else { "Explicit Credentials" }
                Host      = $entry.Host
                Detail    = if ($eventId -eq 4672) { $entry.Extra['PrivilegeList'] } else { $entry.Extra['TargetServerName'] }
            })
        }
    }

    # Assess FFIEC controls
    $withEvidence = 0
    $withoutEvidence = 0

    if ($null -ne $Script:FfiecControlMap -and $Script:FfiecControlMap.Count -gt 0) {
        # Sort control IDs for consistent ordering
        $sortedControlIds = $Script:FfiecControlMap.Keys | Sort-Object

        foreach ($controlId in $sortedControlIds) {
            $control = $Script:FfiecControlMap[$controlId]
            $evidenceCount = 0

            foreach ($entry in $Entries) {
                if (-not $entry.Extra) { continue }

                $matched = $false
                foreach ($pattern in $control.EventPatterns) {
                    $fieldValue = $entry.Extra[$pattern.Field]
                    if ($null -eq $fieldValue) { continue }

                    # Check Values-based matching (exact list)
                    if ($pattern.ContainsKey('Values')) {
                        $fvInt = $fieldValue -as [int]
                        if ($null -ne $fvInt -and $fvInt -in $pattern.Values) {
                            $matched = $true
                            break
                        }
                        if ($fieldValue -in $pattern.Values) {
                            $matched = $true
                            break
                        }
                    }

                    # Check Pattern-based matching (regex)
                    if ($pattern.ContainsKey('Pattern')) {
                        if ([string]$fieldValue -match $pattern.Pattern) {
                            $matched = $true
                            break
                        }
                    }
                }

                if ($matched) { $evidenceCount++ }
            }

            $status = if ($evidenceCount -gt 0) { "Evidence Found" } else { "No Evidence" }
            if ($evidenceCount -gt 0) { $withEvidence++ } else { $withoutEvidence++ }

            $controls.Add(@{
                ControlId     = $controlId
                ControlName   = $control.Name
                Handbook      = $control.Handbook
                Status        = $status
                EvidenceCount = $evidenceCount
            })
        }
    } else {
        # Fallback: build a basic set of compliance checks without the control map
        $basicChecks = @(
            @{ Id = "AC-01"; Name = "Access Control - Authentication Events"; Field = "EventID"; Values = @(4624,4625,4634,4647) }
            @{ Id = "AC-02"; Name = "Access Control - Account Management"; Field = "EventID"; Values = @(4720,4722,4725,4726,4738) }
            @{ Id = "AU-01"; Name = "Audit - Log Integrity Events"; Field = "EventID"; Values = @(1102,4719) }
            @{ Id = "CM-01"; Name = "Change Management - Policy Changes"; Field = "action"; Pattern = "edit_policy|add_policy|del_policy|config_change" }
            @{ Id = "IR-01"; Name = "Incident Response - Security Alerts"; Field = "action"; Pattern = "block|deny|quarantine|alert" }
            @{ Id = "NS-01"; Name = "Network Security - Traffic Events"; Field = "type"; Pattern = "traffic" }
            @{ Id = "RM-01"; Name = "Remote Access - VPN Events"; Field = "action"; Pattern = "tunnel-up|tunnel-down|sslvpn|login" }
            @{ Id = "PM-01"; Name = "Privilege Management - Special Logon"; Field = "EventID"; Values = @(4672,4673) }
        )

        foreach ($check in $basicChecks) {
            $evidenceCount = 0
            foreach ($entry in $Entries) {
                if (-not $entry.Extra) { continue }
                $fieldValue = $entry.Extra[$check.Field]
                if ($null -eq $fieldValue) { continue }

                if ($check.ContainsKey('Values')) {
                    $fvInt = $fieldValue -as [int]
                    if ($null -ne $fvInt -and $fvInt -in $check.Values) { $evidenceCount++; continue }
                    if ($fieldValue -in $check.Values) { $evidenceCount++; continue }
                }
                if ($check.ContainsKey('Pattern')) {
                    if ([string]$fieldValue -match $check.Pattern) { $evidenceCount++; continue }
                }
            }

            $status = if ($evidenceCount -gt 0) { "Evidence Found" } else { "No Evidence" }
            if ($evidenceCount -gt 0) { $withEvidence++ } else { $withoutEvidence++ }

            $controls.Add(@{
                ControlId     = $check.Id
                ControlName   = $check.Name
                Handbook      = "Information Security"
                Status        = $status
                EvidenceCount = $evidenceCount
            })
        }
    }

    return @{
        Controls          = @($controls)
        PrivilegedActivity = @($privilegedActivity)
        LogRetention      = $logRetention
        Summary           = @{
            ControlsAssessed = $controls.Count
            WithEvidence     = $withEvidence
            WithoutEvidence  = $withoutEvidence
        }
    }
}

function Show-ComplianceDialog {
    param($Results)
    if (-not $Results -or $Results.Summary.ControlsAssessed -eq 0) {
        if (-not $Script:UseConsole) {
            [System.Windows.Forms.MessageBox]::Show("No compliance data available.", "Compliance Analysis")
        }
        return
    }

    if ($Script:UseConsole) {
        Write-ComplianceTable -Results $Results
        return
    }

    $dlg = [System.Windows.Forms.Form]::new()
    $dlg.Text = "FFIEC Compliance Analysis"; $dlg.Size = [System.Drawing.Size]::new(950, 600); $dlg.StartPosition = "CenterParent"
    $t = $Script:Themes[$Script:State.ActiveTheme]
    $dlg.BackColor = $t.FormBack; $dlg.ForeColor = $t.FormFore

    $grid = [System.Windows.Forms.DataGridView]::new()
    $grid.Dock = "Fill"; $grid.ReadOnly = $true; $grid.AllowUserToAddRows = $false
    $grid.BackgroundColor = $t.GridBack; $grid.DefaultCellStyle.BackColor = $t.GridBack; $grid.DefaultCellStyle.ForeColor = $t.FormFore
    $grid.ColumnHeadersDefaultCellStyle.BackColor = $t.GridBack; $grid.ColumnHeadersDefaultCellStyle.ForeColor = $t.FormFore
    $grid.EnableHeadersVisualStyles = $false
    $grid.Columns.Add("ControlId", "Control ID") | Out-Null
    $grid.Columns.Add("ControlName", "Control Name") | Out-Null
    $grid.Columns.Add("Handbook", "Handbook") | Out-Null
    $grid.Columns.Add("Status", "Status") | Out-Null
    $grid.Columns.Add("EvidenceCount", "Evidence Count") | Out-Null

    foreach ($ctrl in $Results.Controls) {
        $rowIdx = $grid.Rows.Add($ctrl.ControlId, $ctrl.ControlName, $ctrl.Handbook, $ctrl.Status, $ctrl.EvidenceCount)
        if ($ctrl.Status -eq "Evidence Found") {
            $grid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Green
        } else {
            $grid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Red
        }
    }
    $grid.AutoResizeColumns()

    # Add summary label at bottom
    $summaryPanel = [System.Windows.Forms.Panel]::new()
    $summaryPanel.Dock = "Bottom"; $summaryPanel.Height = 50
    $summaryPanel.BackColor = $t.FormBack

    $retentionStr = ""
    if ($Results.LogRetention.From -and $Results.LogRetention.To) {
        $retentionStr = "Log Retention: $($Results.LogRetention.From.ToString('yyyy-MM-dd')) to $($Results.LogRetention.To.ToString('yyyy-MM-dd')) ($($Results.LogRetention.Days) days)"
    }

    $summaryLabel = [System.Windows.Forms.Label]::new()
    $summaryLabel.Dock = "Fill"; $summaryLabel.TextAlign = "MiddleLeft"
    $summaryLabel.ForeColor = $t.FormFore
    $summaryLabel.Text = "Controls: $($Results.Summary.ControlsAssessed) | With Evidence: $($Results.Summary.WithEvidence) | Without Evidence: $($Results.Summary.WithoutEvidence) | Privileged Events: $($Results.PrivilegedActivity.Count) | $retentionStr"
    $summaryPanel.Controls.Add($summaryLabel)

    $dlg.Controls.Add($grid)
    $dlg.Controls.Add($summaryPanel)
    $dlg.ShowDialog($Script:UI.Form) | Out-Null
    $dlg.Dispose()
}

function Write-ComplianceTable {
    param($Results)
    $r = $Script:ANSIReset
    $ct = $Script:ConsoleThemes[$Script:State.ActiveTheme]

    Write-Host "`n$($ct.Title)FFIEC Compliance Analysis$r"
    Write-Host "$($ct.INFO)  Controls Assessed: $($Results.Summary.ControlsAssessed)  |  With Evidence: $($Results.Summary.WithEvidence)  |  Without Evidence: $($Results.Summary.WithoutEvidence)$r"

    if ($Results.LogRetention.From -and $Results.LogRetention.To) {
        Write-Host "$($ct.INFO)  Log Retention: $($Results.LogRetention.From.ToString('yyyy-MM-dd')) to $($Results.LogRetention.To.ToString('yyyy-MM-dd')) ($($Results.LogRetention.Days) days)$r"
    }
    Write-Host ""

    Write-Host "$($ct.Header){0,-14} {1,-45} {2,-25} {3,-16} {4}$r" -f "Control ID", "Control Name", "Handbook", "Status", "Evidence"
    Write-Host "$($ct.Border)$([string][char]0x2500 * 110)$r"

    foreach ($ctrl in $Results.Controls) {
        $statusIndicator = if ($ctrl.Status -eq "Evidence Found") { "[+]" } else { "[-]" }
        $color = if ($ctrl.Status -eq "Evidence Found") { $ct.INFO } else { $ct.ERROR }
        Write-Host "$color{0,-14} {1,-45} {2,-25} {3,-16} {4}$r" -f $ctrl.ControlId, $ctrl.ControlName, $ctrl.Handbook, "$statusIndicator $($ctrl.Status)", $ctrl.EvidenceCount
    }

    if ($Results.PrivilegedActivity.Count -gt 0) {
        Write-Host "`n$($ct.Title)Privileged Account Activity ($($Results.PrivilegedActivity.Count) events)$r"
        Write-Host "$($ct.Header){0,-20} {1,-8} {2,-25} {3,-25} {4}$r" -f "Time", "EventID", "User", "Type", "Host"
        Write-Host "$($ct.Border)$([string][char]0x2500 * 100)$r"

        $displayCount = [Math]::Min($Results.PrivilegedActivity.Count, 20)
        for ($i = 0; $i -lt $displayCount; $i++) {
            $pa = $Results.PrivilegedActivity[$i]
            $timeStr = if ($pa.Timestamp -ne [datetime]::MinValue) { $pa.Timestamp.ToString("yyyy-MM-dd HH:mm") } else { "" }
            Write-Host "$($ct.WARNING){0,-20} {1,-8} {2,-25} {3,-25} {4}$r" -f $timeStr, $pa.EventID, $pa.User, $pa.Type, $pa.Host
        }
        if ($Results.PrivilegedActivity.Count -gt 20) {
            Write-Host "$($ct.INFO)  ... and $($Results.PrivilegedActivity.Count - 20) more privileged events$r"
        }
    }
    Write-Host ""
}
