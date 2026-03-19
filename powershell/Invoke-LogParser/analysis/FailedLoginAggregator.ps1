function Get-FailedLoginAggregation {
    param([System.Collections.Generic.List[object]]$Entries)

    $aggregated = @{}  # Key: username, Value: details

    foreach ($entry in $Entries) {
        $user = $null
        $sourceIp = $null
        $isFailedLogin = $false

        # Windows EVTX Event 4625 (failed logon)
        if ($entry.Extra -and $entry.Extra['EventID'] -and [int]$entry.Extra['EventID'] -eq 4625) {
            $user = $entry.Extra['TargetUserName']
            $sourceIp = $entry.Extra['IpAddress']
            if (-not $sourceIp) { $sourceIp = $entry.Extra['WorkstationName'] }
            $isFailedLogin = $true
        }
        # NPS Access-Reject (PacketType 3)
        elseif ($entry.Extra -and $entry.Extra['PacketTypeName'] -eq 'Access-Reject') {
            $user = $entry.Extra['User-Name']
            if (-not $user) { $user = $entry.Extra['SAM-Account-Name'] }
            $sourceIp = $entry.Extra['Calling-Station-Id']
            if (-not $sourceIp) { $sourceIp = $entry.Extra['Client-IP-Address'] }
            $isFailedLogin = $true
        }
        # FortiGate deny + auth subtype
        elseif ($entry.Extra -and $entry.Extra['type'] -eq 'event' -and $entry.Extra['subtype'] -eq 'user' -and $entry.Extra['action'] -and $entry.Extra['action'] -match 'deny|fail') {
            $user = $entry.Extra['user']
            $sourceIp = $entry.Extra['srcip']
            $isFailedLogin = $true
        }
        # FortiGate auth action deny
        elseif ($entry.Extra -and $entry.Extra['action'] -and $entry.Extra['action'] -match 'deny' -and $entry.Extra['subtype'] -eq 'auth') {
            $user = $entry.Extra['user']
            $sourceIp = $entry.Extra['srcip']
            $isFailedLogin = $true
        }
        # Windows EVTX Event 4771 (Kerberos pre-auth failed)
        elseif ($entry.Extra -and $entry.Extra['EventID'] -and [int]$entry.Extra['EventID'] -eq 4771) {
            $user = $entry.Extra['TargetUserName']
            $sourceIp = $entry.Extra['IpAddress']
            $isFailedLogin = $true
        }
        # NPS Event 6273 (NPS denied access)
        elseif ($entry.Extra -and $entry.Extra['EventID'] -and [int]$entry.Extra['EventID'] -eq 6273) {
            $user = $entry.Extra['SubjectUserName']
            if (-not $user) { $user = $entry.Extra['FullyQualifiedSubjectUserName'] }
            $sourceIp = $entry.Extra['CallingStationID']
            $isFailedLogin = $true
        }

        if (-not $isFailedLogin -or -not $user) { continue }
        if (-not $user) { $user = "(unknown)" }
        if (-not $sourceIp) { $sourceIp = "(unknown)" }

        $key = $user.ToLower()
        if (-not $aggregated.ContainsKey($key)) {
            $aggregated[$key] = @{
                User = $user
                Count = 0
                SourceIPs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                FirstSeen = $entry.Timestamp
                LastSeen = $entry.Timestamp
                Sources = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            }
        }

        $agg = $aggregated[$key]
        $agg.Count++
        $agg.SourceIPs.Add($sourceIp) | Out-Null
        if ($entry.Extra['SourceFormat']) { $agg.Sources.Add($entry.Extra['SourceFormat']) | Out-Null }
        if ($entry.Timestamp -ne [datetime]::MinValue) {
            if ($entry.Timestamp -lt $agg.FirstSeen -or $agg.FirstSeen -eq [datetime]::MinValue) { $agg.FirstSeen = $entry.Timestamp }
            if ($entry.Timestamp -gt $agg.LastSeen) { $agg.LastSeen = $entry.Timestamp }
        }
    }

    return $aggregated.Values | Sort-Object { $_.Count } -Descending
}

function Show-FailedLoginDialog {
    param($Results)
    if (-not $Results -or @($Results).Count -eq 0) {
        if (-not $Script:UseConsole) {
            [System.Windows.Forms.MessageBox]::Show("No failed login events found.", "Failed Login Summary")
        }
        return
    }

    if ($Script:UseConsole) {
        Write-FailedLoginTable -Results $Results
        return
    }

    $dlg = [System.Windows.Forms.Form]::new()
    $dlg.Text = "Failed Login Summary"; $dlg.Size = [System.Drawing.Size]::new(800, 500); $dlg.StartPosition = "CenterParent"
    $t = $Script:Themes[$Script:State.ActiveTheme]
    $dlg.BackColor = $t.FormBack; $dlg.ForeColor = $t.FormFore

    $grid = [System.Windows.Forms.DataGridView]::new()
    $grid.Dock = "Fill"; $grid.ReadOnly = $true; $grid.AllowUserToAddRows = $false
    $grid.BackgroundColor = $t.GridBack; $grid.DefaultCellStyle.BackColor = $t.GridBack; $grid.DefaultCellStyle.ForeColor = $t.FormFore
    $grid.Columns.Add("User", "User") | Out-Null
    $grid.Columns.Add("Count", "Count") | Out-Null
    $grid.Columns.Add("UniqueIPs", "Unique IPs") | Out-Null
    $grid.Columns.Add("FirstSeen", "First Seen") | Out-Null
    $grid.Columns.Add("LastSeen", "Last Seen") | Out-Null
    $grid.Columns.Add("TimeSpan", "Time Span") | Out-Null
    $grid.Columns.Add("Sources", "Log Sources") | Out-Null

    foreach ($r in $Results) {
        $span = if ($r.LastSeen -ne [datetime]::MinValue -and $r.FirstSeen -ne [datetime]::MinValue) {
            ($r.LastSeen - $r.FirstSeen).ToString('d\.hh\:mm\:ss')
        } else { "" }
        $firstStr = if ($r.FirstSeen -ne [datetime]::MinValue) { $r.FirstSeen.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
        $lastStr = if ($r.LastSeen -ne [datetime]::MinValue) { $r.LastSeen.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
        $grid.Rows.Add($r.User, $r.Count, $r.SourceIPs.Count, $firstStr, $lastStr, $span, ($r.Sources -join ", ")) | Out-Null
    }
    $grid.AutoResizeColumns()

    # Double-click to filter main grid
    $grid.Add_CellDoubleClick({
        param($sender, $e)
        if ($e.RowIndex -ge 0) {
            $user = $grid.Rows[$e.RowIndex].Cells[0].Value
            $Script:UI.TxtSearch.Text = $user
            $Script:UI.RadText.Checked = $true
            Invoke-ApplyFilters; Update-StatsBar
            $dlg.Close()
        }
    })

    $dlg.Controls.Add($grid)
    $dlg.ShowDialog($Script:UI.Form) | Out-Null
    $dlg.Dispose()
}

function Write-FailedLoginTable {
    param($Results)
    $r = $Script:ANSIReset
    $ct = $Script:ConsoleThemes[$Script:State.ActiveTheme]

    Write-Host "`n$($ct.Title)Failed Login Summary$r"
    Write-Host "$($ct.Header){0,-30} {1,-8} {2,-12} {3,-20} {4,-20} {5}$r" -f "User", "Count", "Unique IPs", "First Seen", "Last Seen", "Sources"
    Write-Host "$($ct.Border)$([string][char]0x2500 * 120)$r"

    foreach ($res in $Results) {
        $firstStr = if ($res.FirstSeen -ne [datetime]::MinValue) { $res.FirstSeen.ToString("yyyy-MM-dd HH:mm") } else { "" }
        $lastStr = if ($res.LastSeen -ne [datetime]::MinValue) { $res.LastSeen.ToString("yyyy-MM-dd HH:mm") } else { "" }
        $color = if ($res.Count -ge 10) { $ct.ERROR } elseif ($res.Count -ge 5) { $ct.WARNING } else { $ct.INFO }
        Write-Host "$color{0,-30} {1,-8} {2,-12} {3,-20} {4,-20} {5}$r" -f $res.User, $res.Count, $res.SourceIPs.Count, $firstStr, $lastStr, ($res.Sources -join ", ")
    }
    Write-Host ""
}
