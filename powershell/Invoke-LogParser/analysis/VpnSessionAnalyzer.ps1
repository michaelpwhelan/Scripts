function Get-VpnSessionAnalysis {
    param([System.Collections.Generic.List[object]]$Entries)

    $sessions = @{}  # Key: user, Value: list of sessions
    $activeByUser = @{}  # Tracks open sessions per user

    foreach ($entry in $Entries) {
        if (-not $entry.Extra) { continue }

        $user = $null; $action = $null; $remoteIp = $null
        $sentBytes = 0; $rcvdBytes = 0

        # FortiGate VPN events
        if ($entry.Extra['type'] -eq 'event' -and $entry.Extra['subtype'] -eq 'vpn') {
            $user = $entry.Extra['user']
            $action = $entry.Extra['action']
            $remoteIp = $entry.Extra['remip']
            if (-not $remoteIp) { $remoteIp = $entry.Extra['srcip'] }
            if ($entry.Extra['sentbyte']) { $sentBytes = $entry.Extra['sentbyte'] -as [long] }
            if ($entry.Extra['rcvdbyte']) { $rcvdBytes = $entry.Extra['rcvdbyte'] -as [long] }
        }
        # FortiGate tunnel-up/tunnel-down in message
        elseif ($entry.Extra -and $entry.Message -match 'tunnel-(up|down)') {
            $action = "tunnel-$($Matches[1])"
            $user = $entry.Extra['user']
            $remoteIp = $entry.Extra['remip']
            if (-not $remoteIp) { $remoteIp = $entry.Extra['srcip'] }
        }
        # FortiGate SSL VPN
        elseif ($entry.Extra -and $entry.Extra['action'] -match 'ssl-') {
            $user = $entry.Extra['user']
            $action = $entry.Extra['action']
            $remoteIp = $entry.Extra['srcip']
        }

        if (-not $user -or -not $action) { continue }

        $userKey = $user.ToLower()
        if (-not $sessions.ContainsKey($userKey)) {
            $sessions[$userKey] = [System.Collections.Generic.List[object]]::new()
        }

        if ($action -match 'tunnel-up|ssl-new-con|login') {
            $session = @{
                User = $user
                StartTime = $entry.Timestamp
                EndTime = $null
                Duration = $null
                RemoteIP = $remoteIp
                SentBytes = 0
                RcvdBytes = 0
                Active = $true
            }
            $sessions[$userKey].Add($session)
            if (-not $activeByUser.ContainsKey($userKey)) { $activeByUser[$userKey] = 0 }
            $activeByUser[$userKey]++
        }
        elseif ($action -match 'tunnel-down|ssl-exit|logout') {
            # Find matching open session
            $openSession = $sessions[$userKey] | Where-Object { $_.Active } | Select-Object -Last 1
            if ($openSession) {
                $openSession.EndTime = $entry.Timestamp
                $openSession.Active = $false
                $openSession.SentBytes = $sentBytes
                $openSession.RcvdBytes = $rcvdBytes
                if ($openSession.StartTime -ne [datetime]::MinValue -and $entry.Timestamp -ne [datetime]::MinValue) {
                    $openSession.Duration = $entry.Timestamp - $openSession.StartTime
                }
                if ($activeByUser.ContainsKey($userKey)) { $activeByUser[$userKey] = [Math]::Max(0, $activeByUser[$userKey] - 1) }
            }
        }
    }

    # Detect impossible travel: same user from two different /16 subnets within 30 minutes
    $travelFlags = [System.Collections.Generic.List[object]]::new()
    foreach ($userKey in $sessions.Keys) {
        $userSessions = $sessions[$userKey] | Sort-Object { $_.StartTime }
        for ($i = 1; $i -lt $userSessions.Count; $i++) {
            $prev = $userSessions[$i - 1]
            $curr = $userSessions[$i]
            if (-not $prev.RemoteIP -or -not $curr.RemoteIP) { continue }
            if ($curr.StartTime -eq [datetime]::MinValue -or $prev.StartTime -eq [datetime]::MinValue) { continue }

            $timeDiff = ($curr.StartTime - $prev.StartTime).TotalMinutes
            if ($timeDiff -le 30 -and $timeDiff -ge 0) {
                # Compare /16 subnets
                $prevParts = $prev.RemoteIP -split '\.'
                $currParts = $curr.RemoteIP -split '\.'
                if ($prevParts.Count -ge 2 -and $currParts.Count -ge 2) {
                    $prevSubnet = "$($prevParts[0]).$($prevParts[1])"
                    $currSubnet = "$($currParts[0]).$($currParts[1])"
                    if ($prevSubnet -ne $currSubnet) {
                        $travelFlags.Add(@{
                            User = $prev.User
                            IP1 = $prev.RemoteIP; Time1 = $prev.StartTime
                            IP2 = $curr.RemoteIP; Time2 = $curr.StartTime
                            MinutesBetween = [Math]::Round($timeDiff, 1)
                        })
                    }
                }
            }
        }
    }

    return @{
        Sessions = $sessions
        ImpossibleTravel = $travelFlags
        ConcurrentPeak = $activeByUser
    }
}

function Show-VpnSessionDialog {
    param($Results)
    if ($Script:UseConsole) {
        Write-VpnSessionTable -Results $Results
        return
    }

    $dlg = [System.Windows.Forms.Form]::new()
    $dlg.Text = "VPN Session Summary"; $dlg.Size = [System.Drawing.Size]::new(900, 600); $dlg.StartPosition = "CenterParent"
    $t = $Script:Themes[$Script:State.ActiveTheme]
    $dlg.BackColor = $t.FormBack; $dlg.ForeColor = $t.FormFore

    $tabs = [System.Windows.Forms.TabControl]::new()
    $tabs.Dock = "Fill"

    # Sessions tab
    $sessTab = [System.Windows.Forms.TabPage]::new("Sessions")
    $sessGrid = [System.Windows.Forms.DataGridView]::new()
    $sessGrid.Dock = "Fill"; $sessGrid.ReadOnly = $true; $sessGrid.AllowUserToAddRows = $false
    $sessGrid.BackgroundColor = $t.GridBack
    $sessGrid.Columns.Add("User", "User") | Out-Null
    $sessGrid.Columns.Add("Start", "Start") | Out-Null
    $sessGrid.Columns.Add("End", "End") | Out-Null
    $sessGrid.Columns.Add("Duration", "Duration") | Out-Null
    $sessGrid.Columns.Add("RemoteIP", "Remote IP") | Out-Null
    $sessGrid.Columns.Add("Sent", "Sent (bytes)") | Out-Null
    $sessGrid.Columns.Add("Rcvd", "Rcvd (bytes)") | Out-Null

    foreach ($userKey in $Results.Sessions.Keys) {
        foreach ($s in $Results.Sessions[$userKey]) {
            $startStr = if ($s.StartTime -ne [datetime]::MinValue) { $s.StartTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
            $endStr = if ($s.EndTime) { $s.EndTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "(active)" }
            $durStr = if ($s.Duration) { $s.Duration.ToString('d\.hh\:mm\:ss') } else { "" }
            $sessGrid.Rows.Add($s.User, $startStr, $endStr, $durStr, $s.RemoteIP, $s.SentBytes, $s.RcvdBytes) | Out-Null
        }
    }
    $sessGrid.AutoResizeColumns()
    $sessTab.Controls.Add($sessGrid)
    $tabs.TabPages.Add($sessTab)

    # Impossible travel tab
    if ($Results.ImpossibleTravel.Count -gt 0) {
        $travelTab = [System.Windows.Forms.TabPage]::new("Impossible Travel ($($Results.ImpossibleTravel.Count))")
        $travelGrid = [System.Windows.Forms.DataGridView]::new()
        $travelGrid.Dock = "Fill"; $travelGrid.ReadOnly = $true; $travelGrid.AllowUserToAddRows = $false
        $travelGrid.BackgroundColor = $t.GridBack
        $travelGrid.Columns.Add("User", "User") | Out-Null
        $travelGrid.Columns.Add("IP1", "IP 1") | Out-Null
        $travelGrid.Columns.Add("Time1", "Time 1") | Out-Null
        $travelGrid.Columns.Add("IP2", "IP 2") | Out-Null
        $travelGrid.Columns.Add("Time2", "Time 2") | Out-Null
        $travelGrid.Columns.Add("Minutes", "Minutes Between") | Out-Null
        foreach ($tf in $Results.ImpossibleTravel) {
            $travelGrid.Rows.Add($tf.User, $tf.IP1, $tf.Time1.ToString("yyyy-MM-dd HH:mm"), $tf.IP2, $tf.Time2.ToString("yyyy-MM-dd HH:mm"), $tf.MinutesBetween) | Out-Null
        }
        $travelGrid.AutoResizeColumns()
        $travelTab.Controls.Add($travelGrid)
        $tabs.TabPages.Add($travelTab)
    }

    $dlg.Controls.Add($tabs)
    $dlg.ShowDialog($Script:UI.Form) | Out-Null
    $dlg.Dispose()
}

function Write-VpnSessionTable {
    param($Results)
    $r = $Script:ANSIReset
    $ct = $Script:ConsoleThemes[$Script:State.ActiveTheme]

    Write-Host "`n$($ct.Title)VPN Session Summary$r"
    Write-Host "$($ct.Header){0,-25} {1,-20} {2,-20} {3,-15} {4,-16} {5,-12} {6}$r" -f "User", "Start", "End", "Duration", "Remote IP", "Sent", "Rcvd"
    Write-Host "$($ct.Border)$([string][char]0x2500 * 130)$r"

    foreach ($userKey in $Results.Sessions.Keys) {
        foreach ($s in $Results.Sessions[$userKey]) {
            $startStr = if ($s.StartTime -ne [datetime]::MinValue) { $s.StartTime.ToString("yyyy-MM-dd HH:mm") } else { "" }
            $endStr = if ($s.EndTime) { $s.EndTime.ToString("yyyy-MM-dd HH:mm") } else { "(active)" }
            $durStr = if ($s.Duration) { $s.Duration.ToString('d\.hh\:mm\:ss') } else { "" }
            Write-Host "$($ct.INFO){0,-25} {1,-20} {2,-20} {3,-15} {4,-16} {5,-12} {6}$r" -f $s.User, $startStr, $endStr, $durStr, $s.RemoteIP, $s.SentBytes, $s.RcvdBytes
        }
    }

    if ($Results.ImpossibleTravel.Count -gt 0) {
        Write-Host "`n$($ct.ERROR)IMPOSSIBLE TRAVEL FLAGS ($($Results.ImpossibleTravel.Count)):$r"
        foreach ($tf in $Results.ImpossibleTravel) {
            Write-Host "$($ct.WARNING)  $($tf.User): $($tf.IP1) @ $($tf.Time1.ToString('HH:mm')) -> $($tf.IP2) @ $($tf.Time2.ToString('HH:mm')) ($($tf.MinutesBetween) min)$r"
        }
    }
    Write-Host ""
}
