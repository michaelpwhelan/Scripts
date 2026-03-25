function Get-IpsecTunnelAnalysis {
    param([System.Collections.Generic.List[object]]$Entries)

    $tunnels = @{}
    $failures = [System.Collections.Generic.List[object]]::new()

    foreach ($entry in $Entries) {
        if (-not $entry.Extra) { continue }

        $tunnelName = $entry.Extra['TunnelName']
        $isIpsec = $false

        if ($tunnelName) {
            $isIpsec = $true
        } elseif ($entry.Extra['subtype'] -eq 'ipsec' -or $entry.Extra['subtype'] -eq 'vpn') {
            if ($entry.Message -and $entry.Message -match 'IPsec|ipsec|IKE|ike|phase[12]|SA |tunnel|DPD|dpd') {
                $isIpsec = $true
                if (-not $tunnelName -and $entry.Message -match 'tunnel\s+"?([^"]+)"?') {
                    $tunnelName = $Matches[1].Trim()
                }
                if (-not $tunnelName -and $entry.Extra['tunnelid']) {
                    $tunnelName = "tunnel-$($entry.Extra['tunnelid'])"
                }
            }
        } elseif ($entry.Extra['type'] -eq 'event' -and $entry.Message -and $entry.Message -match 'IPsec|ipsec|IKE|ike') {
            $isIpsec = $true
            if ($entry.Message -match 'tunnel\s+"?([^"]+)"?') {
                $tunnelName = $Matches[1].Trim()
            }
        }

        if (-not $isIpsec) { continue }
        if (-not $tunnelName) { $tunnelName = "(unknown)" }

        if (-not $tunnels.ContainsKey($tunnelName)) {
            $tunnels[$tunnelName] = @{
                TunnelName        = $tunnelName
                Status            = "Unknown"
                UpEvents          = [System.Collections.Generic.List[object]]::new()
                DownEvents        = [System.Collections.Generic.List[object]]::new()
                NegotiationOK     = 0
                NegotiationFail   = 0
                DpdTimeouts       = 0
                RekeyEvents       = 0
                FlapCount         = 0
                LastFailureReason = $null
                FirstSeen         = [datetime]::MaxValue
                LastSeen          = [datetime]::MinValue
                TotalUpSeconds    = 0
                RemoteGateway     = $entry.Extra['remip']
            }
        }

        $tunnel = $tunnels[$tunnelName]

        if ($entry.Timestamp -ne [datetime]::MinValue) {
            if ($entry.Timestamp -lt $tunnel.FirstSeen) { $tunnel.FirstSeen = $entry.Timestamp }
            if ($entry.Timestamp -gt $tunnel.LastSeen) { $tunnel.LastSeen = $entry.Timestamp }
        }

        if (-not $tunnel.RemoteGateway -and $entry.Extra['remip']) {
            $tunnel.RemoteGateway = $entry.Extra['remip']
        }

        $action = $entry.Extra['action']
        $msg = $entry.Message

        # Classify the event
        if ($action -match 'tunnel-up' -or ($msg -and $msg -match 'tunnel.*up|SA.*established|phase[12].*completed|IPsec SA.*installed')) {
            $tunnel.Status = "Up"
            $tunnel.UpEvents.Add(@{ Timestamp = $entry.Timestamp; Message = $msg })
            $tunnel.NegotiationOK++
        }
        elseif ($action -match 'tunnel-down' -or ($msg -and $msg -match 'tunnel.*down|SA.*deleted|SA.*expired|tunnel.*removed')) {
            $tunnel.Status = "Down"
            $tunnel.DownEvents.Add(@{ Timestamp = $entry.Timestamp; Message = $msg })
        }
        elseif ($msg -and $msg -match 'negotiation.*fail|phase[12].*fail|IKE.*fail|proposal.*mismatch|no.*proposal.*chosen|auth.*fail') {
            $tunnel.NegotiationFail++
            $reason = if ($msg -match 'proposal.*mismatch') { "Proposal Mismatch" }
                      elseif ($msg -match 'auth.*fail') { "Authentication Failure" }
                      elseif ($msg -match 'timeout') { "Timeout" }
                      elseif ($msg -match 'no.*proposal.*chosen') { "No Proposal Chosen" }
                      else { "Negotiation Failure" }
            $tunnel.LastFailureReason = $reason
            $failures.Add(@{
                TunnelName = $tunnelName
                Timestamp  = $entry.Timestamp
                Reason     = $reason
                Message    = $msg
            })
        }
        elseif ($msg -and $msg -match 'DPD.*timeout|dead.*peer|dpd.*fail') {
            $tunnel.DpdTimeouts++
            $tunnel.LastFailureReason = "DPD Timeout"
            $failures.Add(@{
                TunnelName = $tunnelName
                Timestamp  = $entry.Timestamp
                Reason     = "DPD Timeout"
                Message    = $msg
            })
        }
        elseif ($msg -and $msg -match 'rekey|rekeying|SA.*rekey') {
            $tunnel.RekeyEvents++
        }
    }

    # Calculate per-tunnel metrics
    $upCount = 0; $downCount = 0; $totalFlaps = 0

    foreach ($tunnelName in $tunnels.Keys) {
        $tunnel = $tunnels[$tunnelName]

        # Calculate uptime percentage based on up/down event pairs
        if ($tunnel.UpEvents.Count -gt 0 -and $tunnel.FirstSeen -ne [datetime]::MaxValue -and $tunnel.LastSeen -ne [datetime]::MinValue) {
            $totalSpan = ($tunnel.LastSeen - $tunnel.FirstSeen).TotalSeconds
            if ($totalSpan -gt 0) {
                $upSeconds = 0
                $allEvents = @()
                foreach ($e in $tunnel.UpEvents) { $allEvents += @{ Type = 'Up'; Timestamp = $e.Timestamp } }
                foreach ($e in $tunnel.DownEvents) { $allEvents += @{ Type = 'Down'; Timestamp = $e.Timestamp } }
                $allEvents = $allEvents | Where-Object { $_.Timestamp -ne [datetime]::MinValue } | Sort-Object { $_.Timestamp }

                $lastUp = $null
                foreach ($evt in $allEvents) {
                    if ($evt.Type -eq 'Up') {
                        $lastUp = $evt.Timestamp
                    } elseif ($evt.Type -eq 'Down' -and $lastUp) {
                        $upSeconds += ($evt.Timestamp - $lastUp).TotalSeconds
                        $lastUp = $null
                    }
                }
                # If last event was an up, count until last seen
                if ($lastUp) {
                    $upSeconds += ($tunnel.LastSeen - $lastUp).TotalSeconds
                }
                $tunnel.TotalUpSeconds = $upSeconds
            }
        }

        # Detect flaps: consecutive up/down within short intervals
        $allToggle = @()
        foreach ($e in $tunnel.UpEvents) { $allToggle += @{ Type = 'Up'; Timestamp = $e.Timestamp } }
        foreach ($e in $tunnel.DownEvents) { $allToggle += @{ Type = 'Down'; Timestamp = $e.Timestamp } }
        $allToggle = $allToggle | Where-Object { $_.Timestamp -ne [datetime]::MinValue } | Sort-Object { $_.Timestamp }
        $flapCount = 0
        for ($i = 1; $i -lt $allToggle.Count; $i++) {
            if ($allToggle[$i].Type -ne $allToggle[$i-1].Type) {
                $gap = ($allToggle[$i].Timestamp - $allToggle[$i-1].Timestamp).TotalMinutes
                if ($gap -le 5) { $flapCount++ }
            }
        }
        $tunnel.FlapCount = $flapCount
        $totalFlaps += $flapCount

        if ($tunnel.Status -eq 'Up') { $upCount++ } else { $downCount++ }
    }

    return @{
        Tunnels  = $tunnels
        Failures = @($failures)
        Summary  = @{
            TotalTunnels = $tunnels.Count
            UpCount      = $upCount
            DownCount    = $downCount
            FlapCount    = $totalFlaps
        }
    }
}

function Show-IpsecTunnelDialog {
    param($Results)
    if (-not $Results -or -not $Results.Tunnels -or $Results.Tunnels.Count -eq 0) {
        if (-not $Script:UseConsole) {
            [System.Windows.Forms.MessageBox]::Show("No IPsec tunnel data found.", "IPsec Tunnel Analysis")
        }
        return
    }

    if ($Script:UseConsole) {
        Write-IpsecTunnelTable -Results $Results
        return
    }

    $dlg = [System.Windows.Forms.Form]::new()
    $dlg.Text = "IPsec Tunnel Analysis"; $dlg.Size = [System.Drawing.Size]::new(950, 600); $dlg.StartPosition = "CenterParent"
    $t = $Script:Themes[$Script:State.ActiveTheme]
    $dlg.BackColor = $t.FormBack; $dlg.ForeColor = $t.FormFore

    $grid = [System.Windows.Forms.DataGridView]::new()
    $grid.Dock = "Fill"; $grid.ReadOnly = $true; $grid.AllowUserToAddRows = $false
    $grid.BackgroundColor = $t.GridBack; $grid.DefaultCellStyle.BackColor = $t.GridBack; $grid.DefaultCellStyle.ForeColor = $t.FormFore
    $grid.ColumnHeadersDefaultCellStyle.BackColor = $t.GridBack; $grid.ColumnHeadersDefaultCellStyle.ForeColor = $t.FormFore
    $grid.EnableHeadersVisualStyles = $false
    $grid.Columns.Add("Tunnel", "Tunnel") | Out-Null
    $grid.Columns.Add("Status", "Status") | Out-Null
    $grid.Columns.Add("Uptime", "Uptime %") | Out-Null
    $grid.Columns.Add("Flaps", "Flaps") | Out-Null
    $grid.Columns.Add("LastFailure", "Last Failure") | Out-Null
    $grid.Columns.Add("NegRate", "Negotiation Rate") | Out-Null
    $grid.Columns.Add("Gateway", "Remote GW") | Out-Null

    foreach ($tunnelName in $Results.Tunnels.Keys) {
        $tun = $Results.Tunnels[$tunnelName]
        $totalSpan = 0
        if ($tun.FirstSeen -ne [datetime]::MaxValue -and $tun.LastSeen -ne [datetime]::MinValue) {
            $totalSpan = ($tun.LastSeen - $tun.FirstSeen).TotalSeconds
        }
        $uptimePct = if ($totalSpan -gt 0) { [Math]::Round(($tun.TotalUpSeconds / $totalSpan) * 100, 1) } else { 0 }
        $negTotal = $tun.NegotiationOK + $tun.NegotiationFail
        $negRate = if ($negTotal -gt 0) { "$([Math]::Round(($tun.NegotiationOK / $negTotal) * 100, 1))%" } else { "N/A" }
        $lastFail = if ($tun.LastFailureReason) { $tun.LastFailureReason } else { "" }
        $gw = if ($tun.RemoteGateway) { $tun.RemoteGateway } else { "" }

        $rowIdx = $grid.Rows.Add($tun.TunnelName, $tun.Status, "$uptimePct%", $tun.FlapCount, $lastFail, $negRate, $gw)
        if ($tun.Status -eq 'Down') {
            $grid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Red
        } elseif ($tun.FlapCount -gt 0) {
            $grid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Orange
        } elseif ($tun.Status -eq 'Up') {
            $grid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Green
        }
    }
    $grid.AutoResizeColumns()

    $dlg.Controls.Add($grid)
    $dlg.ShowDialog($Script:UI.Form) | Out-Null
    $dlg.Dispose()
}

function Write-IpsecTunnelTable {
    param($Results)
    $r = $Script:ANSIReset
    $ct = $Script:ConsoleThemes[$Script:State.ActiveTheme]

    Write-Host "`n$($ct.Title)IPsec Tunnel Analysis$r"
    Write-Host "$($ct.INFO)  Total: $($Results.Summary.TotalTunnels)  |  Up: $($Results.Summary.UpCount)  |  Down: $($Results.Summary.DownCount)  |  Flaps: $($Results.Summary.FlapCount)$r"
    Write-Host ""

    Write-Host "$($ct.Header){0,-25} {1,-10} {2,-10} {3,-8} {4,-25} {5,-18} {6}$r" -f "Tunnel", "Status", "Uptime%", "Flaps", "Last Failure", "Negotiation Rate", "Remote GW"
    Write-Host "$($ct.Border)$([string][char]0x2500 * 120)$r"

    foreach ($tunnelName in $Results.Tunnels.Keys) {
        $tun = $Results.Tunnels[$tunnelName]
        $totalSpan = 0
        if ($tun.FirstSeen -ne [datetime]::MaxValue -and $tun.LastSeen -ne [datetime]::MinValue) {
            $totalSpan = ($tun.LastSeen - $tun.FirstSeen).TotalSeconds
        }
        $uptimePct = if ($totalSpan -gt 0) { [Math]::Round(($tun.TotalUpSeconds / $totalSpan) * 100, 1) } else { 0 }
        $negTotal = $tun.NegotiationOK + $tun.NegotiationFail
        $negRate = if ($negTotal -gt 0) { "$([Math]::Round(($tun.NegotiationOK / $negTotal) * 100, 1))%" } else { "N/A" }
        $lastFail = if ($tun.LastFailureReason) { $tun.LastFailureReason } else { "-" }
        $gw = if ($tun.RemoteGateway) { $tun.RemoteGateway } else { "-" }

        $color = if ($tun.Status -eq 'Down') { $ct.ERROR }
                 elseif ($tun.FlapCount -gt 0) { $ct.WARNING }
                 else { $ct.INFO }
        Write-Host "$color{0,-25} {1,-10} {2,-10} {3,-8} {4,-25} {5,-18} {6}$r" -f $tun.TunnelName, $tun.Status, "$uptimePct%", $tun.FlapCount, $lastFail, $negRate, $gw
    }
    Write-Host ""
}
