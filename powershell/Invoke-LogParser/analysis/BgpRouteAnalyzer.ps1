function Get-BgpRouteAnalysis {
    param([System.Collections.Generic.List[object]]$Entries)

    $neighbors = @{}
    $flaps = [System.Collections.Generic.List[object]]::new()
    $routeChanges = [System.Collections.Generic.List[object]]::new()

    foreach ($entry in $Entries) {
        if (-not $entry.Extra) { continue }

        $neighborIp = $entry.Extra['NeighborIp']
        $bgpState = $entry.Extra['BgpState']
        $isBgp = $false

        if ($neighborIp -or $bgpState) {
            $isBgp = $true
        } elseif ($entry.Message -and $entry.Message -match 'BGP|bgp.*neighbor|peer.*(?:up|down|established|idle|active|connect|opensent|openconfirm)') {
            $isBgp = $true
            if (-not $neighborIp -and $entry.Message -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                $neighborIp = $Matches[1]
            }
            if (-not $bgpState -and $entry.Message -match '(Established|Idle|Active|Connect|OpenSent|OpenConfirm|Down|Up)') {
                $bgpState = $Matches[1]
            }
        }

        if (-not $isBgp -or -not $neighborIp) { continue }

        if (-not $neighbors.ContainsKey($neighborIp)) {
            $neighbors[$neighborIp] = @{
                NeighborIP     = $neighborIp
                CurrentState   = $null
                Transitions    = [System.Collections.Generic.List[object]]::new()
                LastChange     = [datetime]::MinValue
                FlapCount      = 0
                ASN            = $entry.Extra['RemoteAS']
                Description    = $entry.Extra['Description']
            }
        }

        $neighbor = $neighbors[$neighborIp]

        if ($bgpState) {
            $prevState = $neighbor.CurrentState
            $neighbor.CurrentState = $bgpState
            if ($entry.Timestamp -ne [datetime]::MinValue) {
                $neighbor.LastChange = $entry.Timestamp
            }
            if ($prevState -and $prevState -ne $bgpState) {
                $neighbor.Transitions.Add(@{
                    FromState = $prevState
                    ToState   = $bgpState
                    Timestamp = $entry.Timestamp
                })
            }
        }

        # Track route changes
        if ($entry.Message -and $entry.Message -match 'route.*(?:add|withdraw|update|change)|prefix.*(?:received|advertised)') {
            $routeChanges.Add(@{
                NeighborIP = $neighborIp
                Timestamp  = $entry.Timestamp
                Message    = $entry.Message
                Action     = if ($entry.Message -match 'withdraw') { "Withdraw" }
                             elseif ($entry.Message -match 'add|advertised') { "Add" }
                             else { "Update" }
            })
        }
    }

    # Detect flaps: 3+ state transitions within 10 minutes for a neighbor
    $establishedCount = 0
    foreach ($neighborIp in $neighbors.Keys) {
        $neighbor = $neighbors[$neighborIp]

        if ($neighbor.CurrentState -and $neighbor.CurrentState -match 'Established|Up') {
            $establishedCount++
        }

        $transitions = $neighbor.Transitions | Sort-Object { $_.Timestamp }
        if ($transitions.Count -lt 3) { continue }

        for ($i = 0; $i -lt $transitions.Count - 2; $i++) {
            $t1 = $transitions[$i]
            if ($t1.Timestamp -eq [datetime]::MinValue) { continue }

            $windowEnd = $t1.Timestamp.AddMinutes(10)
            $windowTransitions = @($transitions[$i..($transitions.Count - 1)] | Where-Object {
                $_.Timestamp -ne [datetime]::MinValue -and $_.Timestamp -le $windowEnd
            })

            if ($windowTransitions.Count -ge 3) {
                $neighbor.FlapCount++
                $flaps.Add(@{
                    NeighborIP       = $neighborIp
                    StartTime        = $t1.Timestamp
                    EndTime          = $windowTransitions[-1].Timestamp
                    TransitionCount  = $windowTransitions.Count
                    States           = ($windowTransitions | ForEach-Object { $_.ToState }) -join " -> "
                })
                # Skip past this flap window to avoid double-counting
                while ($i -lt $transitions.Count - 1 -and $transitions[$i].Timestamp -le $windowEnd) { $i++ }
                break
            }
        }
    }

    return @{
        Neighbors    = $neighbors
        Flaps        = @($flaps)
        RouteChanges = @($routeChanges)
        Summary      = @{
            TotalNeighbors   = $neighbors.Count
            EstablishedCount = $establishedCount
            FlapCount        = $flaps.Count
        }
    }
}

function Show-BgpRouteDialog {
    param($Results)
    if (-not $Results -or -not $Results.Neighbors -or $Results.Neighbors.Count -eq 0) {
        if (-not $Script:UseConsole) {
            [System.Windows.Forms.MessageBox]::Show("No BGP routing data found.", "BGP Route Analysis")
        }
        return
    }

    if ($Script:UseConsole) {
        Write-BgpRouteTable -Results $Results
        return
    }

    $dlg = [System.Windows.Forms.Form]::new()
    $dlg.Text = "BGP Route Analysis"; $dlg.Size = [System.Drawing.Size]::new(900, 600); $dlg.StartPosition = "CenterParent"
    $t = $Script:Themes[$Script:State.ActiveTheme]
    $dlg.BackColor = $t.FormBack; $dlg.ForeColor = $t.FormFore

    $tabs = [System.Windows.Forms.TabControl]::new()
    $tabs.Dock = "Fill"

    # Neighbors tab
    $neighborsTab = [System.Windows.Forms.TabPage]::new("Neighbors ($($Results.Neighbors.Count))")
    $neighborsGrid = [System.Windows.Forms.DataGridView]::new()
    $neighborsGrid.Dock = "Fill"; $neighborsGrid.ReadOnly = $true; $neighborsGrid.AllowUserToAddRows = $false
    $neighborsGrid.BackgroundColor = $t.GridBack; $neighborsGrid.DefaultCellStyle.BackColor = $t.GridBack; $neighborsGrid.DefaultCellStyle.ForeColor = $t.FormFore
    $neighborsGrid.ColumnHeadersDefaultCellStyle.BackColor = $t.GridBack; $neighborsGrid.ColumnHeadersDefaultCellStyle.ForeColor = $t.FormFore
    $neighborsGrid.EnableHeadersVisualStyles = $false
    $neighborsGrid.Columns.Add("NeighborIP", "Neighbor IP") | Out-Null
    $neighborsGrid.Columns.Add("CurrentState", "Current State") | Out-Null
    $neighborsGrid.Columns.Add("Transitions", "Transitions") | Out-Null
    $neighborsGrid.Columns.Add("LastChange", "Last Change") | Out-Null
    $neighborsGrid.Columns.Add("Flaps", "Flaps") | Out-Null

    foreach ($neighborIp in $Results.Neighbors.Keys) {
        $n = $Results.Neighbors[$neighborIp]
        $lastChangeStr = if ($n.LastChange -ne [datetime]::MinValue) { $n.LastChange.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
        $rowIdx = $neighborsGrid.Rows.Add($n.NeighborIP, $n.CurrentState, $n.Transitions.Count, $lastChangeStr, $n.FlapCount)
        if ($n.FlapCount -gt 0) {
            $neighborsGrid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Red
        } elseif ($n.CurrentState -match 'Established|Up') {
            $neighborsGrid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Green
        }
    }
    $neighborsGrid.AutoResizeColumns()
    $neighborsTab.Controls.Add($neighborsGrid)
    $tabs.TabPages.Add($neighborsTab)

    # Flaps tab
    if ($Results.Flaps.Count -gt 0) {
        $flapsTab = [System.Windows.Forms.TabPage]::new("Flaps ($($Results.Flaps.Count))")
        $flapsGrid = [System.Windows.Forms.DataGridView]::new()
        $flapsGrid.Dock = "Fill"; $flapsGrid.ReadOnly = $true; $flapsGrid.AllowUserToAddRows = $false
        $flapsGrid.BackgroundColor = $t.GridBack; $flapsGrid.DefaultCellStyle.BackColor = $t.GridBack; $flapsGrid.DefaultCellStyle.ForeColor = $t.FormFore
        $flapsGrid.ColumnHeadersDefaultCellStyle.BackColor = $t.GridBack; $flapsGrid.ColumnHeadersDefaultCellStyle.ForeColor = $t.FormFore
        $flapsGrid.EnableHeadersVisualStyles = $false
        $flapsGrid.Columns.Add("NeighborIP", "Neighbor IP") | Out-Null
        $flapsGrid.Columns.Add("Start", "Start") | Out-Null
        $flapsGrid.Columns.Add("End", "End") | Out-Null
        $flapsGrid.Columns.Add("Transitions", "Transitions") | Out-Null
        $flapsGrid.Columns.Add("States", "State Sequence") | Out-Null

        foreach ($f in $Results.Flaps) {
            $startStr = if ($f.StartTime -ne [datetime]::MinValue) { $f.StartTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
            $endStr = if ($f.EndTime -ne [datetime]::MinValue) { $f.EndTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
            $flapsGrid.Rows.Add($f.NeighborIP, $startStr, $endStr, $f.TransitionCount, $f.States) | Out-Null
        }
        $flapsGrid.AutoResizeColumns()
        $flapsTab.Controls.Add($flapsGrid)
        $tabs.TabPages.Add($flapsTab)
    }

    $dlg.Controls.Add($tabs)
    $dlg.ShowDialog($Script:UI.Form) | Out-Null
    $dlg.Dispose()
}

function Write-BgpRouteTable {
    param($Results)
    $r = $Script:ANSIReset
    $ct = $Script:ConsoleThemes[$Script:State.ActiveTheme]

    Write-Host "`n$($ct.Title)BGP Route Analysis$r"
    Write-Host "$($ct.INFO)  Total Neighbors: $($Results.Summary.TotalNeighbors)  |  Established: $($Results.Summary.EstablishedCount)  |  Flaps Detected: $($Results.Summary.FlapCount)$r"
    Write-Host ""

    Write-Host "$($ct.Header){0,-18} {1,-15} {2,-14} {3,-22} {4,-8}$r" -f "Neighbor IP", "Current State", "Transitions", "Last Change", "Flaps"
    Write-Host "$($ct.Border)$([string][char]0x2500 * 80)$r"

    foreach ($neighborIp in $Results.Neighbors.Keys) {
        $n = $Results.Neighbors[$neighborIp]
        $lastChangeStr = if ($n.LastChange -ne [datetime]::MinValue) { $n.LastChange.ToString("yyyy-MM-dd HH:mm") } else { "" }
        $color = if ($n.FlapCount -gt 0) { $ct.ERROR }
                 elseif ($n.CurrentState -match 'Established|Up') { $ct.INFO }
                 else { $ct.WARNING }
        Write-Host "$color{0,-18} {1,-15} {2,-14} {3,-22} {4,-8}$r" -f $n.NeighborIP, $n.CurrentState, $n.Transitions.Count, $lastChangeStr, $n.FlapCount
    }

    if ($Results.Flaps.Count -gt 0) {
        Write-Host "`n$($ct.ERROR)FLAP WARNINGS ($($Results.Flaps.Count)):$r"
        foreach ($f in $Results.Flaps) {
            $startStr = if ($f.StartTime -ne [datetime]::MinValue) { $f.StartTime.ToString("yyyy-MM-dd HH:mm") } else { "?" }
            Write-Host "$($ct.WARNING)  $($f.NeighborIP): $($f.TransitionCount) transitions starting $startStr ($($f.States))$r"
        }
    }
    Write-Host ""
}
