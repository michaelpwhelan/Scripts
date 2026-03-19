function Get-NpsSessionAnalysis {
    param([System.Collections.Generic.List[object]]$Entries)

    $nasSummary = @{}
    $userSummary = @{}
    $reasonCodes = @{}
    $totalRequests = 0
    $acceptCount = 0
    $rejectCount = 0
    $uniqueUsers = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $uniqueNas = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($entry in $Entries) {
        if (-not $entry.Extra) { continue }

        $packetType = $entry.Extra['PacketTypeName']
        if (-not $packetType) { continue }

        $totalRequests++

        $nasIp = $entry.Extra['NAS-IP-Address']
        if (-not $nasIp) { $nasIp = $entry.Extra['Client-IP-Address'] }
        if (-not $nasIp) { $nasIp = $entry.Extra['NASIPAddress'] }
        if (-not $nasIp) { $nasIp = "(unknown)" }

        $userName = $entry.Extra['User-Name']
        if (-not $userName) { $userName = $entry.Extra['SAM-Account-Name'] }
        if (-not $userName) { $userName = $entry.Extra['FullyQualifiedSubjectUserName'] }
        if (-not $userName) { $userName = "(unknown)" }

        $nasName = $entry.Extra['Client-Friendly-Name']
        if (-not $nasName) { $nasName = $entry.Extra['NASIdentifier'] }
        if (-not $nasName) { $nasName = $nasIp }

        $isAccept = $packetType -match 'Accept'
        $isReject = $packetType -match 'Reject'

        if ($isAccept) { $acceptCount++ }
        if ($isReject) { $rejectCount++ }

        $uniqueUsers.Add($userName) | Out-Null
        $uniqueNas.Add($nasIp) | Out-Null

        # NAS Summary
        if (-not $nasSummary.ContainsKey($nasIp)) {
            $nasSummary[$nasIp] = @{
                NasIP        = $nasIp
                NasName      = $nasName
                AcceptCount  = 0
                RejectCount  = 0
                TotalCount   = 0
                UniqueUsers  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                FirstSeen    = $entry.Timestamp
                LastSeen     = $entry.Timestamp
            }
        }
        $nas = $nasSummary[$nasIp]
        $nas.TotalCount++
        if ($isAccept) { $nas.AcceptCount++ }
        if ($isReject) { $nas.RejectCount++ }
        $nas.UniqueUsers.Add($userName) | Out-Null
        if ($entry.Timestamp -ne [datetime]::MinValue) {
            if ($entry.Timestamp -lt $nas.FirstSeen -or $nas.FirstSeen -eq [datetime]::MinValue) { $nas.FirstSeen = $entry.Timestamp }
            if ($entry.Timestamp -gt $nas.LastSeen) { $nas.LastSeen = $entry.Timestamp }
        }

        # User Summary
        $userKey = $userName.ToLower()
        if (-not $userSummary.ContainsKey($userKey)) {
            $userSummary[$userKey] = @{
                UserName     = $userName
                AcceptCount  = 0
                RejectCount  = 0
                TotalCount   = 0
                NasDevices   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                CallingStations = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                LastSeen     = $entry.Timestamp
            }
        }
        $usr = $userSummary[$userKey]
        $usr.TotalCount++
        if ($isAccept) { $usr.AcceptCount++ }
        if ($isReject) { $usr.RejectCount++ }
        $usr.NasDevices.Add($nasIp) | Out-Null
        $callingStation = $entry.Extra['Calling-Station-Id']
        if ($callingStation) { $usr.CallingStations.Add($callingStation) | Out-Null }
        if ($entry.Timestamp -ne [datetime]::MinValue -and $entry.Timestamp -gt $usr.LastSeen) {
            $usr.LastSeen = $entry.Timestamp
        }

        # Reason codes for failures
        if ($isReject) {
            $reasonCode = $entry.Extra['Reason-Code']
            $reasonTranslation = $entry.Extra['ReasonCodeTranslation']
            if (-not $reasonTranslation -and $reasonCode) {
                $reasonTranslation = switch ($reasonCode) {
                    '0'  { "IAS_SUCCESS" }
                    '1'  { "IAS_INTERNAL_ERROR" }
                    '2'  { "IAS_ACCESS_DENIED" }
                    '3'  { "IAS_MALFORMED_REQUEST" }
                    '16' { "IAS_GLOBAL_CATALOG_UNAVAILABLE" }
                    '17' { "IAS_DOMAIN_UNAVAILABLE" }
                    '18' { "IAS_SERVER_UNAVAILABLE" }
                    '21' { "IAS_NO_SUCH_DOMAIN" }
                    '22' { "IAS_NO_SUCH_USER" }
                    '23' { "IAS_AUTH_FAILURE" }
                    '32' { "IAS_LOCAL_USERS_ONLY" }
                    '33' { "IAS_PASSWORD_MUST_CHANGE" }
                    '34' { "IAS_ACCOUNT_DISABLED" }
                    '35' { "IAS_ACCOUNT_EXPIRED" }
                    '36' { "IAS_ACCOUNT_LOCKED" }
                    '37' { "IAS_INVALID_LOGON_HOURS" }
                    '48' { "IAS_NO_POLICY_MATCH" }
                    '49' { "IAS_DIALIN_LOCKED_OUT" }
                    '65' { "IAS_NO_RECORD" }
                    '66' { "IAS_SESSION_TIMEOUT" }
                    default { "Code $reasonCode" }
                }
            }
            if (-not $reasonTranslation) { $reasonTranslation = "Unknown" }

            $rcKey = $reasonTranslation
            if (-not $reasonCodes.ContainsKey($rcKey)) {
                $reasonCodes[$rcKey] = @{
                    Reason     = $reasonTranslation
                    ReasonCode = $reasonCode
                    Count      = 0
                    Users      = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                }
            }
            $reasonCodes[$rcKey].Count++
            $reasonCodes[$rcKey].Users.Add($userName) | Out-Null
        }
    }

    $sortedReasons = $reasonCodes.Values | Sort-Object { $_.Count } -Descending

    return @{
        NasSummary  = $nasSummary
        UserSummary = $userSummary
        ReasonCodes = @($sortedReasons)
        Summary     = @{
            TotalRequests = $totalRequests
            AcceptCount   = $acceptCount
            RejectCount   = $rejectCount
            UniqueUsers   = $uniqueUsers.Count
            UniqueNas     = $uniqueNas.Count
        }
    }
}

function Show-NpsSessionDialog {
    param($Results)
    if (-not $Results -or $Results.Summary.TotalRequests -eq 0) {
        if (-not $Script:UseConsole) {
            [System.Windows.Forms.MessageBox]::Show("No NPS/RADIUS data found.", "NPS Session Analysis")
        }
        return
    }

    if ($Script:UseConsole) {
        Write-NpsSessionTable -Results $Results
        return
    }

    $dlg = [System.Windows.Forms.Form]::new()
    $dlg.Text = "NPS Session Analysis"; $dlg.Size = [System.Drawing.Size]::new(950, 600); $dlg.StartPosition = "CenterParent"
    $t = $Script:Themes[$Script:State.ActiveTheme]
    $dlg.BackColor = $t.FormBack; $dlg.ForeColor = $t.FormFore

    $tabs = [System.Windows.Forms.TabControl]::new()
    $tabs.Dock = "Fill"

    # NAS Summary tab
    $nasTab = [System.Windows.Forms.TabPage]::new("NAS Summary ($($Results.NasSummary.Count))")
    $nasGrid = [System.Windows.Forms.DataGridView]::new()
    $nasGrid.Dock = "Fill"; $nasGrid.ReadOnly = $true; $nasGrid.AllowUserToAddRows = $false
    $nasGrid.BackgroundColor = $t.GridBack; $nasGrid.DefaultCellStyle.BackColor = $t.GridBack; $nasGrid.DefaultCellStyle.ForeColor = $t.FormFore
    $nasGrid.ColumnHeadersDefaultCellStyle.BackColor = $t.GridBack; $nasGrid.ColumnHeadersDefaultCellStyle.ForeColor = $t.FormFore
    $nasGrid.EnableHeadersVisualStyles = $false
    $nasGrid.Columns.Add("NasIP", "NAS IP") | Out-Null
    $nasGrid.Columns.Add("NasName", "NAS Name") | Out-Null
    $nasGrid.Columns.Add("Total", "Total") | Out-Null
    $nasGrid.Columns.Add("Accept", "Accept") | Out-Null
    $nasGrid.Columns.Add("Reject", "Reject") | Out-Null
    $nasGrid.Columns.Add("SuccessRate", "Success %") | Out-Null
    $nasGrid.Columns.Add("UniqueUsers", "Users") | Out-Null

    foreach ($nasIp in $Results.NasSummary.Keys) {
        $nas = $Results.NasSummary[$nasIp]
        $successPct = if ($nas.TotalCount -gt 0) { [Math]::Round(($nas.AcceptCount / $nas.TotalCount) * 100, 1) } else { 0 }
        $rowIdx = $nasGrid.Rows.Add($nas.NasIP, $nas.NasName, $nas.TotalCount, $nas.AcceptCount, $nas.RejectCount, "$successPct%", $nas.UniqueUsers.Count)
        if ($nas.RejectCount -gt $nas.AcceptCount) {
            $nasGrid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Red
        }
    }
    $nasGrid.AutoResizeColumns()
    $nasTab.Controls.Add($nasGrid)
    $tabs.TabPages.Add($nasTab)

    # User Summary tab
    $userTab = [System.Windows.Forms.TabPage]::new("User Summary ($($Results.UserSummary.Count))")
    $userGrid = [System.Windows.Forms.DataGridView]::new()
    $userGrid.Dock = "Fill"; $userGrid.ReadOnly = $true; $userGrid.AllowUserToAddRows = $false
    $userGrid.BackgroundColor = $t.GridBack; $userGrid.DefaultCellStyle.BackColor = $t.GridBack; $userGrid.DefaultCellStyle.ForeColor = $t.FormFore
    $userGrid.ColumnHeadersDefaultCellStyle.BackColor = $t.GridBack; $userGrid.ColumnHeadersDefaultCellStyle.ForeColor = $t.FormFore
    $userGrid.EnableHeadersVisualStyles = $false
    $userGrid.Columns.Add("User", "User") | Out-Null
    $userGrid.Columns.Add("Total", "Total") | Out-Null
    $userGrid.Columns.Add("Accept", "Accept") | Out-Null
    $userGrid.Columns.Add("Reject", "Reject") | Out-Null
    $userGrid.Columns.Add("SuccessRate", "Success %") | Out-Null
    $userGrid.Columns.Add("NasDevices", "NAS Devices") | Out-Null
    $userGrid.Columns.Add("Stations", "Calling Stations") | Out-Null

    $sortedUsers = $Results.UserSummary.Values | Sort-Object { $_.RejectCount } -Descending
    foreach ($usr in $sortedUsers) {
        $successPct = if ($usr.TotalCount -gt 0) { [Math]::Round(($usr.AcceptCount / $usr.TotalCount) * 100, 1) } else { 0 }
        $rowIdx = $userGrid.Rows.Add($usr.UserName, $usr.TotalCount, $usr.AcceptCount, $usr.RejectCount, "$successPct%", $usr.NasDevices.Count, $usr.CallingStations.Count)
        if ($usr.RejectCount -gt 0 -and $usr.AcceptCount -eq 0) {
            $userGrid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Red
        } elseif ($usr.RejectCount -gt $usr.AcceptCount) {
            $userGrid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::OrangeRed
        }
    }
    $userGrid.AutoResizeColumns()
    $userTab.Controls.Add($userGrid)
    $tabs.TabPages.Add($userTab)

    # Failure Reasons tab
    if ($Results.ReasonCodes.Count -gt 0) {
        $reasonTab = [System.Windows.Forms.TabPage]::new("Failure Reasons ($($Results.ReasonCodes.Count))")
        $reasonGrid = [System.Windows.Forms.DataGridView]::new()
        $reasonGrid.Dock = "Fill"; $reasonGrid.ReadOnly = $true; $reasonGrid.AllowUserToAddRows = $false
        $reasonGrid.BackgroundColor = $t.GridBack; $reasonGrid.DefaultCellStyle.BackColor = $t.GridBack; $reasonGrid.DefaultCellStyle.ForeColor = $t.FormFore
        $reasonGrid.ColumnHeadersDefaultCellStyle.BackColor = $t.GridBack; $reasonGrid.ColumnHeadersDefaultCellStyle.ForeColor = $t.FormFore
        $reasonGrid.EnableHeadersVisualStyles = $false
        $reasonGrid.Columns.Add("Reason", "Reason") | Out-Null
        $reasonGrid.Columns.Add("Code", "Code") | Out-Null
        $reasonGrid.Columns.Add("Count", "Count") | Out-Null
        $reasonGrid.Columns.Add("AffectedUsers", "Affected Users") | Out-Null

        foreach ($rc in $Results.ReasonCodes) {
            $reasonGrid.Rows.Add($rc.Reason, $rc.ReasonCode, $rc.Count, $rc.Users.Count) | Out-Null
        }
        $reasonGrid.AutoResizeColumns()
        $reasonTab.Controls.Add($reasonGrid)
        $tabs.TabPages.Add($reasonTab)
    }

    $dlg.Controls.Add($tabs)
    $dlg.ShowDialog($Script:UI.Form) | Out-Null
    $dlg.Dispose()
}

function Write-NpsSessionTable {
    param($Results)
    $r = $Script:ANSIReset
    $ct = $Script:ConsoleThemes[$Script:State.ActiveTheme]

    Write-Host "`n$($ct.Title)NPS Session Analysis$r"
    Write-Host "$($ct.INFO)  Requests: $($Results.Summary.TotalRequests)  |  Accept: $($Results.Summary.AcceptCount)  |  Reject: $($Results.Summary.RejectCount)  |  Users: $($Results.Summary.UniqueUsers)  |  NAS: $($Results.Summary.UniqueNas)$r"
    Write-Host ""

    # NAS Summary
    Write-Host "$($ct.Title)NAS Summary$r"
    Write-Host "$($ct.Header){0,-18} {1,-25} {2,-8} {3,-8} {4,-8} {5,-10} {6}$r" -f "NAS IP", "NAS Name", "Total", "Accept", "Reject", "Success%", "Users"
    Write-Host "$($ct.Border)$([string][char]0x2500 * 100)$r"

    foreach ($nasIp in $Results.NasSummary.Keys) {
        $nas = $Results.NasSummary[$nasIp]
        $successPct = if ($nas.TotalCount -gt 0) { [Math]::Round(($nas.AcceptCount / $nas.TotalCount) * 100, 1) } else { 0 }
        $color = if ($nas.RejectCount -gt $nas.AcceptCount) { $ct.ERROR } elseif ($nas.RejectCount -gt 0) { $ct.WARNING } else { $ct.INFO }
        Write-Host "$color{0,-18} {1,-25} {2,-8} {3,-8} {4,-8} {5,-10} {6}$r" -f $nas.NasIP, $nas.NasName, $nas.TotalCount, $nas.AcceptCount, $nas.RejectCount, "$successPct%", $nas.UniqueUsers.Count
    }

    # Top failure reasons
    if ($Results.ReasonCodes.Count -gt 0) {
        Write-Host "`n$($ct.Title)Top Failure Reasons$r"
        Write-Host "$($ct.Header){0,-40} {1,-8} {2,-8} {3}$r" -f "Reason", "Code", "Count", "Affected Users"
        Write-Host "$($ct.Border)$([string][char]0x2500 * 80)$r"

        foreach ($rc in $Results.ReasonCodes) {
            Write-Host "$($ct.WARNING){0,-40} {1,-8} {2,-8} {3}$r" -f $rc.Reason, $rc.ReasonCode, $rc.Count, $rc.Users.Count
        }
    }
    Write-Host ""
}
