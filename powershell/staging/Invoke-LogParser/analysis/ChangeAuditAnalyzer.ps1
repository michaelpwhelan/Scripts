function Get-ChangeAuditAnalysis {
    param([System.Collections.Generic.List[object]]$Entries)

    $changes = [System.Collections.Generic.List[object]]::new()
    $byCategory = @{}
    $byRisk = @{ 'HIGH' = 0; 'MEDIUM' = 0; 'LOW' = 0 }

    # AD account change EventIDs
    $adAccountIds = @(4720,4721,4722,4723,4724,4725,4726,4738,4740,4741,4742,4743)
    # AD group change EventIDs
    $adGroupIds = @(4728,4729,4730,4731,4732,4733,4734,4735,4737,4754,4755,4756,4757,4758)
    # AD directory object changes
    $adDirectoryIds = @(5136,5137,5138,5139,5141)
    # Security group IDs (high risk)
    $securityGroupIds = @(4728,4729,4732,4733,4756,4757)
    # Admin account EventIDs
    $adminEventIds = @(4672,4648)

    foreach ($entry in $Entries) {
        if (-not $entry.Extra) { continue }

        $isChange = $false
        $category = $null
        $risk = $null
        $who = $null
        $what = $null
        $detail = $null
        $source = $null

        $eventId = $entry.Extra['EventID'] -as [int]
        $sourceFormat = $entry.Extra['SourceFormat']

        # AD Changes via EVTX
        if ($eventId -and $eventId -gt 0) {
            if ($eventId -in $adAccountIds) {
                $isChange = $true
                $category = "Account Change"
                $who = $entry.Extra['SubjectUserName']
                if (-not $who) { $who = $entry.Extra['TargetUserName'] }
                $what = switch ($eventId) {
                    4720 { "User account created" }
                    4721 { "User account disabled (deleted)" }
                    4722 { "User account enabled" }
                    4723 { "Password change attempted" }
                    4724 { "Password reset attempted" }
                    4725 { "User account disabled" }
                    4726 { "User account deleted" }
                    4738 { "User account changed" }
                    4740 { "User account locked out" }
                    4741 { "Computer account created" }
                    4742 { "Computer account changed" }
                    4743 { "Computer account deleted" }
                    default { "Account event $eventId" }
                }
                $detail = $entry.Extra['TargetUserName']
                $risk = if ($eventId -in @(4720, 4726, 4724)) { "HIGH" } else { "MEDIUM" }
                $source = "Active Directory"
            }
            elseif ($eventId -in $adGroupIds) {
                $isChange = $true
                $category = "Group Change"
                $who = $entry.Extra['SubjectUserName']
                $what = switch ($eventId) {
                    4728 { "Member added to security group" }
                    4729 { "Member removed from security group" }
                    4730 { "Security group deleted" }
                    4731 { "Security group created" }
                    4732 { "Member added to local group" }
                    4733 { "Member removed from local group" }
                    4734 { "Local group deleted" }
                    4735 { "Local group changed" }
                    4737 { "Security group changed" }
                    4754 { "Universal group created" }
                    4755 { "Universal group changed" }
                    4756 { "Member added to universal group" }
                    4757 { "Member removed from universal group" }
                    4758 { "Universal group deleted" }
                    default { "Group event $eventId" }
                }
                $detail = $entry.Extra['TargetUserName']
                if ($entry.Extra['MemberName']) { $detail = "$detail (member: $($entry.Extra['MemberName']))" }
                $risk = if ($eventId -in $securityGroupIds) { "HIGH" } else { "MEDIUM" }
                $source = "Active Directory"
            }
            elseif ($eventId -in $adDirectoryIds) {
                $isChange = $true
                $category = "Directory Object Change"
                $who = $entry.Extra['SubjectUserName']
                $what = switch ($eventId) {
                    5136 { "Directory object modified" }
                    5137 { "Directory object created" }
                    5138 { "Directory object undeleted" }
                    5139 { "Directory object moved" }
                    5141 { "Directory object deleted" }
                    default { "Directory event $eventId" }
                }
                $detail = $entry.Extra['ObjectDN']
                if (-not $detail) { $detail = $entry.Extra['ObjectClass'] }
                $risk = "MEDIUM"
                $source = "Active Directory"
            }
        }

        # FortiManager audit changes
        if (-not $isChange -and $sourceFormat -eq 'fortimanager-audit') {
            $action = $entry.Extra['action']
            if ($action) {
                $isChange = $true
                $category = "FortiManager Change"
                $who = $entry.Extra['user']
                if (-not $who) { $who = $entry.Extra['admin'] }
                $what = $action
                $detail = $entry.Message
                $source = "FortiManager"

                if ($action -match 'policy|firewall|rule') {
                    $risk = "HIGH"
                    $category = "Firewall Policy Change"
                } elseif ($action -match 'config|setting|system') {
                    $risk = "MEDIUM"
                    $category = "Configuration Change"
                } else {
                    $risk = "LOW"
                }
            }
        }

        # Entra audit changes
        if (-not $isChange -and $sourceFormat -eq 'entra-audit') {
            $result = $entry.Extra['Result']
            $activity = $entry.Extra['ActivityDisplayName']
            if (-not $activity) { $activity = $entry.Extra['Activity'] }
            if ($activity) {
                $isChange = $true
                $category = "Entra ID Change"
                $who = $entry.Extra['UserPrincipalName']
                if (-not $who) { $who = $entry.Extra['InitiatedBy'] }
                $what = $activity
                $detail = if ($result) { "Result: $result" } else { "" }
                if ($entry.Extra['TargetResources']) { $detail = "$detail Target: $($entry.Extra['TargetResources'])" }
                $source = "Entra ID"

                if ($activity -match 'admin|role|privilege|conditional.*access|security') {
                    $risk = "HIGH"
                } elseif ($activity -match 'user|group|application|policy') {
                    $risk = "MEDIUM"
                } else {
                    $risk = "LOW"
                }
            }
        }

        # FortiGate configuration changes
        if (-not $isChange -and $sourceFormat -eq 'fortigate-conf') {
            $isChange = $true
            $category = "FortiGate Config"
            $who = $entry.Extra['user']
            if (-not $who) { $who = $entry.Extra['admin'] }
            $what = "Configuration change"
            $detail = $entry.Message
            $source = "FortiGate"
            $risk = "MEDIUM"

            if ($entry.Message -and $entry.Message -match 'admin|firewall.*policy|security') {
                $risk = "HIGH"
            }
        }

        # FortiGate event/system config changes
        if (-not $isChange -and $entry.Extra['type'] -eq 'event' -and $entry.Extra['subtype'] -eq 'system') {
            $action = $entry.Extra['action']
            if ($action -and $action -match 'edit|add|delete|config') {
                $isChange = $true
                $category = "System Config Change"
                $who = $entry.Extra['user']
                if (-not $who) { $who = $entry.Extra['admin'] }
                $what = $action
                $detail = $entry.Message
                $source = "FortiGate"
                $risk = if ($action -match 'firewall|admin|security') { "HIGH" } else { "MEDIUM" }
            }
        }

        if (-not $isChange) { continue }
        if (-not $who) { $who = "(unknown)" }
        if (-not $what) { $what = "(unspecified)" }
        if (-not $detail) { $detail = "" }
        if (-not $source) { $source = if ($sourceFormat) { $sourceFormat } else { "Unknown" } }
        if (-not $risk) { $risk = "LOW" }

        # Truncate long detail strings
        if ($detail -and $detail.Length -gt 200) { $detail = $detail.Substring(0, 200) + "..." }

        $changes.Add(@{
            Timestamp = $entry.Timestamp
            Source    = $source
            Category  = $category
            Risk      = $risk
            Who       = $who
            What      = $what
            Detail    = $detail
        })

        if (-not $byCategory.ContainsKey($category)) { $byCategory[$category] = 0 }
        $byCategory[$category]++
        $byRisk[$risk]++
    }

    # Sort timeline by timestamp
    $sortedChanges = $changes | Sort-Object { $_.Timestamp }

    return @{
        Changes    = @($sortedChanges)
        ByCategory = $byCategory
        ByRisk     = $byRisk
        Summary    = @{
            Total  = $changes.Count
            High   = $byRisk['HIGH']
            Medium = $byRisk['MEDIUM']
            Low    = $byRisk['LOW']
        }
    }
}

function Show-ChangeAuditDialog {
    param($Results)
    if (-not $Results -or $Results.Summary.Total -eq 0) {
        if (-not $Script:UseConsole) {
            [System.Windows.Forms.MessageBox]::Show("No change audit events found.", "Change Audit Analysis")
        }
        return
    }

    if ($Script:UseConsole) {
        Write-ChangeAuditTable -Results $Results
        return
    }

    $dlg = [System.Windows.Forms.Form]::new()
    $dlg.Text = "Change Audit Analysis"; $dlg.Size = [System.Drawing.Size]::new(1000, 600); $dlg.StartPosition = "CenterParent"
    $t = $Script:Themes[$Script:State.ActiveTheme]
    $dlg.BackColor = $t.FormBack; $dlg.ForeColor = $t.FormFore

    $grid = [System.Windows.Forms.DataGridView]::new()
    $grid.Dock = "Fill"; $grid.ReadOnly = $true; $grid.AllowUserToAddRows = $false
    $grid.BackgroundColor = $t.GridBack; $grid.DefaultCellStyle.BackColor = $t.GridBack; $grid.DefaultCellStyle.ForeColor = $t.FormFore
    $grid.ColumnHeadersDefaultCellStyle.BackColor = $t.GridBack; $grid.ColumnHeadersDefaultCellStyle.ForeColor = $t.FormFore
    $grid.EnableHeadersVisualStyles = $false
    $grid.Columns.Add("Time", "Time") | Out-Null
    $grid.Columns.Add("Source", "Source") | Out-Null
    $grid.Columns.Add("Category", "Category") | Out-Null
    $grid.Columns.Add("Risk", "Risk") | Out-Null
    $grid.Columns.Add("Who", "Who") | Out-Null
    $grid.Columns.Add("What", "What") | Out-Null
    $grid.Columns.Add("Detail", "Detail") | Out-Null

    foreach ($c in $Results.Changes) {
        $timeStr = if ($c.Timestamp -ne [datetime]::MinValue) { $c.Timestamp.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
        $rowIdx = $grid.Rows.Add($timeStr, $c.Source, $c.Category, $c.Risk, $c.Who, $c.What, $c.Detail)
        switch ($c.Risk) {
            'HIGH'   { $grid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Red }
            'MEDIUM' { $grid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Orange }
        }
    }
    $grid.AutoResizeColumns()

    $dlg.Controls.Add($grid)
    $dlg.ShowDialog($Script:UI.Form) | Out-Null
    $dlg.Dispose()
}

function Write-ChangeAuditTable {
    param($Results)
    $r = $Script:ANSIReset
    $ct = $Script:ConsoleThemes[$Script:State.ActiveTheme]

    Write-Host "`n$($ct.Title)Change Audit Analysis$r"
    Write-Host "$($ct.INFO)  Total: $($Results.Summary.Total)  |  High: $($Results.Summary.High)  |  Medium: $($Results.Summary.Medium)  |  Low: $($Results.Summary.Low)$r"
    Write-Host ""

    Write-Host "$($ct.Header){0,-20} {1,-16} {2,-22} {3,-8} {4,-20} {5,-30} {6}$r" -f "Time", "Source", "Category", "Risk", "Who", "What", "Detail"
    Write-Host "$($ct.Border)$([string][char]0x2500 * 140)$r"

    foreach ($c in $Results.Changes) {
        $timeStr = if ($c.Timestamp -ne [datetime]::MinValue) { $c.Timestamp.ToString("yyyy-MM-dd HH:mm") } else { "" }
        $whatTrunc = if ($c.What.Length -gt 28) { $c.What.Substring(0, 28) } else { $c.What }
        $detailTrunc = if ($c.Detail -and $c.Detail.Length -gt 40) { $c.Detail.Substring(0, 40) } else { $c.Detail }

        $color = switch ($c.Risk) {
            'HIGH'   { $ct.ERROR }
            'MEDIUM' { $ct.WARNING }
            'LOW'    { $ct.INFO }
            default  { $ct.INFO }
        }
        Write-Host "$color{0,-20} {1,-16} {2,-22} {3,-8} {4,-20} {5,-30} {6}$r" -f $timeStr, $c.Source, $c.Category, $c.Risk, $c.Who, $whatTrunc, $detailTrunc
    }
    Write-Host ""
}
