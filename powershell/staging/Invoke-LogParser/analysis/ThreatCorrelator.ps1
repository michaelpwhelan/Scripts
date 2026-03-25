function Get-ThreatCorrelation {
    param([System.Collections.Generic.List[object]]$Entries)

    $entities = @{}
    $threatEvents = [System.Collections.Generic.List[object]]::new()
    $failedLoginCounts = @{}

    # Weights for threat scoring
    $weights = @{
        DefenderAlert = 10
        IpsDeny       = 5
        UtmBlock      = 3
        FailedLogin   = 2
        IocMatch      = 15
    }

    # First pass: count failed logins per user for brute force detection
    foreach ($entry in $Entries) {
        if (-not $entry.Extra) { continue }
        $eventId = $entry.Extra['EventID'] -as [int]
        if ($eventId -eq 4625 -or $entry.Extra['PacketTypeName'] -eq 'Access-Reject' -or
            ($entry.Extra['action'] -match 'deny|fail' -and $entry.Extra['subtype'] -match 'user|auth')) {
            $user = $entry.Extra['TargetUserName']
            if (-not $user) { $user = $entry.Extra['User-Name'] }
            if (-not $user) { $user = $entry.Extra['user'] }
            if ($user) {
                $userKey = $user.ToLower()
                if (-not $failedLoginCounts.ContainsKey($userKey)) { $failedLoginCounts[$userKey] = 0 }
                $failedLoginCounts[$userKey]++
            }
        }
    }

    # Second pass: identify all threat indicators
    foreach ($entry in $Entries) {
        if (-not $entry.Extra) { continue }

        $threatType = $null
        $threatDetail = $null
        $score = 0
        $entityId = $null
        $entityType = $null
        $sourceFormat = $entry.Extra['SourceFormat']

        # Defender alerts
        if ($sourceFormat -eq 'defender-alerts' -or ($entry.Extra['AlertTitle'] -and $entry.Extra['Severity'])) {
            $threatType = "Defender Alert"
            $threatDetail = $entry.Extra['AlertTitle']
            if (-not $threatDetail) { $threatDetail = $entry.Extra['Title'] }
            if (-not $threatDetail) { $threatDetail = $entry.Message }
            $score = $weights.DefenderAlert

            $entityId = $entry.Extra['ComputerDnsName']
            if (-not $entityId) { $entityId = $entry.Extra['DeviceName'] }
            if (-not $entityId) { $entityId = $entry.Host }
            $entityType = "Host"

            # Check if there's a user entity too
            $defUser = $entry.Extra['AccountName']
            if (-not $defUser) { $defUser = $entry.Extra['UserPrincipalName'] }
            if ($defUser) {
                $userEntityKey = "user:$($defUser.ToLower())"
                if (-not $entities.ContainsKey($userEntityKey)) {
                    $entities[$userEntityKey] = @{
                        EntityId    = $defUser
                        EntityType  = "User"
                        ThreatScore = 0
                        Indicators  = [System.Collections.Generic.List[string]]::new()
                        Sources     = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                        TopThreat   = $null
                        Events      = [System.Collections.Generic.List[object]]::new()
                    }
                }
                $entities[$userEntityKey].ThreatScore += $score
                $entities[$userEntityKey].Indicators.Add($threatType)
                if ($sourceFormat) { $entities[$userEntityKey].Sources.Add($sourceFormat) | Out-Null }
                if (-not $entities[$userEntityKey].TopThreat) { $entities[$userEntityKey].TopThreat = $threatDetail }
            }
        }

        # FortiGate UTM events with deny/block
        if (-not $threatType -and $entry.Extra['type'] -eq 'utm' -and $entry.Extra['action'] -match 'deny|block|dropped') {
            $utmSubtype = $entry.Extra['subtype']
            if ($utmSubtype -eq 'ips') {
                $threatType = "IPS Deny"
                $score = $weights.IpsDeny
            } else {
                $threatType = "UTM Block"
                $score = $weights.UtmBlock
            }
            $threatDetail = $entry.Extra['attack']
            if (-not $threatDetail) { $threatDetail = $entry.Extra['msg'] }
            if (-not $threatDetail) { $threatDetail = $entry.Message }

            $entityId = $entry.Extra['srcip']
            if (-not $entityId) { $entityId = $entry.Extra['dstip'] }
            $entityType = "IP"
        }

        # IPS events (type=utm, subtype=ips)
        if (-not $threatType -and $entry.Extra['type'] -eq 'utm' -and $entry.Extra['subtype'] -eq 'ips') {
            $threatType = "IPS Event"
            $score = $weights.IpsDeny
            $threatDetail = $entry.Extra['attack']
            if (-not $threatDetail) { $threatDetail = $entry.Extra['msg'] }
            if (-not $threatDetail) { $threatDetail = $entry.Message }

            $entityId = $entry.Extra['srcip']
            $entityType = "IP"
        }

        # Brute force indicators (users with >5 failed logins)
        if (-not $threatType) {
            $user = $entry.Extra['TargetUserName']
            if (-not $user) { $user = $entry.Extra['User-Name'] }
            if (-not $user) { $user = $entry.Extra['user'] }

            $eventId = $entry.Extra['EventID'] -as [int]
            $isFailedLogin = ($eventId -eq 4625 -or $entry.Extra['PacketTypeName'] -eq 'Access-Reject' -or
                ($entry.Extra['action'] -match 'deny|fail' -and $entry.Extra['subtype'] -match 'user|auth'))

            if ($isFailedLogin -and $user) {
                $userKey = $user.ToLower()
                if ($failedLoginCounts.ContainsKey($userKey) -and $failedLoginCounts[$userKey] -gt 5) {
                    $threatType = "Brute Force"
                    $score = $weights.FailedLogin
                    $threatDetail = "Failed login ($($failedLoginCounts[$userKey]) attempts)"
                    $entityId = $user
                    $entityType = "User"
                }
            }
        }

        # IOC matches
        if (-not $threatType -and $entry.Extra['IocMatch'] -eq $true) {
            $threatType = "IOC Match"
            $score = $weights.IocMatch
            $threatDetail = "Matched IOC: $($entry.Extra['IocMatchedValue'])"
            if ($entry.Extra['IocDescription']) { $threatDetail += " ($($entry.Extra['IocDescription']))" }

            $entityId = $entry.Extra['srcip']
            if (-not $entityId) { $entityId = $entry.Extra['dstip'] }
            if (-not $entityId) { $entityId = $entry.Host }
            $entityType = "IP"
        }

        if (-not $threatType -or -not $entityId) { continue }

        # Build entity key
        $entityKey = "$($entityType.ToLower()):$($entityId.ToLower())"

        if (-not $entities.ContainsKey($entityKey)) {
            $entities[$entityKey] = @{
                EntityId    = $entityId
                EntityType  = $entityType
                ThreatScore = 0
                Indicators  = [System.Collections.Generic.List[string]]::new()
                Sources     = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                TopThreat   = $null
                Events      = [System.Collections.Generic.List[object]]::new()
            }
        }

        $entity = $entities[$entityKey]
        $entity.ThreatScore += $score
        $entity.Indicators.Add($threatType)
        if ($sourceFormat) { $entity.Sources.Add($sourceFormat) | Out-Null }
        if (-not $entity.TopThreat -or $score -gt $weights.FailedLogin) {
            $entity.TopThreat = $threatDetail
        }
        $entity.Events.Add(@{
            Timestamp   = $entry.Timestamp
            ThreatType  = $threatType
            Detail      = $threatDetail
            Score       = $score
            Source      = $sourceFormat
        })

        $threatEvents.Add(@{
            Timestamp  = $entry.Timestamp
            EntityId   = $entityId
            EntityType = $entityType
            ThreatType = $threatType
            Detail     = $threatDetail
            Score      = $score
            Source     = $sourceFormat
        })
    }

    # Multi-source correlation bonus: if entity appears across multiple threat categories, boost score
    foreach ($entityKey in $entities.Keys) {
        $entity = $entities[$entityKey]
        $uniqueIndicatorTypes = $entity.Indicators | Select-Object -Unique
        if (@($uniqueIndicatorTypes).Count -gt 1) {
            $bonus = (@($uniqueIndicatorTypes).Count - 1) * 5
            $entity.ThreatScore += $bonus
        }
    }

    # Classify risk levels
    $highRisk = 0; $mediumRisk = 0; $lowRisk = 0
    foreach ($entityKey in $entities.Keys) {
        $s = $entities[$entityKey].ThreatScore
        if ($s -ge 20) { $highRisk++ }
        elseif ($s -ge 10) { $mediumRisk++ }
        else { $lowRisk++ }
    }

    # Sort threat events by score descending
    $sortedEvents = $threatEvents | Sort-Object { $_.Score } -Descending

    return @{
        Entities     = $entities
        ThreatEvents = @($sortedEvents)
        Summary      = @{
            TotalIndicators = $threatEvents.Count
            UniqueEntities  = $entities.Count
            HighRisk        = $highRisk
            MediumRisk      = $mediumRisk
            LowRisk         = $lowRisk
        }
    }
}

function Show-ThreatCorrelationDialog {
    param($Results)
    if (-not $Results -or $Results.Summary.UniqueEntities -eq 0) {
        if (-not $Script:UseConsole) {
            [System.Windows.Forms.MessageBox]::Show("No threat indicators found.", "Threat Correlation")
        }
        return
    }

    if ($Script:UseConsole) {
        Write-ThreatCorrelationTable -Results $Results
        return
    }

    $dlg = [System.Windows.Forms.Form]::new()
    $dlg.Text = "Threat Correlation Analysis"; $dlg.Size = [System.Drawing.Size]::new(1000, 600); $dlg.StartPosition = "CenterParent"
    $t = $Script:Themes[$Script:State.ActiveTheme]
    $dlg.BackColor = $t.FormBack; $dlg.ForeColor = $t.FormFore

    $grid = [System.Windows.Forms.DataGridView]::new()
    $grid.Dock = "Fill"; $grid.ReadOnly = $true; $grid.AllowUserToAddRows = $false
    $grid.BackgroundColor = $t.GridBack; $grid.DefaultCellStyle.BackColor = $t.GridBack; $grid.DefaultCellStyle.ForeColor = $t.FormFore
    $grid.ColumnHeadersDefaultCellStyle.BackColor = $t.GridBack; $grid.ColumnHeadersDefaultCellStyle.ForeColor = $t.FormFore
    $grid.EnableHeadersVisualStyles = $false
    $grid.Columns.Add("Entity", "Entity") | Out-Null
    $grid.Columns.Add("Type", "Type") | Out-Null
    $grid.Columns.Add("ThreatScore", "Threat Score") | Out-Null
    $grid.Columns.Add("Indicators", "Indicators") | Out-Null
    $grid.Columns.Add("Sources", "Sources") | Out-Null
    $grid.Columns.Add("TopThreat", "Top Threat") | Out-Null

    # Sort entities by threat score descending
    $sortedEntities = $Results.Entities.Values | Sort-Object { $_.ThreatScore } -Descending

    foreach ($entity in $sortedEntities) {
        $indicatorSummary = ($entity.Indicators | Group-Object | ForEach-Object { "$($_.Name)($($_.Count))" }) -join ", "
        $sourcesSummary = $entity.Sources -join ", "
        $topThreat = if ($entity.TopThreat) {
            if ($entity.TopThreat.Length -gt 60) { $entity.TopThreat.Substring(0, 60) + "..." } else { $entity.TopThreat }
        } else { "" }

        $rowIdx = $grid.Rows.Add($entity.EntityId, $entity.EntityType, $entity.ThreatScore, $indicatorSummary, $sourcesSummary, $topThreat)

        if ($entity.ThreatScore -ge 20) {
            $grid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Red
        } elseif ($entity.ThreatScore -ge 10) {
            $grid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::OrangeRed
        } elseif ($entity.ThreatScore -ge 5) {
            $grid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Orange
        }
    }
    $grid.AutoResizeColumns()

    $dlg.Controls.Add($grid)
    $dlg.ShowDialog($Script:UI.Form) | Out-Null
    $dlg.Dispose()
}

function Write-ThreatCorrelationTable {
    param($Results)
    $r = $Script:ANSIReset
    $ct = $Script:ConsoleThemes[$Script:State.ActiveTheme]

    Write-Host "`n$($ct.Title)Threat Correlation Analysis$r"
    Write-Host "$($ct.INFO)  Indicators: $($Results.Summary.TotalIndicators)  |  Entities: $($Results.Summary.UniqueEntities)  |  High: $($Results.Summary.HighRisk)  |  Medium: $($Results.Summary.MediumRisk)  |  Low: $($Results.Summary.LowRisk)$r"
    Write-Host ""

    Write-Host "$($ct.Header){0,-25} {1,-8} {2,-12} {3,-35} {4,-25} {5}$r" -f "Entity", "Type", "Score", "Indicators", "Sources", "Top Threat"
    Write-Host "$($ct.Border)$([string][char]0x2500 * 130)$r"

    $sortedEntities = $Results.Entities.Values | Sort-Object { $_.ThreatScore } -Descending

    foreach ($entity in $sortedEntities) {
        $indicatorSummary = ($entity.Indicators | Group-Object | ForEach-Object { "$($_.Name)($($_.Count))" }) -join ", "
        if ($indicatorSummary.Length -gt 33) { $indicatorSummary = $indicatorSummary.Substring(0, 33) }
        $sourcesSummary = $entity.Sources -join ", "
        if ($sourcesSummary.Length -gt 23) { $sourcesSummary = $sourcesSummary.Substring(0, 23) }
        $topThreat = if ($entity.TopThreat) {
            if ($entity.TopThreat.Length -gt 40) { $entity.TopThreat.Substring(0, 40) } else { $entity.TopThreat }
        } else { "" }

        $color = if ($entity.ThreatScore -ge 20) { $ct.ERROR }
                 elseif ($entity.ThreatScore -ge 10) { $ct.WARNING }
                 else { $ct.INFO }
        Write-Host "$color{0,-25} {1,-8} {2,-12} {3,-35} {4,-25} {5}$r" -f $entity.EntityId, $entity.EntityType, $entity.ThreatScore, $indicatorSummary, $sourcesSummary, $topThreat
    }
    Write-Host ""
}
