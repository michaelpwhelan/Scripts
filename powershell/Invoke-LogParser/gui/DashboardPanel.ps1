# ═══════════════════════════════════════════════════════════════════════════════
# DASHBOARD PANEL — Configurable widget dashboard view
# ═══════════════════════════════════════════════════════════════════════════════

$Script:DashboardWidgets = @{}

function New-WidgetGroupBox {
    param(
        [string]$Title,
        [System.Windows.Forms.Control]$Content,
        [int]$Width = 0,
        [int]$Height = 0
    )
    $grp = [System.Windows.Forms.GroupBox]::new()
    $grp.Text = $Title
    $fgColor = Get-ThemeColor 'FormFore' ([System.Drawing.Color]::FromArgb(220, 220, 220))
    $grp.ForeColor = $fgColor
    $grp.Font = [System.Drawing.Font]::new("Segoe UI", 8.5, [System.Drawing.FontStyle]::Bold)

    if ($Width -gt 0 -and $Height -gt 0) {
        $grp.Size = [System.Drawing.Size]::new($Width, $Height)
    }
    else {
        $grp.Size = [System.Drawing.Size]::new($Content.Width + 12, $Content.Height + 26)
    }

    $Content.Location = [System.Drawing.Point]::new(4, 18)
    $Content.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Bottom
    $grp.Controls.Add($Content)
    $grp.Margin = [System.Windows.Forms.Padding]::new(4)
    return $grp
}

function New-DashboardPanel {
    $outerPanel = [System.Windows.Forms.Panel]::new()
    $outerPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
    $bgColor = Get-ThemeColor 'PanelBack' ([System.Drawing.Color]::FromArgb(35, 35, 35))
    $outerPanel.BackColor = $bgColor

    $flow = [System.Windows.Forms.FlowLayoutPanel]::new()
    $flow.Dock = [System.Windows.Forms.DockStyle]::Fill
    $flow.AutoScroll = $true
    $flow.WrapContents = $true
    $flow.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
    $flow.Padding = [System.Windows.Forms.Padding]::new(6)
    $flow.BackColor = $bgColor

    $outerPanel.Controls.Add($flow)

    $Script:UI.DashboardFlow = $flow
    $Script:UI.DashboardPanel = $outerPanel

    # Placeholder label
    $placeholder = [System.Windows.Forms.Label]::new()
    $placeholder.Text = "Dashboard will populate when log data is loaded."
    $placeholder.AutoSize = $true
    $placeholder.Font = [System.Drawing.Font]::new("Segoe UI", 10)
    $placeholder.ForeColor = Get-ThemeColor 'FormFore' ([System.Drawing.Color]::FromArgb(160, 160, 160))
    $placeholder.Padding = [System.Windows.Forms.Padding]::new(20, 40, 20, 20)
    $flow.Controls.Add($placeholder)

    return $outerPanel
}

function Update-DashboardPanel {
    param([System.Collections.Generic.List[object]]$Entries)

    $flow = $Script:UI.DashboardFlow
    if (-not $flow) { return }

    # Suspend layout for batch updates
    $flow.SuspendLayout()

    # Clear existing widgets
    $controlsToDispose = [System.Collections.Generic.List[object]]::new()
    foreach ($ctrl in $flow.Controls) { $controlsToDispose.Add($ctrl) }
    $flow.Controls.Clear()
    foreach ($ctrl in $controlsToDispose) {
        try { $ctrl.Dispose() } catch { }
    }
    $Script:DashboardWidgets = @{}

    if (-not $Entries -or $Entries.Count -eq 0) {
        $noDataLabel = [System.Windows.Forms.Label]::new()
        $noDataLabel.Text = "No log data loaded. Open a file to populate the dashboard."
        $noDataLabel.AutoSize = $true
        $noDataLabel.Font = [System.Drawing.Font]::new("Segoe UI", 10)
        $noDataLabel.ForeColor = Get-ThemeColor 'FormFore' ([System.Drawing.Color]::FromArgb(160, 160, 160))
        $noDataLabel.Padding = [System.Windows.Forms.Padding]::new(20, 40, 20, 20)
        $flow.Controls.Add($noDataLabel)
        $flow.ResumeLayout($true)
        return
    }

    # Calculate available width for the flow layout
    $availWidth = $flow.ClientSize.Width - 20
    if ($availWidth -lt 400) { $availWidth = 800 }

    # ── Compute data for widgets ──────────────────────────────────────────────

    # Severity counts
    $sevCounts = @{ CRITICAL = 0; ERROR = 0; WARNING = 0; INFO = 0; DEBUG = 0; TRACE = 0; UNKNOWN = 0 }
    $sources = @{}
    $destIps = @{}
    $eventTypes = @{}

    foreach ($entry in $Entries) {
        if ($sevCounts.ContainsKey($entry.Level)) { $sevCounts[$entry.Level]++ }
        else { $sevCounts['UNKNOWN']++ }

        if ($entry.Source) {
            if ($sources.ContainsKey($entry.Source)) { $sources[$entry.Source]++ }
            else { $sources[$entry.Source] = 1 }
        }

        if ($entry.Extra) {
            if ($entry.Extra['dstip']) {
                $dst = [string]$entry.Extra['dstip']
                if ($destIps.ContainsKey($dst)) { $destIps[$dst]++ }
                else { $destIps[$dst] = 1 }
            }
            if ($entry.Extra['type']) {
                $etype = [string]$entry.Extra['type']
                if ($eventTypes.ContainsKey($etype)) { $eventTypes[$etype]++ }
                else { $eventTypes[$etype] = 1 }
            }
        }
    }

    # Sparkline: event volume over time buckets
    $sparkValues = Build-VolumeSparkline -Entries $Entries -BucketCount 40

    # ── ROW 1: Summary Section ────────────────────────────────────────────────

    # Full-width separator / row label
    $row1Label = New-SectionLabel "Summary"
    $flow.Controls.Add($row1Label)

    # Severity Donut
    $donut = New-SeverityDonutWidget -Size 200 -Counts $sevCounts
    $donutGroup = New-WidgetGroupBox -Title "Severity" -Content $donut
    $flow.Controls.Add($donutGroup)
    $Script:DashboardWidgets['Donut'] = $donut

    # Sparkline of event volume
    $sparkPanel = [System.Windows.Forms.Panel]::new()
    $sparkPanel.Size = [System.Drawing.Size]::new(310, 80)
    $sparkPanel.BackColor = Get-ThemeColor 'PanelBack' ([System.Drawing.Color]::FromArgb(35, 35, 35))

    $sparkTitle = [System.Windows.Forms.Label]::new()
    $sparkTitle.Text = "Event Volume"
    $sparkTitle.Font = [System.Drawing.Font]::new("Segoe UI", 7.5)
    $sparkTitle.ForeColor = Get-ThemeColor 'FormFore' ([System.Drawing.Color]::FromArgb(180, 180, 180))
    $sparkTitle.Location = [System.Drawing.Point]::new(4, 2)
    $sparkTitle.AutoSize = $true
    $sparkPanel.Controls.Add($sparkTitle)

    $sparkline = New-SparklineWidget -Width 300 -Height 50 -Values $sparkValues
    $sparkline.Location = [System.Drawing.Point]::new(4, 18)
    $sparkPanel.Controls.Add($sparkline)

    $countLabel = [System.Windows.Forms.Label]::new()
    $countLabel.Text = "$($Entries.Count.ToString('N0')) entries"
    $countLabel.Font = [System.Drawing.Font]::new("Segoe UI", 7)
    $countLabel.ForeColor = Get-ThemeColor 'FormFore' ([System.Drawing.Color]::FromArgb(140, 140, 140))
    $countLabel.Location = [System.Drawing.Point]::new(4, 66)
    $countLabel.AutoSize = $true
    $sparkPanel.Controls.Add($countLabel)

    $sparkGroup = New-WidgetGroupBox -Title "Volume" -Content $sparkPanel
    $flow.Controls.Add($sparkGroup)
    $Script:DashboardWidgets['Sparkline'] = $sparkline

    # Anomaly traffic light (if baseline is available)
    $anomalyStatus = "GREEN"
    $anomalyLabel = "Status"
    $baselineAvailable = $false
    try {
        $baselines = Get-BaselineList
        if ($baselines -and @($baselines).Count -gt 0) {
            $baselineAvailable = $true
            $anomalyResult = Get-AnomalyDetection -Entries $Entries
            if ($anomalyResult -and $anomalyResult.Summary) {
                $critAnomalies = $anomalyResult.Summary.Critical
                $highAnomalies = $anomalyResult.Summary.High
                if ($critAnomalies -gt 0) {
                    $anomalyStatus = "RED"
                    $anomalyLabel = "$critAnomalies critical"
                }
                elseif ($highAnomalies -gt 0) {
                    $anomalyStatus = "YELLOW"
                    $anomalyLabel = "$highAnomalies high"
                }
                else {
                    $anomalyStatus = "GREEN"
                    $anomalyLabel = "Normal"
                }
            }
        }
    } catch { }

    if ($baselineAvailable) {
        $trafficLight = New-AnomalyIndicatorWidget -Width 80 -Height 190 -Status $anomalyStatus -Label $anomalyLabel
        $tlGroup = New-WidgetGroupBox -Title "Anomaly" -Content $trafficLight
        $flow.Controls.Add($tlGroup)
        $Script:DashboardWidgets['TrafficLight'] = $trafficLight
    }

    # ── ROW 2: Timeline ──────────────────────────────────────────────────────

    $row2Label = New-SectionLabel "Timeline"
    $flow.Controls.Add($row2Label)

    $timelineWidth = [Math]::Max(600, $availWidth - 20)
    $timeline = New-TimelineWidget -Width $timelineWidth -Height 150 -Entries $Entries
    $timelineGroup = New-WidgetGroupBox -Title "Event Timeline" -Content $timeline -Width ($timelineWidth + 12) -Height 176
    $flow.Controls.Add($timelineGroup)
    $Script:DashboardWidgets['Timeline'] = $timeline

    # ── ROW 3: Details ────────────────────────────────────────────────────────

    $row3Label = New-SectionLabel "Analysis"
    $flow.Controls.Add($row3Label)

    # Top Sources bar chart
    $sourceData = @()
    $topSources = $sources.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
    foreach ($s in $topSources) {
        $sourceData += @{ Label = $s.Key; Value = [int]$s.Value }
    }
    $sourceChart = New-BarChartWidget -Width 400 -Height 250 -Data $sourceData -Title "Top Sources" -MaxBars 10
    $sourceGroup = New-WidgetGroupBox -Title "Top Sources" -Content $sourceChart
    $flow.Controls.Add($sourceGroup)
    $Script:DashboardWidgets['TopSources'] = $sourceChart

    # Heatmap
    $heatmap = New-HeatmapWidget -Width 500 -Height 200 -Entries $Entries
    $heatmapGroup = New-WidgetGroupBox -Title "Activity Heatmap" -Content $heatmap
    $flow.Controls.Add($heatmapGroup)
    $Script:DashboardWidgets['Heatmap'] = $heatmap

    # ── ROW 4: Network (if topology available) ────────────────────────────────

    $hasTopology = ($null -ne $Script:Topology -and $null -ne $Script:Topology.sites)

    if ($hasTopology) {
        $row4Label = New-SectionLabel "Network"
        $flow.Controls.Add($row4Label)

        $siteHealth = Get-SiteHealthFromEntries -Entries $Entries
        $siteMap = New-SiteMapWidget -Width 600 -Height 350 -SiteHealth $siteHealth
        $siteMapGroup = New-WidgetGroupBox -Title "Site Health Map" -Content $siteMap
        $flow.Controls.Add($siteMapGroup)
        $Script:DashboardWidgets['SiteMap'] = $siteMap
    }

    # Event type or destination bar chart
    $secondBarData = @()
    $secondBarTitle = ""
    if ($destIps.Count -gt 0) {
        $secondBarTitle = "Top Destinations"
        $topDest = $destIps.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
        foreach ($d in $topDest) {
            $secondBarData += @{ Label = $d.Key; Value = [int]$d.Value }
        }
    }
    elseif ($eventTypes.Count -gt 0) {
        $secondBarTitle = "Event Types"
        $topTypes = $eventTypes.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
        foreach ($t in $topTypes) {
            $secondBarData += @{ Label = $t.Key; Value = [int]$t.Value }
        }
    }
    if ($secondBarData.Count -gt 0) {
        $secondChart = New-BarChartWidget -Width 400 -Height 250 -Data $secondBarData -Title $secondBarTitle -MaxBars 10
        $secondGroup = New-WidgetGroupBox -Title $secondBarTitle -Content $secondChart
        $flow.Controls.Add($secondGroup)
        $Script:DashboardWidgets['SecondBar'] = $secondChart
    }

    $flow.ResumeLayout($true)
}

function New-SectionLabel {
    param([string]$Text)
    $lbl = [System.Windows.Forms.Label]::new()
    $lbl.Text = $Text
    $lbl.Font = [System.Drawing.Font]::new("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $lbl.ForeColor = Get-ThemeColor 'FormFore' ([System.Drawing.Color]::FromArgb(200, 200, 200))
    $lbl.AutoSize = $false
    $lbl.Size = [System.Drawing.Size]::new(2000, 22)
    $lbl.Padding = [System.Windows.Forms.Padding]::new(2, 4, 0, 0)
    $lbl.Margin = [System.Windows.Forms.Padding]::new(0, 2, 0, 0)
    # Draw underline
    $lbl.Add_Paint({
        param($sender, $e)
        $lineColor = Get-ThemeColor 'GridLines' ([System.Drawing.Color]::FromArgb(70, 70, 70))
        $pen = [System.Drawing.Pen]::new($lineColor, 1)
        $e.Graphics.DrawLine($pen, 0, $sender.Height - 1, $sender.Width, $sender.Height - 1)
        $pen.Dispose()
    })
    return $lbl
}

function Build-VolumeSparkline {
    param(
        [System.Collections.Generic.List[object]]$Entries,
        [int]$BucketCount = 40
    )

    if (-not $Entries -or $Entries.Count -eq 0) { return @() }

    # Find time range
    $minTime = [datetime]::MaxValue
    $maxTime = [datetime]::MinValue
    $hasTimestamp = $false
    foreach ($entry in $Entries) {
        if ($entry.Timestamp -ne [datetime]::MinValue) {
            $hasTimestamp = $true
            if ($entry.Timestamp -lt $minTime) { $minTime = $entry.Timestamp }
            if ($entry.Timestamp -gt $maxTime) { $maxTime = $entry.Timestamp }
        }
    }

    if (-not $hasTimestamp) { return @() }

    $totalSpan = ($maxTime - $minTime).TotalSeconds
    if ($totalSpan -lt 1) { return @(,$Entries.Count) }

    $buckets = [int[]]::new($BucketCount)
    $bucketSpan = $totalSpan / $BucketCount

    foreach ($entry in $Entries) {
        if ($entry.Timestamp -eq [datetime]::MinValue) { continue }
        $sec = ($entry.Timestamp - $minTime).TotalSeconds
        $bi = [Math]::Min($BucketCount - 1, [Math]::Max(0, [int]([Math]::Floor($sec / $bucketSpan))))
        $buckets[$bi]++
    }

    return $buckets
}

# ═══════════════════════════════════════════════════════════════════════════════
# DASHBOARD TAB MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

function Show-DashboardTab {
    $form = $Script:UI.Form
    if (-not $form) { return }

    # Look for existing TabControl, or find where to place dashboard
    $tabControl = $Script:UI.DashboardTabControl

    if (-not $tabControl) {
        # Create a TabControl to hold existing grid view + dashboard
        $tabControl = [System.Windows.Forms.TabControl]::new()
        $tabControl.Dock = [System.Windows.Forms.DockStyle]::Fill
        $tabControl.Font = [System.Drawing.Font]::new("Segoe UI", 8.5)

        $bgColor = Get-ThemeColor 'PanelBack' ([System.Drawing.Color]::FromArgb(35, 35, 35))
        $fgColor = Get-ThemeColor 'FormFore' ([System.Drawing.Color]::FromArgb(220, 220, 220))

        # Create "Log View" tab with existing content
        $logTab = [System.Windows.Forms.TabPage]::new("Log View")
        $logTab.BackColor = $bgColor
        $logTab.ForeColor = $fgColor

        # Move existing InnerSplit (grid + detail) into the Log View tab
        $innerSplit = $Script:UI.InnerSplit
        $outerSplit = $Script:UI.OuterSplit
        if ($innerSplit -and $outerSplit) {
            $outerSplit.Panel2.Controls.Remove($innerSplit)
            $innerSplit.Dock = [System.Windows.Forms.DockStyle]::Fill
            $logTab.Controls.Add($innerSplit)
        }

        $tabControl.TabPages.Add($logTab)

        # Create "Dashboard" tab
        $dashTab = [System.Windows.Forms.TabPage]::new("Dashboard")
        $dashTab.BackColor = $bgColor
        $dashTab.ForeColor = $fgColor
        $Script:UI.DashboardTab = $dashTab

        $dashPanel = New-DashboardPanel
        $dashTab.Controls.Add($dashPanel)

        $tabControl.TabPages.Add($dashTab)

        # Place tab control where InnerSplit was
        if ($outerSplit) {
            $outerSplit.Panel2.Controls.Add($tabControl)
        }
        else {
            $form.Controls.Add($tabControl)
            $tabControl.BringToFront()
        }

        $Script:UI.DashboardTabControl = $tabControl
        $Script:UI.LogViewTab = $logTab
    }

    # Switch to dashboard tab
    $dashIdx = -1
    for ($i = 0; $i -lt $tabControl.TabPages.Count; $i++) {
        if ($tabControl.TabPages[$i].Text -eq "Dashboard") {
            $dashIdx = $i
            break
        }
    }
    if ($dashIdx -ge 0) {
        $tabControl.SelectedIndex = $dashIdx
    }

    # Update with current data
    $entries = if ($Script:State.FilteredEntries -and $Script:State.FilteredEntries.Count -gt 0) {
        $Script:State.FilteredEntries
    }
    elseif ($Script:State.AllEntries -and $Script:State.AllEntries.Count -gt 0) {
        $Script:State.AllEntries
    }
    else { $null }

    Update-DashboardPanel -Entries $entries
}

function Hide-DashboardTab {
    $tabControl = $Script:UI.DashboardTabControl
    if (-not $tabControl) { return }

    # Switch to log view tab
    for ($i = 0; $i -lt $tabControl.TabPages.Count; $i++) {
        if ($tabControl.TabPages[$i].Text -eq "Log View") {
            $tabControl.SelectedIndex = $i
            break
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# DASHBOARD PRESETS
# ═══════════════════════════════════════════════════════════════════════════════

function Get-DashboardPreset {
    param([string]$PresetName)

    switch ($PresetName) {
        "SecurityOverview" {
            return @{
                Name = "Security Overview"
                Description = "Security-focused dashboard with severity distribution, anomaly detection, and threat timeline."
                Widgets = @(
                    @{ Type = "SeverityDonut";     Size = 200;  Title = "Severity" }
                    @{ Type = "AnomalyIndicator";  Width = 80;  Height = 190; Title = "Anomaly Status" }
                    @{ Type = "Timeline";          Width = 800; Height = 150; Title = "Event Timeline" }
                    @{ Type = "BarChart";           Width = 400; Height = 250; Title = "Top Sources"; DataSource = "Sources"; MaxBars = 10 }
                    @{ Type = "Heatmap";            Width = 500; Height = 200; Title = "Activity Heatmap" }
                )
            }
        }
        "NetworkHealth" {
            return @{
                Name = "Network Health"
                Description = "Network-focused dashboard with site health map, tunnel status, and BGP state."
                Widgets = @(
                    @{ Type = "SiteMap";           Width = 600; Height = 350; Title = "Site Health Map" }
                    @{ Type = "AnomalyIndicator";  Width = 80;  Height = 190; Title = "Network Status" }
                    @{ Type = "Timeline";          Width = 800; Height = 150; Title = "Network Event Timeline" }
                    @{ Type = "BarChart";           Width = 400; Height = 250; Title = "Top Destinations"; DataSource = "Destinations"; MaxBars = 10 }
                    @{ Type = "Sparkline";          Width = 300; Height = 50;  Title = "Event Volume" }
                )
            }
        }
        "ComplianceStatus" {
            return @{
                Name = "Compliance Status"
                Description = "Compliance-focused dashboard with severity breakdown and audit trail visibility."
                Widgets = @(
                    @{ Type = "SeverityDonut";     Size = 200;  Title = "Severity Distribution" }
                    @{ Type = "Sparkline";          Width = 300; Height = 50;  Title = "Event Volume" }
                    @{ Type = "Timeline";          Width = 800; Height = 150; Title = "Audit Event Timeline" }
                    @{ Type = "BarChart";           Width = 400; Height = 250; Title = "Top Sources"; DataSource = "Sources"; MaxBars = 10 }
                    @{ Type = "BarChart";           Width = 400; Height = 250; Title = "Event Types"; DataSource = "EventTypes"; MaxBars = 10 }
                    @{ Type = "Heatmap";            Width = 500; Height = 200; Title = "Activity Heatmap" }
                )
            }
        }
        default {
            return $null
        }
    }
}

function Apply-DashboardPreset {
    param(
        [string]$PresetName,
        [System.Collections.Generic.List[object]]$Entries
    )

    $preset = Get-DashboardPreset -PresetName $PresetName
    if (-not $preset) {
        if ($Script:UI.StatusLabel) {
            Update-StatusBar "Unknown dashboard preset: $PresetName" -IsError
        }
        return
    }

    $flow = $Script:UI.DashboardFlow
    if (-not $flow) { return }

    $flow.SuspendLayout()

    # Clear existing
    $controlsToDispose = [System.Collections.Generic.List[object]]::new()
    foreach ($ctrl in $flow.Controls) { $controlsToDispose.Add($ctrl) }
    $flow.Controls.Clear()
    foreach ($ctrl in $controlsToDispose) {
        try { $ctrl.Dispose() } catch { }
    }
    $Script:DashboardWidgets = @{}

    if (-not $Entries -or $Entries.Count -eq 0) {
        $noDataLabel = [System.Windows.Forms.Label]::new()
        $noDataLabel.Text = "No log data loaded for preset '$($preset.Name)'."
        $noDataLabel.AutoSize = $true
        $noDataLabel.Font = [System.Drawing.Font]::new("Segoe UI", 10)
        $noDataLabel.ForeColor = Get-ThemeColor 'FormFore' ([System.Drawing.Color]::FromArgb(160, 160, 160))
        $noDataLabel.Padding = [System.Windows.Forms.Padding]::new(20, 40, 20, 20)
        $flow.Controls.Add($noDataLabel)
        $flow.ResumeLayout($true)
        return
    }

    # Precompute data
    $sevCounts = @{ CRITICAL = 0; ERROR = 0; WARNING = 0; INFO = 0; DEBUG = 0; TRACE = 0; UNKNOWN = 0 }
    $sources = @{}; $destIps = @{}; $eventTypes = @{}

    foreach ($entry in $Entries) {
        if ($sevCounts.ContainsKey($entry.Level)) { $sevCounts[$entry.Level]++ }
        else { $sevCounts['UNKNOWN']++ }

        if ($entry.Source) {
            if ($sources.ContainsKey($entry.Source)) { $sources[$entry.Source]++ }
            else { $sources[$entry.Source] = 1 }
        }
        if ($entry.Extra) {
            if ($entry.Extra['dstip']) {
                $dst = [string]$entry.Extra['dstip']
                if ($destIps.ContainsKey($dst)) { $destIps[$dst]++ }
                else { $destIps[$dst] = 1 }
            }
            if ($entry.Extra['type']) {
                $etype = [string]$entry.Extra['type']
                if ($eventTypes.ContainsKey($etype)) { $eventTypes[$etype]++ }
                else { $eventTypes[$etype] = 1 }
            }
        }
    }

    # Preset title
    $presetLabel = New-SectionLabel $preset.Name
    $flow.Controls.Add($presetLabel)

    $widgetIdx = 0
    foreach ($wSpec in $preset.Widgets) {
        $widgetIdx++
        $wTitle = if ($wSpec.Title) { $wSpec.Title } else { $wSpec.Type }

        switch ($wSpec.Type) {
            "SeverityDonut" {
                $size = if ($wSpec.Size) { $wSpec.Size } else { 200 }
                $widget = New-SeverityDonutWidget -Size $size -Counts $sevCounts
                $grp = New-WidgetGroupBox -Title $wTitle -Content $widget
                $flow.Controls.Add($grp)
                $Script:DashboardWidgets["Preset_Donut_$widgetIdx"] = $widget
            }
            "AnomalyIndicator" {
                $aWidth = if ($wSpec.Width) { $wSpec.Width } else { 80 }
                $aHeight = if ($wSpec.Height) { $wSpec.Height } else { 190 }
                $aStatus = "GREEN"; $aLabel = "Status"
                try {
                    $baselines = Get-BaselineList
                    if ($baselines -and @($baselines).Count -gt 0) {
                        $anomalyResult = Get-AnomalyDetection -Entries $Entries
                        if ($anomalyResult -and $anomalyResult.Summary) {
                            if ($anomalyResult.Summary.Critical -gt 0) {
                                $aStatus = "RED"; $aLabel = "$($anomalyResult.Summary.Critical) critical"
                            }
                            elseif ($anomalyResult.Summary.High -gt 0) {
                                $aStatus = "YELLOW"; $aLabel = "$($anomalyResult.Summary.High) high"
                            }
                            else { $aStatus = "GREEN"; $aLabel = "Normal" }
                        }
                    }
                    else { $aStatus = "GREEN"; $aLabel = "No baseline" }
                } catch { $aStatus = "GREEN"; $aLabel = "N/A" }
                $widget = New-AnomalyIndicatorWidget -Width $aWidth -Height $aHeight -Status $aStatus -Label $aLabel
                $grp = New-WidgetGroupBox -Title $wTitle -Content $widget
                $flow.Controls.Add($grp)
                $Script:DashboardWidgets["Preset_Anomaly_$widgetIdx"] = $widget
            }
            "Timeline" {
                $tWidth = if ($wSpec.Width) { $wSpec.Width } else { 800 }
                $tHeight = if ($wSpec.Height) { $wSpec.Height } else { 150 }
                $widget = New-TimelineWidget -Width $tWidth -Height $tHeight -Entries $Entries
                $grp = New-WidgetGroupBox -Title $wTitle -Content $widget -Width ($tWidth + 12) -Height ($tHeight + 26)
                $flow.Controls.Add($grp)
                $Script:DashboardWidgets["Preset_Timeline_$widgetIdx"] = $widget
            }
            "BarChart" {
                $bWidth = if ($wSpec.Width) { $wSpec.Width } else { 400 }
                $bHeight = if ($wSpec.Height) { $wSpec.Height } else { 250 }
                $bMax = if ($wSpec.MaxBars) { $wSpec.MaxBars } else { 10 }
                $barData = @()
                switch ($wSpec.DataSource) {
                    "Sources" {
                        $topItems = $sources.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $bMax
                        foreach ($item in $topItems) { $barData += @{ Label = $item.Key; Value = [int]$item.Value } }
                    }
                    "Destinations" {
                        $topItems = $destIps.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $bMax
                        foreach ($item in $topItems) { $barData += @{ Label = $item.Key; Value = [int]$item.Value } }
                    }
                    "EventTypes" {
                        $topItems = $eventTypes.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $bMax
                        foreach ($item in $topItems) { $barData += @{ Label = $item.Key; Value = [int]$item.Value } }
                    }
                    default {
                        $topItems = $sources.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $bMax
                        foreach ($item in $topItems) { $barData += @{ Label = $item.Key; Value = [int]$item.Value } }
                    }
                }
                $widget = New-BarChartWidget -Width $bWidth -Height $bHeight -Data $barData -Title $wTitle -MaxBars $bMax
                $grp = New-WidgetGroupBox -Title $wTitle -Content $widget
                $flow.Controls.Add($grp)
                $Script:DashboardWidgets["Preset_Bar_$widgetIdx"] = $widget
            }
            "Heatmap" {
                $hmWidth = if ($wSpec.Width) { $wSpec.Width } else { 500 }
                $hmHeight = if ($wSpec.Height) { $wSpec.Height } else { 200 }
                $widget = New-HeatmapWidget -Width $hmWidth -Height $hmHeight -Entries $Entries
                $grp = New-WidgetGroupBox -Title $wTitle -Content $widget
                $flow.Controls.Add($grp)
                $Script:DashboardWidgets["Preset_Heatmap_$widgetIdx"] = $widget
            }
            "SiteMap" {
                $smWidth = if ($wSpec.Width) { $wSpec.Width } else { 600 }
                $smHeight = if ($wSpec.Height) { $wSpec.Height } else { 350 }
                $siteHealth = @{}
                try { $siteHealth = Get-SiteHealthFromEntries -Entries $Entries } catch { }
                $widget = New-SiteMapWidget -Width $smWidth -Height $smHeight -SiteHealth $siteHealth
                $grp = New-WidgetGroupBox -Title $wTitle -Content $widget
                $flow.Controls.Add($grp)
                $Script:DashboardWidgets["Preset_SiteMap_$widgetIdx"] = $widget
            }
            "Sparkline" {
                $slWidth = if ($wSpec.Width) { $wSpec.Width } else { 300 }
                $slHeight = if ($wSpec.Height) { $wSpec.Height } else { 50 }
                $sparkVals = Build-VolumeSparkline -Entries $Entries -BucketCount 40
                $widget = New-SparklineWidget -Width $slWidth -Height $slHeight -Values $sparkVals
                $grp = New-WidgetGroupBox -Title $wTitle -Content $widget
                $flow.Controls.Add($grp)
                $Script:DashboardWidgets["Preset_Sparkline_$widgetIdx"] = $widget
            }
        }
    }

    $flow.ResumeLayout($true)

    if ($Script:UI.StatusLabel) {
        Update-StatusBar "Dashboard preset '$($preset.Name)' applied"
    }
}
