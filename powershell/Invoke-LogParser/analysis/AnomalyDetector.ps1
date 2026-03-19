# ═══════════════════════════════════════════════════════════════════════════════
# ANOMALY DETECTOR — Detect deviations from behavioral baselines
# ═══════════════════════════════════════════════════════════════════════════════

function Get-AnomalyDetection {
    param(
        [System.Collections.Generic.List[object]]$Entries,
        [string]$BaselineName = ""
    )

    if (-not $Entries -or $Entries.Count -eq 0) {
        Write-Log "Anomaly detection: no entries provided" -Level WARNING
        return @{
            Anomalies    = @()
            Summary      = @{ Total = 0; Critical = 0; High = 0; Medium = 0; Low = 0 }
            BaselineName = ""
            BaselineDate = $null
        }
    }

    try {
        # If no baseline name specified, find the most recent one
        if ([string]::IsNullOrWhiteSpace($BaselineName)) {
            $baselines = Get-BaselineList
            if (-not $baselines -or @($baselines).Count -eq 0) {
                Write-Log "Anomaly detection: no baselines available. Build a baseline first using Build-Baseline." -Level WARNING
                return @{
                    Anomalies    = @()
                    Summary      = @{ Total = 0; Critical = 0; High = 0; Medium = 0; Low = 0 }
                    BaselineName = ""
                    BaselineDate = $null
                    Message      = "No baseline profiles found. Build a baseline from historical data first."
                }
            }

            # Pick the most recently created baseline
            $sorted = $baselines | Sort-Object { $_.CreatedAt } -Descending
            $BaselineName = $sorted[0].Name
            Write-Log "Anomaly detection: using most recent baseline '$BaselineName'"
        }

        # Load the baseline to get metadata
        $baseline = Load-BaselineProfile -Name $BaselineName
        if (-not $baseline) {
            Write-Log "Anomaly detection: baseline '$BaselineName' could not be loaded" -Level ERROR
            return @{
                Anomalies    = @()
                Summary      = @{ Total = 0; Critical = 0; High = 0; Medium = 0; Low = 0 }
                BaselineName = $BaselineName
                BaselineDate = $null
                Message      = "Failed to load baseline '$BaselineName'."
            }
        }

        # Run comparison
        $anomalies = Compare-Baseline -Entries $Entries -BaselineName $BaselineName

        # Sort anomalies by severity (Critical first) then by absolute deviation descending
        $severityOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3 }
        $sortedAnomalies = $anomalies | Sort-Object {
            $so = $severityOrder[$_.Severity]
            if ($null -eq $so) { $so = 99 }
            $so
        }, { [Math]::Abs($_.Deviation) } -Descending

        # Build summary counts
        $critCount = 0; $highCount = 0; $medCount = 0; $lowCount = 0
        foreach ($a in $sortedAnomalies) {
            switch ($a.Severity) {
                'Critical' { $critCount++ }
                'High'     { $highCount++ }
                'Medium'   { $medCount++ }
                'Low'      { $lowCount++ }
            }
        }

        $baselineDate = $null
        try { $baselineDate = [datetime]$baseline.CreatedAt } catch { }

        Write-Log "Anomaly detection complete: $(@($sortedAnomalies).Count) anomalies (Critical: $critCount, High: $highCount, Medium: $medCount, Low: $lowCount)"

        return @{
            Anomalies    = @($sortedAnomalies)
            Summary      = @{
                Total    = @($sortedAnomalies).Count
                Critical = $critCount
                High     = $highCount
                Medium   = $medCount
                Low      = $lowCount
            }
            BaselineName = $BaselineName
            BaselineDate = $baselineDate
        }
    } catch {
        Write-Log "Anomaly detection failed: $_" -Level ERROR
        return @{
            Anomalies    = @()
            Summary      = @{ Total = 0; Critical = 0; High = 0; Medium = 0; Low = 0 }
            BaselineName = $BaselineName
            BaselineDate = $null
        }
    }
}

function Show-AnomalyDialog {
    param($Results)

    if (-not $Results -or $Results.Summary.Total -eq 0) {
        $msg = if ($Results.Message) { $Results.Message } else { "No anomalies detected against the baseline." }
        if (-not $Script:UseConsole) {
            [System.Windows.Forms.MessageBox]::Show($msg, "Anomaly Detection")
        } else {
            Write-Host $msg
        }
        return
    }

    if ($Script:UseConsole) {
        Write-AnomalyTable -Results $Results
        return
    }

    $dlg = [System.Windows.Forms.Form]::new()
    $dlg.Text = "Anomaly Detection Results (vs baseline: $($Results.BaselineName))"
    $dlg.Size = [System.Drawing.Size]::new(1100, 650)
    $dlg.StartPosition = "CenterParent"
    $t = $Script:Themes[$Script:State.ActiveTheme]
    $dlg.BackColor = $t.FormBack
    $dlg.ForeColor = $t.FormFore

    # Summary panel at the top
    $summaryPanel = [System.Windows.Forms.Panel]::new()
    $summaryPanel.Dock = "Top"
    $summaryPanel.Height = 50
    $summaryPanel.BackColor = $t.FormBack

    $summaryLabel = [System.Windows.Forms.Label]::new()
    $summaryLabel.Dock = "Fill"
    $summaryLabel.TextAlign = "MiddleLeft"
    $summaryLabel.Font = [System.Drawing.Font]::new("Consolas", 10, [System.Drawing.FontStyle]::Bold)
    $summaryLabel.ForeColor = $t.FormFore

    $baselineDateStr = if ($Results.BaselineDate) { $Results.BaselineDate.ToString("yyyy-MM-dd HH:mm") } else { "unknown" }
    $summaryLabel.Text = "  Baseline: $($Results.BaselineName) (created: $baselineDateStr)  |  " +
        "Total: $($Results.Summary.Total)  |  Critical: $($Results.Summary.Critical)  |  " +
        "High: $($Results.Summary.High)  |  Medium: $($Results.Summary.Medium)  |  Low: $($Results.Summary.Low)"

    $summaryPanel.Controls.Add($summaryLabel)

    # DataGridView for anomaly details
    $grid = [System.Windows.Forms.DataGridView]::new()
    $grid.Dock = "Fill"
    $grid.ReadOnly = $true
    $grid.AllowUserToAddRows = $false
    $grid.BackgroundColor = $t.GridBack
    $grid.DefaultCellStyle.BackColor = $t.GridBack
    $grid.DefaultCellStyle.ForeColor = $t.FormFore
    $grid.ColumnHeadersDefaultCellStyle.BackColor = $t.GridBack
    $grid.ColumnHeadersDefaultCellStyle.ForeColor = $t.FormFore
    $grid.EnableHeadersVisualStyles = $false
    $grid.DefaultCellStyle.WrapMode = [System.Windows.Forms.DataGridViewTriState]::True
    $grid.AutoSizeRowsMode = [System.Windows.Forms.DataGridViewAutoSizeRowsMode]::AllCells

    $grid.Columns.Add("Severity", "Severity") | Out-Null
    $grid.Columns.Add("Type", "Type") | Out-Null
    $grid.Columns.Add("Metric", "Metric") | Out-Null
    $grid.Columns.Add("Expected", "Expected") | Out-Null
    $grid.Columns.Add("Actual", "Actual") | Out-Null
    $grid.Columns.Add("Deviation", "Deviation") | Out-Null
    $grid.Columns.Add("Description", "Description") | Out-Null

    # Set column widths
    $grid.Columns[0].Width = 75   # Severity
    $grid.Columns[1].Width = 95   # Type
    $grid.Columns[2].Width = 180  # Metric
    $grid.Columns[3].Width = 150  # Expected
    $grid.Columns[4].Width = 130  # Actual
    $grid.Columns[5].Width = 75   # Deviation
    $grid.Columns[6].Width = 350  # Description

    foreach ($anomaly in $Results.Anomalies) {
        $devStr = if ($anomaly.Type -eq 'Volume') {
            "$([Math]::Round([Math]::Abs($anomaly.Deviation), 2))s"
        } else {
            "$([Math]::Round([Math]::Abs($anomaly.Deviation), 2))"
        }

        $rowIdx = $grid.Rows.Add(
            $anomaly.Severity,
            $anomaly.Type,
            $anomaly.Metric,
            $anomaly.Expected,
            $anomaly.Actual,
            $devStr,
            $anomaly.Description
        )

        switch ($anomaly.Severity) {
            'Critical' { $grid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Red }
            'High'     { $grid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::OrangeRed }
            'Medium'   { $grid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Orange }
            'Low'      { $grid.Rows[$rowIdx].DefaultCellStyle.ForeColor = $t.FormFore }
        }
    }

    $dlg.Controls.Add($grid)
    $dlg.Controls.Add($summaryPanel)
    $dlg.ShowDialog($Script:UI.Form) | Out-Null
    $dlg.Dispose()
}

function Write-AnomalyTable {
    param($Results)

    $r = $Script:ANSIReset
    $ct = $Script:ConsoleThemes[$Script:State.ActiveTheme]

    $baselineDateStr = if ($Results.BaselineDate) { $Results.BaselineDate.ToString("yyyy-MM-dd HH:mm") } else { "unknown" }

    Write-Host ""
    Write-Host "$($ct.Title)Anomaly Detection Results (vs baseline: $($Results.BaselineName))$r"
    Write-Host "$($ct.INFO)  Baseline created: $baselineDateStr$r"
    Write-Host "$($ct.INFO)  Total: $($Results.Summary.Total)  |  Critical: $($Results.Summary.Critical)  |  High: $($Results.Summary.High)  |  Medium: $($Results.Summary.Medium)  |  Low: $($Results.Summary.Low)$r"
    Write-Host ""

    if ($Results.Summary.Total -eq 0) {
        Write-Host "$($ct.INFO)  No anomalies detected.$r"
        Write-Host ""
        return
    }

    # Table header
    Write-Host "$($ct.Header){0,-10} {1,-14} {2,-35} {3,-25} {4,-25} {5,-10} {6}$r" -f "Severity", "Type", "Metric", "Expected", "Actual", "Deviation", "Description"
    Write-Host "$($ct.Border)$([string][char]0x2500 * 150)$r"

    foreach ($anomaly in $Results.Anomalies) {
        $color = switch ($anomaly.Severity) {
            'Critical' { $ct.CRITICAL }
            'High'     { $ct.ERROR }
            'Medium'   { $ct.WARNING }
            'Low'      { $ct.INFO }
            default    { $ct.INFO }
        }

        $devStr = if ($anomaly.Type -eq 'Volume') {
            "$([Math]::Round([Math]::Abs($anomaly.Deviation), 2))s"
        } else {
            "$([Math]::Round([Math]::Abs($anomaly.Deviation), 2))"
        }

        # Truncate long fields for console display
        $metric = $anomaly.Metric
        if ($metric.Length -gt 33) { $metric = $metric.Substring(0, 33) }
        $expected = [string]$anomaly.Expected
        if ($expected.Length -gt 23) { $expected = $expected.Substring(0, 23) }
        $actual = [string]$anomaly.Actual
        if ($actual.Length -gt 23) { $actual = $actual.Substring(0, 23) }
        $desc = $anomaly.Description
        if ($desc.Length -gt 60) { $desc = $desc.Substring(0, 60) }

        Write-Host "$color{0,-10} {1,-14} {2,-35} {3,-25} {4,-25} {5,-10} {6}$r" -f $anomaly.Severity, $anomaly.Type, $metric, $expected, $actual, $devStr, $desc
    }

    Write-Host ""

    # Group anomalies by type for a quick summary
    $byType = @{}
    foreach ($a in $Results.Anomalies) {
        if (-not $byType.ContainsKey($a.Type)) { $byType[$a.Type] = 0 }
        $byType[$a.Type]++
    }
    $typeSummary = ($byType.GetEnumerator() | Sort-Object Value -Descending | ForEach-Object { "$($_.Key): $($_.Value)" }) -join "  |  "
    Write-Host "$($ct.Dim)  By type: $typeSummary$r"
    Write-Host ""
}
