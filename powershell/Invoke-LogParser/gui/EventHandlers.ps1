# EventHandlers.ps1 — GUI event handler functions

function Populate-DetailPane {
    param($entry)
    $rtb = $Script:UI.DetailBox
    $rtb.Clear()
    $t = $Script:Themes[$Script:State.ActiveTheme]

    $fields = [ordered]@{
        "Timestamp" = if ($entry.Timestamp -ne [datetime]::MinValue) { $entry.Timestamp.ToString("yyyy-MM-dd HH:mm:ss.fff") } else { "(none)" }
        "Level"     = $entry.Level
        "Source"    = $entry.Source
        "Host"      = $entry.Host
        "Message"   = $entry.Message
    }

    # Add Extra fields
    if ($entry.Extra) {
        foreach ($k in ($entry.Extra.Keys | Sort-Object)) {
            $fields[$k] = [string]$entry.Extra[$k]
        }
        # Event ID annotation
        if ($entry.Extra['EventID'] -and $entry.Extra['EventIdAnnotation']) {
            $fields['EventID'] = "$($entry.Extra['EventID'])  -- $($entry.Extra['EventIdAnnotation'])"
        }
        # NPS reason code translation
        if ($entry.Extra['Reason-Code'] -and $entry.Extra['ReasonCodeTranslation']) {
            $fields['Reason-Code'] = "$($entry.Extra['Reason-Code'])  -- $($entry.Extra['ReasonCodeTranslation'])"
        }
    }

    $fields["Raw Line"] = $entry.RawLine

    # Determine search term for highlighting
    $searchText = $Script:UI.TxtSearch.Text
    $useRegex = $Script:UI.RadRegex.Checked
    $highlightBack = if ($t.HighlightBack) { $t.HighlightBack } else { [System.Drawing.Color]::Yellow }

    foreach ($k in $fields.Keys) {
        $rtb.SelectionFont = [System.Drawing.Font]::new("Consolas", 9.5, [System.Drawing.FontStyle]::Bold)
        $rtb.SelectionColor = $t.DetailFore
        $rtb.AppendText("${k}: ")
        $rtb.SelectionFont = [System.Drawing.Font]::new("Consolas", 9.5)
        $val = $fields[$k]
        if ($val.Length -gt 2000) { $val = $val.Substring(0, 2000) + "... (truncated)" }
        $rtb.AppendText("$val`n")
    }

    # Highlight search matches in detail pane
    if ($searchText) {
        try {
            if ($useRegex) {
                $rx = [regex]::new($searchText, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                $ms = $rx.Matches($rtb.Text)
                foreach ($m in $ms) {
                    $rtb.Select($m.Index, $m.Length)
                    $rtb.SelectionBackColor = $highlightBack
                }
            } else {
                $startIdx = 0
                $searchUpper = $searchText.ToUpper()
                $textUpper = $rtb.Text.ToUpper()
                while (($startIdx = $textUpper.IndexOf($searchUpper, $startIdx)) -ge 0) {
                    $rtb.Select($startIdx, $searchText.Length)
                    $rtb.SelectionBackColor = $highlightBack
                    $startIdx += $searchText.Length
                }
            }
        } catch { }
        $rtb.Select(0, 0)
    }
}

function On-OpenFile {
    $ofd = [System.Windows.Forms.OpenFileDialog]::new()
    $ofd.Filter = "All Log Files|*.log;*.txt;*.evtx;*.csv;*.json;*.jsonl;*.ndjson;*.xml;*.conf;*.gz;*.zip|" +
                  "Log Files (*.log)|*.log|Text Files (*.txt)|*.txt|Event Logs (*.evtx)|*.evtx|" +
                  "FortiGate Config (*.conf)|*.conf|CSV Files (*.csv)|*.csv|" +
                  "JSON Files (*.json;*.jsonl;*.ndjson)|*.json;*.jsonl;*.ndjson|" +
                  "XML Files (*.xml)|*.xml|Compressed (*.gz;*.zip)|*.gz;*.zip|All Files (*.*)|*.*"
    $ofd.Title = "Open Log File"
    if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        Open-LogFile $ofd.FileName
    }
}

function On-OpenSpecificFile {
    param([string]$Path)
    if (Test-Path $Path) { Open-LogFile $Path }
    else { Update-StatusBar "File not found: $Path" -IsError }
}

function Open-LogFile {
    param([string]$Path)
    Stop-TailMode
    Stop-ParseRunspace

    $Script:State.OriginalPath = $null
    $actualPath = $Path

    # Handle compressed files
    $ext = [System.IO.Path]::GetExtension($Path).ToLower()
    if ($ext -eq '.gz' -or $ext -eq '.zip') {
        Update-StatusBar "Decompressing..."
        $decompressed = Expand-CompressedFile $Path
        if (-not $decompressed) {
            Update-StatusBar "Decompression failed" -IsError
            return
        }
        $Script:State.OriginalPath = $Path
        $actualPath = $decompressed
    }

    # Binary file detection
    try {
        $bytes = [byte[]]::new(512)
        $fs2 = [System.IO.FileStream]::new($actualPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $bytesRead = $fs2.Read($bytes, 0, 512)
        $fs2.Close(); $fs2.Dispose()
        # Empty file check
        if ($bytesRead -eq 0) {
            Update-StatusBar "File is empty" -IsError
            return
        }
        if ($bytesRead -lt 512) { $bytes = $bytes[0..($bytesRead - 1)] }
        $nullCount = ($bytes | Where-Object { $_ -eq 0 }).Count
        if ($ext -ne '.evtx' -and $nullCount -gt 10) {
            Update-StatusBar "File does not appear to be a text-based log" -IsError
            return
        }
    } catch { }

    $Script:State.FilePath = $actualPath
    $displayPath = if ($Script:State.OriginalPath) { $Script:State.OriginalPath } else { $Path }
    $Script:UI.LblFilePath.Text = [System.IO.Path]::GetFileName($displayPath)
    $Script:UI.StatusFileLabel.Text = $displayPath
    Add-RecentFile $Path

    # Auto-detect or use selected format
    $formatIdx = $Script:UI.CmbFormat.SelectedIndex
    $parserId = "auto"
    if ($formatIdx -gt 0) {
        $parserKeys = @($Script:Parsers.Keys)
        $parserId = $parserKeys[$formatIdx - 1]
    }

    if ($parserId -eq "auto") {
        Update-StatusBar "Detecting format..."
        $parserId = Invoke-AutoDetect $actualPath
        if (-not $parserId) {
            Update-StatusBar "File does not appear to be a text-based log" -IsError
            return
        }
    }

    $Script:State.Format = $parserId
    $parserName = $Script:Parsers[$parserId].Name
    Update-StatusBar "Parsing with $parserName..."
    $Script:UI.ProgressBar.Value = 10

    # For EVTX and small files, parse synchronously; for larger files, use runspace
    $fileSize = (Get-Item $actualPath).Length
    if ($parserId -eq "windows-evtx" -or $parserId -eq "nps-radius" -or $parserId -eq "csv-auto" -or $fileSize -lt 1MB) {
        # Synchronous parse
        $Script:State.IsParsing = $true
        try {
            $entries = Invoke-ParserForFile -ParserId $parserId -FilePath $actualPath -Encoding $Script:State.Encoding
            if ($entries) {
                $Script:State.AllEntries.Clear()
                foreach ($e in $entries) { $Script:State.AllEntries.Add($e) }
            }
            $Script:State.IsParsing = $false
            Invoke-ApplyFilters
            Update-StatsBar
            Update-StatusBar "Parsed $($Script:State.AllEntries.Count) entries ($parserName)"
            $Script:UI.ProgressBar.Value = 100
        } catch {
            $Script:State.IsParsing = $false
            Update-StatusBar "Parse error: $_" -IsError
        }
    } else {
        # Background parse
        Start-ParseRunspace -FilePath $actualPath -ParserId $parserId -Encoding $Script:State.Encoding
    }

    # Auto-size columns based on format
    if ($Script:UI.DataGrid) {
        switch -Wildcard ($parserId) {
            "fortigate-conf" { $Script:UI.DataGrid.Columns['Source'].Width = 180 }
            "windows-evtx"   { $Script:UI.DataGrid.Columns['Source'].Width = 160 }
            "fortigate-kv"   { $Script:UI.DataGrid.Columns['Source'].Width = 140 }
            "nps-radius"     { $Script:UI.DataGrid.Columns['Source'].Width = 140 }
        }
    }

    # Set tail byte offset
    try { $Script:State.TailByteOffset = (Get-Item $actualPath).Length } catch { }
}

function On-ReloadFile {
    if ($Script:State.FilePath -or $Script:State.OriginalPath) {
        $path = if ($Script:State.OriginalPath) { $Script:State.OriginalPath } else { $Script:State.FilePath }
        Open-LogFile $path
    }
}

function On-ParseClick {
    if ($Script:State.FilePath) { On-ReloadFile }
    else { On-OpenFile }
}

function On-TailToggle {
    if ($Script:State.TailMode) {
        Stop-TailMode
        $Script:UI.BtnTail.Text = "Tail: OFF"
    } else {
        Start-TailMode
        if ($Script:State.TailMode) { $Script:UI.BtnTail.Text = "Tail: ON" }
    }
}

function On-ThemeToggle {
    $themeOrder = @("Dark", "Light", "HighContrast", "SolarizedDark", "Nord", "Monokai")
    $currentIdx = [Array]::IndexOf($themeOrder, $Script:State.ActiveTheme)
    $nextIdx = ($currentIdx + 1) % $themeOrder.Count
    Set-Theme $themeOrder[$nextIdx]
}

function On-GoToLine {
    $input2 = [Microsoft.VisualBasic.Interaction]::InputBox("Enter entry number:", "Go to Line", "")
    if ([string]::IsNullOrWhiteSpace($input2)) { return }
    $lineNum = $input2 -as [int]
    if ($null -eq $lineNum) { return }
    for ($i = 0; $i -lt $Script:State.FilteredEntries.Count; $i++) {
        if ($Script:State.FilteredEntries[$i].Index -eq $lineNum) {
            $Script:UI.DataGrid.ClearSelection()
            $Script:UI.DataGrid.FirstDisplayedScrollingRowIndex = $i
            $Script:UI.DataGrid.Rows[$i].Selected = $true
            return
        }
    }
    Update-StatusBar "Entry #$lineNum not found in current filter"
}

function On-GridColumnHeaderClick {
    param([int]$ColIndex)
    $propName = switch ($ColIndex) {
        1 { "Index" }
        2 { "Timestamp" }
        3 { "Level" }
        4 { "Source" }
        5 { "Message" }
        default { $null }
    }
    if (-not $propName) { return }

    if ($Script:State.SortColumn -eq $ColIndex) {
        $Script:State.SortAscending = -not $Script:State.SortAscending
    } else {
        $Script:State.SortColumn = $ColIndex
        $Script:State.SortAscending = $true
    }

    $sorted = if ($Script:State.SortAscending) {
        $Script:State.FilteredEntries | Sort-Object -Property $propName
    } else {
        $Script:State.FilteredEntries | Sort-Object -Property $propName -Descending
    }

    $Script:State.FilteredEntries.Clear()
    foreach ($e in $sorted) { $Script:State.FilteredEntries.Add($e) }
    $Script:UI.DataGrid.Invalidate()
}

# --- New menu item handlers ---

function On-OpenMultipleFiles {
    $ofd = [System.Windows.Forms.OpenFileDialog]::new()
    $ofd.Filter = "All Log Files|*.log;*.txt;*.evtx;*.csv;*.json;*.jsonl;*.ndjson;*.xml;*.conf;*.gz;*.zip|All Files (*.*)|*.*"
    $ofd.Title = "Open Multiple Log Files"
    $ofd.Multiselect = $true
    if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        Invoke-TimelineMerge -FilePaths $ofd.FileNames
    }
}

function On-GenerateAuditReport {
    if ($Script:State.AllEntries.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No log data loaded. Open files first.", "Audit Report")
        return
    }
    $sfd = [System.Windows.Forms.SaveFileDialog]::new()
    $sfd.Filter = "HTML Files (*.html)|*.html"
    $sfd.FileName = "audit_report_$(Get-Date -Format 'yyyyMMdd').html"
    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        New-AuditReport -OutputPath $sfd.FileName -Entries $Script:State.AllEntries
        Update-StatusBar "Audit report generated: $($sfd.FileName)"
    }
}

function On-ShowStatistics {
    if ($Script:State.AllEntries.Count -eq 0) { return }
    Show-StatisticsDialog -Entries $Script:State.FilteredEntries
}

function On-ImportIocFile {
    $ofd = [System.Windows.Forms.OpenFileDialog]::new()
    $ofd.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $ofd.Title = "Import IOC List"
    if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        Import-IocFile -FilePath $ofd.FileName
        Invoke-IocMatch -Entries $Script:State.AllEntries
        Invoke-ApplyFilters
        Update-StatusBar "IOC matching complete: $($Script:State.IocSet.MatchCount) matches"
    }
}

function On-FailedLoginSummary {
    if ($Script:State.AllEntries.Count -eq 0) { return }
    $results = Get-FailedLoginAggregation -Entries $Script:State.AllEntries
    Show-FailedLoginDialog -Results $results
}

function On-VpnSessionSummary {
    if ($Script:State.AllEntries.Count -eq 0) { return }
    $results = Get-VpnSessionAnalysis -Entries $Script:State.AllEntries
    Show-VpnSessionDialog -Results $results
}

# --- v4.0 Analysis Handlers ---

function On-BgpRouteAnalysis {
    if ($Script:State.AllEntries.Count -eq 0) { return }
    $results = Get-BgpRouteAnalysis -Entries $Script:State.AllEntries
    Show-BgpRouteDialog -Results $results
}

function On-IpsecTunnelAnalysis {
    if ($Script:State.AllEntries.Count -eq 0) { return }
    $results = Get-IpsecTunnelAnalysis -Entries $Script:State.AllEntries
    Show-IpsecTunnelDialog -Results $results
}

function On-NpsSessionAnalysis {
    if ($Script:State.AllEntries.Count -eq 0) { return }
    $results = Get-NpsSessionAnalysis -Entries $Script:State.AllEntries
    Show-NpsSessionDialog -Results $results
}

function On-CertExpiryTracker {
    if ($Script:State.AllEntries.Count -eq 0) { return }
    $results = Get-CertExpiryAnalysis -Entries $Script:State.AllEntries
    Show-CertExpiryDialog -Results $results
}

function On-ChangeAuditAnalysis {
    if ($Script:State.AllEntries.Count -eq 0) { return }
    $results = Get-ChangeAuditAnalysis -Entries $Script:State.AllEntries
    Show-ChangeAuditDialog -Results $results
}

function On-ThreatCorrelation {
    if ($Script:State.AllEntries.Count -eq 0) { return }
    $results = Get-ThreatCorrelation -Entries $Script:State.AllEntries
    Show-ThreatCorrelationDialog -Results $results
}

function On-CrossSourceCorrelation {
    if ($Script:State.AllEntries.Count -eq 0) { return }
    $results = Invoke-CrossSourceCorrelation -Entries $Script:State.AllEntries
    Show-CorrelationDialog -Results $results
}

function On-ComplianceAssessment {
    if ($Script:State.AllEntries.Count -eq 0) { return }
    $results = Get-ComplianceAnalysis -Entries $Script:State.AllEntries
    Show-ComplianceDialog -Results $results
}

# --- v4.0 Report Handlers ---

function On-GenerateMorningBriefing {
    if ($Script:State.AllEntries.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No log data loaded. Open files first.", "Morning Briefing")
        return
    }
    $sfd = [System.Windows.Forms.SaveFileDialog]::new()
    $sfd.Filter = "HTML Files (*.html)|*.html"
    $sfd.FileName = "morning_briefing_$(Get-Date -Format 'yyyyMMdd').html"
    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        New-MorningBriefing -OutputPath $sfd.FileName -Entries $Script:State.AllEntries
        Update-StatusBar "Morning briefing generated: $($sfd.FileName)"
    }
}

function On-GenerateSiteHealthReport {
    if ($Script:State.AllEntries.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No log data loaded. Open files first.", "Site Health Report")
        return
    }
    $sfd = [System.Windows.Forms.SaveFileDialog]::new()
    $sfd.Filter = "HTML Files (*.html)|*.html"
    $sfd.FileName = "site_health_$(Get-Date -Format 'yyyyMMdd').html"
    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        New-SiteHealthReport -OutputPath $sfd.FileName -Entries $Script:State.AllEntries
        Update-StatusBar "Site health report generated: $($sfd.FileName)"
    }
}

function On-GenerateIncidentTimeline {
    if ($Script:State.AllEntries.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No log data loaded. Open files first.", "Incident Timeline")
        return
    }
    $sfd = [System.Windows.Forms.SaveFileDialog]::new()
    $sfd.Filter = "HTML Files (*.html)|*.html"
    $sfd.FileName = "incident_timeline_$(Get-Date -Format 'yyyyMMdd').html"
    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        New-IncidentTimeline -OutputPath $sfd.FileName -Entries $Script:State.AllEntries
        Update-StatusBar "Incident timeline generated: $($sfd.FileName)"
    }
}

function On-GenerateFfiecReport {
    if ($Script:State.AllEntries.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No log data loaded. Open files first.", "FFIEC Compliance Report")
        return
    }
    $sfd = [System.Windows.Forms.SaveFileDialog]::new()
    $sfd.Filter = "HTML Files (*.html)|*.html"
    $sfd.FileName = "ffiec_compliance_$(Get-Date -Format 'yyyyMMdd').html"
    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        New-FfiecComplianceReport -OutputPath $sfd.FileName -Entries $Script:State.AllEntries
        Update-StatusBar "FFIEC compliance report generated: $($sfd.FileName)"
    }
}

function On-GenerateVulnerabilityReport {
    if ($Script:State.AllEntries.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No log data loaded. Open files first.", "Vulnerability Report")
        return
    }
    $sfd = [System.Windows.Forms.SaveFileDialog]::new()
    $sfd.Filter = "HTML Files (*.html)|*.html"
    $sfd.FileName = "vulnerability_report_$(Get-Date -Format 'yyyyMMdd').html"
    if ($sfd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        New-VulnerabilityReport -OutputPath $sfd.FileName -Entries $Script:State.AllEntries
        Update-StatusBar "Vulnerability report generated: $($sfd.FileName)"
    }
}

# --- v5.0 Handlers ---

function On-AnomalyDetection {
    if ($Script:State.AllEntries.Count -eq 0) { return }
    $results = Get-AnomalyDetection -Entries $Script:State.AllEntries
    Show-AnomalyDialog -Results $results
}

function On-TriageCheck {
    if ($Script:State.AllEntries.Count -eq 0) { return }
    $results = Invoke-TriageCheck -Entries $Script:State.AllEntries
    Show-TriageDialog -Results $results
}

function On-ShowDashboard {
    if ($Script:State.AllEntries.Count -eq 0) { return }
    Show-DashboardTab
    Update-DashboardPanel -Entries $Script:State.AllEntries
}

function On-ConnectorStatus {
    $statuses = Get-ConnectorStatus
    if (-not $statuses -or @($statuses).Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No connectors configured.", "Connector Status")
        return
    }
    $dlg = [System.Windows.Forms.Form]::new()
    $dlg.Text = "Connector Status"; $dlg.Size = [System.Drawing.Size]::new(600, 400); $dlg.StartPosition = "CenterParent"
    $t = $Script:Themes[$Script:State.ActiveTheme]
    $dlg.BackColor = $t.FormBack; $dlg.ForeColor = $t.FormFore
    $grid = [System.Windows.Forms.DataGridView]::new()
    $grid.Dock = "Fill"; $grid.ReadOnly = $true; $grid.AllowUserToAddRows = $false
    $grid.BackgroundColor = $t.GridBack
    $grid.Columns.Add("Name", "Connector") | Out-Null
    $grid.Columns.Add("Status", "Status") | Out-Null
    $grid.Columns.Add("LastPull", "Last Pull") | Out-Null
    $grid.Columns.Add("Error", "Last Error") | Out-Null
    foreach ($s in $statuses) {
        $lastPull = if ($s.LastPull) { $S.LastPull.ToString("yyyy-MM-dd HH:mm:ss") } else { "(never)" }
        $grid.Rows.Add($s.Name, $s.Status, $lastPull, $s.LastError) | Out-Null
    }
    $grid.AutoResizeColumns()
    $dlg.Controls.Add($grid)
    $dlg.ShowDialog($Script:UI.Form) | Out-Null
    $dlg.Dispose()
}

function On-DiffCompare {
    if ($Script:State.AllEntries.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No log data loaded. Open files first.", "Diff / Compare")
        return
    }
    # Simple implementation: compare first half vs second half by timestamp
    $midpoint = [int]($Script:State.AllEntries.Count / 2)
    $period1 = [System.Collections.Generic.List[object]]::new()
    $period2 = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $midpoint; $i++) { $period1.Add($Script:State.AllEntries[$i]) }
    for ($i = $midpoint; $i -lt $Script:State.AllEntries.Count; $i++) { $period2.Add($Script:State.AllEntries[$i]) }
    $results = Compare-LogPeriods -Period1 $period1 -Period2 $period2 -Period1Label "First Half" -Period2Label "Second Half"
    Show-DiffDialog -Results $results -DiffType "Periods"
}
