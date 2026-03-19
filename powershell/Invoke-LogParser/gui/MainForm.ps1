# MainForm.ps1 — Main form builder and recent files menu

# Load VisualBasic for InputBox (Windows GUI only)
if (-not $Script:UseConsole) {
    try { Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction SilentlyContinue } catch {}
}

$Script:UI = @{}

function Update-RecentFilesMenu {
    if (-not $Script:UI.RecentMenu) { return }
    $Script:UI.RecentMenu.DropDownItems.Clear()
    foreach ($f in $Script:State.RecentFiles) {
        $item = [System.Windows.Forms.ToolStripMenuItem]::new($f)
        $path = $f
        $item.Add_Click({ On-OpenSpecificFile $path }.GetNewClosure())
        $Script:UI.RecentMenu.DropDownItems.Add($item) | Out-Null
    }
}

function New-MainForm {
    # --- Main Form ---
    $form = [System.Windows.Forms.Form]::new()
    $form.Text = $Config.WindowTitle
    $form.MinimumSize = [System.Drawing.Size]::new($Config.MinWidth, $Config.MinHeight)
    $form.Size = [System.Drawing.Size]::new($Config.DefaultWidth, $Config.DefaultHeight)
    $form.StartPosition = "CenterScreen"
    $form.Font = [System.Drawing.Font]::new("Segoe UI", 9)
    $form.KeyPreview = $true
    # DPI Awareness
    $form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
    # Drag-and-drop support
    $form.AllowDrop = $true
    $form.Add_DragEnter({ if ($_.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) { $_.Effect = 'Copy' } })
    $form.Add_DragDrop({ $files = $_.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop); if ($files.Count -gt 0) { Open-LogFile $files[0] } })
    $Script:UI.Form = $form

    # --- Menu Strip ---
    $menuStrip = [System.Windows.Forms.MenuStrip]::new()
    $Script:UI.MenuStrip = $menuStrip

    # File menu
    $fileMenu = [System.Windows.Forms.ToolStripMenuItem]::new("&File")
    $openItem = [System.Windows.Forms.ToolStripMenuItem]::new("&Open...`tCtrl+O")
    $openItem.Add_Click({ On-OpenFile })
    $openItem.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::O

    # Multi-file open
    $openMultiItem = [System.Windows.Forms.ToolStripMenuItem]::new("Open &Multiple Files...")
    $openMultiItem.Add_Click({ On-OpenMultipleFiles })

    $reloadItem = [System.Windows.Forms.ToolStripMenuItem]::new("&Reload`tCtrl+R")
    $reloadItem.Add_Click({ On-ReloadFile })
    $reloadItem.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::R
    $Script:UI.RecentMenu = [System.Windows.Forms.ToolStripMenuItem]::new("Recent Files")
    $sep1 = [System.Windows.Forms.ToolStripSeparator]::new()
    $exportCsvItem = [System.Windows.Forms.ToolStripMenuItem]::new("Export &CSV...`tCtrl+E")
    $exportCsvItem.Add_Click({ Export-ToCsv })
    $exportCsvItem.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::E
    $exportHtmlItem = [System.Windows.Forms.ToolStripMenuItem]::new("Export &HTML...`tCtrl+Shift+E")
    $exportHtmlItem.Add_Click({ Export-ToHtml })
    $exportHtmlItem.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::Shift -bor [System.Windows.Forms.Keys]::E

    $sep2 = [System.Windows.Forms.ToolStripSeparator]::new()
    $exitItem = [System.Windows.Forms.ToolStripMenuItem]::new("E&xit")
    $exitItem.Add_Click({ $Script:UI.Form.Close() })
    $fileMenu.DropDownItems.AddRange(@($openItem, $openMultiItem, $reloadItem, $Script:UI.RecentMenu, $sep1, $exportCsvItem, $exportHtmlItem, $sep2, $exitItem))

    # View menu
    $viewMenu = [System.Windows.Forms.ToolStripMenuItem]::new("&View")
    $themeItem = [System.Windows.Forms.ToolStripMenuItem]::new("Toggle &Theme`tCtrl+D")
    $themeItem.Add_Click({ On-ThemeToggle })
    $themeItem.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::D
    $goToLineItem = [System.Windows.Forms.ToolStripMenuItem]::new("&Go to Line...`tCtrl+G")
    $goToLineItem.Add_Click({ On-GoToLine })
    $goToLineItem.ShortcutKeys = [System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::G

    # Statistics
    $statsItem = [System.Windows.Forms.ToolStripMenuItem]::new("&Statistics...")
    $statsItem.Add_Click({ On-ShowStatistics })

    $dashboardItem = [System.Windows.Forms.ToolStripMenuItem]::new("&Dashboard")
    $dashboardItem.Add_Click({ On-ShowDashboard })

    $viewMenu.DropDownItems.AddRange(@($themeItem, $goToLineItem, $statsItem, $dashboardItem))

    # Tools menu
    $toolsMenu = [System.Windows.Forms.ToolStripMenuItem]::new("&Tools")
    $regexItem = [System.Windows.Forms.ToolStripMenuItem]::new("Set Custom &Regex Pattern...")
    $regexItem.Add_Click({
        $pattern = [Microsoft.VisualBasic.Interaction]::InputBox(
            "Enter regex with named groups:`n(?<timestamp>...) (?<level>...) (?<source>...) (?<message>...)",
            "Custom Regex Pattern",
            $(if ($Script:State.CustomRegex) { $Script:State.CustomRegex } else { "" })
        )
        if ($pattern) {
            $Script:State.CustomRegex = $pattern
            Update-StatusBar "Custom regex set. Select 'User-Defined Regex' format to use."
        }
    })

    # Tools menu additions: IOC import
    $iocItem = [System.Windows.Forms.ToolStripMenuItem]::new("Import &IOC List...")
    $iocItem.Add_Click({ On-ImportIocFile })

    # Analysis submenu
    $analysisMenu = [System.Windows.Forms.ToolStripMenuItem]::new("&Analysis")
    $failedLoginItem = [System.Windows.Forms.ToolStripMenuItem]::new("&Failed Login Summary")
    $failedLoginItem.Add_Click({ On-FailedLoginSummary })
    $vpnItem = [System.Windows.Forms.ToolStripMenuItem]::new("&VPN Session Summary")
    $vpnItem.Add_Click({ On-VpnSessionSummary })
    $bgpItem = [System.Windows.Forms.ToolStripMenuItem]::new("&BGP Route Analysis")
    $bgpItem.Add_Click({ On-BgpRouteAnalysis })
    $ipsecItem = [System.Windows.Forms.ToolStripMenuItem]::new("&IPsec Tunnel Analysis")
    $ipsecItem.Add_Click({ On-IpsecTunnelAnalysis })
    $npsItem = [System.Windows.Forms.ToolStripMenuItem]::new("&NPS Session Analysis")
    $npsItem.Add_Click({ On-NpsSessionAnalysis })
    $certItem = [System.Windows.Forms.ToolStripMenuItem]::new("&Certificate Expiry Tracker")
    $certItem.Add_Click({ On-CertExpiryTracker })
    $changeItem = [System.Windows.Forms.ToolStripMenuItem]::new("C&hange Audit Trail")
    $changeItem.Add_Click({ On-ChangeAuditAnalysis })
    $threatItem = [System.Windows.Forms.ToolStripMenuItem]::new("&Threat Correlation")
    $threatItem.Add_Click({ On-ThreatCorrelation })
    $corrItem = [System.Windows.Forms.ToolStripMenuItem]::new("Cross-&Source Correlation")
    $corrItem.Add_Click({ On-CrossSourceCorrelation })
    $compItem = [System.Windows.Forms.ToolStripMenuItem]::new("Co&mpliance Assessment")
    $compItem.Add_Click({ On-ComplianceAssessment })
    $anomalyItem = [System.Windows.Forms.ToolStripMenuItem]::new("A&nomaly Detection")
    $anomalyItem.Add_Click({ On-AnomalyDetection })
    $triageItem = [System.Windows.Forms.ToolStripMenuItem]::new("&Triage Check")
    $triageItem.Add_Click({ On-TriageCheck })
    $analysisMenu.DropDownItems.AddRange(@($failedLoginItem, $vpnItem, [System.Windows.Forms.ToolStripSeparator]::new(), $bgpItem, $ipsecItem, $npsItem, [System.Windows.Forms.ToolStripSeparator]::new(), $certItem, $changeItem, $threatItem, $corrItem, $compItem, [System.Windows.Forms.ToolStripSeparator]::new(), $anomalyItem, $triageItem))

    # Reports submenu
    $reportsMenu = [System.Windows.Forms.ToolStripMenuItem]::new("&Reports")
    $auditRptItem = [System.Windows.Forms.ToolStripMenuItem]::new("&Audit Report...")
    $auditRptItem.Add_Click({ On-GenerateAuditReport })
    $morningItem = [System.Windows.Forms.ToolStripMenuItem]::new("&Morning Briefing...")
    $morningItem.Add_Click({ On-GenerateMorningBriefing })
    $siteItem = [System.Windows.Forms.ToolStripMenuItem]::new("&Site Health Report...")
    $siteItem.Add_Click({ On-GenerateSiteHealthReport })
    $timelineItem = [System.Windows.Forms.ToolStripMenuItem]::new("&Incident Timeline...")
    $timelineItem.Add_Click({ On-GenerateIncidentTimeline })
    $ffiecItem = [System.Windows.Forms.ToolStripMenuItem]::new("&FFIEC Compliance Report...")
    $ffiecItem.Add_Click({ On-GenerateFfiecReport })
    $vulnItem = [System.Windows.Forms.ToolStripMenuItem]::new("&Vulnerability Report...")
    $vulnItem.Add_Click({ On-GenerateVulnerabilityReport })
    $reportsMenu.DropDownItems.AddRange(@($auditRptItem, [System.Windows.Forms.ToolStripSeparator]::new(), $morningItem, $siteItem, $timelineItem, $ffiecItem, $vulnItem))

    $diffItem = [System.Windows.Forms.ToolStripMenuItem]::new("&Diff / Compare...")
    $diffItem.Add_Click({ On-DiffCompare })

    $toolsMenu.DropDownItems.AddRange(@($regexItem, [System.Windows.Forms.ToolStripSeparator]::new(), $iocItem, [System.Windows.Forms.ToolStripSeparator]::new(), $analysisMenu, $reportsMenu, [System.Windows.Forms.ToolStripSeparator]::new(), $diffItem))

    # Investigations menu
    $investigationsMenu = [System.Windows.Forms.ToolStripMenuItem]::new("&Investigations")
    $Script:UI.InvestigationsMenu = $investigationsMenu
    # Will be populated by analysis/InvestigationTemplates.ps1 after loading

    # Connectors menu (v5.0)
    $connectorsMenu = [System.Windows.Forms.ToolStripMenuItem]::new("&Connectors")
    $connStatusItem = [System.Windows.Forms.ToolStripMenuItem]::new("Connection &Status...")
    $connStatusItem.Add_Click({ On-ConnectorStatus })
    $connectorsMenu.DropDownItems.Add($connStatusItem) | Out-Null
    $Script:UI.ConnectorsMenu = $connectorsMenu

    # Help menu
    $helpMenu = [System.Windows.Forms.ToolStripMenuItem]::new("&Help")
    $aboutItem = [System.Windows.Forms.ToolStripMenuItem]::new("&About")
    $aboutItem.Add_Click({
        [System.Windows.Forms.MessageBox]::Show(
            "Universal Log Parser v$($Config.Version)`n`nA sysadmin-grade log analysis tool.`nSupports 32 log formats, SQL query language, anomaly detection,`nlive connectors, network topology awareness, and automated triage.`n6 themes: Dark, Light, High Contrast, Solarized Dark, Nord, Monokai`n`nKeyboard Shortcuts:`nCtrl+O  Open file`nCtrl+R  Reload`nCtrl+F or /  Search`nCtrl+B  Toggle bookmark`nCtrl+D  Cycle theme`nCtrl+E  Export CSV`nCtrl+G  Go to line`nCtrl+T  Toggle tail mode`nCtrl+Plus/Minus  Font size`nDrag-and-drop to open files",
            "About", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information
        )
    })
    $helpMenu.DropDownItems.Add($aboutItem) | Out-Null

    $menuStrip.Items.AddRange(@($fileMenu, $viewMenu, $toolsMenu, $investigationsMenu, $connectorsMenu, $helpMenu))
    $form.MainMenuStrip = $menuStrip
    $form.Controls.Add($menuStrip)

    # --- Tool Strip ---
    $toolStrip = [System.Windows.Forms.ToolStrip]::new()
    $toolStrip.GripStyle = "Hidden"
    $btnOpen = [System.Windows.Forms.ToolStripButton]::new("Open")
    $btnOpen.ToolTipText = "Open log file (Ctrl+O)"
    $btnOpen.Add_Click({ On-OpenFile })
    $btnReload = [System.Windows.Forms.ToolStripButton]::new("Reload")
    $btnReload.ToolTipText = "Reload current file (Ctrl+R)"
    $btnReload.Add_Click({ On-ReloadFile })

    $Script:UI.BtnTail = [System.Windows.Forms.ToolStripButton]::new("Tail: OFF")
    $Script:UI.BtnTail.ToolTipText = "Toggle live tail mode (Ctrl+T)"
    $Script:UI.BtnTail.Add_Click({ On-TailToggle })

    $sepTs = [System.Windows.Forms.ToolStripSeparator]::new()
    $lblFormat = [System.Windows.Forms.ToolStripLabel]::new("Format:")
    $Script:UI.CmbFormat = [System.Windows.Forms.ToolStripComboBox]::new()
    $Script:UI.CmbFormat.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $Script:UI.CmbFormat.Items.AddRange(@("Auto-Detect"))
    foreach ($pid2 in $Script:Parsers.Keys) { $Script:UI.CmbFormat.Items.Add($Script:Parsers[$pid2].Name) | Out-Null }
    $Script:UI.CmbFormat.SelectedIndex = 0
    $Script:UI.CmbFormat.ToolTipText = "Select log format (or leave Auto-Detect)"

    $lblFile = [System.Windows.Forms.ToolStripLabel]::new("File:")
    $Script:UI.LblFilePath = [System.Windows.Forms.ToolStripLabel]::new("(none)")

    $sepTs2 = [System.Windows.Forms.ToolStripSeparator]::new()
    $btnParse = [System.Windows.Forms.ToolStripButton]::new("Parse")
    $btnParse.ToolTipText = "Parse the loaded file"
    $btnParse.Add_Click({ On-ParseClick })

    $toolStrip.Items.AddRange(@($btnOpen, $btnReload, $Script:UI.BtnTail, $sepTs, $lblFormat, $Script:UI.CmbFormat, $sepTs2, $lblFile, $Script:UI.LblFilePath, $btnParse))
    $form.Controls.Add($toolStrip)

    # --- Status Strip ---
    $statusStrip = [System.Windows.Forms.StatusStrip]::new()
    $Script:UI.StatusLabel = [System.Windows.Forms.ToolStripStatusLabel]::new("Ready")
    $Script:UI.StatusLabel.Spring = $false
    $Script:UI.StatusLabel.AutoSize = $true
    $Script:UI.StatusEntryCount = [System.Windows.Forms.ToolStripStatusLabel]::new("")
    $Script:UI.StatusBookmarkLabel = [System.Windows.Forms.ToolStripStatusLabel]::new("")
    $Script:UI.StatusFileLabel = [System.Windows.Forms.ToolStripStatusLabel]::new("")
    $Script:UI.StatusFileLabel.Spring = $true
    $Script:UI.ProgressBar = [System.Windows.Forms.ToolStripProgressBar]::new()
    $Script:UI.ProgressBar.Minimum = 0; $Script:UI.ProgressBar.Maximum = 100; $Script:UI.ProgressBar.Value = 0
    $statusStrip.Items.AddRange(@($Script:UI.StatusLabel, $Script:UI.StatusEntryCount, $Script:UI.StatusBookmarkLabel, $Script:UI.StatusFileLabel, $Script:UI.ProgressBar))
    $form.Controls.Add($statusStrip)

    # --- Query Bar (v5.0) ---
    $queryPanel = [System.Windows.Forms.Panel]::new()
    $queryPanel.Dock = [System.Windows.Forms.DockStyle]::Top
    $queryPanel.Height = 30
    $lblQuery = [System.Windows.Forms.Label]::new()
    $lblQuery.Text = "Query:"
    $lblQuery.AutoSize = $true
    $lblQuery.Location = [System.Drawing.Point]::new(5, 6)
    $Script:UI.TxtQuery = [System.Windows.Forms.TextBox]::new()
    $Script:UI.TxtQuery.Location = [System.Drawing.Point]::new(52, 3)
    $Script:UI.TxtQuery.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $Script:UI.TxtQuery.Width = $Config.DefaultWidth - 120
    $Script:UI.TxtQuery.Font = [System.Drawing.Font]::new("Consolas", 9.5)
    $btnRunQuery = [System.Windows.Forms.Button]::new()
    $btnRunQuery.Text = "Run"
    $btnRunQuery.Width = 50
    $btnRunQuery.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $btnRunQuery.Location = [System.Drawing.Point]::new($Config.DefaultWidth - 65, 2)
    $btnRunQuery.Add_Click({
        $query = $Script:UI.TxtQuery.Text
        if ([string]::IsNullOrWhiteSpace($query)) { return }
        try {
            $result = Invoke-QueryFilter -QueryString $query -Entries $Script:State.AllEntries
            if ($result -is [System.Collections.Generic.List[object]] -or $result -is [array]) {
                $Script:State.FilteredEntries = [System.Collections.Generic.List[object]]::new()
                foreach ($e in $result) { $Script:State.FilteredEntries.Add($e) }
                if ($Script:UI.DataGrid) {
                    $Script:UI.DataGrid.RowCount = $Script:State.FilteredEntries.Count
                    $Script:UI.DataGrid.Invalidate()
                }
                Update-StatusBar "Query returned $($Script:State.FilteredEntries.Count) results"
            } else {
                # Aggregation result — show in detail pane
                $Script:UI.DetailBox.Clear()
                $Script:UI.DetailBox.AppendText((Format-QueryResults $result))
                Update-StatusBar "Query aggregation complete"
            }
            Update-StatsBar
        } catch {
            Update-StatusBar "Query error: $_" -IsError
        }
    })
    $queryPanel.Controls.AddRange(@($lblQuery, $Script:UI.TxtQuery, $btnRunQuery))
    $form.Controls.Add($queryPanel)

    # --- Outer Split (Filter panel | Main area) ---
    $outerSplit = [System.Windows.Forms.SplitContainer]::new()
    $outerSplit.Dock = "Fill"
    $outerSplit.Orientation = "Vertical"
    $outerSplit.FixedPanel = "Panel1"
    $outerSplit.SplitterDistance = $Config.FilterPanelWidth
    $outerSplit.SplitterWidth = 4
    $Script:UI.OuterSplit = $outerSplit

    # --- Filter Panel (left) ---
    $filterPanel = [System.Windows.Forms.Panel]::new()
    $filterPanel.Dock = "Fill"
    $filterPanel.AutoScroll = $true
    $filterPanel.Padding = [System.Windows.Forms.Padding]::new(8)

    $y = 10
    $lw = 195  # label/control width

    # Search
    $lblSearch = [System.Windows.Forms.Label]::new()
    $lblSearch.Text = "Search:"; $lblSearch.Location = [System.Drawing.Point]::new(8, $y); $lblSearch.AutoSize = $true
    $filterPanel.Controls.Add($lblSearch); $y += 20

    $Script:UI.TxtSearch = [System.Windows.Forms.TextBox]::new()
    $Script:UI.TxtSearch.Location = [System.Drawing.Point]::new(8, $y); $Script:UI.TxtSearch.Width = $lw
    $filterPanel.Controls.Add($Script:UI.TxtSearch); $y += 26

    # Search debounce timer (300ms)
    $Script:UI.FilterDebounceTimer = [System.Windows.Forms.Timer]::new()
    $Script:UI.FilterDebounceTimer.Interval = 300
    $Script:UI.FilterDebounceTimer.Add_Tick({
        $Script:UI.FilterDebounceTimer.Stop()
        Invoke-ApplyFilters
        Update-StatsBar
    })

    $Script:UI.TxtSearch.Add_TextChanged({
        $Script:UI.FilterDebounceTimer.Stop()
        $Script:UI.FilterDebounceTimer.Start()
    })
    # Keep the Enter key handler for immediate apply
    $Script:UI.TxtSearch.Add_KeyDown({
        if ($_.KeyCode -eq 'Return') {
            $Script:UI.FilterDebounceTimer.Stop()
            Invoke-ApplyFilters; Update-StatsBar; $_.SuppressKeyPress = $true
        }
    })

    $Script:UI.RadText = [System.Windows.Forms.RadioButton]::new()
    $Script:UI.RadText.Text = "Text"; $Script:UI.RadText.Location = [System.Drawing.Point]::new(8, $y)
    $Script:UI.RadText.AutoSize = $true; $Script:UI.RadText.Checked = $true
    $Script:UI.RadRegex = [System.Windows.Forms.RadioButton]::new()
    $Script:UI.RadRegex.Text = "Regex"; $Script:UI.RadRegex.Location = [System.Drawing.Point]::new(80, $y)
    $Script:UI.RadRegex.AutoSize = $true
    $filterPanel.Controls.Add($Script:UI.RadText); $filterPanel.Controls.Add($Script:UI.RadRegex); $y += 28

    # Level filter
    $lblLevel = [System.Windows.Forms.Label]::new()
    $lblLevel.Text = "Level:"; $lblLevel.Location = [System.Drawing.Point]::new(8, $y); $lblLevel.AutoSize = $true
    $filterPanel.Controls.Add($lblLevel); $y += 20

    $Script:UI.CmbLevel = [System.Windows.Forms.ComboBox]::new()
    $Script:UI.CmbLevel.DropDownStyle = "DropDownList"
    $Script:UI.CmbLevel.Items.AddRange(@("ALL", "CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "TRACE"))
    $Script:UI.CmbLevel.SelectedIndex = 0
    $Script:UI.CmbLevel.Location = [System.Drawing.Point]::new(8, $y); $Script:UI.CmbLevel.Width = $lw
    $filterPanel.Controls.Add($Script:UI.CmbLevel); $y += 28

    # Auto-filter on CmbLevel change
    $Script:UI.CmbLevel.Add_SelectedIndexChanged({ $Script:UI.FilterDebounceTimer.Stop(); $Script:UI.FilterDebounceTimer.Start() })

    # Date range
    $lblFrom = [System.Windows.Forms.Label]::new()
    $lblFrom.Text = "From:"; $lblFrom.Location = [System.Drawing.Point]::new(8, $y); $lblFrom.AutoSize = $true
    $filterPanel.Controls.Add($lblFrom); $y += 20

    $Script:UI.DtpFrom = [System.Windows.Forms.DateTimePicker]::new()
    $Script:UI.DtpFrom.Location = [System.Drawing.Point]::new(8, $y); $Script:UI.DtpFrom.Width = $lw
    $Script:UI.DtpFrom.Format = "Custom"; $Script:UI.DtpFrom.CustomFormat = "yyyy-MM-dd HH:mm"
    $Script:UI.DtpFrom.ShowCheckBox = $true; $Script:UI.DtpFrom.Checked = $false
    $filterPanel.Controls.Add($Script:UI.DtpFrom); $y += 28

    # Auto-filter on DtpFrom change
    $Script:UI.DtpFrom.Add_ValueChanged({ if ($Script:UI.DtpFrom.Checked) { $Script:UI.FilterDebounceTimer.Stop(); $Script:UI.FilterDebounceTimer.Start() } })

    $lblTo = [System.Windows.Forms.Label]::new()
    $lblTo.Text = "To:"; $lblTo.Location = [System.Drawing.Point]::new(8, $y); $lblTo.AutoSize = $true
    $filterPanel.Controls.Add($lblTo); $y += 20

    $Script:UI.DtpTo = [System.Windows.Forms.DateTimePicker]::new()
    $Script:UI.DtpTo.Location = [System.Drawing.Point]::new(8, $y); $Script:UI.DtpTo.Width = $lw
    $Script:UI.DtpTo.Format = "Custom"; $Script:UI.DtpTo.CustomFormat = "yyyy-MM-dd HH:mm"
    $Script:UI.DtpTo.ShowCheckBox = $true; $Script:UI.DtpTo.Checked = $false
    $filterPanel.Controls.Add($Script:UI.DtpTo); $y += 28

    # Auto-filter on DtpTo change
    $Script:UI.DtpTo.Add_ValueChanged({ if ($Script:UI.DtpTo.Checked) { $Script:UI.FilterDebounceTimer.Stop(); $Script:UI.FilterDebounceTimer.Start() } })

    # Source filter
    $lblSource = [System.Windows.Forms.Label]::new()
    $lblSource.Text = "Source:"; $lblSource.Location = [System.Drawing.Point]::new(8, $y); $lblSource.AutoSize = $true
    $filterPanel.Controls.Add($lblSource); $y += 20

    $Script:UI.TxtSource = [System.Windows.Forms.TextBox]::new()
    $Script:UI.TxtSource.Location = [System.Drawing.Point]::new(8, $y); $Script:UI.TxtSource.Width = $lw
    $filterPanel.Controls.Add($Script:UI.TxtSource); $y += 30

    # Auto-filter on TxtSource change
    $Script:UI.TxtSource.Add_TextChanged({ $Script:UI.FilterDebounceTimer.Stop(); $Script:UI.FilterDebounceTimer.Start() })

    # Quick level checkboxes
    $lblQuick = [System.Windows.Forms.Label]::new()
    $lblQuick.Text = "Quick Levels:"; $lblQuick.Location = [System.Drawing.Point]::new(8, $y); $lblQuick.AutoSize = $true
    $filterPanel.Controls.Add($lblQuick); $y += 20

    $Script:UI.ChkCritical = [System.Windows.Forms.CheckBox]::new()
    $Script:UI.ChkCritical.Text = "CRITICAL"; $Script:UI.ChkCritical.Checked = $true
    $Script:UI.ChkCritical.Location = [System.Drawing.Point]::new(8, $y); $Script:UI.ChkCritical.AutoSize = $true
    $filterPanel.Controls.Add($Script:UI.ChkCritical); $y += 22
    $Script:UI.ChkCritical.Add_CheckedChanged({ $Script:UI.FilterDebounceTimer.Stop(); $Script:UI.FilterDebounceTimer.Start() })

    $Script:UI.ChkError = [System.Windows.Forms.CheckBox]::new()
    $Script:UI.ChkError.Text = "ERROR"; $Script:UI.ChkError.Checked = $true
    $Script:UI.ChkError.Location = [System.Drawing.Point]::new(8, $y); $Script:UI.ChkError.AutoSize = $true
    $filterPanel.Controls.Add($Script:UI.ChkError); $y += 22
    $Script:UI.ChkError.Add_CheckedChanged({ $Script:UI.FilterDebounceTimer.Stop(); $Script:UI.FilterDebounceTimer.Start() })

    $Script:UI.ChkWarning = [System.Windows.Forms.CheckBox]::new()
    $Script:UI.ChkWarning.Text = "WARNING"; $Script:UI.ChkWarning.Checked = $true
    $Script:UI.ChkWarning.Location = [System.Drawing.Point]::new(8, $y); $Script:UI.ChkWarning.AutoSize = $true
    $filterPanel.Controls.Add($Script:UI.ChkWarning); $y += 22
    $Script:UI.ChkWarning.Add_CheckedChanged({ $Script:UI.FilterDebounceTimer.Stop(); $Script:UI.FilterDebounceTimer.Start() })

    $Script:UI.ChkInfo = [System.Windows.Forms.CheckBox]::new()
    $Script:UI.ChkInfo.Text = "INFO"; $Script:UI.ChkInfo.Checked = $true
    $Script:UI.ChkInfo.Location = [System.Drawing.Point]::new(8, $y); $Script:UI.ChkInfo.AutoSize = $true
    $filterPanel.Controls.Add($Script:UI.ChkInfo); $y += 22
    $Script:UI.ChkInfo.Add_CheckedChanged({ $Script:UI.FilterDebounceTimer.Stop(); $Script:UI.FilterDebounceTimer.Start() })

    $Script:UI.ChkDebug = [System.Windows.Forms.CheckBox]::new()
    $Script:UI.ChkDebug.Text = "DEBUG"; $Script:UI.ChkDebug.Checked = $true
    $Script:UI.ChkDebug.Location = [System.Drawing.Point]::new(8, $y); $Script:UI.ChkDebug.AutoSize = $true
    $filterPanel.Controls.Add($Script:UI.ChkDebug); $y += 28
    $Script:UI.ChkDebug.Add_CheckedChanged({ $Script:UI.FilterDebounceTimer.Stop(); $Script:UI.FilterDebounceTimer.Start() })

    # Bookmarks only
    $Script:UI.ChkBookmarksOnly = [System.Windows.Forms.CheckBox]::new()
    $Script:UI.ChkBookmarksOnly.Text = "Bookmarks only"; $Script:UI.ChkBookmarksOnly.Checked = $false
    $Script:UI.ChkBookmarksOnly.Location = [System.Drawing.Point]::new(8, $y); $Script:UI.ChkBookmarksOnly.AutoSize = $true
    $filterPanel.Controls.Add($Script:UI.ChkBookmarksOnly); $y += 30
    $Script:UI.ChkBookmarksOnly.Add_CheckedChanged({ $Script:UI.FilterDebounceTimer.Stop(); $Script:UI.FilterDebounceTimer.Start() })

    # Apply / Clear buttons
    $btnApply = [System.Windows.Forms.Button]::new()
    $btnApply.Text = "Apply"; $btnApply.Location = [System.Drawing.Point]::new(8, $y)
    $btnApply.Size = [System.Drawing.Size]::new(90, 28)
    $btnApply.Add_Click({ Invoke-ApplyFilters; Update-StatsBar })

    $btnClear = [System.Windows.Forms.Button]::new()
    $btnClear.Text = "Clear"; $btnClear.Location = [System.Drawing.Point]::new(105, $y)
    $btnClear.Size = [System.Drawing.Size]::new(90, 28)
    $btnClear.Add_Click({
        $Script:UI.TxtSearch.Text = ""
        $Script:UI.TxtSource.Text = ""
        $Script:UI.CmbLevel.SelectedIndex = 0
        $Script:UI.DtpFrom.Checked = $false
        $Script:UI.DtpTo.Checked = $false
        $Script:UI.ChkCritical.Checked = $true; $Script:UI.ChkError.Checked = $true
        $Script:UI.ChkWarning.Checked = $true; $Script:UI.ChkInfo.Checked = $true
        $Script:UI.ChkDebug.Checked = $true
        $Script:UI.ChkBookmarksOnly.Checked = $false
        $Script:UI.RadText.Checked = $true
        Invoke-ApplyFilters; Update-StatsBar
    })
    $filterPanel.Controls.Add($btnApply); $filterPanel.Controls.Add($btnClear); $y += 35

    # Profile buttons
    $lblProfiles = [System.Windows.Forms.Label]::new()
    $lblProfiles.Text = "--- Profiles ---"; $lblProfiles.Location = [System.Drawing.Point]::new(8, $y); $lblProfiles.AutoSize = $true
    $filterPanel.Controls.Add($lblProfiles); $y += 22

    $btnSaveProfile = [System.Windows.Forms.Button]::new()
    $btnSaveProfile.Text = "Save Query"; $btnSaveProfile.Location = [System.Drawing.Point]::new(8, $y)
    $btnSaveProfile.Size = [System.Drawing.Size]::new(90, 28)
    $btnSaveProfile.Add_Click({ Save-FilterProfile })

    $btnLoadProfile = [System.Windows.Forms.Button]::new()
    $btnLoadProfile.Text = "Load Query"; $btnLoadProfile.Location = [System.Drawing.Point]::new(105, $y)
    $btnLoadProfile.Size = [System.Drawing.Size]::new(90, 28)
    $btnLoadProfile.Add_Click({ Load-FilterProfile })
    $filterPanel.Controls.Add($btnSaveProfile); $filterPanel.Controls.Add($btnLoadProfile); $y += 35

    # Bookmark section
    $lblBookmarks = [System.Windows.Forms.Label]::new()
    $lblBookmarks.Text = "--- Bookmarks ---"; $lblBookmarks.Location = [System.Drawing.Point]::new(8, $y); $lblBookmarks.AutoSize = $true
    $filterPanel.Controls.Add($lblBookmarks); $y += 22

    $Script:UI.BookmarkCountLabel = [System.Windows.Forms.Label]::new()
    $Script:UI.BookmarkCountLabel.Text = "Bookmarks: 0"; $Script:UI.BookmarkCountLabel.Location = [System.Drawing.Point]::new(8, $y); $Script:UI.BookmarkCountLabel.AutoSize = $true
    $filterPanel.Controls.Add($Script:UI.BookmarkCountLabel); $y += 22

    $btnGoTo = [System.Windows.Forms.Button]::new()
    $btnGoTo.Text = "Go To"; $btnGoTo.Location = [System.Drawing.Point]::new(8, $y)
    $btnGoTo.Size = [System.Drawing.Size]::new(90, 28); $btnGoTo.Add_Click({ Show-BookmarkList })
    $btnClearBm = [System.Windows.Forms.Button]::new()
    $btnClearBm.Text = "Clear All"; $btnClearBm.Location = [System.Drawing.Point]::new(105, $y)
    $btnClearBm.Size = [System.Drawing.Size]::new(90, 28)
    $btnClearBm.Add_Click({
        foreach ($e in $Script:State.AllEntries) { $e.Bookmarked = $false }
        $Script:State.BookmarkedSet.Clear()
        $Script:UI.DataGrid.Invalidate()
        Update-BookmarkCount
    })
    $filterPanel.Controls.Add($btnGoTo); $filterPanel.Controls.Add($btnClearBm)

    $outerSplit.Panel1.Controls.Add($filterPanel)

    # --- Inner Split (Grid | Detail pane) ---
    $innerSplit = [System.Windows.Forms.SplitContainer]::new()
    $innerSplit.Dock = "Fill"
    $innerSplit.Orientation = "Horizontal"
    $innerSplit.SplitterDistance = $Config.DefaultHeight - $Config.DetailPaneHeight - 200
    $innerSplit.SplitterWidth = 4
    $Script:UI.InnerSplit = $innerSplit

    # --- Stats Panel ---
    $statsPanel = [System.Windows.Forms.FlowLayoutPanel]::new()
    $statsPanel.Dock = "Top"
    $statsPanel.Height = 24
    $statsPanel.WrapContents = $false
    $Script:UI.StatsLabel = [System.Windows.Forms.Label]::new()
    $Script:UI.StatsLabel.AutoSize = $true
    $Script:UI.StatsLabel.Text = ""
    $Script:UI.StatsLabel.Font = [System.Drawing.Font]::new("Consolas", 8.5)
    $statsPanel.Controls.Add($Script:UI.StatsLabel)
    $Script:UI.StatsPanel = $statsPanel

    # --- DataGridView ---
    $grid = [System.Windows.Forms.DataGridView]::new()
    $grid.Dock = "Fill"
    $grid.VirtualMode = $true
    $grid.ReadOnly = $true
    $grid.AllowUserToAddRows = $false
    $grid.AllowUserToDeleteRows = $false
    $grid.AllowUserToResizeRows = $false
    $grid.SelectionMode = "FullRowSelect"
    $grid.MultiSelect = $true
    $grid.RowHeadersVisible = $false
    $grid.ColumnHeadersHeightSizeMode = "AutoSize"
    $grid.AutoSizeColumnsMode = "None"
    $grid.DoubleBuffered = $true  # Requires reflection for DataGridView
    # Enable double buffering via reflection
    $dgvType = $grid.GetType()
    $pi = $dgvType.GetProperty("DoubleBuffered", [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic)
    if ($pi) { $pi.SetValue($grid, $true) }

    # Columns: Star, #, Timestamp, Level, Source, Message
    $colStar = [System.Windows.Forms.DataGridViewTextBoxColumn]::new()
    $colStar.Name = "Star"; $colStar.HeaderText = [string][char]0x2605; $colStar.Width = 28; $colStar.SortMode = "NotSortable"; $colStar.Resizable = "False"
    $colIdx = [System.Windows.Forms.DataGridViewTextBoxColumn]::new()
    $colIdx.Name = "Index"; $colIdx.HeaderText = "#"; $colIdx.Width = 60
    $colTs = [System.Windows.Forms.DataGridViewTextBoxColumn]::new()
    $colTs.Name = "Timestamp"; $colTs.HeaderText = "Timestamp"; $colTs.Width = 150
    $colLevel = [System.Windows.Forms.DataGridViewTextBoxColumn]::new()
    $colLevel.Name = "Level"; $colLevel.HeaderText = "Level"; $colLevel.Width = 80
    $colSource = [System.Windows.Forms.DataGridViewTextBoxColumn]::new()
    $colSource.Name = "Source"; $colSource.HeaderText = "Source"; $colSource.Width = 120
    $colMsg = [System.Windows.Forms.DataGridViewTextBoxColumn]::new()
    $colMsg.Name = "Message"; $colMsg.HeaderText = "Message"; $colMsg.AutoSizeMode = "Fill"

    $grid.Columns.AddRange(@($colStar, $colIdx, $colTs, $colLevel, $colSource, $colMsg))

    # Column width persistence: restore saved widths
    if ($Script:State.ColumnWidths.Count -gt 0) {
        foreach ($col in $grid.Columns) {
            if ($Script:State.ColumnWidths.ContainsKey($col.Name)) {
                $col.Width = $Script:State.ColumnWidths[$col.Name]
            }
        }
    }
    # Save widths on column resize
    $grid.Add_ColumnWidthChanged({
        param($sender, $e)
        $col = $grid.Columns[$e.Column.Index]
        $Script:State.ColumnWidths[$col.Name] = $col.Width
    })

    # Virtual mode: CellValueNeeded
    $grid.Add_CellValueNeeded({
        param($sender, $e)
        if ($e.RowIndex -ge $Script:State.FilteredEntries.Count) { return }
        $entry = $Script:State.FilteredEntries[$e.RowIndex]
        switch ($e.ColumnIndex) {
            0 { $e.Value = if ($entry.Bookmarked) { [string][char]0x2605 } else { "" } }
            1 { $e.Value = $entry.Index }
            2 { $e.Value = if ($entry.Timestamp -ne [datetime]::MinValue) { $entry.Timestamp.ToString("yyyy-MM-dd HH:mm:ss") } else { "" } }
            3 { $e.Value = $entry.Level }
            4 { $e.Value = $entry.Source }
            5 { $e.Value = $entry.Message.Split("`n")[0] }
        }
    })

    # CellPainting: severity colors + bookmark star
    $grid.Add_CellFormatting({
        param($sender, $e)
        if ($e.RowIndex -lt 0 -or $e.RowIndex -ge $Script:State.FilteredEntries.Count) { return }
        $entry = $Script:State.FilteredEntries[$e.RowIndex]
        $t = $Script:Themes[$Script:State.ActiveTheme]
        $sevColors = $t.SeverityColors

        if ($sevColors.ContainsKey($entry.Level)) {
            $sc = $sevColors[$entry.Level]
            if ($sc.Back) { $e.CellStyle.BackColor = $sc.Back }
            if ($sc.Fore) { $e.CellStyle.ForeColor = $sc.Fore }
        }

        # Star column color
        if ($e.ColumnIndex -eq 0 -and $entry.Bookmarked) {
            $e.CellStyle.ForeColor = [System.Drawing.Color]::Gold
        }
    })

    # Selection changed -> populate detail pane
    $grid.Add_SelectionChanged({
        if ($Script:UI.DataGrid.SelectedRows.Count -eq 0) { return }
        $idx = $Script:UI.DataGrid.SelectedRows[0].Index
        if ($idx -ge $Script:State.FilteredEntries.Count) { return }
        $entry = $Script:State.FilteredEntries[$idx]
        Populate-DetailPane $entry
    })

    # Column header click -> sort
    $grid.Add_ColumnHeaderMouseClick({
        param($sender, $e)
        if ($e.ColumnIndex -le 0) { return }  # Skip star column
        On-GridColumnHeaderClick $e.ColumnIndex
    })

    # Click on star column -> toggle bookmark
    $grid.Add_CellClick({
        param($sender, $e)
        if ($e.ColumnIndex -eq 0 -and $e.RowIndex -ge 0) {
            Toggle-Bookmark $e.RowIndex
        }
    })

    # Right-click context menu (extracted to ContextMenu.ps1)
    $grid.ContextMenuStrip = New-GridContextMenu $grid

    # Font size adjustment (Ctrl+Plus/Minus/MouseWheel)
    $grid.Add_KeyDown({
        param($sender, $e)
        if ($e.Control -and ($e.KeyCode -eq 'Oemplus' -or $e.KeyCode -eq 'Add')) {
            $Script:State.FontSize = [Math]::Min(20, $Script:State.FontSize + 1)
            $grid.DefaultCellStyle.Font = [System.Drawing.Font]::new("Segoe UI", $Script:State.FontSize)
            $grid.AlternatingRowsDefaultCellStyle.Font = $grid.DefaultCellStyle.Font
            $e.Handled = $true
        }
        if ($e.Control -and ($e.KeyCode -eq 'OemMinus' -or $e.KeyCode -eq 'Subtract')) {
            $Script:State.FontSize = [Math]::Max(6, $Script:State.FontSize - 1)
            $grid.DefaultCellStyle.Font = [System.Drawing.Font]::new("Segoe UI", $Script:State.FontSize)
            $grid.AlternatingRowsDefaultCellStyle.Font = $grid.DefaultCellStyle.Font
            $e.Handled = $true
        }
    })
    $grid.Add_MouseWheel({
        param($sender, $e)
        if ([System.Windows.Forms.Control]::ModifierKeys -eq [System.Windows.Forms.Keys]::Control) {
            $delta = if ($e.Delta -gt 0) { 1 } else { -1 }
            $Script:State.FontSize = [Math]::Max(6, [Math]::Min(20, $Script:State.FontSize + $delta))
            $grid.DefaultCellStyle.Font = [System.Drawing.Font]::new("Segoe UI", $Script:State.FontSize)
            $grid.AlternatingRowsDefaultCellStyle.Font = $grid.DefaultCellStyle.Font
        }
    })

    $Script:UI.DataGrid = $grid

    # Assemble inner split: grid on top, detail on bottom
    $gridPanel = [System.Windows.Forms.Panel]::new()
    $gridPanel.Dock = "Fill"
    $gridPanel.Controls.Add($grid)
    $gridPanel.Controls.Add($statsPanel)
    $statsPanel.BringToFront()
    $grid.BringToFront()

    $innerSplit.Panel1.Controls.Add($gridPanel)

    # --- Detail Pane ---
    $detailBox = [System.Windows.Forms.RichTextBox]::new()
    $detailBox.Dock = "Fill"
    $detailBox.ReadOnly = $true
    $detailBox.Font = [System.Drawing.Font]::new("Consolas", 9.5)
    $detailBox.WordWrap = $true
    $detailBox.BorderStyle = "None"
    $Script:UI.DetailBox = $detailBox
    $innerSplit.Panel2.Controls.Add($detailBox)

    $outerSplit.Panel2.Controls.Add($innerSplit)
    $form.Controls.Add($outerSplit)

    # Ensure proper z-order
    $outerSplit.BringToFront()

    # --- Drain Timer (for background parse results) ---
    $drainTimer = [System.Windows.Forms.Timer]::new()
    $drainTimer.Interval = $Config.DrainTimerMs
    $drainTimer.Add_Tick({ Receive-ParseResults })
    $drainTimer.Start()
    $Script:State.DrainTimer = $drainTimer

    # --- Keyboard shortcuts ---
    $form.Add_KeyDown({
        param($sender, $e)
        # Ctrl+F or / -> focus search
        if (($e.Control -and $e.KeyCode -eq 'F') -or ($e.KeyCode -eq 'OemQuestion' -and -not $e.Shift -and -not $e.Control -and $form.ActiveControl -ne $Script:UI.TxtSearch)) {
            $Script:UI.TxtSearch.Focus(); $e.Handled = $true; $e.SuppressKeyPress = $true
        }
        # Ctrl+B -> toggle bookmark
        if ($e.Control -and $e.KeyCode -eq 'B') {
            if ($Script:UI.DataGrid.SelectedRows.Count -gt 0) { Toggle-Bookmark $Script:UI.DataGrid.SelectedRows[0].Index }
            $e.Handled = $true
        }
        # Ctrl+Down -> next bookmark
        if ($e.Control -and $e.KeyCode -eq 'Down') {
            $current = if ($Script:UI.DataGrid.SelectedRows.Count -gt 0) { $Script:UI.DataGrid.SelectedRows[0].Index } else { -1 }
            $next = Get-NextBookmark $current
            if ($next -ge 0) { $Script:UI.DataGrid.ClearSelection(); $Script:UI.DataGrid.Rows[$next].Selected = $true; $Script:UI.DataGrid.FirstDisplayedScrollingRowIndex = $next }
            $e.Handled = $true
        }
        # Ctrl+Up -> prev bookmark
        if ($e.Control -and $e.KeyCode -eq 'Up') {
            $current = if ($Script:UI.DataGrid.SelectedRows.Count -gt 0) { $Script:UI.DataGrid.SelectedRows[0].Index } else { 0 }
            $prev = Get-PreviousBookmark $current
            if ($prev -ge 0) { $Script:UI.DataGrid.ClearSelection(); $Script:UI.DataGrid.Rows[$prev].Selected = $true; $Script:UI.DataGrid.FirstDisplayedScrollingRowIndex = $prev }
            $e.Handled = $true
        }
        # Ctrl+T -> toggle tail
        if ($e.Control -and $e.KeyCode -eq 'T') {
            On-TailToggle; $e.Handled = $true
        }
        # Ctrl+C -> copy
        if ($e.Control -and $e.KeyCode -eq 'C' -and -not $Script:UI.DetailBox.Focused) {
            Copy-SelectionToClipboard; $e.Handled = $true; $e.SuppressKeyPress = $true
        }
        # Ctrl+Shift+S -> save profile
        if ($e.Control -and $e.Shift -and $e.KeyCode -eq 'S') {
            Save-FilterProfile; $e.Handled = $true
        }
        # F5 -> reload
        if ($e.KeyCode -eq 'F5') { On-ReloadFile; $e.Handled = $true }
        # Escape -> clear search or close
        if ($e.KeyCode -eq 'Escape') {
            if ($Script:UI.TxtSearch.Focused) { $Script:UI.TxtSearch.Text = ""; $Script:UI.DataGrid.Focus() }
            $e.Handled = $true
        }
        # Home/End -> jump to first/last
        if ($e.KeyCode -eq 'Home' -and -not $e.Control -and $Script:UI.DataGrid.Focused) {
            if ($Script:UI.DataGrid.RowCount -gt 0) { $Script:UI.DataGrid.ClearSelection(); $Script:UI.DataGrid.FirstDisplayedScrollingRowIndex = 0; $Script:UI.DataGrid.Rows[0].Selected = $true }
        }
        if ($e.KeyCode -eq 'End' -and -not $e.Control -and $Script:UI.DataGrid.Focused) {
            $last = $Script:UI.DataGrid.RowCount - 1
            if ($last -ge 0) { $Script:UI.DataGrid.ClearSelection(); $Script:UI.DataGrid.FirstDisplayedScrollingRowIndex = $last; $Script:UI.DataGrid.Rows[$last].Selected = $true }
        }
    })

    # --- Form Closing ---
    $form.Add_FormClosing({
        Stop-TailMode
        Stop-ParseRunspace
        if ($Script:State.DrainTimer) { $Script:State.DrainTimer.Stop(); $Script:State.DrainTimer.Dispose() }
        if ($Script:UI.FilterDebounceTimer) { $Script:UI.FilterDebounceTimer.Stop(); $Script:UI.FilterDebounceTimer.Dispose() }
        Save-Settings
        if (Test-Path $Config.TempDir) {
            try { Remove-Item $Config.TempDir -Recurse -Force -ErrorAction SilentlyContinue } catch { }
        }
    })

    return $form
}
