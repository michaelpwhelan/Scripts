# ═══════════════════════════════════════════════════════════════════════════════
# PROFILES & PERSISTENCE
# ═══════════════════════════════════════════════════════════════════════════════

function Get-SettingsPath {
    $dir = if ($Script:IsWindowsOS -and $env:APPDATA) { Join-Path $env:APPDATA "LogParser" } else { Join-Path $HOME ".config/LogParser" }
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    return Join-Path $dir "settings.json"
}

function Save-Settings {
    try {
        $settings = @{
            theme = $Script:State.ActiveTheme
            recentFiles = @($Script:State.RecentFiles)
            filterProfiles = @($Script:State.FilterProfiles)
            fontSize = $Script:State.FontSize
            columnWidths = $Script:State.ColumnWidths
            lastWindowSize = @{
                width = $Script:UI.Form.Width
                height = $Script:UI.Form.Height
            }
            lastSplitterPositions = @{
                outer = $Script:UI.OuterSplit.SplitterDistance
                inner = $Script:UI.InnerSplit.SplitterDistance
            }
            lastFormatOverride = $Script:State.Format
        }
        $json = $settings | ConvertTo-Json -Depth 4
        [System.IO.File]::WriteAllText((Get-SettingsPath), $json)
    } catch {
        Write-Log "Failed to save settings: $_" -Level WARNING
    }
}

function Load-Settings {
    $path = Get-SettingsPath
    if (-not (Test-Path $path)) { return }
    try {
        $json = [System.IO.File]::ReadAllText($path)
        $settings = $json | ConvertFrom-Json
        if ($settings.theme) { $Script:State.ActiveTheme = $settings.theme }
        if ($settings.recentFiles) {
            $Script:State.RecentFiles.Clear()
            foreach ($f in $settings.recentFiles) { $Script:State.RecentFiles.Add($f) }
        }
        if ($settings.filterProfiles) {
            $Script:State.FilterProfiles = @($settings.filterProfiles)
        }
        if ($settings.fontSize) { $Script:State.FontSize = $settings.fontSize }
        if ($settings.columnWidths) {
            $settings.columnWidths.PSObject.Properties | ForEach-Object {
                $Script:State.ColumnWidths[$_.Name] = $_.Value
            }
        }
        if ($settings.lastWindowSize -and $Script:UI.Form) {
            $Script:UI.Form.Width = $settings.lastWindowSize.width
            $Script:UI.Form.Height = $settings.lastWindowSize.height
        }
        if ($settings.lastSplitterPositions -and $Script:UI.OuterSplit) {
            try {
                $Script:UI.OuterSplit.SplitterDistance = $settings.lastSplitterPositions.outer
                $Script:UI.InnerSplit.SplitterDistance = $settings.lastSplitterPositions.inner
            } catch { }
        }
    } catch {
        Write-Log "Failed to load settings: $_" -Level WARNING
    }
}

function Add-RecentFile {
    param([string]$Path)
    $Script:State.RecentFiles.Remove($Path) | Out-Null
    $Script:State.RecentFiles.Insert(0, $Path)
    while ($Script:State.RecentFiles.Count -gt 10) { $Script:State.RecentFiles.RemoveAt(10) }
    Update-RecentFilesMenu
}

function Save-FilterProfile {
    $name = [Microsoft.VisualBasic.Interaction]::InputBox("Enter profile name:", "Save Filter Profile", "")
    if ([string]::IsNullOrWhiteSpace($name)) { return }
    $profile = Get-FilterState
    $profile['Name'] = $name
    if (-not $Script:State.FilterProfiles) { $Script:State.FilterProfiles = @() }
    $Script:State.FilterProfiles = @($Script:State.FilterProfiles | Where-Object { $_.Name -ne $name }) + @($profile)
    Save-Settings
    Update-StatusBar "Profile '$name' saved"
}

function Load-FilterProfile {
    if (-not $Script:State.FilterProfiles -or $Script:State.FilterProfiles.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No saved profiles.", "Load Profile", [System.Windows.Forms.MessageBoxButtons]::OK)
        return
    }
    $dlg = [System.Windows.Forms.Form]::new()
    $dlg.Text = "Load Filter Profile"; $dlg.Size = [System.Drawing.Size]::new(300, 200); $dlg.StartPosition = "CenterParent"
    $t = $Script:Themes[$Script:State.ActiveTheme]
    $dlg.BackColor = $t.FormBack; $dlg.ForeColor = $t.FormFore

    $lb = [System.Windows.Forms.ListBox]::new()
    $lb.Dock = "Fill"; $lb.BackColor = $t.DetailBack; $lb.ForeColor = $t.DetailFore
    foreach ($p in $Script:State.FilterProfiles) { $lb.Items.Add($p.Name) | Out-Null }
    $lb.Add_DoubleClick({
        $sel = $lb.SelectedIndex
        if ($sel -ge 0) {
            $prof = $Script:State.FilterProfiles[$sel]
            # Apply profile to controls
            $Script:UI.TxtSearch.Text = if ($prof.SearchText) { $prof.SearchText } else { "" }
            $Script:UI.RadRegex.Checked = [bool]$prof.UseRegex
            $Script:UI.RadText.Checked = -not [bool]$prof.UseRegex
            if ($prof.Levels) {
                $levels = @($prof.Levels)
                $Script:UI.ChkCritical.Checked = "CRITICAL" -in $levels
                $Script:UI.ChkError.Checked = "ERROR" -in $levels
                $Script:UI.ChkWarning.Checked = "WARNING" -in $levels
                $Script:UI.ChkInfo.Checked = "INFO" -in $levels
                $Script:UI.ChkDebug.Checked = "DEBUG" -in $levels
            }
            $Script:UI.TxtSource.Text = if ($prof.Source) { $prof.Source } else { "" }
            Invoke-ApplyFilters
            Update-StatsBar
            $dlg.Close()
        }
    })
    $dlg.Controls.Add($lb)
    $dlg.ShowDialog($Script:UI.Form) | Out-Null
    $dlg.Dispose()
}
