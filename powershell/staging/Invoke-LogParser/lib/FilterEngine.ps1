# ═══════════════════════════════════════════════════════════════════════════════
# FILTER ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

function Get-FilterState {
    $levels = [System.Collections.Generic.List[string]]::new()
    if ($Script:UI.ChkCritical.Checked) { $levels.Add("CRITICAL") }
    if ($Script:UI.ChkError.Checked) { $levels.Add("ERROR") }
    if ($Script:UI.ChkWarning.Checked) { $levels.Add("WARNING") }
    if ($Script:UI.ChkInfo.Checked) { $levels.Add("INFO") }
    if ($Script:UI.ChkDebug.Checked) { $levels.Add("DEBUG") }
    # If level dropdown is not ALL, use it
    $ddLevel = $Script:UI.CmbLevel.SelectedItem
    if ($ddLevel -and $ddLevel -ne "ALL" -and $levels.Count -eq 5) {
        $levels.Clear(); $levels.Add($ddLevel)
    }

    return @{
        SearchText  = $Script:UI.TxtSearch.Text
        UseRegex    = $Script:UI.RadRegex.Checked
        Levels      = $levels
        DateFrom    = if ($Script:UI.DtpFrom.Checked) { $Script:UI.DtpFrom.Value } else { $null }
        DateTo      = if ($Script:UI.DtpTo.Checked) { $Script:UI.DtpTo.Value.Date.AddDays(1).AddSeconds(-1) } else { $null }
        Source      = $Script:UI.TxtSource.Text
        BookmarksOnly = $Script:UI.ChkBookmarksOnly.Checked
    }
}

function Invoke-ApplyFilters {
    # For GUI mode, read filter state from controls
    if (-not $Script:UseConsole -and $Script:UI.DataGrid) {
        $filter = Get-FilterState
    } else {
        return  # Console mode uses its own filtering in Invoke-ConsoleMode
    }

    # Build into new list (FIXES race condition — old code did Clear() leaving RowCount out of sync)
    $newFiltered = [System.Collections.Generic.List[object]]::new()

    $hasSearch = -not [string]::IsNullOrWhiteSpace($filter.SearchText)
    $hasSource = -not [string]::IsNullOrWhiteSpace($filter.Source)
    $hasDateFrom = $null -ne $filter.DateFrom
    $hasDateTo = $null -ne $filter.DateTo
    $levelSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$filter.Levels, [System.StringComparer]::OrdinalIgnoreCase)
    $allLevels = $levelSet.Count -ge 5
    $searchUpper = if ($hasSearch) { $filter.SearchText.ToUpper() } else { "" }

    # FIX: Cache compiled regex instead of recompiling every filter run
    $regex = $null
    if ($hasSearch -and $filter.UseRegex) {
        $cacheKey = $filter.SearchText
        if ($Script:State.RegexCache.ContainsKey($cacheKey)) {
            $regex = $Script:State.RegexCache[$cacheKey]
        } else {
            try {
                $regex = [regex]::new($filter.SearchText, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled)
                $Script:State.RegexCache[$cacheKey] = $regex
            } catch {
                if ($Script:UI.TxtSearch) {
                    $Script:UI.TxtSearch.BackColor = [System.Drawing.Color]::FromArgb(255, 200, 200)
                }
                return
            }
        }
    }
    if ($Script:UI.TxtSearch -and $Script:UI.TxtSearch.BackColor.R -eq 255 -and $Script:UI.TxtSearch.BackColor.G -eq 200) {
        $Script:UI.TxtSearch.BackColor = $Script:Themes[$Script:State.ActiveTheme].TextBoxBack
    }

    foreach ($entry in $Script:State.AllEntries) {
        if (-not $allLevels -and -not $levelSet.Contains($entry.Level)) { continue }
        if ($filter.BookmarksOnly -and -not $entry.Bookmarked) { continue }
        if ($entry.Timestamp -ne [datetime]::MinValue) {
            if ($hasDateFrom -and $entry.Timestamp -lt $filter.DateFrom) { continue }
            if ($hasDateTo -and $entry.Timestamp -gt $filter.DateTo) { continue }
        }
        if ($hasSource) {
            if (-not $entry.Source -or $entry.Source.IndexOf($filter.Source, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        }
        if ($hasSearch) {
            if ($regex) {
                if (-not ($regex.IsMatch($entry.Message) -or $regex.IsMatch($entry.RawLine) -or $regex.IsMatch($entry.Source))) { continue }
            } else {
                $msgUp = $entry.Message.ToUpper()
                $rawUp = $entry.RawLine.ToUpper()
                $srcUp = $entry.Source.ToUpper()
                if (-not ($msgUp.Contains($searchUpper) -or $rawUp.Contains($searchUpper) -or $srcUp.Contains($searchUpper))) { continue }
            }
        }
        $newFiltered.Add($entry)
    }

    # Atomic swap (FIX: prevents race condition)
    if ($Script:UI.DataGrid) {
        $Script:UI.DataGrid.RowCount = 0
    }
    $Script:State.FilteredEntries = $newFiltered
    if ($Script:UI.DataGrid) {
        $Script:UI.DataGrid.RowCount = $newFiltered.Count
        if ($newFiltered.Count -gt 0) { $Script:UI.DataGrid.Invalidate() }
    }

    Update-StatusBar "Showing $($newFiltered.Count) of $($Script:State.AllEntries.Count) entries"
}

function Load-PresetFilterProfiles {
    $profilePath = Join-Path $Config.ScriptRoot "data" "filter-profiles.json"
    if (-not (Test-Path $profilePath)) { return }
    try {
        $content = [System.IO.File]::ReadAllText($profilePath)
        $Script:State.PresetFilterProfiles = ($content | ConvertFrom-Json)
        Write-Log "Loaded $($Script:State.PresetFilterProfiles.Count) preset filter profiles"
    } catch {
        Write-Log "Failed to load filter profiles: $_" -Level WARNING
    }
}
