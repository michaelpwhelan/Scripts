# ═══════════════════════════════════════════════════════════════════════════════
# BOOKMARKS
# ═══════════════════════════════════════════════════════════════════════════════

function Toggle-Bookmark {
    param([int]$FilteredIndex)
    if ($FilteredIndex -lt 0 -or $FilteredIndex -ge $Script:State.FilteredEntries.Count) { return }
    $entry = $Script:State.FilteredEntries[$FilteredIndex]
    $entry.Bookmarked = -not $entry.Bookmarked
    if ($entry.Bookmarked) {
        $Script:State.BookmarkedSet.Add($entry.Index) | Out-Null
    } else {
        $Script:State.BookmarkedSet.Remove($entry.Index) | Out-Null
    }
    $Script:UI.DataGrid.InvalidateRow($FilteredIndex)
    Update-BookmarkCount
}

function Get-NextBookmark {
    param([int]$CurrentIndex)
    for ($i = $CurrentIndex + 1; $i -lt $Script:State.FilteredEntries.Count; $i++) {
        if ($Script:State.FilteredEntries[$i].Bookmarked) { return $i }
    }
    # Wrap around
    for ($i = 0; $i -lt $CurrentIndex; $i++) {
        if ($Script:State.FilteredEntries[$i].Bookmarked) { return $i }
    }
    return -1
}

function Get-PreviousBookmark {
    param([int]$CurrentIndex)
    for ($i = $CurrentIndex - 1; $i -ge 0; $i--) {
        if ($Script:State.FilteredEntries[$i].Bookmarked) { return $i }
    }
    for ($i = $Script:State.FilteredEntries.Count - 1; $i -gt $CurrentIndex; $i--) {
        if ($Script:State.FilteredEntries[$i].Bookmarked) { return $i }
    }
    return -1
}

function Update-BookmarkCount {
    $count = $Script:State.BookmarkedSet.Count
    $Script:UI.BookmarkCountLabel.Text = "Bookmarks: $count"
    $Script:UI.StatusBookmarkLabel.Text = if ($count -gt 0) { [char]0x2605 + "$count bookmarked" } else { "" }
}

function Show-BookmarkList {
    $bookmarks = $Script:State.FilteredEntries | Where-Object { $_.Bookmarked }
    if (-not $bookmarks -or @($bookmarks).Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No bookmarked entries.", "Bookmarks", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
        return
    }

    $dlg = [System.Windows.Forms.Form]::new()
    $dlg.Text = "Bookmarked Entries"
    $dlg.Size = [System.Drawing.Size]::new(600, 400)
    $dlg.StartPosition = "CenterParent"
    $t = $Script:Themes[$Script:State.ActiveTheme]
    $dlg.BackColor = $t.FormBack; $dlg.ForeColor = $t.FormFore

    $lb = [System.Windows.Forms.ListBox]::new()
    $lb.Dock = "Fill"; $lb.BackColor = $t.DetailBack; $lb.ForeColor = $t.DetailFore
    $lb.Font = [System.Drawing.Font]::new("Consolas", 9)
    foreach ($b in $bookmarks) {
        $lb.Items.Add("#$($b.Index) [$($b.Level)] $($b.Message.Substring(0, [Math]::Min(80, $b.Message.Length)))") | Out-Null
    }
    $lb.Add_DoubleClick({
        $sel = $lb.SelectedIndex
        if ($sel -ge 0) {
            $bm = @($bookmarks)[$sel]
            $gridIdx = $Script:State.FilteredEntries.IndexOf($bm)
            if ($gridIdx -ge 0) {
                $Script:UI.DataGrid.ClearSelection()
                $Script:UI.DataGrid.FirstDisplayedScrollingRowIndex = $gridIdx
                $Script:UI.DataGrid.Rows[$gridIdx].Selected = $true
            }
            $dlg.Close()
        }
    })
    $dlg.Controls.Add($lb)
    $dlg.ShowDialog($Script:UI.Form) | Out-Null
    $dlg.Dispose()
}
