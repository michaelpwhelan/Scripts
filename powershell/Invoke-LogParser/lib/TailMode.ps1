# ═══════════════════════════════════════════════════════════════════════════════
# TAIL MODE
# ═══════════════════════════════════════════════════════════════════════════════

function Start-TailMode {
    if (-not $Script:State.FilePath) { return }
    if ($Script:State.OriginalPath) {
        Update-StatusBar "Tail unavailable: compressed source"
        return
    }
    $Script:State.TailMode = $true
    # Set byte offset to current end of file
    try {
        $fi = [System.IO.FileInfo]::new($Script:State.FilePath)
        $Script:State.TailByteOffset = $fi.Length
    } catch { $Script:State.TailByteOffset = 0L }

    $Script:State.TailTimer = [System.Windows.Forms.Timer]::new()
    $Script:State.TailTimer.Interval = $Config.TailPollMs
    $Script:State.TailTimer.Add_Tick({ Invoke-TailPoll })
    $Script:State.TailTimer.Start()
    Update-StatusBar "Tail mode active"
}

function Stop-TailMode {
    $Script:State.TailMode = $false
    if ($Script:State.TailTimer) {
        $Script:State.TailTimer.Stop()
        $Script:State.TailTimer.Dispose()
        $Script:State.TailTimer = $null
    }
    Update-StatusBar "Tail mode stopped"
}

function Invoke-TailPoll {
    if (-not $Script:State.FilePath -or -not $Script:State.TailMode) { return }
    try {
        $fi = [System.IO.FileInfo]::new($Script:State.FilePath)
        $currentSize = $fi.Length
        if ($currentSize -lt $Script:State.TailByteOffset) {
            Update-StatusBar "File rotated - reparsing"
            $Script:State.TailByteOffset = 0L
            $Script:State.AllEntries.Clear()
            $Script:State.FilteredEntries = [System.Collections.Generic.List[object]]::new()
            $Script:State.BookmarkedSet.Clear()
            if ($Script:UI.DataGrid) { $Script:UI.DataGrid.RowCount = 0 }
        }
        if ($currentSize -le $Script:State.TailByteOffset) { return }

        $parserId = $Script:State.Format
        if ($parserId -eq "auto") { $parserId = "plaintext" }

        $result = Invoke-ParserForTail -ParserId $parserId -FilePath $Script:State.FilePath -ByteOffset $Script:State.TailByteOffset
        if ($null -eq $result) { return }

        if ($result.Entries -and $result.Entries.Count -gt 0) {
            foreach ($e in $result.Entries) { $Script:State.AllEntries.Add($e) }
            $Script:State.TailByteOffset = $result.NewOffset
            Invoke-ApplyFilters
            Update-StatsBar
            # Auto-scroll
            if ($Script:UI.DataGrid -and $Script:UI.DataGrid.RowCount -gt 0) {
                $lastVisible = $Script:UI.DataGrid.FirstDisplayedScrollingRowIndex + $Script:UI.DataGrid.DisplayedRowCount($true) - 1
                if ($lastVisible -ge $Script:UI.DataGrid.RowCount - 5) {
                    $Script:UI.DataGrid.FirstDisplayedScrollingRowIndex = [Math]::Max(0, $Script:UI.DataGrid.RowCount - 1)
                }
            }
        }
    } catch {
        Write-Log "Tail poll error: $_" -Level WARNING
    }
}
