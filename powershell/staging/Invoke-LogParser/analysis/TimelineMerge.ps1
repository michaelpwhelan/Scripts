function Invoke-TimelineMerge {
    param(
        [string[]]$FilePaths,
        [string]$Encoding = "UTF-8"
    )

    $Script:State.AllEntries.Clear()
    $Script:State.FilteredEntries = [System.Collections.Generic.List[object]]::new()
    $Script:State.BookmarkedSet.Clear()
    $Script:State.LoadedFiles.Clear()
    if ($Script:UI.DataGrid) { $Script:UI.DataGrid.RowCount = 0 }

    $totalEntries = [System.Collections.Generic.List[object]]::new()
    $globalIdx = 0

    foreach ($filePath in $FilePaths) {
        if (-not (Test-Path $filePath)) {
            Write-Log "File not found: $filePath" -Level WARNING
            continue
        }

        $actualPath = $filePath
        $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
        if ($ext -eq '.gz' -or $ext -eq '.zip') {
            $actualPath = Expand-CompressedFile $filePath
            if (-not $actualPath) { continue }
        }

        # Auto-detect format
        $parserId = Invoke-AutoDetect $actualPath
        if (-not $parserId) { $parserId = "plaintext" }

        $fileName = [System.IO.Path]::GetFileName($filePath)
        if ($Script:UI.StatusLabel) { Update-StatusBar "Parsing $fileName..." }

        # Parse
        $entries = Invoke-ParserForFile -ParserId $parserId -FilePath $actualPath -Encoding $Encoding
        if ($entries) {
            foreach ($e in $entries) {
                $e.Extra['SourceFile'] = $fileName
                $e.Extra['SourceFormat'] = $parserId
                $e | Add-Member -NotePropertyName 'Index' -NotePropertyValue $globalIdx -Force
                $totalEntries.Add($e)
                $globalIdx++
            }
        }
        $Script:State.LoadedFiles.Add($filePath)

        # Enforce entry limit
        if ($totalEntries.Count -ge $Config.MaxEntries) {
            Write-Log "Entry limit reached ($($Config.MaxEntries)). Stopping." -Level WARNING
            break
        }
    }

    # Sort by timestamp for timeline merge
    $sorted = $totalEntries | Sort-Object { $_.Timestamp }
    $idx = 0
    foreach ($e in $sorted) {
        $e | Add-Member -NotePropertyName 'Index' -NotePropertyValue $idx -Force
        $Script:State.AllEntries.Add($e)
        $idx++
    }

    # Add SourceFile column to grid if multiple files loaded
    if ($Script:UI.DataGrid -and $Script:State.LoadedFiles.Count -gt 1) {
        $existingCol = $Script:UI.DataGrid.Columns['SourceFile']
        if (-not $existingCol) {
            $colFile = [System.Windows.Forms.DataGridViewTextBoxColumn]::new()
            $colFile.Name = "SourceFile"; $colFile.HeaderText = "Source File"; $colFile.Width = 120
            $Script:UI.DataGrid.Columns.Insert(5, $colFile)  # Before Message column
        }
    }

    $Script:State.Format = "timeline-merge"
    if ($Script:UI.StatusLabel) {
        Update-StatusBar "Merged $($Script:State.AllEntries.Count) entries from $($Script:State.LoadedFiles.Count) files"
    }
    Invoke-ApplyFilters
    if (Get-Command Update-StatsBar -ErrorAction SilentlyContinue) { Update-StatsBar }
}
