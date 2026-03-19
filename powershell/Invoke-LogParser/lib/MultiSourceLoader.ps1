# MultiSourceLoader.ps1 — Enhanced multi-source file loading with progress

function Invoke-MultiSourceLoad {
    param(
        [string[]]$FilePaths,
        [string]$Encoding = "UTF-8",
        [scriptblock]$ProgressCallback = $null
    )

    $Script:State.AllEntries.Clear()
    $Script:State.FilteredEntries = [System.Collections.Generic.List[object]]::new()
    $Script:State.BookmarkedSet.Clear()
    $Script:State.LoadedFiles.Clear()
    if ($Script:UI.DataGrid) { $Script:UI.DataGrid.RowCount = 0 }

    $totalEntries = [System.Collections.Generic.List[object]]::new()
    $globalIdx = 0
    $fileCount = $FilePaths.Count
    $currentFile = 0

    foreach ($filePath in $FilePaths) {
        $currentFile++
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

        $parserId = Invoke-AutoDetect $actualPath
        if (-not $parserId) { $parserId = "plaintext" }

        $fileName = [System.IO.Path]::GetFileName($filePath)
        if ($ProgressCallback) {
            & $ProgressCallback @{ File = $fileName; Current = $currentFile; Total = $fileCount; Percent = [Math]::Round(($currentFile / $fileCount) * 100) }
        }
        if ($Script:UI.StatusLabel) { Update-StatusBar "Loading $fileName ($currentFile of $fileCount)..." }

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

        if ($totalEntries.Count -ge $Config.MaxEntries) {
            Write-Log "Entry limit reached ($($Config.MaxEntries)). Stopping." -Level WARNING
            break
        }
    }

    # Sort by timestamp
    $sorted = $totalEntries | Sort-Object { $_.Timestamp }
    $idx = 0
    foreach ($e in $sorted) {
        $e | Add-Member -NotePropertyName 'Index' -NotePropertyValue $idx -Force
        $Script:State.AllEntries.Add($e)
        $idx++
    }

    # Add SourceFile column to grid if multiple files
    if ($Script:UI.DataGrid -and $Script:State.LoadedFiles.Count -gt 1) {
        $existingCol = $Script:UI.DataGrid.Columns['SourceFile']
        if (-not $existingCol) {
            $colFile = [System.Windows.Forms.DataGridViewTextBoxColumn]::new()
            $colFile.Name = "SourceFile"; $colFile.HeaderText = "Source File"; $colFile.Width = 120
            $Script:UI.DataGrid.Columns.Insert(5, $colFile)
        }
    }

    $Script:State.Format = "multi-source"
    if ($Script:UI.StatusLabel) {
        Update-StatusBar "Loaded $($Script:State.AllEntries.Count) entries from $($Script:State.LoadedFiles.Count) files"
    }
    Invoke-ApplyFilters
    if (Get-Command Update-StatsBar -ErrorAction SilentlyContinue) { Update-StatsBar }
}

function Get-FileSourceMetadata {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return $null }
    $info = Get-Item $FilePath
    $parserId = Invoke-AutoDetect $FilePath
    return @{
        FilePath = $FilePath
        FileName = $info.Name
        Size = $info.Length
        SizeFormatted = if ($info.Length -ge 1MB) { "{0:N1} MB" -f ($info.Length / 1MB) } elseif ($info.Length -ge 1KB) { "{0:N1} KB" -f ($info.Length / 1KB) } else { "$($info.Length) bytes" }
        DetectedFormat = $parserId
        FormatName = if ($parserId -and $Script:Parsers.ContainsKey($parserId)) { $Script:Parsers[$parserId].Name } else { "Unknown" }
        LastModified = $info.LastWriteTime
    }
}
