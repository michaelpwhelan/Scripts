# ═══════════════════════════════════════════════════════════════════════════════
# CACHE MANAGER — Parsed data caching for fast re-opening
# ═══════════════════════════════════════════════════════════════════════════════

$Script:CacheStats = @{
    Hits   = 0
    Misses = 0
}

function Get-CachePath {
    $dir = Join-Path $Config.ScriptRoot "data" "cache"
    if (-not (Test-Path $dir)) {
        try {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        } catch {
            Write-Log "Failed to create cache directory: $_" -Level ERROR
            return $null
        }
    }
    return $dir
}

function Get-CacheKey {
    param([string]$FilePath)

    if (-not (Test-Path $FilePath)) {
        return $null
    }

    try {
        $fileInfo = [System.IO.FileInfo]::new($FilePath)
        $parserVersion = if ($Config.Version) { $Config.Version } else { '0.0.0' }

        # Build a deterministic string from: full path + size + last write time + parser version
        $hashInput = "$($fileInfo.FullName)|$($fileInfo.Length)|$($fileInfo.LastWriteTimeUtc.Ticks)|$parserVersion"

        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($hashInput)
            $hashBytes = $sha256.ComputeHash($bytes)

            # Convert to hex string
            $sb = [System.Text.StringBuilder]::new($hashBytes.Length * 2)
            foreach ($b in $hashBytes) {
                $sb.Append($b.ToString('x2')) | Out-Null
            }
            return $sb.ToString()
        } finally {
            $sha256.Dispose()
        }
    } catch {
        Write-Log "Failed to compute cache key for '$FilePath': $_" -Level ERROR
        return $null
    }
}

function Get-CachedParse {
    param([string]$FilePath)

    $cacheDir = Get-CachePath
    if (-not $cacheDir) {
        $Script:CacheStats.Misses++
        return $null
    }

    $cacheKey = Get-CacheKey -FilePath $FilePath
    if (-not $cacheKey) {
        $Script:CacheStats.Misses++
        return $null
    }

    $cachePath = Join-Path $cacheDir "$cacheKey.json"
    if (-not (Test-Path $cachePath)) {
        $Script:CacheStats.Misses++
        return $null
    }

    try {
        $cacheContent = [System.IO.File]::ReadAllText($cachePath)
        $cacheData = $cacheContent | ConvertFrom-Json

        # Validate cache metadata
        if (-not $cacheData.Metadata -or -not $cacheData.Entries) {
            Write-Log "Invalid cache file structure for '$FilePath'" -Level WARNING
            $Script:CacheStats.Misses++
            return $null
        }

        # Verify the file hasn't changed since caching
        if (Test-Path $FilePath) {
            $fileInfo = [System.IO.FileInfo]::new($FilePath)
            $cachedSize = [long]$cacheData.Metadata.FileSize
            $cachedTicks = [long]$cacheData.Metadata.LastWriteTicks

            if ($fileInfo.Length -ne $cachedSize -or $fileInfo.LastWriteTimeUtc.Ticks -ne $cachedTicks) {
                Write-Log "Cache stale for '$FilePath' (file changed)" -Level WARNING
                # Remove stale cache file
                try { [System.IO.File]::Delete($cachePath) } catch { }
                $Script:CacheStats.Misses++
                return $null
            }
        }

        # Convert cached entries back to the expected list format
        $entries = [System.Collections.Generic.List[object]]::new()

        foreach ($cachedEntry in $cacheData.Entries) {
            # Rebuild Extra hashtable from PSCustomObject
            $extra = @{}
            if ($cachedEntry.Extra) {
                foreach ($prop in $cachedEntry.Extra.PSObject.Properties) {
                    $extra[$prop.Name] = $prop.Value
                }
            }

            $entry = [PSCustomObject]@{
                Index     = [int]$cachedEntry.Index
                Timestamp = if ($cachedEntry.Timestamp) {
                    $ts = [datetime]::MinValue
                    if ([datetime]::TryParse([string]$cachedEntry.Timestamp, [ref]$ts)) { $ts } else { [datetime]::MinValue }
                } else { [datetime]::MinValue }
                Level     = if ($cachedEntry.Level) { [string]$cachedEntry.Level } else { 'UNKNOWN' }
                Source    = if ($cachedEntry.Source) { [string]$cachedEntry.Source } else { '' }
                Host      = if ($cachedEntry.Host) { [string]$cachedEntry.Host } else { '' }
                Message   = if ($cachedEntry.Message) { [string]$cachedEntry.Message } else { '' }
                RawLine   = if ($cachedEntry.RawLine) { [string]$cachedEntry.RawLine } else { '' }
                Extra     = $extra
                Bookmarked = $false
            }
            $entries.Add($entry)
        }

        # Update last access time for LRU tracking
        try {
            [System.IO.File]::SetLastAccessTimeUtc($cachePath, [datetime]::UtcNow)
        } catch { }

        $Script:CacheStats.Hits++
        Write-Log "Cache hit for '$([System.IO.Path]::GetFileName($FilePath))': $($entries.Count) entries loaded from cache"
        return $entries

    } catch {
        Write-Log "Failed to read cache for '$FilePath': $_" -Level WARNING
        # Remove corrupt cache file
        try { [System.IO.File]::Delete($cachePath) } catch { }
        $Script:CacheStats.Misses++
        return $null
    }
}

function Save-ParseCache {
    param(
        [string]$FilePath,
        [System.Collections.Generic.List[object]]$Entries,
        [string]$ParserId
    )

    if (-not $Entries -or $Entries.Count -eq 0) { return }

    $cacheDir = Get-CachePath
    if (-not $cacheDir) { return }

    $cacheKey = Get-CacheKey -FilePath $FilePath
    if (-not $cacheKey) { return }

    $cachePath = Join-Path $cacheDir "$cacheKey.json"

    try {
        $fileInfo = [System.IO.FileInfo]::new($FilePath)

        # Build cache data structure with metadata header
        $cacheData = @{
            Metadata = @{
                OriginalFile   = $fileInfo.FullName
                FileName       = $fileInfo.Name
                FileSize       = $fileInfo.Length
                LastWriteTicks = $fileInfo.LastWriteTimeUtc.Ticks
                ParserVersion  = if ($Config.Version) { $Config.Version } else { '0.0.0' }
                ParserId       = $ParserId
                EntryCount     = $Entries.Count
                CachedAt       = (Get-Date).ToString('o')
                CacheKey       = $cacheKey
            }
            Entries = [System.Collections.Generic.List[object]]::new()
        }

        # Serialize entries, converting datetime to ISO 8601 strings for reliable round-tripping
        foreach ($entry in $Entries) {
            $serialized = @{
                Index     = $entry.Index
                Timestamp = if ($entry.Timestamp -ne [datetime]::MinValue) { $entry.Timestamp.ToString('o') } else { $null }
                Level     = $entry.Level
                Source    = $entry.Source
                Host      = $entry.Host
                Message   = $entry.Message
                RawLine   = $entry.RawLine
                Extra     = $entry.Extra
            }
            $cacheData.Entries.Add($serialized)
        }

        $json = $cacheData | ConvertTo-Json -Depth 6 -Compress
        [System.IO.File]::WriteAllText($cachePath, $json, [System.Text.Encoding]::UTF8)

        Write-Log "Cached parse results for '$($fileInfo.Name)': $($Entries.Count) entries ($([Math]::Round($json.Length / 1024, 1))KB)"

        # Check if eviction is needed after writing
        $maxCacheSize = 500MB
        Invoke-CacheEviction -MaxSizeBytes $maxCacheSize

    } catch {
        Write-Log "Failed to cache parse results for '$FilePath': $_" -Level WARNING
        # Clean up partial cache file
        if (Test-Path $cachePath) {
            try { [System.IO.File]::Delete($cachePath) } catch { }
        }
    }
}

function Clear-ParseCache {
    $cacheDir = Get-CachePath
    if (-not $cacheDir -or -not (Test-Path $cacheDir)) {
        Write-Log "No cache directory to clear"
        return
    }

    try {
        $cacheFiles = @(Get-ChildItem -Path $cacheDir -Filter "*.json" -File -ErrorAction SilentlyContinue)
        $totalSize = 0

        foreach ($file in $cacheFiles) {
            $totalSize += $file.Length
            try {
                [System.IO.File]::Delete($file.FullName)
            } catch {
                Write-Log "Failed to delete cache file '$($file.Name)': $_" -Level WARNING
            }
        }

        $Script:CacheStats.Hits = 0
        $Script:CacheStats.Misses = 0

        Write-Log "Parse cache cleared: $($cacheFiles.Count) files removed ($([Math]::Round($totalSize / 1MB, 2))MB freed)"
    } catch {
        Write-Log "Failed to clear parse cache: $_" -Level ERROR
    }
}

function Get-CacheStats {
    $cacheDir = Get-CachePath
    $fileCount = 0
    $totalSize = 0
    $oldestAccess = [datetime]::MaxValue
    $newestAccess = [datetime]::MinValue
    $totalEntries = 0

    if ($cacheDir -and (Test-Path $cacheDir)) {
        $cacheFiles = @(Get-ChildItem -Path $cacheDir -Filter "*.json" -File -ErrorAction SilentlyContinue)
        $fileCount = $cacheFiles.Count

        foreach ($file in $cacheFiles) {
            $totalSize += $file.Length
            if ($file.LastAccessTimeUtc -lt $oldestAccess) { $oldestAccess = $file.LastAccessTimeUtc }
            if ($file.LastAccessTimeUtc -gt $newestAccess) { $newestAccess = $file.LastAccessTimeUtc }

            # Read entry count from metadata without loading full file
            try {
                $reader = [System.IO.StreamReader]::new($file.FullName)
                try {
                    # Read enough to find EntryCount in metadata
                    $buffer = New-Object char[] 1024
                    $charsRead = $reader.Read($buffer, 0, 1024)
                    $header = [string]::new($buffer, 0, $charsRead)
                    if ($header -match '"EntryCount"\s*:\s*(\d+)') {
                        $totalEntries += [int]$Matches[1]
                    }
                } finally {
                    $reader.Close()
                }
            } catch { }
        }
    }

    $totalHitsAndMisses = $Script:CacheStats.Hits + $Script:CacheStats.Misses
    $hitRate = if ($totalHitsAndMisses -gt 0) {
        [Math]::Round(($Script:CacheStats.Hits / $totalHitsAndMisses) * 100, 1)
    } else { 0.0 }

    return @{
        CacheDirectory = $cacheDir
        FileCount      = $fileCount
        TotalSizeBytes = $totalSize
        TotalSizeMB    = [Math]::Round($totalSize / 1MB, 2)
        TotalEntries   = $totalEntries
        Hits           = $Script:CacheStats.Hits
        Misses         = $Script:CacheStats.Misses
        HitRate        = $hitRate
        OldestAccess   = if ($oldestAccess -ne [datetime]::MaxValue) { $oldestAccess } else { $null }
        NewestAccess   = if ($newestAccess -ne [datetime]::MinValue) { $newestAccess } else { $null }
    }
}

function Invoke-CacheEviction {
    param([long]$MaxSizeBytes = 500MB)

    $cacheDir = Get-CachePath
    if (-not $cacheDir -or -not (Test-Path $cacheDir)) { return }

    try {
        $cacheFiles = @(Get-ChildItem -Path $cacheDir -Filter "*.json" -File -ErrorAction SilentlyContinue)
        if ($cacheFiles.Count -eq 0) { return }

        # Calculate total cache size
        $totalSize = 0
        foreach ($file in $cacheFiles) {
            $totalSize += $file.Length
        }

        if ($totalSize -le $MaxSizeBytes) { return }

        # Sort by last access time ascending (oldest first) for LRU eviction
        $sortedFiles = @($cacheFiles | Sort-Object LastAccessTimeUtc)

        $evictedCount = 0
        $evictedSize = 0

        foreach ($file in $sortedFiles) {
            if ($totalSize -le $MaxSizeBytes) { break }

            $fileSize = $file.Length
            try {
                [System.IO.File]::Delete($file.FullName)
                $totalSize -= $fileSize
                $evictedSize += $fileSize
                $evictedCount++
            } catch {
                Write-Log "Failed to evict cache file '$($file.Name)': $_" -Level WARNING
            }
        }

        if ($evictedCount -gt 0) {
            Write-Log "Cache eviction: removed $evictedCount files ($([Math]::Round($evictedSize / 1MB, 2))MB), remaining $([Math]::Round($totalSize / 1MB, 2))MB"
        }
    } catch {
        Write-Log "Cache eviction failed: $_" -Level ERROR
    }
}
