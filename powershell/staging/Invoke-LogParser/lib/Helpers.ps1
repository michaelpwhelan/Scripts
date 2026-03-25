# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

# HTML encoding helper (no System.Web dependency)
function Invoke-HtmlEncode {
    param([string]$Text)
    if (-not $Text) { return "" }
    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;')
}

function ConvertTo-LogEntry {
    param([hashtable]$Fields)
    [PSCustomObject]@{
        Index      = [int]($Fields['Index'] -as [int])
        Timestamp  = if ($Fields['Timestamp'] -is [datetime]) { $Fields['Timestamp'] } else {
            $ts = [datetime]::MinValue
            if ($Fields['Timestamp'] -and [datetime]::TryParse([string]$Fields['Timestamp'], [ref]$ts)) { $ts } else { [datetime]::MinValue }
        }
        Level      = if ($Fields['Level']) { $Fields['Level'].ToUpper() } else { "UNKNOWN" }
        Source     = if ($Fields['Source']) { [string]$Fields['Source'] } else { "" }
        Host       = if ($Fields['Host']) { [string]$Fields['Host'] } else { "" }
        Message    = if ($Fields['Message']) { [string]$Fields['Message'] } else { "" }
        RawLine    = if ($Fields['RawLine']) { [string]$Fields['RawLine'] } else { "" }
        Extra      = if ($Fields['Extra']) { $Fields['Extra'] } else { @{} }
        Bookmarked = $false
    }
}

function Get-LevelFromText {
    param([string]$Text)
    if (-not $Text) { return "UNKNOWN" }
    $upper = $Text.ToUpper()
    if ($upper -match '\b(CRITICAL|CRIT|FATAL|EMERG|EMERGENCY|ALERT)\b') { return "CRITICAL" }
    if ($upper -match '\b(ERROR|ERR|FAIL|FAILED|FAILURE)\b') { return "ERROR" }
    if ($upper -match '\b(WARNING|WARN)\b') { return "WARNING" }
    if ($upper -match '\b(INFO|INFORMATION|NOTICE)\b') { return "INFO" }
    if ($upper -match '\b(DEBUG|DBG)\b') { return "DEBUG" }
    if ($upper -match '\b(TRACE|VERBOSE)\b') { return "TRACE" }
    return "UNKNOWN"
}

function Expand-CompressedFile {
    param([string]$FilePath)
    $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()
    if ($ext -ne '.gz' -and $ext -ne '.zip') { return $FilePath }

    if (-not (Test-Path $Config.TempDir)) {
        New-Item -ItemType Directory -Path $Config.TempDir -Force | Out-Null
    }
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($FilePath)
    $tempFile = Join-Path $Config.TempDir "$baseName`_$(Get-Date -Format 'yyyyMMddHHmmss')"

    try {
        if ($ext -eq '.gz') {
            $inStream = [System.IO.File]::OpenRead($FilePath)
            $gzStream = [System.IO.Compression.GZipStream]::new($inStream, [System.IO.Compression.CompressionMode]::Decompress)
            $outStream = [System.IO.File]::Create($tempFile)
            $gzStream.CopyTo($outStream)
            $outStream.Close(); $gzStream.Close(); $inStream.Close()
        } elseif ($ext -eq '.zip') {
            $archive = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
            $entry = $archive.Entries | Select-Object -First 1
            if ($entry) {
                $tempFile = Join-Path $Config.TempDir $entry.Name
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $tempFile, $true)
            }
            $archive.Dispose()
        }
        return $tempFile
    } catch {
        Write-Log "Decompression failed: $_" -Level ERROR
        return $null
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# HELPER SCRIPTBLOCK — for use in runspaces (replaces string-serialized pattern)
# ═══════════════════════════════════════════════════════════════════════════════

$Script:HelperScriptBlock = {
    function ConvertTo-LogEntry {
        param([hashtable]$Fields)
        [PSCustomObject]@{
            Index      = [int]($Fields['Index'] -as [int])
            Timestamp  = if ($Fields['Timestamp'] -is [datetime]) { $Fields['Timestamp'] } else {
                $ts = [datetime]::MinValue
                if ($Fields['Timestamp'] -and [datetime]::TryParse([string]$Fields['Timestamp'], [ref]$ts)) { $ts } else { [datetime]::MinValue }
            }
            Level      = if ($Fields['Level']) { $Fields['Level'].ToUpper() } else { "UNKNOWN" }
            Source     = if ($Fields['Source']) { [string]$Fields['Source'] } else { "" }
            Host       = if ($Fields['Host']) { [string]$Fields['Host'] } else { "" }
            Message    = if ($Fields['Message']) { [string]$Fields['Message'] } else { "" }
            RawLine    = if ($Fields['RawLine']) { [string]$Fields['RawLine'] } else { "" }
            Extra      = if ($Fields['Extra']) { $Fields['Extra'] } else { @{} }
            Bookmarked = $false
        }
    }
    function Get-LevelFromText {
        param([string]$Text)
        if (-not $Text) { return "UNKNOWN" }
        $upper = $Text.ToUpper()
        if ($upper -match '\b(CRITICAL|CRIT|FATAL|EMERG|EMERGENCY|ALERT)\b') { return "CRITICAL" }
        if ($upper -match '\b(ERROR|ERR|FAIL|FAILED|FAILURE)\b') { return "ERROR" }
        if ($upper -match '\b(WARNING|WARN)\b') { return "WARNING" }
        if ($upper -match '\b(INFO|INFORMATION|NOTICE)\b') { return "INFO" }
        if ($upper -match '\b(DEBUG|DBG)\b') { return "DEBUG" }
        if ($upper -match '\b(TRACE|VERBOSE)\b') { return "TRACE" }
        return "UNKNOWN"
    }
}
