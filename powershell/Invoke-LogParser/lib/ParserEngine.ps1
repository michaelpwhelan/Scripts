# ═══════════════════════════════════════════════════════════════════════════════
# PARSER HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

function Register-Parser {
    param(
        [string]$Id,
        [string]$Name,
        [string[]]$Extensions,
        [scriptblock]$AutoDetect,
        [scriptblock]$Parse,
        [bool]$SupportsTail = $false
    )
    $Script:Parsers[$Id] = [PSCustomObject]@{
        Name = $Name; Id = $Id; Extensions = $Extensions
        AutoDetect = $AutoDetect; Parse = $Parse
        SupportsTail = $SupportsTail
    }
}

function Invoke-AutoDetect {
    param([string]$FilePath)
    try {
        $reader = [System.IO.StreamReader]::new($FilePath, [System.Text.Encoding]::UTF8, $true)
        $firstLines = [System.Collections.Generic.List[string]]::new()
        for ($i = 0; $i -lt 20 -and -not $reader.EndOfStream; $i++) {
            $firstLines.Add($reader.ReadLine())
        }
        $reader.Close()
        $reader.Dispose()
    } catch {
        Write-Log "Failed to read file for auto-detect: $_" -Level ERROR
        return "plaintext"
    }
    if ($firstLines.Count -eq 0) { return "plaintext" }

    # Check for binary content
    $hasBinary = $false
    foreach ($line in $firstLines) {
        if ($line -and $line -match '[\x00-\x08\x0E-\x1F]') { $hasBinary = $true; break }
    }
    if ($hasBinary) { return $null }

    foreach ($parserId in $Script:Parsers.Keys) {
        if ($parserId -eq "plaintext" -or $parserId -eq "generic-regex") { continue }
        $parser = $Script:Parsers[$parserId]
        try {
            $result = & $parser.AutoDetect $firstLines $FilePath
            if ($result) { return $parserId }
        } catch { }
    }
    return "plaintext"
}

# ═══════════════════════════════════════════════════════════════════════════════
# UNIFIED PARSER ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

function Invoke-ParserForFile {
    param([string]$ParserId, [string]$FilePath, [string]$Encoding)
    $parser = $Script:Parsers[$ParserId]
    if ($parser.SupportsTail) {
        # Tail-capable parsers take ($reader, $startIndex)
        $reader = [System.IO.StreamReader]::new($FilePath, [System.Text.Encoding]::GetEncoding($Encoding))
        try { $entries = & $parser.Parse $reader 0 }
        finally { $reader.Close(); $reader.Dispose() }
        return $entries
    } else {
        # File-based parsers take ($filePath, $encoding)
        return & $parser.Parse $FilePath $Encoding
    }
}

function Invoke-ParserForTail {
    param([string]$ParserId, [string]$FilePath, [long]$ByteOffset)
    $parser = $Script:Parsers[$ParserId]
    if (-not $parser.SupportsTail) { return $null }
    $fs = [System.IO.FileStream]::new($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    $fs.Position = $ByteOffset
    $reader = [System.IO.StreamReader]::new($fs, [System.Text.Encoding]::UTF8)
    $startIdx = $Script:State.AllEntries.Count
    try {
        $entries = & $parser.Parse $reader $startIdx
    } finally {
        $newOffset = $fs.Position
        $reader.Close(); $fs.Close()
    }
    return @{ Entries = $entries; NewOffset = $newOffset }
}

# ═══════════════════════════════════════════════════════════════════════════════
# PARSE ENGINE (Background Runspace)
# ═══════════════════════════════════════════════════════════════════════════════

function Start-ParseRunspace {
    param([string]$FilePath, [string]$ParserId, [string]$Encoding)

    Stop-ParseRunspace
    $Script:State.IsParsing = $true
    $Script:State.AllEntries.Clear()
    $Script:State.FilteredEntries.Clear()
    $Script:State.BookmarkedSet.Clear()
    $Script:State.SortColumn = -1

    $parser = $Script:Parsers[$ParserId]
    $parseBlock = $parser.Parse
    $supportsTail = $parser.SupportsTail
    $queue = $Script:State.ResultQueue
    $helperBlock = $Script:HelperScriptBlock

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $Script:State.ParseRunspace = [runspacefactory]::CreateRunspace($iss)
    $Script:State.ParseRunspace.Open()

    $ps = [powershell]::Create()
    $ps.Runspace = $Script:State.ParseRunspace
    $ps.AddScript({
        param($filePath2, $parseBlock2, $encoding2, $queue2, $helperBlock2, $supportsTail2)
        # Define helpers in the runspace from scriptblock
        . $helperBlock2
        try {
            if ($supportsTail2) {
                $reader = [System.IO.StreamReader]::new($filePath2, [System.Text.Encoding]::GetEncoding($encoding2))
                try { $entries = & $parseBlock2 $reader 0 }
                finally { $reader.Close(); $reader.Dispose() }
            } else {
                $entries = & $parseBlock2 $filePath2 $encoding2
            }
            if ($entries) {
                foreach ($e in $entries) { $queue2.Enqueue($e) }
            }
            $queue2.Enqueue("__PARSE_COMPLETE__")
        } catch {
            $queue2.Enqueue("__PARSE_ERROR__:$_")
        }
    }).AddArgument($FilePath).AddArgument($parseBlock).AddArgument($Encoding).AddArgument($queue).AddArgument($helperBlock).AddArgument($supportsTail) | Out-Null

    $Script:State.ParseHandle = $ps.BeginInvoke()
    $Script:State.ParsePowerShell = $ps
}

function Stop-ParseRunspace {
    if ($Script:State.ParsePowerShell) {
        try {
            $Script:State.ParsePowerShell.Stop()
            $Script:State.ParsePowerShell.Dispose()
        } catch { }
        $Script:State.ParsePowerShell = $null
    }
    if ($Script:State.ParseRunspace) {
        try { $Script:State.ParseRunspace.Close(); $Script:State.ParseRunspace.Dispose() } catch { }
        $Script:State.ParseRunspace = $null
    }
    $Script:State.ParseHandle = $null
    $Script:State.IsParsing = $false
    # Drain any remaining items
    $item = $null
    while ($Script:State.ResultQueue.TryDequeue([ref]$item)) { }
}

function Receive-ParseResults {
    $item = $null
    $count = 0
    while ($Script:State.ResultQueue.TryDequeue([ref]$item) -and $count -lt 500) {
        if ($item -is [string]) {
            if ($item -eq "__PARSE_COMPLETE__") {
                $Script:State.IsParsing = $false
                Update-StatusBar "Parsed $($Script:State.AllEntries.Count) entries"
                Invoke-ApplyFilters
                Update-StatsBar
                return
            }
            if ($item.StartsWith("__PARSE_ERROR__:")) {
                $Script:State.IsParsing = $false
                $errMsg = $item.Substring(16)
                Update-StatusBar "Parse error: $errMsg" -IsError
                return
            }
        }
        $Script:State.AllEntries.Add($item)
        $count++
    }
    if ($count -gt 0) {
        Invoke-ApplyFilters
        Update-StatsBar
        $Script:UI.ProgressBar.Value = [Math]::Min(100, $Script:State.AllEntries.Count / 100)
    }
}

function Get-ParserById {
    param([string]$Id)
    if ($Script:Parsers.ContainsKey($Id)) { return $Script:Parsers[$Id] }
    return $null
}
