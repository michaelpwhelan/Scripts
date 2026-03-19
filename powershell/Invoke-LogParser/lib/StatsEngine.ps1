# ═══════════════════════════════════════════════════════════════════════════════
# STATS ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

function Get-SeverityCounts {
    param([System.Collections.Generic.List[object]]$Entries)
    $counts = @{ CRITICAL = 0; ERROR = 0; WARNING = 0; INFO = 0; DEBUG = 0; TRACE = 0; UNKNOWN = 0 }
    foreach ($e in $Entries) {
        if ($counts.ContainsKey($e.Level)) { $counts[$e.Level]++ } else { $counts['UNKNOWN']++ }
    }
    return $counts
}

function Update-StatsBar {
    if (-not $Script:UI.StatsLabel) { return }
    $filtered = $Script:State.FilteredEntries
    $counts = @{ CRITICAL = 0; ERROR = 0; WARNING = 0; INFO = 0; DEBUG = 0; TRACE = 0; UNKNOWN = 0 }
    $eventIds = @{}; $sources = @{}

    foreach ($e in $filtered) {
        if ($counts.ContainsKey($e.Level)) { $counts[$e.Level]++ } else { $counts['UNKNOWN']++ }
        if ($e.Extra -and $e.Extra['EventID']) {
            $eid = [string]$e.Extra['EventID']
            if ($eventIds.ContainsKey($eid)) { $eventIds[$eid]++ } else { $eventIds[$eid] = 1 }
        }
        if ($e.Source) {
            if ($sources.ContainsKey($e.Source)) { $sources[$e.Source]++ } else { $sources[$e.Source] = 1 }
        }
    }

    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add("$($filtered.Count) entries")
    $sevParts = @()
    if ($counts['CRITICAL'] -gt 0) { $sevParts += "CRIT:$($counts['CRITICAL'])" }
    if ($counts['ERROR'] -gt 0) { $sevParts += "ERR:$($counts['ERROR'])" }
    if ($counts['WARNING'] -gt 0) { $sevParts += "WARN:$($counts['WARNING'])" }
    $sevParts += "INFO:$($counts['INFO'])"
    $parts.Add($sevParts -join "  ")

    if ($eventIds.Count -gt 0) {
        $topIds = $eventIds.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5
        $idStr = ($topIds | ForEach-Object { "$($_.Key)($($_.Value))" }) -join " "
        $parts.Add("Top IDs: $idStr")
    }
    if ($sources.Count -gt 0) {
        $topSrc = $sources.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5
        $srcStr = ($topSrc | ForEach-Object { "$($_.Key)($($_.Value))" }) -join " "
        $parts.Add("Top Sources: $srcStr")
    }

    $Script:UI.StatsLabel.Text = $parts -join "  |  "
}

function Get-SourceFileStats {
    $stats = @{}
    foreach ($e in $Script:State.AllEntries) {
        $file = if ($e.Extra -and $e.Extra['SourceFile']) { $e.Extra['SourceFile'] } else { "(single file)" }
        if (-not $stats.ContainsKey($file)) {
            $stats[$file] = @{ Total = 0; CRITICAL = 0; ERROR = 0; WARNING = 0; INFO = 0; DEBUG = 0; Format = "" }
        }
        $stats[$file].Total++
        if ($stats[$file].ContainsKey($e.Level)) { $stats[$file][$e.Level]++ }
        if (-not $stats[$file].Format -and $e.Extra -and $e.Extra['SourceFormat']) { $stats[$file].Format = $e.Extra['SourceFormat'] }
    }
    return $stats
}
