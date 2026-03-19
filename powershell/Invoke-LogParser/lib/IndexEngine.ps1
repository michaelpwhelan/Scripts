# ═══════════════════════════════════════════════════════════════════════════════
# INDEX ENGINE — On-parse indexing for fast query execution
# ═══════════════════════════════════════════════════════════════════════════════

function Build-EntryIndex {
    param([System.Collections.Generic.List[object]]$Entries)

    if (-not $Entries -or $Entries.Count -eq 0) {
        Write-Log "No entries to index" -Level WARNING
        return @{ IndexedFields = @(); EntryCount = 0; BuildTimeMs = 0 }
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    # Initialize index structures
    $byLevel = @{}
    $bySource = @{}
    $byHour = @{}
    $byField = @{}
    $byTimestamp = [System.Collections.Generic.List[object]]::new($Entries.Count)

    # Key Extra fields to index for fast lookup
    $indexableFields = @('EventID', 'action', 'srcip', 'dstip', 'user', 'User-Name',
                         'TargetUserName', 'SubjectUserName', 'PacketTypeName',
                         'devname', 'DeviceName', 'ComputerName', 'SourceFormat',
                         'subtype', 'type', 'Reason-Code', 'TunnelName',
                         'NeighborIp', 'NAS-IP-Address', 'VmName')

    # Initialize hour buckets
    for ($h = 0; $h -lt 24; $h++) {
        $byHour[$h] = [System.Collections.Generic.List[int]]::new()
    }

    # Initialize field index containers
    foreach ($fieldName in $indexableFields) {
        $byField[$fieldName] = @{}
    }

    # Single pass through all entries
    for ($i = 0; $i -lt $Entries.Count; $i++) {
        $entry = $Entries[$i]

        # Level index
        $level = $entry.Level
        if ($level) {
            if (-not $byLevel.ContainsKey($level)) {
                $byLevel[$level] = [System.Collections.Generic.List[int]]::new()
            }
            $byLevel[$level].Add($i)
        }

        # Source index
        $source = $entry.Source
        if ($source) {
            if (-not $bySource.ContainsKey($source)) {
                $bySource[$source] = [System.Collections.Generic.List[int]]::new()
            }
            $bySource[$source].Add($i)
        }

        # Timestamp-based indexes
        if ($entry.Timestamp -ne [datetime]::MinValue) {
            # Hour of day index
            $hour = $entry.Timestamp.Hour
            $byHour[$hour].Add($i)

            # Sorted timestamp index for binary search
            $byTimestamp.Add(@{ Index = $i; Timestamp = $entry.Timestamp })
        }

        # Extra field indexes
        if ($entry.Extra) {
            foreach ($fieldName in $indexableFields) {
                $val = $entry.Extra[$fieldName]
                if ($null -ne $val) {
                    $strVal = [string]$val
                    if (-not $byField[$fieldName].ContainsKey($strVal)) {
                        $byField[$fieldName][$strVal] = [System.Collections.Generic.List[int]]::new()
                    }
                    $byField[$fieldName][$strVal].Add($i)
                }
            }
        }
    }

    # Sort timestamp index for binary search
    $sortedTimestamps = @($byTimestamp | Sort-Object { $_.Timestamp })

    # Remove empty field indexes to save memory
    $populatedFields = [System.Collections.Generic.List[string]]::new()
    $keysToRemove = [System.Collections.Generic.List[string]]::new()
    foreach ($fieldName in $byField.Keys) {
        if ($byField[$fieldName].Count -gt 0) {
            $populatedFields.Add($fieldName)
        } else {
            $keysToRemove.Add($fieldName)
        }
    }
    foreach ($key in $keysToRemove) {
        $byField.Remove($key)
    }

    # Store in state
    $Script:State.EntryIndex = @{
        ByLevel     = $byLevel
        BySource    = $bySource
        ByHour      = $byHour
        ByField     = $byField
        ByTimestamp  = $sortedTimestamps
        EntryCount  = $Entries.Count
        BuildTime   = $sw.Elapsed
        IndexedFields = @($populatedFields)
    }

    $sw.Stop()

    $fieldSummary = ($populatedFields | Select-Object -First 10) -join ', '
    if ($populatedFields.Count -gt 10) { $fieldSummary += " (+$($populatedFields.Count - 10) more)" }
    Write-Log "Index built: $($Entries.Count) entries, $($populatedFields.Count) fields ($fieldSummary) in $($sw.ElapsedMilliseconds)ms"

    return @{
        IndexedFields = @($populatedFields)
        EntryCount    = $Entries.Count
        BuildTimeMs   = [int]$sw.ElapsedMilliseconds
    }
}

function Search-Index {
    param(
        [string]$Field,
        [string]$Value,
        [string]$Operator = "eq"
    )

    $index = $Script:State.EntryIndex
    if (-not $index) {
        Write-Log "No entry index available, falling back to full scan" -Level WARNING
        return Invoke-FullScanSearch -Field $Field -Value $Value -Operator $Operator
    }

    # Check built-in indexes first
    if ($Field -eq 'Level' -and $Operator -eq 'eq') {
        if ($index.ByLevel.ContainsKey($Value)) {
            return @($index.ByLevel[$Value])
        }
        return @()
    }

    if ($Field -eq 'Source' -and $Operator -eq 'eq') {
        if ($index.BySource.ContainsKey($Value)) {
            return @($index.BySource[$Value])
        }
        return @()
    }

    if ($Field -eq 'Source' -and $Operator -eq 'prefix') {
        $results = [System.Collections.Generic.List[int]]::new()
        foreach ($srcKey in $index.BySource.Keys) {
            if ($srcKey.StartsWith($Value, [System.StringComparison]::OrdinalIgnoreCase)) {
                foreach ($idx in $index.BySource[$srcKey]) {
                    $results.Add($idx)
                }
            }
        }
        return @($results | Sort-Object)
    }

    if ($Field -eq 'Hour' -and $Operator -eq 'eq') {
        $hourVal = 0
        if ([int]::TryParse($Value, [ref]$hourVal) -and $hourVal -ge 0 -and $hourVal -lt 24) {
            if ($index.ByHour.ContainsKey($hourVal)) {
                return @($index.ByHour[$hourVal])
            }
        }
        return @()
    }

    # Extra field indexes
    if ($index.ByField.ContainsKey($Field)) {
        $fieldIndex = $index.ByField[$Field]

        switch ($Operator) {
            'eq' {
                if ($fieldIndex.ContainsKey($Value)) {
                    return @($fieldIndex[$Value])
                }
                return @()
            }
            'prefix' {
                $results = [System.Collections.Generic.List[int]]::new()
                foreach ($key in $fieldIndex.Keys) {
                    if ($key.StartsWith($Value, [System.StringComparison]::OrdinalIgnoreCase)) {
                        foreach ($idx in $fieldIndex[$key]) {
                            $results.Add($idx)
                        }
                    }
                }
                return @($results | Sort-Object)
            }
            'gt' {
                return Invoke-NumericFieldSearch -FieldIndex $fieldIndex -Value $Value -Operator 'gt'
            }
            'lt' {
                return Invoke-NumericFieldSearch -FieldIndex $fieldIndex -Value $Value -Operator 'lt'
            }
            'gte' {
                return Invoke-NumericFieldSearch -FieldIndex $fieldIndex -Value $Value -Operator 'gte'
            }
            'lte' {
                return Invoke-NumericFieldSearch -FieldIndex $fieldIndex -Value $Value -Operator 'lte'
            }
            default {
                Write-Log "Unknown search operator '$Operator', falling back to eq" -Level WARNING
                if ($fieldIndex.ContainsKey($Value)) {
                    return @($fieldIndex[$Value])
                }
                return @()
            }
        }
    }

    # Field not indexed, fall back to full scan
    Write-Log "Field '$Field' not indexed, performing full scan" -Level WARNING
    return Invoke-FullScanSearch -Field $Field -Value $Value -Operator $Operator
}

function Invoke-NumericFieldSearch {
    param(
        [hashtable]$FieldIndex,
        [string]$Value,
        [string]$Operator
    )

    $targetNum = 0.0
    if (-not [double]::TryParse($Value, [ref]$targetNum)) {
        return @()
    }

    $results = [System.Collections.Generic.List[int]]::new()

    foreach ($key in $FieldIndex.Keys) {
        $keyNum = 0.0
        if ([double]::TryParse($key, [ref]$keyNum)) {
            $match = $false
            switch ($Operator) {
                'gt'  { $match = $keyNum -gt $targetNum }
                'lt'  { $match = $keyNum -lt $targetNum }
                'gte' { $match = $keyNum -ge $targetNum }
                'lte' { $match = $keyNum -le $targetNum }
            }
            if ($match) {
                foreach ($idx in $FieldIndex[$key]) {
                    $results.Add($idx)
                }
            }
        }
    }

    return @($results | Sort-Object)
}

function Invoke-FullScanSearch {
    param(
        [string]$Field,
        [string]$Value,
        [string]$Operator
    )

    $entries = $Script:State.AllEntries
    if (-not $entries -or $entries.Count -eq 0) { return @() }

    $results = [System.Collections.Generic.List[int]]::new()

    for ($i = 0; $i -lt $entries.Count; $i++) {
        $entry = $entries[$i]
        $fieldVal = $null

        # Check standard fields
        switch ($Field) {
            'Level'   { $fieldVal = $entry.Level }
            'Source'  { $fieldVal = $entry.Source }
            'Host'    { $fieldVal = $entry.Host }
            'Message' { $fieldVal = $entry.Message }
            default {
                # Check Extra
                if ($entry.Extra -and $entry.Extra[$Field]) {
                    $fieldVal = [string]$entry.Extra[$Field]
                }
            }
        }

        if ($null -eq $fieldVal) { continue }

        $strVal = [string]$fieldVal
        $match = $false

        switch ($Operator) {
            'eq' {
                $match = $strVal -eq $Value
            }
            'prefix' {
                $match = $strVal.StartsWith($Value, [System.StringComparison]::OrdinalIgnoreCase)
            }
            'gt' {
                $numA = 0.0; $numB = 0.0
                if ([double]::TryParse($strVal, [ref]$numA) -and [double]::TryParse($Value, [ref]$numB)) {
                    $match = $numA -gt $numB
                }
            }
            'lt' {
                $numA = 0.0; $numB = 0.0
                if ([double]::TryParse($strVal, [ref]$numA) -and [double]::TryParse($Value, [ref]$numB)) {
                    $match = $numA -lt $numB
                }
            }
            'gte' {
                $numA = 0.0; $numB = 0.0
                if ([double]::TryParse($strVal, [ref]$numA) -and [double]::TryParse($Value, [ref]$numB)) {
                    $match = $numA -ge $numB
                }
            }
            'lte' {
                $numA = 0.0; $numB = 0.0
                if ([double]::TryParse($strVal, [ref]$numA) -and [double]::TryParse($Value, [ref]$numB)) {
                    $match = $numA -le $numB
                }
            }
        }

        if ($match) { $results.Add($i) }
    }

    return @($results)
}

function Search-TimeRange {
    param(
        [datetime]$From,
        [datetime]$To
    )

    $index = $Script:State.EntryIndex
    if (-not $index -or -not $index.ByTimestamp -or $index.ByTimestamp.Count -eq 0) {
        # No index: fall back to linear scan
        Write-Log "No timestamp index available, performing linear scan" -Level WARNING
        $results = [System.Collections.Generic.List[int]]::new()
        $entries = $Script:State.AllEntries
        if ($entries) {
            for ($i = 0; $i -lt $entries.Count; $i++) {
                $ts = $entries[$i].Timestamp
                if ($ts -ne [datetime]::MinValue -and $ts -ge $From -and $ts -le $To) {
                    $results.Add($i)
                }
            }
        }
        return @($results)
    }

    $sorted = $index.ByTimestamp

    # Binary search for the start position (first entry >= $From)
    $startIdx = Invoke-BinarySearchTimestamp -SortedEntries $sorted -Target $From -FindFirst $true

    if ($startIdx -lt 0 -or $startIdx -ge $sorted.Count) {
        return @()
    }

    # Binary search for the end position (last entry <= $To)
    $endIdx = Invoke-BinarySearchTimestamp -SortedEntries $sorted -Target $To -FindFirst $false

    if ($endIdx -lt 0) {
        return @()
    }

    # Clamp bounds
    if ($startIdx -gt $endIdx) {
        return @()
    }

    # Collect indices in the range
    $results = [System.Collections.Generic.List[int]]::new($endIdx - $startIdx + 1)
    for ($i = $startIdx; $i -le $endIdx; $i++) {
        $results.Add($sorted[$i].Index)
    }

    return @($results)
}

function Invoke-BinarySearchTimestamp {
    param(
        [object[]]$SortedEntries,
        [datetime]$Target,
        [bool]$FindFirst
    )

    $lo = 0
    $hi = $SortedEntries.Count - 1
    $result = -1

    if ($FindFirst) {
        # Find leftmost position where Timestamp >= Target
        while ($lo -le $hi) {
            $mid = [int](($lo + $hi) / 2)
            $midTs = $SortedEntries[$mid].Timestamp
            if ($midTs -ge $Target) {
                $result = $mid
                $hi = $mid - 1
            } else {
                $lo = $mid + 1
            }
        }
    } else {
        # Find rightmost position where Timestamp <= Target
        while ($lo -le $hi) {
            $mid = [int](($lo + $hi) / 2)
            $midTs = $SortedEntries[$mid].Timestamp
            if ($midTs -le $Target) {
                $result = $mid
                $lo = $mid + 1
            } else {
                $hi = $mid - 1
            }
        }
    }

    return $result
}

function Clear-EntryIndex {
    $Script:State.EntryIndex = $null
    Write-Log "Entry index cleared"
}

function Get-IndexStats {
    $index = $Script:State.EntryIndex
    if (-not $index) {
        return @{
            Available    = $false
            EntryCount   = 0
            LevelBuckets = 0
            SourceBuckets = 0
            FieldsIndexed = 0
            IndexedFields = @()
            TimestampEntries = 0
            BuildTimeMs  = 0
            MemoryEstimateKB = 0
        }
    }

    # Estimate memory usage
    $memEstimate = 0

    # Level index: count of all index entries
    $levelEntries = 0
    foreach ($key in $index.ByLevel.Keys) {
        $levelEntries += $index.ByLevel[$key].Count
    }
    $memEstimate += $levelEntries * 4  # 4 bytes per int index

    # Source index
    $sourceEntries = 0
    foreach ($key in $index.BySource.Keys) {
        $sourceEntries += $index.BySource[$key].Count
    }
    $memEstimate += $sourceEntries * 4

    # Field indexes
    $fieldEntries = 0
    $fieldBucketCount = 0
    foreach ($fieldName in $index.ByField.Keys) {
        $fieldIdx = $index.ByField[$fieldName]
        $fieldBucketCount += $fieldIdx.Count
        foreach ($key in $fieldIdx.Keys) {
            $fieldEntries += $fieldIdx[$key].Count
        }
    }
    $memEstimate += $fieldEntries * 4

    # Timestamp index: each entry is ~24 bytes (int + datetime)
    $memEstimate += $index.ByTimestamp.Count * 24

    # Hour index
    $hourEntries = 0
    foreach ($key in $index.ByHour.Keys) {
        $hourEntries += $index.ByHour[$key].Count
    }
    $memEstimate += $hourEntries * 4

    $buildMs = if ($index.BuildTime) { [int]$index.BuildTime.TotalMilliseconds } else { 0 }

    return @{
        Available        = $true
        EntryCount       = $index.EntryCount
        LevelBuckets     = $index.ByLevel.Count
        SourceBuckets    = $index.BySource.Count
        FieldsIndexed    = $index.ByField.Count
        IndexedFields    = @($index.IndexedFields)
        TimestampEntries = $index.ByTimestamp.Count
        HourBuckets      = 24
        FieldBucketCount = $fieldBucketCount
        TotalIndexEntries = $levelEntries + $sourceEntries + $fieldEntries + $hourEntries + $index.ByTimestamp.Count
        BuildTimeMs      = $buildMs
        MemoryEstimateKB = [Math]::Round($memEstimate / 1024, 1)
    }
}
