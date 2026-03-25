# ═══════════════════════════════════════════════════════════════════════════════
# BASELINE ENGINE — Learn "normal" from historical data, detect deviations
# ═══════════════════════════════════════════════════════════════════════════════

function Get-BaselinePath {
    $dir = Join-Path $Config.ScriptRoot "data" "baselines"
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    return $dir
}

function Save-BaselineProfile {
    param(
        [hashtable]$Profile,
        [string]$Name
    )
    try {
        $dir = Get-BaselinePath
        $filePath = Join-Path $dir "$Name.json"
        $json = $Profile | ConvertTo-Json -Depth 6
        [System.IO.File]::WriteAllText($filePath, $json)
        Write-Log "Baseline profile saved: $Name"
    } catch {
        Write-Log "Failed to save baseline profile '$Name': $_" -Level ERROR
        throw
    }
}

function Load-BaselineProfile {
    param([string]$Name)
    $dir = Get-BaselinePath
    $filePath = Join-Path $dir "$Name.json"
    if (-not (Test-Path $filePath)) {
        Write-Log "Baseline profile not found: $Name" -Level ERROR
        return $null
    }
    try {
        $json = [System.IO.File]::ReadAllText($filePath)
        $raw = $json | ConvertFrom-Json

        # Convert PSCustomObject back to hashtable structure
        $profile = @{
            Name         = $raw.Name
            CreatedAt    = [datetime]$raw.CreatedAt
            EntryCount   = [int]$raw.EntryCount
            DateRange    = @{
                From = [datetime]$raw.DateRange.From
                To   = [datetime]$raw.DateRange.To
            }
            SourceFilter = $raw.SourceFilter
            SiteFilter   = $raw.SiteFilter
            Volume       = @{
                HourlyMean    = @($raw.Volume.HourlyMean | ForEach-Object { [decimal]$_ })
                HourlyStdDev  = @($raw.Volume.HourlyStdDev | ForEach-Object { [decimal]$_ })
                DailyMean     = @($raw.Volume.DailyMean | ForEach-Object { [decimal]$_ })
                DailyStdDev   = @($raw.Volume.DailyStdDev | ForEach-Object { [decimal]$_ })
                MinutelyMean  = [decimal]$raw.Volume.MinutelyMean
                MinutelyStdDev = [decimal]$raw.Volume.MinutelyStdDev
            }
            Severity     = @{}
            TopSources   = @{}
            TopFields    = @{}
            UserPatterns = @{}
            SequencePatterns = @{}
        }

        # Severity distribution
        foreach ($prop in $raw.Severity.PSObject.Properties) {
            $profile.Severity[$prop.Name] = [decimal]$prop.Value
        }

        # Top sources
        foreach ($prop in $raw.TopSources.PSObject.Properties) {
            $profile.TopSources[$prop.Name] = [decimal]$prop.Value
        }

        # Top fields — nested hashtable
        foreach ($field in $raw.TopFields.PSObject.Properties) {
            $profile.TopFields[$field.Name] = @{}
            foreach ($val in $field.Value.PSObject.Properties) {
                $profile.TopFields[$field.Name][$val.Name] = [decimal]$val.Value
            }
        }

        # User patterns
        foreach ($prop in $raw.UserPatterns.PSObject.Properties) {
            $profile.UserPatterns[$prop.Name] = @($prop.Value)
        }

        # Sequence patterns
        foreach ($prop in $raw.SequencePatterns.PSObject.Properties) {
            $profile.SequencePatterns[$prop.Name] = [decimal]$prop.Value
        }

        Write-Log "Baseline profile loaded: $Name"
        return $profile
    } catch {
        Write-Log "Failed to load baseline profile '$Name': $_" -Level ERROR
        return $null
    }
}

function Get-ZScore {
    param(
        [decimal]$Value,
        [decimal]$Mean,
        [decimal]$StdDev
    )
    $denominator = [Math]::Max(0.001, [double]$StdDev)
    return ([double]$Value - [double]$Mean) / $denominator
}

# ───────────────────────────────────────────────────────────────────────────────
# Build-Baseline — Analyze a dataset and produce a baseline profile
# ───────────────────────────────────────────────────────────────────────────────
function Build-Baseline {
    param(
        [System.Collections.Generic.List[object]]$Entries,
        [string]$Name,
        [string]$SourceFilter = "",
        [string]$SiteFilter = ""
    )

    if (-not $Entries -or $Entries.Count -eq 0) {
        Write-Log "Cannot build baseline: no entries provided" -Level WARNING
        return $null
    }

    if ([string]::IsNullOrWhiteSpace($Name)) {
        Write-Log "Cannot build baseline: name is required" -Level ERROR
        return $null
    }

    Write-Log "Building baseline '$Name' from $($Entries.Count) entries..."

    try {
        # Apply filters
        $filtered = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $Entries) {
            if ($SourceFilter -and $entry.Extra) {
                $srcFmt = $entry.Extra['SourceFormat']
                if ($srcFmt -and $srcFmt -ne $SourceFilter) { continue }
            }
            if ($SiteFilter -and $entry.Extra) {
                $site = $entry.Extra['site']
                if (-not $site) { $site = $entry.Extra['vdom'] }
                if ($site -and $site -ne $SiteFilter) { continue }
            }
            $filtered.Add($entry)
        }

        if ($filtered.Count -eq 0) {
            Write-Log "No entries match the specified filters" -Level WARNING
            return $null
        }

        # ── Date range ──
        $earliestTimestamp = [datetime]::MaxValue
        $latestTimestamp = [datetime]::MinValue
        foreach ($entry in $filtered) {
            if ($entry.Timestamp -ne [datetime]::MinValue) {
                if ($entry.Timestamp -lt $earliestTimestamp) { $earliestTimestamp = $entry.Timestamp }
                if ($entry.Timestamp -gt $latestTimestamp) { $latestTimestamp = $entry.Timestamp }
            }
        }

        # ── Volume statistics — hourly buckets ──
        # Group entries by date+hour to get per-hour counts across all days
        $hourBuckets = @{}  # "yyyy-MM-dd HH" → count
        foreach ($entry in $filtered) {
            if ($entry.Timestamp -eq [datetime]::MinValue) { continue }
            $bucket = $entry.Timestamp.ToString("yyyy-MM-dd HH")
            if ($hourBuckets.ContainsKey($bucket)) { $hourBuckets[$bucket]++ }
            else { $hourBuckets[$bucket] = 1 }
        }

        # Compute per-hour-of-day mean and stddev
        $hourlyGroups = @{}  # 0..23 → list of counts
        for ($h = 0; $h -lt 24; $h++) { $hourlyGroups[$h] = [System.Collections.Generic.List[decimal]]::new() }

        foreach ($kvp in $hourBuckets.GetEnumerator()) {
            $hourOfDay = [int]($kvp.Key.Substring($kvp.Key.Length - 2))
            $hourlyGroups[$hourOfDay].Add([decimal]$kvp.Value)
        }

        # Determine the number of distinct days in the dataset
        $distinctDays = @{}
        foreach ($entry in $filtered) {
            if ($entry.Timestamp -ne [datetime]::MinValue) {
                $dayKey = $entry.Timestamp.ToString("yyyy-MM-dd")
                $distinctDays[$dayKey] = $true
            }
        }
        $totalDays = [Math]::Max(1, $distinctDays.Count)

        # Fill in zero-count hours for days that had no events in that hour
        for ($h = 0; $h -lt 24; $h++) {
            $observedDaysForHour = $hourlyGroups[$h].Count
            $missingDays = $totalDays - $observedDaysForHour
            for ($z = 0; $z -lt $missingDays; $z++) {
                $hourlyGroups[$h].Add([decimal]0)
            }
        }

        $hourlyMean = @(0.0) * 24
        $hourlyStdDev = @(0.0) * 24
        for ($h = 0; $h -lt 24; $h++) {
            $values = $hourlyGroups[$h]
            if ($values.Count -gt 0) {
                $sum = [decimal]0
                foreach ($v in $values) { $sum += $v }
                $mean = $sum / $values.Count
                $hourlyMean[$h] = [Math]::Round([double]$mean, 4)

                $varianceSum = [decimal]0
                foreach ($v in $values) {
                    $diff = $v - $mean
                    $varianceSum += $diff * $diff
                }
                $variance = $varianceSum / [Math]::Max(1, $values.Count)
                $hourlyStdDev[$h] = [Math]::Round([Math]::Sqrt([double]$variance), 4)
            }
        }

        # ── Volume statistics — daily (day-of-week) buckets ──
        $dayOfWeekBuckets = @{}  # "yyyy-MM-dd" → count
        foreach ($entry in $filtered) {
            if ($entry.Timestamp -eq [datetime]::MinValue) { continue }
            $dayKey = $entry.Timestamp.ToString("yyyy-MM-dd")
            if ($dayOfWeekBuckets.ContainsKey($dayKey)) { $dayOfWeekBuckets[$dayKey]++ }
            else { $dayOfWeekBuckets[$dayKey] = 1 }
        }

        $dowGroups = @{}  # 0=Monday..6=Sunday → list of daily counts
        for ($d = 0; $d -lt 7; $d++) { $dowGroups[$d] = [System.Collections.Generic.List[decimal]]::new() }

        foreach ($kvp in $dayOfWeekBuckets.GetEnumerator()) {
            $dateObj = [datetime]::ParseExact($kvp.Key, "yyyy-MM-dd", $null)
            # Convert DayOfWeek (Sun=0..Sat=6) to Mon=0..Sun=6
            $dowIndex = ([int]$dateObj.DayOfWeek + 6) % 7
            $dowGroups[$dowIndex].Add([decimal]$kvp.Value)
        }

        # Determine the number of weeks covered
        $totalWeeks = [Math]::Max(1, [Math]::Ceiling($totalDays / 7.0))
        for ($d = 0; $d -lt 7; $d++) {
            $observedWeeksForDay = $dowGroups[$d].Count
            $missingWeeks = $totalWeeks - $observedWeeksForDay
            for ($z = 0; $z -lt $missingWeeks; $z++) {
                $dowGroups[$d].Add([decimal]0)
            }
        }

        $dailyMean = @(0.0) * 7
        $dailyStdDev = @(0.0) * 7
        for ($d = 0; $d -lt 7; $d++) {
            $values = $dowGroups[$d]
            if ($values.Count -gt 0) {
                $sum = [decimal]0
                foreach ($v in $values) { $sum += $v }
                $mean = $sum / $values.Count
                $dailyMean[$d] = [Math]::Round([double]$mean, 4)

                $varianceSum = [decimal]0
                foreach ($v in $values) {
                    $diff = $v - $mean
                    $varianceSum += $diff * $diff
                }
                $variance = $varianceSum / [Math]::Max(1, $values.Count)
                $dailyStdDev[$d] = [Math]::Round([Math]::Sqrt([double]$variance), 4)
            }
        }

        # ── Volume statistics — minutely ──
        $minuteBuckets = @{}
        foreach ($entry in $filtered) {
            if ($entry.Timestamp -eq [datetime]::MinValue) { continue }
            $minKey = $entry.Timestamp.ToString("yyyy-MM-dd HH:mm")
            if ($minuteBuckets.ContainsKey($minKey)) { $minuteBuckets[$minKey]++ }
            else { $minuteBuckets[$minKey] = 1 }
        }

        $minutelyMean = [decimal]0
        $minutelyStdDev = [decimal]0
        if ($minuteBuckets.Count -gt 0) {
            $minValues = [System.Collections.Generic.List[decimal]]::new()
            foreach ($kvp in $minuteBuckets.GetEnumerator()) {
                $minValues.Add([decimal]$kvp.Value)
            }
            $sum = [decimal]0
            foreach ($v in $minValues) { $sum += $v }
            $minutelyMean = [Math]::Round([double]($sum / $minValues.Count), 4)

            $varianceSum = [decimal]0
            foreach ($v in $minValues) {
                $diff = $v - $minutelyMean
                $varianceSum += $diff * $diff
            }
            $variance = $varianceSum / [Math]::Max(1, $minValues.Count)
            $minutelyStdDev = [Math]::Round([Math]::Sqrt([double]$variance), 4)
        }

        # ── Severity distribution ──
        $severityCounts = @{ CRITICAL = 0; ERROR = 0; WARNING = 0; INFO = 0; DEBUG = 0 }
        foreach ($entry in $filtered) {
            $lvl = $entry.Level
            if ($severityCounts.ContainsKey($lvl)) { $severityCounts[$lvl]++ }
        }
        $totalEntries = $filtered.Count
        $severityPct = @{}
        foreach ($key in $severityCounts.Keys) {
            $severityPct[$key] = [Math]::Round(($severityCounts[$key] / [Math]::Max(1, $totalEntries)) * 100, 4)
        }

        # ── Top sources ──
        $sourceCounts = @{}
        foreach ($entry in $filtered) {
            $src = $entry.Source
            if (-not $src) { $src = "(unknown)" }
            if ($sourceCounts.ContainsKey($src)) { $sourceCounts[$src]++ }
            else { $sourceCounts[$src] = 1 }
        }
        $topSources = @{}
        $sortedSources = $sourceCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 20
        foreach ($s in $sortedSources) {
            $topSources[$s.Key] = [Math]::Round(($s.Value / [Math]::Max(1, $totalEntries)) * 100, 4)
        }

        # ── Top fields — track value distributions for key fields ──
        $trackedFields = @('dstport', 'srcport', 'action', 'srcip', 'dstip', 'proto', 'app',
                           'EventID', 'LogonType', 'Status', 'SubStatus', 'FailureReason',
                           'PacketTypeName', 'AuthenticationProvider', 'subtype', 'type')
        $fieldCounts = @{}
        foreach ($f in $trackedFields) { $fieldCounts[$f] = @{} }

        foreach ($entry in $filtered) {
            if (-not $entry.Extra) { continue }
            foreach ($f in $trackedFields) {
                $val = $entry.Extra[$f]
                if (-not $val) { continue }
                $valStr = [string]$val
                if (-not $fieldCounts[$f].ContainsKey($valStr)) {
                    $fieldCounts[$f][$valStr] = 0
                }
                $fieldCounts[$f][$valStr]++
            }
        }

        $topFields = @{}
        foreach ($f in $trackedFields) {
            if ($fieldCounts[$f].Count -eq 0) { continue }
            $topFields[$f] = @{}
            $fieldTotal = 0
            foreach ($kvp in $fieldCounts[$f].GetEnumerator()) { $fieldTotal += $kvp.Value }
            $sortedVals = $fieldCounts[$f].GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 50
            foreach ($sv in $sortedVals) {
                $topFields[$f][$sv.Key] = [Math]::Round(($sv.Value / [Math]::Max(1, $fieldTotal)) * 100, 4)
            }
        }

        # ── User patterns — user→IP associations ──
        $userIps = @{}
        $userFields = @('user', 'User-Name', 'TargetUserName', 'SubjectUserName', 'UserPrincipalName', 'AccountName')
        $ipFields = @('srcip', 'IPAddress', 'IpAddress', 'Calling-Station-Id')
        foreach ($entry in $filtered) {
            if (-not $entry.Extra) { continue }
            $userName = $null
            foreach ($uf in $userFields) {
                $userName = $entry.Extra[$uf]
                if ($userName) { break }
            }
            if (-not $userName) { continue }

            $userIp = $null
            foreach ($ipf in $ipFields) {
                $userIp = $entry.Extra[$ipf]
                if ($userIp) { break }
            }
            if (-not $userIp) { continue }

            $userKey = $userName.ToLower()
            if (-not $userIps.ContainsKey($userKey)) {
                $userIps[$userKey] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            }
            $userIps[$userKey].Add($userIp) | Out-Null
        }

        $userPatterns = @{}
        foreach ($kvp in $userIps.GetEnumerator()) {
            $userPatterns[$kvp.Key] = @($kvp.Value)
        }

        # ── Sequence patterns — pair frequencies ──
        $pairCounts = @{}
        $sortedByTime = $filtered | Where-Object { $_.Timestamp -ne [datetime]::MinValue } | Sort-Object { $_.Timestamp }
        $prevEntry = $null
        foreach ($entry in $sortedByTime) {
            if ($null -ne $prevEntry) {
                $span = $entry.Timestamp - $prevEntry.Timestamp
                # Only count pairs within a 5-minute window
                if ($span.TotalMinutes -le 5) {
                    $prevLabel = $prevEntry.Level
                    if ($prevEntry.Extra -and $prevEntry.Extra['EventID']) {
                        $prevLabel = "EID:$($prevEntry.Extra['EventID'])"
                    } elseif ($prevEntry.Extra -and $prevEntry.Extra['action']) {
                        $prevLabel = "act:$($prevEntry.Extra['action'])"
                    }

                    $currLabel = $entry.Level
                    if ($entry.Extra -and $entry.Extra['EventID']) {
                        $currLabel = "EID:$($entry.Extra['EventID'])"
                    } elseif ($entry.Extra -and $entry.Extra['action']) {
                        $currLabel = "act:$($entry.Extra['action'])"
                    }

                    $pairKey = "$prevLabel->$currLabel"
                    if ($pairCounts.ContainsKey($pairKey)) { $pairCounts[$pairKey]++ }
                    else { $pairCounts[$pairKey] = 1 }
                }
            }
            $prevEntry = $entry
        }

        $sequencePatterns = @{}
        $sortedPairs = $pairCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 100
        $totalPairs = 0
        foreach ($kvp in $pairCounts.GetEnumerator()) { $totalPairs += $kvp.Value }
        foreach ($sp in $sortedPairs) {
            $sequencePatterns[$sp.Key] = [Math]::Round(($sp.Value / [Math]::Max(1, $totalPairs)) * 100, 4)
        }

        # ── Assemble baseline profile ──
        $profile = @{
            Name         = $Name
            CreatedAt    = (Get-Date).ToString("o")
            EntryCount   = $filtered.Count
            DateRange    = @{
                From = if ($earliestTimestamp -ne [datetime]::MaxValue) { $earliestTimestamp.ToString("o") } else { $null }
                To   = if ($latestTimestamp -ne [datetime]::MinValue) { $latestTimestamp.ToString("o") } else { $null }
            }
            SourceFilter = $SourceFilter
            SiteFilter   = $SiteFilter
            Volume       = @{
                HourlyMean     = $hourlyMean
                HourlyStdDev   = $hourlyStdDev
                DailyMean      = $dailyMean
                DailyStdDev    = $dailyStdDev
                MinutelyMean   = $minutelyMean
                MinutelyStdDev = $minutelyStdDev
            }
            Severity     = $severityPct
            TopSources   = $topSources
            TopFields    = $topFields
            UserPatterns = $userPatterns
            SequencePatterns = $sequencePatterns
        }

        Save-BaselineProfile -Profile $profile -Name $Name
        Write-Log "Baseline '$Name' built successfully ($($filtered.Count) entries, $totalDays days)"
        return $profile
    } catch {
        Write-Log "Failed to build baseline '$Name': $_" -Level ERROR
        return $null
    }
}

# ───────────────────────────────────────────────────────────────────────────────
# Compare-Baseline — Compare current data against a stored baseline
# ───────────────────────────────────────────────────────────────────────────────
function Compare-Baseline {
    param(
        [System.Collections.Generic.List[object]]$Entries,
        [string]$BaselineName,
        [decimal]$SensitivityMultiplier = 1.0
    )

    if (-not $Entries -or $Entries.Count -eq 0) {
        Write-Log "Cannot compare: no entries provided" -Level WARNING
        return @()
    }

    $baseline = Load-BaselineProfile -Name $BaselineName
    if (-not $baseline) {
        Write-Log "Cannot compare: baseline '$BaselineName' not found" -Level ERROR
        return @()
    }

    Write-Log "Comparing $($Entries.Count) entries against baseline '$BaselineName'..."

    $anomalies = [System.Collections.Generic.List[object]]::new()

    try {
        # ── Volume anomalies — Hourly ──
        $currentHourCounts = @(0) * 24
        $totalDays = @{}
        foreach ($entry in $Entries) {
            if ($entry.Timestamp -eq [datetime]::MinValue) { continue }
            $h = $entry.Timestamp.Hour
            $currentHourCounts[$h]++
            $dayKey = $entry.Timestamp.ToString("yyyy-MM-dd")
            $totalDays[$dayKey] = $true
        }
        $numDays = [Math]::Max(1, $totalDays.Count)

        for ($h = 0; $h -lt 24; $h++) {
            $currentMean = [decimal]($currentHourCounts[$h] / $numDays)
            $baselineMean = [decimal]$baseline.Volume.HourlyMean[$h]
            $baselineStdDev = [decimal]$baseline.Volume.HourlyStdDev[$h]

            $zScore = Get-ZScore -Value $currentMean -Mean $baselineMean -StdDev $baselineStdDev
            $absZ = [Math]::Abs($zScore)
            $scaledThreshold = 1.0 / [Math]::Max(0.1, [double]$SensitivityMultiplier)

            if ($absZ -gt $scaledThreshold) {
                $severity = if ($absZ -gt 4) { "Critical" }
                            elseif ($absZ -gt 3) { "High" }
                            elseif ($absZ -gt 2) { "Medium" }
                            else { "Low" }
                $direction = if ($zScore -gt 0) { "above" } else { "below" }

                # Collect sample events from this hour
                $samples = [System.Collections.Generic.List[object]]::new()
                foreach ($entry in $Entries) {
                    if ($entry.Timestamp -ne [datetime]::MinValue -and $entry.Timestamp.Hour -eq $h) {
                        $samples.Add($entry)
                        if ($samples.Count -ge 5) { break }
                    }
                }

                $confidence = [Math]::Min(100, [Math]::Round($absZ * 20, 2))

                $anomalies.Add(@{
                    Type              = "Volume"
                    Severity          = $severity
                    Metric            = "Hourly event rate at hour $($h):00"
                    Expected          = "$baselineMean events/hour (stddev: $baselineStdDev)"
                    Actual            = "$currentMean events/hour"
                    Deviation         = [Math]::Round($zScore, 4)
                    Confidence        = $confidence
                    ContributingEvents = @($samples)
                    Description       = "Event volume at hour ${h}:00 is ${absZ}sigma ${direction} baseline mean ($currentMean vs $baselineMean)"
                })
            }
        }

        # ── Volume anomalies — Daily (day-of-week) ──
        $currentDowCounts = @(0) * 7
        $dowDays = @{}
        for ($d = 0; $d -lt 7; $d++) { $dowDays[$d] = @{} }
        foreach ($entry in $Entries) {
            if ($entry.Timestamp -eq [datetime]::MinValue) { continue }
            $dowIndex = ([int]$entry.Timestamp.DayOfWeek + 6) % 7
            $dayKey = $entry.Timestamp.ToString("yyyy-MM-dd")
            $dowDays[$dowIndex][$dayKey] = $true
            $currentDowCounts[$dowIndex]++
        }

        $dowNames = @("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
        for ($d = 0; $d -lt 7; $d++) {
            $numWeeksForDay = [Math]::Max(1, $dowDays[$d].Count)
            $currentMean = [decimal]($currentDowCounts[$d] / $numWeeksForDay)
            $baselineMean = [decimal]$baseline.Volume.DailyMean[$d]
            $baselineStdDev = [decimal]$baseline.Volume.DailyStdDev[$d]

            $zScore = Get-ZScore -Value $currentMean -Mean $baselineMean -StdDev $baselineStdDev
            $absZ = [Math]::Abs($zScore)
            $scaledThreshold = 1.0 / [Math]::Max(0.1, [double]$SensitivityMultiplier)

            if ($absZ -gt $scaledThreshold) {
                $severity = if ($absZ -gt 4) { "Critical" }
                            elseif ($absZ -gt 3) { "High" }
                            elseif ($absZ -gt 2) { "Medium" }
                            else { "Low" }
                $direction = if ($zScore -gt 0) { "above" } else { "below" }
                $confidence = [Math]::Min(100, [Math]::Round($absZ * 20, 2))

                $anomalies.Add(@{
                    Type              = "Volume"
                    Severity          = $severity
                    Metric            = "Daily event rate on $($dowNames[$d])"
                    Expected          = "$baselineMean events/day (stddev: $baselineStdDev)"
                    Actual            = "$currentMean events/day"
                    Deviation         = [Math]::Round($zScore, 4)
                    Confidence        = $confidence
                    ContributingEvents = @()
                    Description       = "Event volume on $($dowNames[$d]) is ${absZ}sigma ${direction} baseline ($currentMean vs $baselineMean)"
                })
            }
        }

        # ── Volume anomalies — Minutely ──
        $minuteBuckets = @{}
        foreach ($entry in $Entries) {
            if ($entry.Timestamp -eq [datetime]::MinValue) { continue }
            $minKey = $entry.Timestamp.ToString("yyyy-MM-dd HH:mm")
            if ($minuteBuckets.ContainsKey($minKey)) { $minuteBuckets[$minKey]++ }
            else { $minuteBuckets[$minKey] = 1 }
        }
        if ($minuteBuckets.Count -gt 0) {
            $minValues = [System.Collections.Generic.List[decimal]]::new()
            foreach ($kvp in $minuteBuckets.GetEnumerator()) { $minValues.Add([decimal]$kvp.Value) }
            $sum = [decimal]0
            foreach ($v in $minValues) { $sum += $v }
            $currentMinMean = $sum / $minValues.Count

            $zScore = Get-ZScore -Value $currentMinMean -Mean $baseline.Volume.MinutelyMean -StdDev $baseline.Volume.MinutelyStdDev
            $absZ = [Math]::Abs($zScore)
            $scaledThreshold = 1.0 / [Math]::Max(0.1, [double]$SensitivityMultiplier)

            if ($absZ -gt $scaledThreshold) {
                $severity = if ($absZ -gt 4) { "Critical" }
                            elseif ($absZ -gt 3) { "High" }
                            elseif ($absZ -gt 2) { "Medium" }
                            else { "Low" }
                $direction = if ($zScore -gt 0) { "above" } else { "below" }
                $confidence = [Math]::Min(100, [Math]::Round($absZ * 20, 2))

                # Find peak minute samples
                $peakMinutes = $minuteBuckets.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 3
                $peakDesc = ($peakMinutes | ForEach-Object { "$($_.Key): $($_.Value) events" }) -join "; "

                $anomalies.Add(@{
                    Type              = "Volume"
                    Severity          = $severity
                    Metric            = "Per-minute event rate (overall)"
                    Expected          = "$($baseline.Volume.MinutelyMean) events/min (stddev: $($baseline.Volume.MinutelyStdDev))"
                    Actual            = "$([Math]::Round($currentMinMean, 4)) events/min"
                    Deviation         = [Math]::Round($zScore, 4)
                    Confidence        = $confidence
                    ContributingEvents = @()
                    Description       = "Average per-minute event rate is ${absZ}sigma ${direction} baseline. Peak minutes: $peakDesc"
                })
            }
        }

        # ── Distribution anomalies — Severity ──
        $currentSevCounts = @{ CRITICAL = 0; ERROR = 0; WARNING = 0; INFO = 0; DEBUG = 0 }
        foreach ($entry in $Entries) {
            if ($currentSevCounts.ContainsKey($entry.Level)) { $currentSevCounts[$entry.Level]++ }
        }
        $totalCurrent = $Entries.Count
        foreach ($level in @('CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG')) {
            $currentPct = [Math]::Round(($currentSevCounts[$level] / [Math]::Max(1, $totalCurrent)) * 100, 4)
            $baselinePct = [decimal]0
            if ($baseline.Severity.ContainsKey($level)) { $baselinePct = $baseline.Severity[$level] }

            $diff = [Math]::Abs($currentPct - $baselinePct)
            # Significance threshold based on sensitivity: 10% shift by default
            $threshold = 10 / [Math]::Max(0.1, [double]$SensitivityMultiplier)

            if ($diff -gt $threshold) {
                $severity = if ($level -eq 'CRITICAL' -and $currentPct -gt $baselinePct) { "Critical" }
                            elseif ($level -eq 'ERROR' -and $currentPct -gt $baselinePct) { "High" }
                            elseif ($diff -gt 30) { "High" }
                            elseif ($diff -gt 20) { "Medium" }
                            else { "Low" }
                $direction = if ($currentPct -gt $baselinePct) { "increase" } else { "decrease" }
                $confidence = [Math]::Min(100, [Math]::Round($diff * 2, 2))

                $anomalies.Add(@{
                    Type              = "Distribution"
                    Severity          = $severity
                    Metric            = "$level event proportion"
                    Expected          = "$baselinePct%"
                    Actual            = "$currentPct%"
                    Deviation         = [Math]::Round($diff, 4)
                    Confidence        = $confidence
                    ContributingEvents = @()
                    Description       = "$level events show a ${diff}% ${direction} (${currentPct}% vs baseline ${baselinePct}%)"
                })
            }
        }

        # ── Temporal anomalies — Activity in normally quiet hours ──
        for ($h = 0; $h -lt 24; $h++) {
            $baselineMean = [decimal]$baseline.Volume.HourlyMean[$h]
            $currentCount = $currentHourCounts[$h]

            # Detect activity in normally-quiet hours (baseline mean < 1 but current has events)
            if ($baselineMean -lt 1 -and $currentCount -gt 0) {
                $samples = [System.Collections.Generic.List[object]]::new()
                foreach ($entry in $Entries) {
                    if ($entry.Timestamp -ne [datetime]::MinValue -and $entry.Timestamp.Hour -eq $h) {
                        $samples.Add($entry)
                        if ($samples.Count -ge 5) { break }
                    }
                }

                $severity = if ($currentCount -gt 50) { "High" }
                            elseif ($currentCount -gt 10) { "Medium" }
                            else { "Low" }
                $confidence = [Math]::Min(100, [Math]::Round([double]$currentCount * 5, 2))

                $anomalies.Add(@{
                    Type              = "Temporal"
                    Severity          = $severity
                    Metric            = "Activity during quiet hour $($h):00"
                    Expected          = "Near-zero activity (baseline mean: $baselineMean)"
                    Actual            = "$currentCount events"
                    Deviation         = [decimal]$currentCount
                    Confidence        = $confidence
                    ContributingEvents = @($samples)
                    Description       = "Detected $currentCount events at hour ${h}:00, which is normally a quiet period (baseline mean: $baselineMean)"
                })
            }
        }

        # ── Relational anomalies — New user+IP pairs ──
        $userFields = @('user', 'User-Name', 'TargetUserName', 'SubjectUserName', 'UserPrincipalName', 'AccountName')
        $ipFields = @('srcip', 'IPAddress', 'IpAddress', 'Calling-Station-Id')

        foreach ($entry in $Entries) {
            if (-not $entry.Extra) { continue }

            $userName = $null
            foreach ($uf in $userFields) {
                $userName = $entry.Extra[$uf]
                if ($userName) { break }
            }
            if (-not $userName) { continue }

            $userIp = $null
            foreach ($ipf in $ipFields) {
                $userIp = $entry.Extra[$ipf]
                if ($userIp) { break }
            }
            if (-not $userIp) { continue }

            $userKey = $userName.ToLower()
            if ($baseline.UserPatterns.ContainsKey($userKey)) {
                $knownIps = @($baseline.UserPatterns[$userKey])
                $ipKnown = $false
                foreach ($kip in $knownIps) {
                    if ($kip -eq $userIp) { $ipKnown = $true; break }
                }
                if (-not $ipKnown) {
                    # Check if we already flagged this exact pair
                    $alreadyFlagged = $false
                    foreach ($existing in $anomalies) {
                        if ($existing.Type -eq 'Relational' -and $existing.Metric -eq "New IP for user '$userKey': $userIp") {
                            $alreadyFlagged = $true
                            break
                        }
                    }
                    if (-not $alreadyFlagged) {
                        $anomalies.Add(@{
                            Type              = "Relational"
                            Severity          = "Medium"
                            Metric            = "New IP for user '$userKey': $userIp"
                            Expected          = "Known IPs: $($knownIps -join ', ')"
                            Actual            = "New IP: $userIp"
                            Deviation         = [decimal]0
                            Confidence        = [decimal]75
                            ContributingEvents = @($entry)
                            Description       = "User '$userKey' connected from IP $userIp which is not in the baseline (known: $($knownIps -join ', '))"
                        })
                    }
                }
            }
        }

        # ── New patterns — Values in top fields not seen in baseline ──
        $trackedFields = @('dstport', 'action', 'srcip', 'dstip', 'EventID', 'proto', 'app')
        foreach ($fieldName in $trackedFields) {
            if (-not $baseline.TopFields.ContainsKey($fieldName)) { continue }
            $baselineValues = $baseline.TopFields[$fieldName]

            $currentFieldCounts = @{}
            foreach ($entry in $Entries) {
                if (-not $entry.Extra) { continue }
                $val = $entry.Extra[$fieldName]
                if (-not $val) { continue }
                $valStr = [string]$val
                if ($currentFieldCounts.ContainsKey($valStr)) { $currentFieldCounts[$valStr]++ }
                else { $currentFieldCounts[$valStr] = 1 }
            }

            $currentTotal = 0
            foreach ($kvp in $currentFieldCounts.GetEnumerator()) { $currentTotal += $kvp.Value }
            if ($currentTotal -eq 0) { continue }

            # Threshold for reporting new values: must appear in >1% of field occurrences
            $reportThreshold = 1 / [Math]::Max(0.1, [double]$SensitivityMultiplier)

            foreach ($kvp in $currentFieldCounts.GetEnumerator()) {
                $pct = [Math]::Round(($kvp.Value / [Math]::Max(1, $currentTotal)) * 100, 4)
                if ($pct -lt $reportThreshold) { continue }

                if (-not $baselineValues.ContainsKey($kvp.Key)) {
                    $severity = if ($pct -gt 20) { "High" }
                                elseif ($pct -gt 10) { "Medium" }
                                else { "Low" }
                    $confidence = [Math]::Min(100, [Math]::Round($pct * 3, 2))

                    # Collect sample events
                    $samples = [System.Collections.Generic.List[object]]::new()
                    foreach ($entry in $Entries) {
                        if ($entry.Extra -and $entry.Extra[$fieldName] -and [string]$entry.Extra[$fieldName] -eq $kvp.Key) {
                            $samples.Add($entry)
                            if ($samples.Count -ge 5) { break }
                        }
                    }

                    $anomalies.Add(@{
                        Type              = "NewPattern"
                        Severity          = $severity
                        Metric            = "New value for field '$fieldName': $($kvp.Key)"
                        Expected          = "Not present in baseline top values"
                        Actual            = "$($kvp.Value) occurrences ($pct%)"
                        Deviation         = $pct
                        Confidence        = $confidence
                        ContributingEvents = @($samples)
                        Description       = "Field '$fieldName' has a new value '$($kvp.Key)' not seen in baseline, appearing $($kvp.Value) times ($pct% of field occurrences)"
                    })
                }
            }
        }

        # ── Distribution anomalies — Significant shift in top field percentages ──
        foreach ($fieldName in $trackedFields) {
            if (-not $baseline.TopFields.ContainsKey($fieldName)) { continue }
            $baselineValues = $baseline.TopFields[$fieldName]

            $currentFieldCounts = @{}
            foreach ($entry in $Entries) {
                if (-not $entry.Extra) { continue }
                $val = $entry.Extra[$fieldName]
                if (-not $val) { continue }
                $valStr = [string]$val
                if ($currentFieldCounts.ContainsKey($valStr)) { $currentFieldCounts[$valStr]++ }
                else { $currentFieldCounts[$valStr] = 1 }
            }

            $currentTotal = 0
            foreach ($kvp in $currentFieldCounts.GetEnumerator()) { $currentTotal += $kvp.Value }
            if ($currentTotal -eq 0) { continue }

            foreach ($bkvp in $baselineValues.GetEnumerator()) {
                $baselinePct = [decimal]$bkvp.Value
                $currentCount = 0
                if ($currentFieldCounts.ContainsKey($bkvp.Key)) {
                    $currentCount = $currentFieldCounts[$bkvp.Key]
                }
                $currentPct = [Math]::Round(($currentCount / [Math]::Max(1, $currentTotal)) * 100, 4)
                $diff = [Math]::Abs($currentPct - $baselinePct)

                $threshold = 15 / [Math]::Max(0.1, [double]$SensitivityMultiplier)
                if ($diff -gt $threshold -and $baselinePct -gt 5) {
                    $severity = if ($diff -gt 40) { "High" }
                                elseif ($diff -gt 25) { "Medium" }
                                else { "Low" }
                    $direction = if ($currentPct -gt $baselinePct) { "increase" } else { "decrease" }
                    $confidence = [Math]::Min(100, [Math]::Round($diff * 2, 2))

                    $anomalies.Add(@{
                        Type              = "Distribution"
                        Severity          = $severity
                        Metric            = "Field '$fieldName' value '$($bkvp.Key)' proportion"
                        Expected          = "$baselinePct%"
                        Actual            = "$currentPct%"
                        Deviation         = [Math]::Round($diff, 4)
                        Confidence        = $confidence
                        ContributingEvents = @()
                        Description       = "Field '$fieldName' value '$($bkvp.Key)' shows a ${diff}% ${direction} (${currentPct}% vs baseline ${baselinePct}%)"
                    })
                }
            }
        }

        Write-Log "Comparison complete: found $($anomalies.Count) anomalies"
        return @($anomalies)
    } catch {
        Write-Log "Failed to compare against baseline '$BaselineName': $_" -Level ERROR
        return @()
    }
}

# ───────────────────────────────────────────────────────────────────────────────
# Update-Baseline — Incrementally update baseline with new data
# ───────────────────────────────────────────────────────────────────────────────
function Update-Baseline {
    param(
        [System.Collections.Generic.List[object]]$Entries,
        [string]$BaselineName,
        [decimal]$LearningRate = 0.1
    )

    if (-not $Entries -or $Entries.Count -eq 0) {
        Write-Log "Cannot update baseline: no entries provided" -Level WARNING
        return $null
    }

    $existing = Load-BaselineProfile -Name $BaselineName
    if (-not $existing) {
        Write-Log "Baseline '$BaselineName' not found, building new baseline instead" -Level WARNING
        return (Build-Baseline -Entries $Entries -Name $BaselineName)
    }

    Write-Log "Updating baseline '$BaselineName' with $($Entries.Count) new entries (learning rate: $LearningRate)..."

    try {
        $lr = [double]$LearningRate
        $oldWeight = 1.0 - $lr

        # Build a temporary profile from the new data for blending
        $newProfile = Build-Baseline -Entries $Entries -Name "__temp_update__"
        if (-not $newProfile) {
            Write-Log "Failed to build profile from new data for update" -Level ERROR
            return $null
        }

        # Remove the temp file
        $tempPath = Join-Path (Get-BaselinePath) "__temp_update__.json"
        if (Test-Path $tempPath) { Remove-Item $tempPath -Force }

        # ── Blend volume — hourly ──
        for ($h = 0; $h -lt 24; $h++) {
            $existing.Volume.HourlyMean[$h] = [Math]::Round(
                $oldWeight * [double]$existing.Volume.HourlyMean[$h] + $lr * [double]$newProfile.Volume.HourlyMean[$h], 4)
            $existing.Volume.HourlyStdDev[$h] = [Math]::Round(
                $oldWeight * [double]$existing.Volume.HourlyStdDev[$h] + $lr * [double]$newProfile.Volume.HourlyStdDev[$h], 4)
        }

        # ── Blend volume — daily ──
        for ($d = 0; $d -lt 7; $d++) {
            $existing.Volume.DailyMean[$d] = [Math]::Round(
                $oldWeight * [double]$existing.Volume.DailyMean[$d] + $lr * [double]$newProfile.Volume.DailyMean[$d], 4)
            $existing.Volume.DailyStdDev[$d] = [Math]::Round(
                $oldWeight * [double]$existing.Volume.DailyStdDev[$d] + $lr * [double]$newProfile.Volume.DailyStdDev[$d], 4)
        }

        # ── Blend volume — minutely ──
        $existing.Volume.MinutelyMean = [Math]::Round(
            $oldWeight * [double]$existing.Volume.MinutelyMean + $lr * [double]$newProfile.Volume.MinutelyMean, 4)
        $existing.Volume.MinutelyStdDev = [Math]::Round(
            $oldWeight * [double]$existing.Volume.MinutelyStdDev + $lr * [double]$newProfile.Volume.MinutelyStdDev, 4)

        # ── Blend severity distribution ──
        foreach ($level in @('CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG')) {
            $oldVal = if ($existing.Severity.ContainsKey($level)) { [double]$existing.Severity[$level] } else { 0 }
            $newVal = if ($newProfile.Severity.ContainsKey($level)) { [double]$newProfile.Severity[$level] } else { 0 }
            $existing.Severity[$level] = [Math]::Round($oldWeight * $oldVal + $lr * $newVal, 4)
        }

        # ── Blend top sources ──
        $allSources = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($key in $existing.TopSources.Keys) { $allSources.Add($key) | Out-Null }
        foreach ($key in $newProfile.TopSources.Keys) { $allSources.Add($key) | Out-Null }
        $blendedSources = @{}
        foreach ($src in $allSources) {
            $oldVal = if ($existing.TopSources.ContainsKey($src)) { [double]$existing.TopSources[$src] } else { 0 }
            $newVal = if ($newProfile.TopSources.ContainsKey($src)) { [double]$newProfile.TopSources[$src] } else { 0 }
            $blended = [Math]::Round($oldWeight * $oldVal + $lr * $newVal, 4)
            if ($blended -gt 0.01) { $blendedSources[$src] = $blended }
        }
        $existing.TopSources = $blendedSources

        # ── Blend top fields ──
        $allFieldNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($key in $existing.TopFields.Keys) { $allFieldNames.Add($key) | Out-Null }
        foreach ($key in $newProfile.TopFields.Keys) { $allFieldNames.Add($key) | Out-Null }

        foreach ($fieldName in $allFieldNames) {
            $existingField = if ($existing.TopFields.ContainsKey($fieldName)) { $existing.TopFields[$fieldName] } else { @{} }
            $newField = if ($newProfile.TopFields.ContainsKey($fieldName)) { $newProfile.TopFields[$fieldName] } else { @{} }

            $allValues = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($key in $existingField.Keys) { $allValues.Add($key) | Out-Null }
            foreach ($key in $newField.Keys) { $allValues.Add($key) | Out-Null }

            $blendedField = @{}
            foreach ($val in $allValues) {
                $oldVal = if ($existingField.ContainsKey($val)) { [double]$existingField[$val] } else { 0 }
                $newVal = if ($newField.ContainsKey($val)) { [double]$newField[$val] } else { 0 }
                $blended = [Math]::Round($oldWeight * $oldVal + $lr * $newVal, 4)
                if ($blended -gt 0.01) { $blendedField[$val] = $blended }
            }
            $existing.TopFields[$fieldName] = $blendedField
        }

        # ── Merge user patterns — union of known IPs ──
        foreach ($userKey in $newProfile.UserPatterns.Keys) {
            if ($existing.UserPatterns.ContainsKey($userKey)) {
                $existingIps = [System.Collections.Generic.HashSet[string]]::new(
                    [string[]]@($existing.UserPatterns[$userKey]),
                    [System.StringComparer]::OrdinalIgnoreCase
                )
                foreach ($ip in $newProfile.UserPatterns[$userKey]) {
                    $existingIps.Add($ip) | Out-Null
                }
                $existing.UserPatterns[$userKey] = @($existingIps)
            } else {
                $existing.UserPatterns[$userKey] = @($newProfile.UserPatterns[$userKey])
            }
        }

        # ── Blend sequence patterns ──
        $allPairs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($key in $existing.SequencePatterns.Keys) { $allPairs.Add($key) | Out-Null }
        foreach ($key in $newProfile.SequencePatterns.Keys) { $allPairs.Add($key) | Out-Null }
        $blendedSeq = @{}
        foreach ($pair in $allPairs) {
            $oldVal = if ($existing.SequencePatterns.ContainsKey($pair)) { [double]$existing.SequencePatterns[$pair] } else { 0 }
            $newVal = if ($newProfile.SequencePatterns.ContainsKey($pair)) { [double]$newProfile.SequencePatterns[$pair] } else { 0 }
            $blended = [Math]::Round($oldWeight * $oldVal + $lr * $newVal, 4)
            if ($blended -gt 0.01) { $blendedSeq[$pair] = $blended }
        }
        $existing.SequencePatterns = $blendedSeq

        # ── Update metadata ──
        $existing.EntryCount = $existing.EntryCount + $newProfile.EntryCount
        $existing.CreatedAt = (Get-Date).ToString("o")

        # Extend date range
        if ($newProfile.DateRange.From) {
            $newFrom = [datetime]$newProfile.DateRange.From
            $oldFrom = [datetime]$existing.DateRange.From
            if ($newFrom -lt $oldFrom) { $existing.DateRange.From = $newProfile.DateRange.From }
        }
        if ($newProfile.DateRange.To) {
            $newTo = [datetime]$newProfile.DateRange.To
            $oldTo = [datetime]$existing.DateRange.To
            if ($newTo -gt $oldTo) { $existing.DateRange.To = $newProfile.DateRange.To }
        }

        Save-BaselineProfile -Profile $existing -Name $BaselineName
        Write-Log "Baseline '$BaselineName' updated successfully (total entries: $($existing.EntryCount))"
        return $existing
    } catch {
        Write-Log "Failed to update baseline '$BaselineName': $_" -Level ERROR
        return $null
    }
}

# ───────────────────────────────────────────────────────────────────────────────
# Get-BaselineList — List available baseline profiles
# ───────────────────────────────────────────────────────────────────────────────
function Get-BaselineList {
    $dir = Get-BaselinePath
    $results = [System.Collections.Generic.List[object]]::new()

    try {
        $files = Get-ChildItem -Path $dir -Filter "*.json" -File -ErrorAction SilentlyContinue
        if (-not $files) { return @($results) }

        foreach ($file in $files) {
            try {
                $json = [System.IO.File]::ReadAllText($file.FullName)
                $raw = $json | ConvertFrom-Json
                $results.Add(@{
                    Name         = $raw.Name
                    FileName     = $file.Name
                    CreatedAt    = $raw.CreatedAt
                    EntryCount   = $raw.EntryCount
                    SourceFilter = $raw.SourceFilter
                    SiteFilter   = $raw.SiteFilter
                    DateRange    = @{
                        From = $raw.DateRange.From
                        To   = $raw.DateRange.To
                    }
                })
            } catch {
                Write-Log "Failed to read baseline file '$($file.Name)': $_" -Level WARNING
            }
        }
    } catch {
        Write-Log "Failed to enumerate baselines: $_" -Level WARNING
    }

    return @($results)
}

# ───────────────────────────────────────────────────────────────────────────────
# Remove-Baseline — Delete a baseline profile
# ───────────────────────────────────────────────────────────────────────────────
function Remove-Baseline {
    param([string]$BaselineName)

    if ([string]::IsNullOrWhiteSpace($BaselineName)) {
        Write-Log "Cannot remove baseline: name is required" -Level ERROR
        return
    }

    $dir = Get-BaselinePath
    $filePath = Join-Path $dir "$BaselineName.json"

    if (-not (Test-Path $filePath)) {
        Write-Log "Baseline '$BaselineName' not found" -Level WARNING
        return
    }

    try {
        Remove-Item -Path $filePath -Force
        Write-Log "Baseline '$BaselineName' removed"
    } catch {
        Write-Log "Failed to remove baseline '$BaselineName': $_" -Level ERROR
    }
}
