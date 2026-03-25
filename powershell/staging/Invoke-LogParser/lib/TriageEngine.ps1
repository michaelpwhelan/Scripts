# ═══════════════════════════════════════════════════════════════════════════════
# TRIAGE ENGINE — Automated investigation workflows
# ═══════════════════════════════════════════════════════════════════════════════

function Initialize-TriageRules {
    $rulesPath = Join-Path $Config.ScriptRoot "data" "triage-rules.json"
    if (-not (Test-Path $rulesPath)) {
        Write-Log "Triage rules file not found: $rulesPath" -Level WARNING
        $Script:State.TriageRules = @()
        return
    }
    try {
        $content = [System.IO.File]::ReadAllText($rulesPath)
        $parsed = $content | ConvertFrom-Json
        $Script:State.TriageRules = @($parsed)
        $enabledCount = @($Script:State.TriageRules | Where-Object { $_.enabled }).Count
        Write-Log "Loaded $($Script:State.TriageRules.Count) triage rules ($enabledCount enabled)"
    } catch {
        Write-Log "Failed to load triage rules: $_" -Level ERROR
        $Script:State.TriageRules = @()
    }
}

function Invoke-TriageCheck {
    param(
        [System.Collections.Generic.List[object]]$Entries,
        [string[]]$RuleIds = @()
    )

    if (-not $Entries -or $Entries.Count -eq 0) {
        Write-Log "No entries provided for triage check" -Level WARNING
        return @{
            TriageResults = @()
            Summary = @{ Total = 0; Critical = 0; High = 0; Medium = 0; Low = 0; Actions = @() }
        }
    }

    # Load rules if not already loaded
    if (-not $Script:State.TriageRules -or $Script:State.TriageRules.Count -eq 0) {
        Initialize-TriageRules
    }

    $rules = @($Script:State.TriageRules | Where-Object { $_.enabled })
    if ($RuleIds.Count -gt 0) {
        $ruleIdSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$RuleIds, [System.StringComparer]::OrdinalIgnoreCase)
        $rules = @($rules | Where-Object { $ruleIdSet.Contains($_.id) })
    }

    if ($rules.Count -eq 0) {
        Write-Log "No enabled triage rules to evaluate" -Level WARNING
        return @{
            TriageResults = @()
            Summary = @{ Total = 0; Critical = 0; High = 0; Medium = 0; Low = 0; Actions = @() }
        }
    }

    $triageResults = [System.Collections.Generic.List[object]]::new()
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    foreach ($rule in $rules) {
        try {
            $ruleResult = Invoke-EvaluateTriageRule -Rule $rule -Entries $Entries
            if ($ruleResult) {
                $triageResults.Add($ruleResult)
            }
        } catch {
            Write-Log "Error evaluating triage rule '$($rule.id)': $_" -Level ERROR
        }
    }

    $sw.Stop()
    Write-Log "Triage check completed: $($triageResults.Count) findings in $($sw.ElapsedMilliseconds)ms"

    # Build summary
    $summary = @{
        Total    = $triageResults.Count
        Critical = @($triageResults | Where-Object { $_.Severity -eq 'Critical' }).Count
        High     = @($triageResults | Where-Object { $_.Severity -eq 'High' }).Count
        Medium   = @($triageResults | Where-Object { $_.Severity -eq 'Medium' }).Count
        Low      = @($triageResults | Where-Object { $_.Severity -eq 'Low' }).Count
        Actions  = [System.Collections.Generic.List[string]]::new()
    }
    foreach ($result in $triageResults) {
        foreach ($action in $result.RecommendedActions) {
            if (-not $summary.Actions.Contains($action)) {
                $summary.Actions.Add($action)
            }
        }
    }

    return @{
        TriageResults = @($triageResults)
        Summary       = $summary
    }
}

function Invoke-EvaluateTriageRule {
    param(
        [object]$Rule,
        [System.Collections.Generic.List[object]]$Entries
    )

    $triggerType = if ($Rule.trigger -is [PSCustomObject]) { $Rule.trigger.type } else { $Rule.trigger['type'] }

    $matchingEntries = [System.Collections.Generic.List[object]]::new()

    switch ($triggerType) {
        'threshold' {
            $matchingEntries = Invoke-EvaluateThresholdTrigger -Rule $Rule -Entries $Entries
        }
        'pattern' {
            $matchingEntries = Invoke-EvaluatePatternTrigger -Rule $Rule -Entries $Entries
        }
        'sequence' {
            $matchingEntries = Invoke-EvaluateSequenceTrigger -Rule $Rule -Entries $Entries
        }
        default {
            Write-Log "Unknown trigger type '$triggerType' in rule '$($Rule.id)'" -Level WARNING
            return $null
        }
    }

    if (-not $matchingEntries -or $matchingEntries.Count -eq 0) {
        return $null
    }

    # Gather related events by expanding the time window and following correlation keys
    $relatedEvents = Invoke-GatherRelatedEvents -Rule $Rule -TriggerEntries $matchingEntries -AllEntries $Entries

    # Extract affected entities
    $affectedEntities = Invoke-ExtractAffectedEntities -Entries $matchingEntries -RelatedEntries $relatedEvents

    # Enrich with asset context if AssetEngine is available
    $assetContext = @()
    if (Get-Command -Name 'Get-AssetInfo' -ErrorAction SilentlyContinue) {
        try {
            foreach ($entity in $affectedEntities) {
                $assetInfo = Get-AssetInfo -Identifier $entity.Value -ErrorAction SilentlyContinue
                if ($assetInfo) {
                    $assetContext += $assetInfo
                }
            }
        } catch {
            # AssetEngine not available or errored, continue without enrichment
        }
    }

    # Determine severity with escalation
    $severity = Invoke-AssessTriageSeverity -Rule $Rule -MatchCount $matchingEntries.Count -AssetContext $assetContext

    # Build trigger summary
    $triggerSummary = Invoke-BuildTriggerSummary -Rule $Rule -MatchingEntries $matchingEntries

    # Get recommended steps from the rule
    $recommendedSteps = @()
    if ($Rule.recommendedSteps) {
        $recommendedSteps = @($Rule.recommendedSteps)
    }

    # Get actions from the rule
    $actions = @()
    if ($Rule.actions) {
        $actions = @($Rule.actions)
    }

    return @{
        RuleId             = [string]$Rule.id
        RuleName           = [string]$Rule.name
        Severity           = $severity
        Triggered          = [datetime](Get-Date)
        TriggerSummary     = $triggerSummary
        EventCount         = $matchingEntries.Count
        ContributingEvents = @($matchingEntries)
        RelatedEvents      = @($relatedEvents)
        AffectedEntities   = @($affectedEntities)
        AssetContext        = @($assetContext)
        RecommendedActions = $recommendedSteps
        Actions            = $actions
        TicketCreated      = $false
        TicketNumber       = $null
    }
}

function Test-EntryMatchesFilter {
    param(
        [object]$Entry,
        [object]$Filter
    )

    # Level filter
    if ($Filter.levels) {
        $levels = @($Filter.levels)
        if ($levels.Count -gt 0 -and $Entry.Level -and $levels -notcontains $Entry.Level) {
            return $false
        }
    }

    # Source format filter
    if ($Filter.sourceFormatMatch) {
        $sourceFormat = if ($Entry.Extra -and $Entry.Extra['SourceFormat']) { $Entry.Extra['SourceFormat'] } else { '' }
        if (-not $sourceFormat -or $sourceFormat -notmatch $Filter.sourceFormatMatch) {
            return $false
        }
    }

    # Message pattern filter
    if ($Filter.messagePattern) {
        if (-not $Entry.Message -or $Entry.Message -notmatch $Filter.messagePattern) {
            return $false
        }
    }

    # Extra field match filters
    if ($Filter.extraMatch) {
        foreach ($matchDef in @($Filter.extraMatch)) {
            $fieldName = $matchDef.field
            $fieldVal = if ($Entry.Extra -and $Entry.Extra[$fieldName]) { $Entry.Extra[$fieldName] } else { $null }

            if ($null -eq $fieldVal) {
                # Also check direct Extra fields for PSCustomObject from parsed data
                if ($Entry.Extra -is [hashtable] -and $Entry.Extra.ContainsKey($fieldName)) {
                    $fieldVal = $Entry.Extra[$fieldName]
                }
                if ($null -eq $fieldVal) { return $false }
            }

            # Value list match (EventID in [4625, 4771])
            if ($matchDef.values) {
                $matchValues = @($matchDef.values)
                $found = $false
                foreach ($mv in $matchValues) {
                    if ([string]$fieldVal -eq [string]$mv) { $found = $true; break }
                }
                if (-not $found) { return $false }
            }

            # Pattern match (action matches "deny|fail")
            if ($matchDef.pattern) {
                if ([string]$fieldVal -notmatch $matchDef.pattern) { return $false }
            }

            # Comparison match (DaysToExpiry lte 30)
            if ($matchDef.comparison) {
                try {
                    $numVal = [double]$fieldVal
                    $numTarget = [double]$matchDef.value
                    $compResult = $false
                    switch ($matchDef.comparison) {
                        'lte' { $compResult = $numVal -le $numTarget }
                        'lt'  { $compResult = $numVal -lt $numTarget }
                        'gte' { $compResult = $numVal -ge $numTarget }
                        'gt'  { $compResult = $numVal -gt $numTarget }
                        'eq'  { $compResult = $numVal -eq $numTarget }
                        default { $compResult = $false }
                    }
                    if (-not $compResult) { return $false }
                } catch {
                    return $false
                }
            }
        }
    }

    return $true
}

function Invoke-EvaluateThresholdTrigger {
    param(
        [object]$Rule,
        [System.Collections.Generic.List[object]]$Entries
    )

    $trigger = $Rule.trigger
    $filter = $trigger.filter
    $threshold = [int]$trigger.threshold
    $windowMinutes = [int]$trigger.windowMinutes
    $groupByField = if ($trigger.groupBy) { [string]$trigger.groupBy } else { $null }

    # Check for time exclusion on the trigger
    $hasTimeExclusion = $false
    $exclusionDay = $null
    $exclusionStart = $null
    $exclusionEnd = $null
    if ($trigger.timeExclusion) {
        $hasTimeExclusion = $true
        $exclusionDay = $trigger.timeExclusion.day
        $exclusionStart = $trigger.timeExclusion.start
        $exclusionEnd = $trigger.timeExclusion.end
    }

    # First pass: filter matching entries
    $filtered = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $Entries) {
        if (Test-EntryMatchesFilter -Entry $entry -Filter $filter) {
            # Apply time exclusion: events INSIDE the maintenance window do NOT trigger
            if ($hasTimeExclusion -and $entry.Timestamp -ne [datetime]::MinValue) {
                $dayName = $entry.Timestamp.DayOfWeek.ToString()
                if ($dayName -eq $exclusionDay) {
                    $timeStr = $entry.Timestamp.ToString('HH:mm')
                    if ($exclusionStart -and $exclusionEnd -and $timeStr -ge $exclusionStart -and $timeStr -le $exclusionEnd) {
                        continue
                    }
                }
            }
            $filtered.Add($entry)
        }
    }

    if ($filtered.Count -lt $threshold) {
        return [System.Collections.Generic.List[object]]::new()
    }

    # Group by the specified field if set
    if ($groupByField) {
        $groups = @{}
        foreach ($entry in $filtered) {
            $groupVal = $null
            if ($entry.Extra -and $entry.Extra[$groupByField]) {
                $groupVal = [string]$entry.Extra[$groupByField]
            }
            if (-not $groupVal) { $groupVal = '(unknown)' }
            if (-not $groups.ContainsKey($groupVal)) {
                $groups[$groupVal] = [System.Collections.Generic.List[object]]::new()
            }
            $groups[$groupVal].Add($entry)
        }

        # Evaluate threshold per group with sliding window
        $allTriggered = [System.Collections.Generic.List[object]]::new()
        foreach ($groupKey in $groups.Keys) {
            $groupEntries = $groups[$groupKey]
            $windowResult = Invoke-SlidingWindowCheck -Entries $groupEntries -Threshold $threshold -WindowMinutes $windowMinutes
            if ($windowResult -and $windowResult.Count -gt 0) {
                foreach ($e in $windowResult) { $allTriggered.Add($e) }
            }
        }
        return $allTriggered
    } else {
        # No grouping, evaluate threshold with sliding window across all matching entries
        return Invoke-SlidingWindowCheck -Entries $filtered -Threshold $threshold -WindowMinutes $windowMinutes
    }
}

function Invoke-SlidingWindowCheck {
    param(
        [System.Collections.Generic.List[object]]$Entries,
        [int]$Threshold,
        [int]$WindowMinutes
    )

    if ($Entries.Count -lt $Threshold) {
        return [System.Collections.Generic.List[object]]::new()
    }

    # Sort by timestamp
    $sorted = @($Entries | Where-Object { $_.Timestamp -ne [datetime]::MinValue } | Sort-Object Timestamp)
    if ($sorted.Count -lt $Threshold) {
        return [System.Collections.Generic.List[object]]::new()
    }

    $windowSpan = [timespan]::FromMinutes($WindowMinutes)

    # Sliding window: find the densest window that meets threshold
    $bestWindow = [System.Collections.Generic.List[object]]::new()

    for ($i = 0; $i -le $sorted.Count - $Threshold; $i++) {
        $windowStart = $sorted[$i].Timestamp
        $windowEnd = $windowStart.Add($windowSpan)
        $windowEntries = [System.Collections.Generic.List[object]]::new()

        for ($j = $i; $j -lt $sorted.Count; $j++) {
            if ($sorted[$j].Timestamp -le $windowEnd) {
                $windowEntries.Add($sorted[$j])
            } else {
                break
            }
        }

        if ($windowEntries.Count -ge $Threshold -and $windowEntries.Count -gt $bestWindow.Count) {
            $bestWindow = $windowEntries
        }
    }

    return $bestWindow
}

function Invoke-EvaluatePatternTrigger {
    param(
        [object]$Rule,
        [System.Collections.Generic.List[object]]$Entries
    )

    $trigger = $Rule.trigger
    $filter = $trigger.filter

    # Check for time exclusion
    $hasTimeExclusion = $false
    $exclusionDay = $null
    $exclusionStart = $null
    $exclusionEnd = $null
    if ($trigger.timeExclusion) {
        $hasTimeExclusion = $true
        $exclusionDay = $trigger.timeExclusion.day
        $exclusionStart = $trigger.timeExclusion.start
        $exclusionEnd = $trigger.timeExclusion.end
    }

    $matched = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $Entries) {
        if (Test-EntryMatchesFilter -Entry $entry -Filter $filter) {
            if ($hasTimeExclusion -and $entry.Timestamp -ne [datetime]::MinValue) {
                $dayName = $entry.Timestamp.DayOfWeek.ToString()
                if ($dayName -eq $exclusionDay) {
                    $timeStr = $entry.Timestamp.ToString('HH:mm')
                    if ($exclusionStart -and $exclusionEnd -and $timeStr -ge $exclusionStart -and $timeStr -le $exclusionEnd) {
                        continue
                    }
                }
            }
            $matched.Add($entry)
        }
    }

    return $matched
}

function Invoke-EvaluateSequenceTrigger {
    param(
        [object]$Rule,
        [System.Collections.Generic.List[object]]$Entries
    )

    $trigger = $Rule.trigger
    $steps = @($trigger.steps)
    $windowMinutes = [int]$trigger.windowMinutes
    $correlationKey = if ($trigger.correlationKey) { [string]$trigger.correlationKey } else { $null }

    if ($steps.Count -lt 2) {
        Write-Log "Sequence trigger for rule '$($Rule.id)' requires at least 2 steps" -Level WARNING
        return [System.Collections.Generic.List[object]]::new()
    }

    # Match entries for each step
    $stepMatches = @{}
    foreach ($step in $steps) {
        $label = [string]$step.label
        $stepFilter = $step.filter
        $stepMatches[$label] = [System.Collections.Generic.List[object]]::new()

        foreach ($entry in $Entries) {
            if (Test-EntryMatchesFilter -Entry $entry -Filter $stepFilter) {
                $stepMatches[$label].Add($entry)
            }
        }
    }

    # Check each step has at least one match
    foreach ($step in $steps) {
        $label = [string]$step.label
        if ($stepMatches[$label].Count -eq 0) {
            return [System.Collections.Generic.List[object]]::new()
        }
    }

    # Find sequences: step1 followed by step2 within window, correlated by key
    $firstStepLabel = [string]$steps[0].label
    $secondStepLabel = [string]$steps[1].label
    $windowSpan = [timespan]::FromMinutes($windowMinutes)

    $sequenceMatches = [System.Collections.Generic.List[object]]::new()

    foreach ($firstEntry in $stepMatches[$firstStepLabel]) {
        if ($firstEntry.Timestamp -eq [datetime]::MinValue) { continue }

        $windowEnd = $firstEntry.Timestamp.Add($windowSpan)

        foreach ($secondEntry in $stepMatches[$secondStepLabel]) {
            if ($secondEntry.Timestamp -eq [datetime]::MinValue) { continue }
            if ($secondEntry.Timestamp -lt $firstEntry.Timestamp) { continue }
            if ($secondEntry.Timestamp -gt $windowEnd) { continue }

            # Check correlation key match
            if ($correlationKey) {
                $firstVal = if ($firstEntry.Extra -and $firstEntry.Extra[$correlationKey]) { [string]$firstEntry.Extra[$correlationKey] } else { $null }
                $secondVal = if ($secondEntry.Extra -and $secondEntry.Extra[$correlationKey]) { [string]$secondEntry.Extra[$correlationKey] } else { $null }

                if (-not $firstVal -or -not $secondVal) { continue }
                if ($firstVal -ne $secondVal) { continue }
            }

            # Sequence match found
            if (-not $sequenceMatches.Contains($firstEntry)) {
                $sequenceMatches.Add($firstEntry)
            }
            if (-not $sequenceMatches.Contains($secondEntry)) {
                $sequenceMatches.Add($secondEntry)
            }
        }
    }

    return $sequenceMatches
}

function Invoke-GatherRelatedEvents {
    param(
        [object]$Rule,
        [System.Collections.Generic.List[object]]$TriggerEntries,
        [System.Collections.Generic.List[object]]$AllEntries
    )

    $gather = $Rule.gather
    if (-not $gather) { return @() }

    $expandMinutes = if ($gather.expandWindowMinutes) { [int]$gather.expandWindowMinutes } else { 0 }
    $correlationKeys = if ($gather.correlationKeys) { @($gather.correlationKeys) } else { @() }

    if ($expandMinutes -eq 0 -and $correlationKeys.Count -eq 0) {
        return @()
    }

    # Determine the trigger time window
    $triggerTimestamps = @($TriggerEntries | Where-Object { $_.Timestamp -ne [datetime]::MinValue } | ForEach-Object { $_.Timestamp })
    if ($triggerTimestamps.Count -eq 0) { return @() }

    $triggerMin = ($triggerTimestamps | Measure-Object -Minimum).Minimum
    $triggerMax = ($triggerTimestamps | Measure-Object -Maximum).Maximum
    $expandSpan = [timespan]::FromMinutes($expandMinutes)
    $searchFrom = $triggerMin.Subtract($expandSpan)
    $searchTo = $triggerMax.Add($expandSpan)

    # Collect correlation values from trigger entries
    $corrValues = @{}
    foreach ($key in $correlationKeys) {
        $corrValues[$key] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $TriggerEntries) {
            $val = if ($entry.Extra -and $entry.Extra[$key]) { [string]$entry.Extra[$key] } else { $null }
            if ($val) {
                $corrValues[$key].Add($val) | Out-Null
            }
        }
    }

    # Build a set of trigger entry indices to exclude from related results
    $triggerSet = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($entry in $TriggerEntries) {
        $triggerSet.Add($entry.Index) | Out-Null
    }

    # Gather related events within expanded window matching any correlation key
    $related = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $AllEntries) {
        if ($triggerSet.Contains($entry.Index)) { continue }
        if ($entry.Timestamp -eq [datetime]::MinValue) { continue }
        if ($entry.Timestamp -lt $searchFrom -or $entry.Timestamp -gt $searchTo) { continue }

        # Check if entry matches any correlation key value
        $isCorrelated = $false
        if ($correlationKeys.Count -eq 0) {
            # No correlation keys, just use time window
            $isCorrelated = $true
        } else {
            foreach ($key in $correlationKeys) {
                $entryVal = if ($entry.Extra -and $entry.Extra[$key]) { [string]$entry.Extra[$key] } else { $null }
                if ($entryVal -and $corrValues[$key].Contains($entryVal)) {
                    $isCorrelated = $true
                    break
                }
            }
        }

        if ($isCorrelated) {
            $related.Add($entry)
        }
    }

    return @($related)
}

function Invoke-ExtractAffectedEntities {
    param(
        [System.Collections.Generic.List[object]]$Entries,
        [object[]]$RelatedEntries
    )

    $entities = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $entityFields = @{
        'user'                  = 'User'
        'User-Name'             = 'User'
        'TargetUserName'        = 'User'
        'SubjectUserName'       = 'User'
        'UserPrincipalName'     = 'User'
        'srcuser'               = 'User'
        'dstuser'               = 'User'
        'srcip'                 = 'IP'
        'dstip'                 = 'IP'
        'IpAddress'             = 'IP'
        'Calling-Station-Id'    = 'IP'
        'Client-IP-Address'     = 'IP'
        'remip'                 = 'IP'
        'DeviceName'            = 'Device'
        'devname'               = 'Device'
        'ComputerName'          = 'Device'
        'WorkstationName'       = 'Device'
        'NAS-IP-Address'        = 'Device'
        'TunnelName'            = 'Tunnel'
        'NeighborIp'            = 'BGPPeer'
        'VmName'                = 'VM'
        'Subject'               = 'Certificate'
        'Thumbprint'            = 'Certificate'
    }

    $allEntries = [System.Collections.Generic.List[object]]::new()
    foreach ($e in $Entries) { $allEntries.Add($e) }
    if ($RelatedEntries) {
        foreach ($e in $RelatedEntries) { $allEntries.Add($e) }
    }

    foreach ($entry in $allEntries) {
        if (-not $entry.Extra) { continue }
        foreach ($fieldName in $entityFields.Keys) {
            $val = $entry.Extra[$fieldName]
            if ($val -and [string]$val -ne '-' -and [string]$val -ne 'N/A' -and [string]$val -ne 'SYSTEM') {
                $key = "$($entityFields[$fieldName]):$val"
                if (-not $seen.Contains($key)) {
                    $seen.Add($key) | Out-Null
                    $entities.Add(@{
                        Type  = $entityFields[$fieldName]
                        Field = $fieldName
                        Value = [string]$val
                    })
                }
            }
        }
    }

    return @($entities)
}

function Invoke-AssessTriageSeverity {
    param(
        [object]$Rule,
        [int]$MatchCount,
        [object[]]$AssetContext
    )

    $baseSeverity = if ($Rule.severity) { [string]$Rule.severity } else { 'MEDIUM' }

    # Normalize to title case
    $severity = switch ($baseSeverity.ToUpper()) {
        'CRITICAL' { 'Critical' }
        'HIGH'     { 'High' }
        'MEDIUM'   { 'Medium' }
        'LOW'      { 'Low' }
        default    { 'Medium' }
    }

    # Check threshold-based escalation
    if ($Rule.severityEscalation) {
        $escalation = $Rule.severityEscalation

        # Count-based escalation
        if ($escalation.threshold) {
            $escThreshold = [int]$escalation.threshold
            if ($MatchCount -ge $escThreshold -and $escalation.escalateTo) {
                $severity = switch ([string]$escalation.escalateTo.ToUpper()) {
                    'CRITICAL' { 'Critical' }
                    'HIGH'     { 'High' }
                    'MEDIUM'   { 'Medium' }
                    'LOW'      { 'Low' }
                    default    { $severity }
                }
            }
        }

        # Asset criticality-based escalation
        if ($escalation.assetCriticalityMin -and $AssetContext -and $AssetContext.Count -gt 0) {
            $criticalityOrder = @{ 'Critical' = 4; 'High' = 3; 'Medium' = 2; 'Low' = 1 }
            $minRequired = if ($criticalityOrder.ContainsKey($escalation.assetCriticalityMin)) {
                $criticalityOrder[$escalation.assetCriticalityMin]
            } else { 0 }

            foreach ($asset in $AssetContext) {
                $assetCrit = if ($asset.Criticality) { [string]$asset.Criticality } else { 'Low' }
                $assetOrder = if ($criticalityOrder.ContainsKey($assetCrit)) {
                    $criticalityOrder[$assetCrit]
                } else { 0 }

                if ($assetOrder -ge $minRequired -and $escalation.escalateTo) {
                    $severity = switch ([string]$escalation.escalateTo.ToUpper()) {
                        'CRITICAL' { 'Critical' }
                        'HIGH'     { 'High' }
                        'MEDIUM'   { 'Medium' }
                        'LOW'      { 'Low' }
                        default    { $severity }
                    }
                    break
                }
            }
        }
    }

    return $severity
}

function Invoke-BuildTriggerSummary {
    param(
        [object]$Rule,
        [System.Collections.Generic.List[object]]$MatchingEntries
    )

    $count = $MatchingEntries.Count
    $triggerType = if ($Rule.trigger.type) { [string]$Rule.trigger.type } else { 'pattern' }

    # Calculate time span of matching entries
    $timestamps = @($MatchingEntries | Where-Object { $_.Timestamp -ne [datetime]::MinValue } | ForEach-Object { $_.Timestamp })
    $spanText = ''
    if ($timestamps.Count -ge 2) {
        $minTs = ($timestamps | Measure-Object -Minimum).Minimum
        $maxTs = ($timestamps | Measure-Object -Maximum).Maximum
        $span = $maxTs - $minTs
        if ($span.TotalHours -ge 1) {
            $spanText = " in $([Math]::Round($span.TotalHours, 1)) hours"
        } elseif ($span.TotalMinutes -ge 1) {
            $spanText = " in $([Math]::Round($span.TotalMinutes, 0)) minutes"
        } else {
            $spanText = " in $([Math]::Round($span.TotalSeconds, 0)) seconds"
        }
    }

    # Add groupBy context if available
    $groupContext = ''
    if ($triggerType -eq 'threshold' -and $Rule.trigger.groupBy) {
        $groupField = [string]$Rule.trigger.groupBy
        $uniqueGroups = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $MatchingEntries) {
            $val = if ($entry.Extra -and $entry.Extra[$groupField]) { [string]$entry.Extra[$groupField] } else { $null }
            if ($val) { $uniqueGroups.Add($val) | Out-Null }
        }
        if ($uniqueGroups.Count -gt 0) {
            $groupList = ($uniqueGroups | Select-Object -First 3) -join ', '
            if ($uniqueGroups.Count -gt 3) { $groupList += " (+$($uniqueGroups.Count - 3) more)" }
            $groupContext = " for $groupList"
        }
    }

    return "$count matching events$groupContext$spanText - $($Rule.name)"
}

function Show-TriageDialog {
    param($Results)

    if (-not $Results -or @($Results.TriageResults).Count -eq 0) {
        if (-not $Script:UseConsole) {
            [System.Windows.Forms.MessageBox]::Show("No triage findings detected.", "Triage Results")
        } else {
            Write-Host "No triage findings detected."
        }
        return
    }

    if ($Script:UseConsole) {
        Write-TriageTable -Results $Results
        return
    }

    $triageResults = @($Results.TriageResults)
    $summary = $Results.Summary

    $dlg = [System.Windows.Forms.Form]::new()
    $dlg.Text = "Triage Results ($($summary.Total) findings)"
    $dlg.Size = [System.Drawing.Size]::new(1050, 600)
    $dlg.StartPosition = "CenterParent"
    $t = $Script:Themes[$Script:State.ActiveTheme]
    $dlg.BackColor = $t.FormBack
    $dlg.ForeColor = $t.FormFore

    # Summary panel at top
    $summaryPanel = [System.Windows.Forms.Panel]::new()
    $summaryPanel.Dock = "Top"
    $summaryPanel.Height = 40
    $summaryPanel.BackColor = $t.PanelBack

    $summaryLabel = [System.Windows.Forms.Label]::new()
    $summaryLabel.Dock = "Fill"
    $summaryLabel.TextAlign = "MiddleLeft"
    $summaryLabel.Font = [System.Drawing.Font]::new("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $summaryLabel.ForeColor = $t.FormFore
    $summaryParts = [System.Collections.Generic.List[string]]::new()
    $summaryParts.Add("Total: $($summary.Total)")
    if ($summary.Critical -gt 0) { $summaryParts.Add("Critical: $($summary.Critical)") }
    if ($summary.High -gt 0) { $summaryParts.Add("High: $($summary.High)") }
    if ($summary.Medium -gt 0) { $summaryParts.Add("Medium: $($summary.Medium)") }
    if ($summary.Low -gt 0) { $summaryParts.Add("Low: $($summary.Low)") }
    $summaryLabel.Text = "  " + ($summaryParts -join "  |  ")
    $summaryPanel.Controls.Add($summaryLabel)

    # Main grid
    $grid = [System.Windows.Forms.DataGridView]::new()
    $grid.Dock = "Fill"
    $grid.ReadOnly = $true
    $grid.AllowUserToAddRows = $false
    $grid.SelectionMode = "FullRowSelect"
    $grid.BackgroundColor = $t.GridBack
    $grid.DefaultCellStyle.BackColor = $t.GridBack
    $grid.DefaultCellStyle.ForeColor = $t.FormFore
    $grid.DefaultCellStyle.SelectionBackColor = $t.SelectionBack
    $grid.DefaultCellStyle.SelectionForeColor = $t.SelectionFore
    $grid.ColumnHeadersDefaultCellStyle.BackColor = $t.GridHeaderBack
    $grid.ColumnHeadersDefaultCellStyle.ForeColor = $t.GridHeaderFore
    $grid.EnableHeadersVisualStyles = $false

    $grid.Columns.Add("Severity", "Severity") | Out-Null
    $grid.Columns.Add("RuleId", "Rule ID") | Out-Null
    $grid.Columns.Add("RuleName", "Rule Name") | Out-Null
    $grid.Columns.Add("EventCount", "Events") | Out-Null
    $grid.Columns.Add("RelatedCount", "Related") | Out-Null
    $grid.Columns.Add("Entities", "Affected Entities") | Out-Null
    $grid.Columns.Add("TriggerSummary", "Summary") | Out-Null

    foreach ($result in $triageResults) {
        $entitySummary = @($result.AffectedEntities | ForEach-Object { "$($_.Type):$($_.Value)" } | Select-Object -First 5) -join '; '
        if ($result.AffectedEntities.Count -gt 5) {
            $entitySummary += " (+$($result.AffectedEntities.Count - 5) more)"
        }
        $rowIdx = $grid.Rows.Add(
            $result.Severity,
            $result.RuleId,
            $result.RuleName,
            $result.EventCount,
            $result.RelatedEvents.Count,
            $entitySummary,
            $result.TriggerSummary
        )

        # Color severity cell
        $sevCell = $grid.Rows[$rowIdx].Cells[0]
        switch ($result.Severity) {
            'Critical' {
                $sevCell.Style.BackColor = [System.Drawing.Color]::DarkRed
                $sevCell.Style.ForeColor = [System.Drawing.Color]::White
            }
            'High' {
                $sevCell.Style.BackColor = [System.Drawing.Color]::FromArgb(255, 68, 68)
                $sevCell.Style.ForeColor = [System.Drawing.Color]::White
            }
            'Medium' {
                $sevCell.Style.BackColor = [System.Drawing.Color]::FromArgb(255, 140, 0)
                $sevCell.Style.ForeColor = [System.Drawing.Color]::Black
            }
            'Low' {
                $sevCell.Style.BackColor = [System.Drawing.Color]::FromArgb(255, 255, 100)
                $sevCell.Style.ForeColor = [System.Drawing.Color]::Black
            }
        }
    }

    $grid.AutoResizeColumns()

    # Detail panel at bottom
    $detailPanel = [System.Windows.Forms.Panel]::new()
    $detailPanel.Dock = "Bottom"
    $detailPanel.Height = 200
    $detailPanel.BackColor = $t.PanelBack

    $detailBox = [System.Windows.Forms.RichTextBox]::new()
    $detailBox.Dock = "Fill"
    $detailBox.ReadOnly = $true
    $detailBox.BackColor = $t.DetailBack
    $detailBox.ForeColor = $t.DetailFore
    $detailBox.Font = [System.Drawing.Font]::new("Consolas", 9)
    $detailPanel.Controls.Add($detailBox)

    # Selection change: show detail for selected row
    $grid.Add_SelectionChanged({
        if ($grid.SelectedRows.Count -gt 0) {
            $selIdx = $grid.SelectedRows[0].Index
            if ($selIdx -ge 0 -and $selIdx -lt $triageResults.Count) {
                $sel = $triageResults[$selIdx]
                $detailLines = [System.Collections.Generic.List[string]]::new()
                $detailLines.Add("=== $($sel.RuleName) ===")
                $detailLines.Add("Severity: $($sel.Severity)    Events: $($sel.EventCount)    Related: $($sel.RelatedEvents.Count)")
                $detailLines.Add("Trigger: $($sel.TriggerSummary)")
                $detailLines.Add("")
                $detailLines.Add("--- Affected Entities ---")
                foreach ($ent in $sel.AffectedEntities) {
                    $detailLines.Add("  $($ent.Type): $($ent.Value)")
                }
                $detailLines.Add("")
                $detailLines.Add("--- Recommended Actions ---")
                $stepNum = 1
                foreach ($step in $sel.RecommendedActions) {
                    $detailLines.Add("  $stepNum. $step")
                    $stepNum++
                }
                $detailBox.Text = $detailLines -join "`r`n"
            }
        }
    })

    # Double-click to filter main grid by contributing events
    $grid.Add_CellDoubleClick({
        param($sender, $e)
        if ($e.RowIndex -ge 0 -and $e.RowIndex -lt $triageResults.Count) {
            $sel = $triageResults[$e.RowIndex]
            if ($sel.ContributingEvents.Count -gt 0 -and $Script:UI.TxtSearch) {
                # Use the rule name as a search hint
                $Script:UI.TxtSearch.Text = $sel.RuleName
                $Script:UI.RadText.Checked = $true
                Invoke-ApplyFilters
                Update-StatsBar
                $dlg.Close()
            }
        }
    })

    $dlg.Controls.Add($grid)
    $dlg.Controls.Add($detailPanel)
    $dlg.Controls.Add($summaryPanel)
    $dlg.ShowDialog($Script:UI.Form) | Out-Null
    $dlg.Dispose()
}

function Write-TriageTable {
    param($Results)

    $r = $Script:ANSIReset
    $ct = $Script:ConsoleThemes[$Script:State.ActiveTheme]

    $triageResults = @($Results.TriageResults)
    $summary = $Results.Summary

    Write-Host ""
    Write-Host "$($ct.Title)Triage Results$r"

    # Summary line
    $summaryParts = [System.Collections.Generic.List[string]]::new()
    $summaryParts.Add("$($ct.Count)Total: $($summary.Total)$r")
    if ($summary.Critical -gt 0) { $summaryParts.Add("$($ct.CRITICAL)Critical: $($summary.Critical)$r") }
    if ($summary.High -gt 0) { $summaryParts.Add("$($ct.ERROR)High: $($summary.High)$r") }
    if ($summary.Medium -gt 0) { $summaryParts.Add("$($ct.WARNING)Medium: $($summary.Medium)$r") }
    if ($summary.Low -gt 0) { $summaryParts.Add("$($ct.INFO)Low: $($summary.Low)$r") }
    Write-Host ($summaryParts -join "  |  ")
    Write-Host "$($ct.Border)$([string][char]0x2500 * 120)$r"

    Write-Host "$($ct.Header){0,-10} {1,-22} {2,-30} {3,-8} {4,-8} {5}$r" -f "Severity", "Rule ID", "Rule Name", "Events", "Related", "Summary"
    Write-Host "$($ct.Border)$([string][char]0x2500 * 120)$r"

    foreach ($result in $triageResults) {
        $sevColor = switch ($result.Severity) {
            'Critical' { $ct.CRITICAL }
            'High'     { $ct.ERROR }
            'Medium'   { $ct.WARNING }
            'Low'      { $ct.INFO }
            default    { $ct.INFO }
        }

        $summaryTrunc = if ($result.TriggerSummary.Length -gt 40) {
            $result.TriggerSummary.Substring(0, 37) + '...'
        } else { $result.TriggerSummary }

        Write-Host "$sevColor{0,-10} {1,-22} {2,-30} {3,-8} {4,-8} {5}$r" -f $result.Severity, $result.RuleId, $result.RuleName, $result.EventCount, $result.RelatedEvents.Count, $summaryTrunc
    }

    # Per-finding detail
    Write-Host ""
    foreach ($result in $triageResults) {
        $sevColor = switch ($result.Severity) {
            'Critical' { $ct.CRITICAL }
            'High'     { $ct.ERROR }
            'Medium'   { $ct.WARNING }
            'Low'      { $ct.INFO }
            default    { $ct.INFO }
        }

        Write-Host "$($ct.Border)$([string][char]0x2500 * 80)$r"
        Write-Host "$sevColor[$($result.Severity)] $($result.RuleName)$r"
        Write-Host "$($ct.Dim)  $($result.TriggerSummary)$r"

        if ($result.AffectedEntities.Count -gt 0) {
            Write-Host "$($ct.Header)  Affected Entities:$r"
            foreach ($ent in ($result.AffectedEntities | Select-Object -First 10)) {
                Write-Host "$($ct.Dim)    $($ent.Type): $($ent.Value)$r"
            }
            if ($result.AffectedEntities.Count -gt 10) {
                Write-Host "$($ct.Dim)    (+$($result.AffectedEntities.Count - 10) more)$r"
            }
        }

        if ($result.RecommendedActions.Count -gt 0) {
            Write-Host "$($ct.Header)  Recommended Actions:$r"
            $stepNum = 1
            foreach ($step in $result.RecommendedActions) {
                Write-Host "$($ct.Dim)    $stepNum. $step$r"
                $stepNum++
            }
        }
        Write-Host ""
    }
}

function New-TriageReport {
    param(
        [string]$OutputPath,
        $TriageResults
    )

    if (-not $TriageResults -or -not $TriageResults.TriageResults -or @($TriageResults.TriageResults).Count -eq 0) {
        Write-Log "No triage results for report generation" -Level WARNING
        return
    }

    $results = @($TriageResults.TriageResults)
    $summary = $TriageResults.Summary

    try {
        $sw = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.Encoding]::UTF8)

        $sw.WriteLine(@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Triage Report</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: 'Courier New', monospace; margin: 30px; color: #000; background: #fff; max-width: 1200px; margin: 0 auto; padding: 30px; }
  h1 { border-bottom: 2px solid #000; padding-bottom: 8px; }
  h2 { border-left: 4px solid #666; background: #f0f0f0; padding: 6px 12px; margin-top: 25px; }
  h3 { margin-top: 15px; color: #333; }
  .section { margin-bottom: 20px; page-break-inside: avoid; }
  table { border-collapse: collapse; width: 100%; font-size: 12px; }
  th { background: #333; color: #fff; padding: 6px 10px; text-align: left; }
  td { padding: 5px 10px; border: 1px solid #ccc; }
  tr:nth-child(even) td { background: #f8f8f8; }
  code { background: #f0f0f0; border: 1px solid #ddd; padding: 2px 6px; font-family: 'Courier New', monospace; }
  .card { background: #f8f8f8; border: 1px solid #ddd; padding: 12px; display: inline-block; margin: 5px; min-width: 120px; text-align: center; }
  .card h3 { margin: 0 0 4px 0; font-size: 11px; text-transform: uppercase; color: #666; }
  .card .val { font-size: 22px; font-weight: bold; }
  .flag-ok { color: #228B22; font-weight: bold; }
  .flag-warn { color: #DAA520; font-weight: bold; }
  .flag-crit { color: #8B0000; font-weight: bold; }
  .sev-critical { background: #ffe0e0; border-left: 4px solid #8B0000; }
  .sev-high { background: #fff0f0; border-left: 4px solid #cc0000; }
  .sev-medium { background: #fffff0; border-left: 4px solid #DAA520; }
  .sev-low { background: #f0fff0; border-left: 4px solid #228B22; }
  .finding { padding: 15px; margin: 10px 0; }
  .finding h3 { margin-top: 0; }
  .action-list { list-style-type: decimal; padding-left: 20px; }
  .action-list li { margin: 4px 0; }
  .entity-tag { display: inline-block; background: #e8e8e8; border: 1px solid #ccc; border-radius: 3px; padding: 2px 8px; margin: 2px; font-size: 11px; }
  .meta { color: #888; font-size: 11px; margin-top: 30px; border-top: 1px solid #ddd; padding-top: 8px; }
  @media print { h2 { background: #eee !important; } th { background: #333 !important; -webkit-print-color-adjust: exact; } .finding { page-break-inside: avoid; } }
</style></head><body>
<h1>Triage Report</h1>
<p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
<strong>Findings:</strong> $($summary.Total)</p>
"@)

        # Summary cards
        $sw.WriteLine(@"
<div class="section"><h2>1. Executive Summary</h2>
<div class="card"><h3>Total Findings</h3><div class="val">$($summary.Total)</div></div>
<div class="card"><h3>Critical</h3><div class="val flag-crit">$($summary.Critical)</div></div>
<div class="card"><h3>High</h3><div class="val flag-crit">$($summary.High)</div></div>
<div class="card"><h3>Medium</h3><div class="val flag-warn">$($summary.Medium)</div></div>
<div class="card"><h3>Low</h3><div class="val flag-ok">$($summary.Low)</div></div>
</div>
"@)

        # Findings overview table
        $sw.WriteLine("<div class='section'><h2>2. Findings Overview</h2>")
        $sw.WriteLine("<table><tr><th>Severity</th><th>Rule</th><th>Events</th><th>Related</th><th>Summary</th></tr>")
        foreach ($result in $results) {
            $sevClass = switch ($result.Severity) {
                'Critical' { 'flag-crit' }
                'High'     { 'flag-crit' }
                'Medium'   { 'flag-warn' }
                'Low'      { 'flag-ok' }
                default    { '' }
            }
            $sw.WriteLine("<tr><td class='$sevClass'>$($result.Severity)</td><td>$(Invoke-HtmlEncode $result.RuleName)</td><td>$($result.EventCount)</td><td>$($result.RelatedEvents.Count)</td><td>$(Invoke-HtmlEncode $result.TriggerSummary)</td></tr>")
        }
        $sw.WriteLine("</table></div>")

        # Detailed findings
        $findingNum = 1
        $sw.WriteLine("<div class='section'><h2>3. Detailed Findings</h2>")
        foreach ($result in $results) {
            $findingClass = switch ($result.Severity) {
                'Critical' { 'sev-critical' }
                'High'     { 'sev-high' }
                'Medium'   { 'sev-medium' }
                'Low'      { 'sev-low' }
                default    { '' }
            }
            $sw.WriteLine("<div class='finding $findingClass'>")
            $sw.WriteLine("<h3>Finding $findingNum`: $(Invoke-HtmlEncode $result.RuleName) [$($result.Severity)]</h3>")
            $sw.WriteLine("<p><strong>Rule ID:</strong> <code>$(Invoke-HtmlEncode $result.RuleId)</code><br>")
            $sw.WriteLine("<strong>Trigger:</strong> $(Invoke-HtmlEncode $result.TriggerSummary)<br>")
            $sw.WriteLine("<strong>Contributing Events:</strong> $($result.EventCount) | <strong>Related Events:</strong> $($result.RelatedEvents.Count)</p>")

            # Affected entities
            if ($result.AffectedEntities.Count -gt 0) {
                $sw.WriteLine("<h4>Affected Entities</h4><p>")
                foreach ($ent in $result.AffectedEntities) {
                    $sw.WriteLine("<span class='entity-tag'>$($ent.Type): $(Invoke-HtmlEncode $ent.Value)</span>")
                }
                $sw.WriteLine("</p>")
            }

            # Contributing events table (top 20)
            $contribEvents = @($result.ContributingEvents | Select-Object -First 20)
            if ($contribEvents.Count -gt 0) {
                $sw.WriteLine("<h4>Contributing Events</h4>")
                $sw.WriteLine("<table><tr><th>Time</th><th>Level</th><th>Source</th><th>Message</th></tr>")
                foreach ($evt in $contribEvents) {
                    $ts = if ($evt.Timestamp -ne [datetime]::MinValue) { $evt.Timestamp.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                    $msgTrunc = if ($evt.Message.Length -gt 150) { $evt.Message.Substring(0, 147) + '...' } else { $evt.Message }
                    $sw.WriteLine("<tr><td>$ts</td><td>$($evt.Level)</td><td>$(Invoke-HtmlEncode $evt.Source)</td><td>$(Invoke-HtmlEncode $msgTrunc)</td></tr>")
                }
                $sw.WriteLine("</table>")
                if ($result.ContributingEvents.Count -gt 20) {
                    $sw.WriteLine("<p><em>Showing 20 of $($result.ContributingEvents.Count) contributing events.</em></p>")
                }
            }

            # Recommended actions
            if ($result.RecommendedActions.Count -gt 0) {
                $sw.WriteLine("<h4>Recommended Actions</h4><ol class='action-list'>")
                foreach ($action in $result.RecommendedActions) {
                    $sw.WriteLine("<li>$(Invoke-HtmlEncode $action)</li>")
                }
                $sw.WriteLine("</ol>")
            }

            $sw.WriteLine("</div>")
            $findingNum++
        }
        $sw.WriteLine("</div>")

        $sw.WriteLine("<p class='meta'>Generated by Invoke-LogParser | Triage Report</p></body></html>")
        $sw.Close()

        Write-Log "Triage report generated: $OutputPath"
    } catch {
        Write-Log "Failed to generate triage report: $_" -Level ERROR
        if ($sw) {
            try { $sw.Close() } catch { }
        }
    }
}
