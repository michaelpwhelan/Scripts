# FortiAnalyzer Event Log Parser
# Handles FortiAnalyzer log management and system events in KV format

Register-Parser -Id "fortianalyzer-event" -Name "FortiAnalyzer Event Log" -Extensions @(".log") -SupportsTail $true `
    -AutoDetect {
        param($firstLines, $filePath)
        $matchCount = 0
        foreach ($line in $firstLines) {
            if ($line -match 'logid=' -and ($line -match 'devid=FAZ' -or $line -match 'devtype="FortiAnalyzer"')) {
                $matchCount++
            }
        }
        return ($matchCount -ge 2)
    } `
    -Parse {
        param($reader, [int]$startIndex)
        $entries = [System.Collections.Generic.List[object]]::new()
        $idx = $startIndex
        while (-not $reader.EndOfStream) {
            $rawLine = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($rawLine)) { continue }

            # Strip syslog PRI header if present
            $kvLine = $rawLine
            if ($kvLine -match '^\s*<\d+>') {
                $kvLine = $kvLine -replace '^\s*<\d+>\S*\s+\S+\s+\S+\s+\S+\s+\S+\s+', ''
                if ($kvLine -eq $rawLine) {
                    $kvLine = $rawLine -replace '^\s*<\d+>', ''
                }
            }

            # Parse key=value pairs (handles quoted values)
            $extra = @{}
            $matches2 = [regex]::Matches($kvLine, '(\w+)=("(?:[^"\\]|\\.)*"|[^\s]+)')
            foreach ($m in $matches2) {
                $k = $m.Groups[1].Value
                $v = $m.Groups[2].Value.Trim('"')
                $extra[$k] = $v
            }

            # Build timestamp
            $ts = [datetime]::MinValue
            if ($extra['date'] -and $extra['time']) {
                [datetime]::TryParse("$($extra['date']) $($extra['time'])", [ref]$ts) | Out-Null
            }

            # Type/subtype enrichment
            $subtypeDesc = ""
            if ($extra['type'] -and $extra['subtype']) {
                $typeSubtype = "$($extra['type'])/$($extra['subtype'])"
                if ($Script:FortiSubtypeLookup -and $Script:FortiSubtypeLookup.ContainsKey($typeSubtype)) {
                    $subtypeDesc = $Script:FortiSubtypeLookup[$typeSubtype]
                    $extra['SubtypeDescription'] = $subtypeDesc
                }
            }

            # Ensure extra keys are populated
            foreach ($evtKey in @('logid', 'type', 'subtype', 'devid', 'devname', 'action', 'msg', 'diskusage', 'lograte')) {
                if ($extra[$evtKey]) {
                    $extra[$evtKey] = $extra[$evtKey]
                }
            }

            # Map level - prefer explicit level field, then action-based fallback
            $fgLevel = if ($extra['level']) { $extra['level'].ToLower() } else { "" }
            $level = switch -Wildcard ($fgLevel) {
                "emergency" { "CRITICAL" } "alert" { "CRITICAL" } "critical" { "CRITICAL" }
                "error"     { "ERROR" }
                "warning"   { "WARNING" }
                "notice"    { "INFO" } "information" { "INFO" }
                "debug"     { "DEBUG" }
                default {
                    $actionVal = if ($extra['action']) { $extra['action'].ToLower() } else { '' }
                    if ($actionVal -in @('deny', 'fail', 'failed', 'error')) { "ERROR" }
                    elseif ($actionVal -in @('warning', 'full', 'threshold')) { "WARNING" }
                    elseif ($actionVal -in @('accept', 'success', 'complete', 'start', 'stop')) { "INFO" }
                    else { Get-LevelFromText $rawLine }
                }
            }

            $source = if ($extra['devname']) { $extra['devname'] } else { "" }

            # Build message for log management events
            $parts = [System.Collections.Generic.List[string]]::new()

            if ($subtypeDesc) {
                $parts.Add("[$subtypeDesc]")
            }

            if ($extra['action']) { $parts.Add($extra['action']) }

            if ($extra['msg']) {
                $parts.Add($extra['msg'])
            } else {
                # Build context from available fields
                if ($extra['lograte']) { $parts.Add("lograte=$($extra['lograte'])") }
                if ($extra['diskusage']) { $parts.Add("diskusage=$($extra['diskusage'])") }
            }

            if ($parts.Count -gt 0) {
                $msg = $parts -join ' '
            } else {
                $msg = $kvLine.Substring(0, [Math]::Min(200, $kvLine.Length))
            }

            $entries.Add((ConvertTo-LogEntry @{
                Index = $idx; Timestamp = $ts; Level = $level; Source = $source
                Host = $(if ($extra['devname']) { $extra['devname'] } else { "" })
                Message = $msg; RawLine = $rawLine; Extra = $extra
            }))
            $idx++
        }
        return $entries
    }
