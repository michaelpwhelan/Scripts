# FortiManager Audit Log Parser
# Handles FortiManager administrative and audit events in KV format

Register-Parser -Id "fortimanager-audit" -Name "FortiManager Audit Log" -Extensions @(".log") -SupportsTail $true `
    -AutoDetect {
        param($firstLines, $filePath)
        $matchCount = 0
        foreach ($line in $firstLines) {
            if ($line -match 'logid=' -and ($line -match 'devid=FMG' -or $line -match 'devtype="FortiManager"')) {
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

            # Enrichment: check FortiManagerActionLookup if available
            if ($extra['action'] -and $Script:FortiManagerActionLookup -and $Script:FortiManagerActionLookup.ContainsKey($extra['action'])) {
                $extra['ActionDescription'] = $Script:FortiManagerActionLookup[$extra['action']]
            }

            # Populate extra keys for audit context
            foreach ($auditKey in @('logid', 'type', 'subtype', 'devid', 'devname', 'user', 'action', 'msg', 'cat', 'status', 'ADOM')) {
                if ($extra[$auditKey]) {
                    $extra[$auditKey] = $extra[$auditKey]
                }
            }

            # Map level - prefer explicit level field, then action-based mapping
            $fgLevel = if ($extra['level']) { $extra['level'].ToLower() } else { "" }
            $level = switch -Wildcard ($fgLevel) {
                "emergency" { "CRITICAL" } "alert" { "CRITICAL" } "critical" { "CRITICAL" }
                "error"     { "ERROR" }
                "warning"   { "WARNING" }
                "notice"    { "INFO" } "information" { "INFO" }
                "debug"     { "DEBUG" }
                default {
                    $actionVal = if ($extra['action']) { $extra['action'].ToLower() } else { '' }
                    $statusVal = if ($extra['status']) { $extra['status'].ToLower() } else { '' }
                    if ($actionVal -in @('deny', 'fail', 'failed') -or $statusVal -in @('fail', 'failed', 'error')) { "ERROR" }
                    elseif ($actionVal -match 'config[-_]?change|set|delete|add' -or $actionVal -eq 'modify') { "WARNING" }
                    elseif ($actionVal -in @('login', 'logout', 'accept', 'push', 'install') -and $statusVal -ne 'fail') { "INFO" }
                    else { Get-LevelFromText $rawLine }
                }
            }

            $source = if ($extra['devname']) { $extra['devname'] } else { "" }

            # Build message for admin audit events
            $msg = ""
            $actionDisplay = if ($extra['action']) { $extra['action'] } else { "" }
            $msgField = if ($extra['msg']) { $extra['msg'] } else { "" }

            if ($subtypeDesc -and $actionDisplay -and $msgField) {
                $msg = "[$subtypeDesc] $actionDisplay - $msgField"
            } elseif ($subtypeDesc -and $msgField) {
                $msg = "[$subtypeDesc] $msgField"
            } elseif ($subtypeDesc -and $actionDisplay) {
                $msg = "[$subtypeDesc] $actionDisplay"
            } elseif ($actionDisplay -and $msgField) {
                $msg = "$actionDisplay - $msgField"
            } elseif ($msgField) {
                $msg = $msgField
            } elseif ($actionDisplay) {
                $msg = $actionDisplay
            } else {
                $msg = $kvLine.Substring(0, [Math]::Min(200, $kvLine.Length))
            }

            # Append user and ADOM context if available
            if ($extra['user']) {
                $msg = "$msg (user=$($extra['user']))"
            }
            if ($extra['ADOM']) {
                $extra['AdomName'] = $extra['ADOM']
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
