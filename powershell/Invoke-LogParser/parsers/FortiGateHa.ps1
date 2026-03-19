# FortiGate HA Cluster Log Parser
# Handles FortiGate High Availability cluster, failover, heartbeat, and sync events in KV format

Register-Parser -Id "fortigate-ha" -Name "FortiGate HA Cluster Log" -Extensions @(".log") -SupportsTail $true `
    -AutoDetect {
        param($firstLines, $filePath)
        $matchCount = 0
        $lineCount = 0
        foreach ($line in $firstLines) {
            $lineCount++
            if ($lineCount -gt 20) { break }
            # Must be KV format
            if ($line -notmatch '(\w+)=') { continue }
            if ($line -match 'subtype=ha') { $matchCount++ }
            elseif ($line -match '(?i)msg=.*(?:HA|failover|heartbeat|cluster)') { $matchCount++ }
        }
        return ($matchCount -ge 3)
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
            if ($extra['type'] -and $extra['subtype']) {
                $typeSubtype = "$($extra['type'])/$($extra['subtype'])"
                if ($Script:FortiSubtypeLookup -and $Script:FortiSubtypeLookup.ContainsKey($typeSubtype)) {
                    $extra['SubtypeDescription'] = $Script:FortiSubtypeLookup[$typeSubtype]
                }
            }

            # Extract HA-specific fields
            $msgField = if ($extra['msg']) { $extra['msg'] } else { "" }
            $msgLower = $msgField.ToLower()

            # HA Role
            $haRole = ""
            if ($extra['role']) {
                $haRole = $extra['role']
            } elseif ($extra['ha_role']) {
                $haRole = $extra['ha_role']
            } elseif ($msgField -match '(?:role|became)\s+(master|slave|primary|secondary|standalone)') {
                $haRole = $Matches[1]
            }
            $extra['HaRole'] = $haRole

            # HA Group
            $haGroup = ""
            if ($extra['ha_group']) {
                $haGroup = $extra['ha_group']
            } elseif ($extra['group']) {
                $haGroup = $extra['group']
            } elseif ($extra['cluster']) {
                $haGroup = $extra['cluster']
            }
            $extra['HaGroup'] = $haGroup

            # Failover reason
            $failoverReason = ""
            if ($extra['reason']) {
                $failoverReason = $extra['reason']
            } elseif ($msgField -match 'failover\s+(?:reason|due\s+to|because)\s*:?\s*(.+?)(?:\s*$|,)') {
                $failoverReason = $Matches[1].Trim()
            }
            $extra['FailoverReason'] = $failoverReason

            # Member serial
            $memberSerial = ""
            if ($extra['serial']) {
                $memberSerial = $extra['serial']
            } elseif ($extra['sn']) {
                $memberSerial = $extra['sn']
            } elseif ($extra['member_serial']) {
                $memberSerial = $extra['member_serial']
            } elseif ($msgField -match '(?:serial|member|unit)\s*[=:]\s*(FG\w+)') {
                $memberSerial = $Matches[1]
            }
            $extra['MemberSerial'] = $memberSerial

            # Determine level based on HA event type
            $fgLevel = if ($extra['level']) { $extra['level'].ToLower() } else { "" }
            $actionVal = if ($extra['action']) { $extra['action'].ToLower() } else { "" }

            $level = switch -Wildcard ($fgLevel) {
                "emergency" { "CRITICAL" } "alert" { "CRITICAL" } "critical" { "CRITICAL" }
                "error"     { "ERROR" }
                "warning"   { "WARNING" }
                "notice"    { "INFO" } "information" { "INFO" }
                "debug"     { "DEBUG" }
                default {
                    if ($msgLower -match 'failover|split[\s-]brain' -or $actionVal -match 'failover|split-brain') {
                        "CRITICAL"
                    } elseif ($msgLower -match 'member\s+down|unit\s+down|peer\s+(?:lost|down|unreachable)' -or
                              $actionVal -match 'member-down|peer-down') {
                        "ERROR"
                    } elseif ($msgLower -match 'heartbeat\s+(?:lost|miss|timeout|fail)' -or
                              $actionVal -match 'hb-loss|heartbeat-fail') {
                        "WARNING"
                    } elseif ($msgLower -match 'sync\s+(?:ok|success|complete|done)' -or
                              $actionVal -match 'sync-ok|sync-complete') {
                        "INFO"
                    } elseif ($msgLower -match 'heartbeat\s+(?:recover|restore|ok)') {
                        "INFO"
                    } else {
                        Get-LevelFromText $rawLine
                    }
                }
            }

            $source = if ($extra['devname']) { $extra['devname'] } elseif ($extra['srcip']) { $extra['srcip'] } else { "" }

            # Build HA-specific message
            $msg = ""
            if ($msgLower -match 'failover') {
                # Failover event
                $parts = [System.Collections.Generic.List[string]]::new()
                $parts.Add("HA failover:")
                if ($failoverReason) { $parts.Add($failoverReason) }
                elseif ($msgField) { $parts.Add($msgField) }
                if ($haRole) { $parts.Add("role=$haRole") }
                $msg = $parts -join ' '
            } elseif ($msgLower -match 'heartbeat') {
                # Heartbeat event
                $hbStatus = if ($msgLower -match 'lost|miss|timeout|fail') { "lost" }
                            elseif ($msgLower -match 'recover|restore|ok') { "recovered" }
                            else { "event" }
                $parts = [System.Collections.Generic.List[string]]::new()
                $parts.Add("HA heartbeat $hbStatus")
                if ($memberSerial) { $parts.Add("member=$memberSerial") }
                elseif ($extra['peer']) { $parts.Add("member=$($extra['peer'])") }
                $msg = $parts -join ' '
            } elseif ($msgLower -match 'sync|synchroniz') {
                # Sync event
                $syncStatus = if ($msgLower -match 'ok|success|complete|done') { "completed" }
                              elseif ($msgLower -match 'fail|error') { "failed" }
                              elseif ($msgLower -match 'start|begin') { "started" }
                              else { "in progress" }
                $msg = "HA config sync $syncStatus"
            } elseif ($msgField) {
                $msg = $msgField
            } elseif ($actionVal) {
                $parts = [System.Collections.Generic.List[string]]::new()
                $parts.Add($actionVal)
                if ($haRole) { $parts.Add("role=$haRole") }
                if ($memberSerial) { $parts.Add("member=$memberSerial") }
                $msg = $parts -join ' '
            } else {
                $msg = $kvLine.Substring(0, [Math]::Min(200, $kvLine.Length))
            }

            # Prepend subtype description if available
            if ($extra['SubtypeDescription'] -and $msg) { $msg = "[$($extra['SubtypeDescription'])] $msg" }

            $entries.Add((ConvertTo-LogEntry @{
                Index = $idx; Timestamp = $ts; Level = $level; Source = $source
                Host = $(if ($extra['devname']) { $extra['devname'] } else { "" })
                Message = $msg; RawLine = $rawLine; Extra = $extra
            }))
            $idx++
        }
        return $entries
    }
