# FortiGate BGP Routing Log Parser
# Handles FortiGate BGP neighbor, state, and route events in KV format

Register-Parser -Id "fortigate-bgp" -Name "FortiGate BGP Routing Log" -Extensions @(".log") -SupportsTail $true `
    -AutoDetect {
        param($firstLines, $filePath)
        $matchCount = 0
        $lineCount = 0
        foreach ($line in $firstLines) {
            $lineCount++
            if ($lineCount -gt 20) { break }
            # Must be KV format
            if ($line -notmatch '(\w+)=') { continue }
            if ($line -match 'subtype=route') { $matchCount++ }
            elseif ($line -match '(?i)msg=.*(?:BGP|neighbor|prefix|route)') { $matchCount++ }
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

            # Extract BGP-specific fields from KV and message parsing
            $msgField = if ($extra['msg']) { $extra['msg'] } else { "" }

            # Extract neighbor IP
            $neighborIp = ""
            if ($extra['neighbor']) {
                $neighborIp = $extra['neighbor']
            } elseif ($msgField -match '(?:neighbor|peer)\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                $neighborIp = $Matches[1]
            }
            $extra['NeighborIp'] = $neighborIp

            # Extract BGP state
            $bgpState = ""
            if ($extra['state']) {
                $bgpState = $extra['state']
            } elseif ($msgField -match '(?:state|status)\s+(?:changed?\s+(?:to\s+)?)?(\w+)') {
                $bgpState = $Matches[1]
            }
            $extra['BgpState'] = $bgpState

            # Extract prefix count if available
            $prefixCount = ""
            if ($extra['prefixes']) {
                $prefixCount = $extra['prefixes']
            } elseif ($extra['prefixcount']) {
                $prefixCount = $extra['prefixcount']
            } elseif ($msgField -match '(\d+)\s+prefix') {
                $prefixCount = $Matches[1]
            }
            $extra['PrefixCount'] = $prefixCount

            # Enrichment: check BgpStateCodes if available
            if ($bgpState -and $Script:BgpStateCodes -and $Script:BgpStateCodes.ContainsKey($bgpState)) {
                $extra['StateDescription'] = $Script:BgpStateCodes[$bgpState]
            }

            # Determine level based on BGP event type
            $fgLevel = if ($extra['level']) { $extra['level'].ToLower() } else { "" }
            $msgLower = $msgField.ToLower()
            $bgpStateLower = $bgpState.ToLower()

            $level = switch -Wildcard ($fgLevel) {
                "emergency" { "CRITICAL" } "alert" { "CRITICAL" } "critical" { "CRITICAL" }
                "error"     { "ERROR" }
                "warning"   { "WARNING" }
                "notice"    { "INFO" } "information" { "INFO" }
                "debug"     { "DEBUG" }
                default {
                    if ($bgpStateLower -in @('idle', 'down') -or
                        $msgLower -match 'neighbor\s+down|session\s+closed|connection\s+lost|peer\s+down') {
                        "ERROR"
                    } elseif ($bgpStateLower -eq 'established' -or $msgLower -match 'established|session\s+up') {
                        "INFO"
                    } elseif ($bgpStateLower -in @('active', 'connect', 'opensent', 'openconfirm') -or
                              $msgLower -match 'state\s+change|transition') {
                        "WARNING"
                    } else {
                        Get-LevelFromText $rawLine
                    }
                }
            }

            $source = if ($extra['devname']) { $extra['devname'] } elseif ($extra['srcip']) { $extra['srcip'] } else { "" }

            # Build BGP-specific message
            $msg = ""
            if ($msgLower -match 'state' -and $neighborIp) {
                # State change event
                $prevState = ""
                $newState = $bgpState
                if ($msgField -match '(\w+)\s*->\s*(\w+)') {
                    $prevState = $Matches[1]
                    $newState = $Matches[2]
                    $extra['BgpState'] = $newState
                } elseif ($msgField -match 'from\s+(\w+)\s+to\s+(\w+)') {
                    $prevState = $Matches[1]
                    $newState = $Matches[2]
                    $extra['BgpState'] = $newState
                }
                if ($prevState) {
                    $msg = "BGP neighbor $neighborIp state $prevState -> $newState"
                } else {
                    $msg = "BGP neighbor $neighborIp state $newState"
                }
            } elseif ($msgLower -match 'route|prefix|update|withdraw') {
                # Route event
                $prefix = ""
                if ($extra['prefix']) { $prefix = $extra['prefix'] }
                elseif ($msgField -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})') { $prefix = $Matches[1] }

                $nexthop = if ($extra['nexthop']) { $extra['nexthop'] } else { "" }
                $aspath = if ($extra['aspath']) { $extra['aspath'] }
                         elseif ($extra['as_path']) { $extra['as_path'] }
                         else { "" }

                $parts = [System.Collections.Generic.List[string]]::new()
                $parts.Add("BGP route")
                if ($prefix) { $parts.Add($prefix) }
                if ($nexthop) { $parts.Add("via $nexthop") }
                if ($aspath) { $parts.Add($aspath) }
                $msg = $parts -join ' '
            } elseif ($neighborIp -and $bgpState) {
                $msg = "BGP neighbor $neighborIp state $bgpState"
            } elseif ($msgField) {
                $msg = $msgField
            } elseif ($extra['action']) {
                $msg = $extra['action']
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
