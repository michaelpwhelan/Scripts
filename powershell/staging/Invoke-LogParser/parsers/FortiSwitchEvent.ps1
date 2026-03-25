# FortiSwitch Event Log Parser
# Handles FortiSwitch port, STP, MAC, and 802.1X events in KV format

Register-Parser -Id "fortiswitch-event" -Name "FortiSwitch Event Log" -Extensions @(".log") -SupportsTail $true `
    -AutoDetect {
        param($firstLines, $filePath)
        $matchCount = 0
        foreach ($line in $firstLines) {
            if ($line -match '(\w+)=' -and ($line -match 'devid=S' -or $line -match 'devid=FSW' -or $line -match 'devtype="FortiSwitch"')) {
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
            if ($extra['type'] -and $extra['subtype']) {
                $typeSubtype = "$($extra['type'])/$($extra['subtype'])"
                if ($Script:FortiSubtypeLookup -and $Script:FortiSubtypeLookup.ContainsKey($typeSubtype)) {
                    $extra['SubtypeDescription'] = $Script:FortiSubtypeLookup[$typeSubtype]
                }
            }

            # Extract switch-specific fields
            $msgField = if ($extra['msg']) { $extra['msg'] } else { "" }
            $msgLower = $msgField.ToLower()

            # Port name
            $portName = ""
            if ($extra['port']) {
                $portName = $extra['port']
            } elseif ($extra['interface']) {
                $portName = $extra['interface']
            } elseif ($extra['portname']) {
                $portName = $extra['portname']
            } elseif ($msgField -match '(?:port|interface)\s+([\w/.-]+)') {
                $portName = $Matches[1]
            }
            $extra['PortName'] = $portName

            # Port status
            $portStatus = ""
            if ($extra['portstatus']) {
                $portStatus = $extra['portstatus']
            } elseif ($extra['linkstatus']) {
                $portStatus = $extra['linkstatus']
            } elseif ($msgLower -match '(?:port|link)\s+(?:is\s+)?(up|down)') {
                $portStatus = $Matches[1]
            }
            $extra['PortStatus'] = $portStatus

            # VLAN ID
            $vlanId = ""
            if ($extra['vlan']) {
                $vlanId = $extra['vlan']
            } elseif ($extra['vlanid']) {
                $vlanId = $extra['vlanid']
            } elseif ($msgField -match '(?:vlan|VLAN)\s*(\d+)') {
                $vlanId = $Matches[1]
            }
            $extra['VlanId'] = $vlanId

            # MAC address
            $macAddress = ""
            if ($extra['mac']) {
                $macAddress = $extra['mac']
            } elseif ($extra['srcmac']) {
                $macAddress = $extra['srcmac']
            } elseif ($extra['macaddr']) {
                $macAddress = $extra['macaddr']
            } elseif ($msgField -match '([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})') {
                $macAddress = $Matches[1]
            }
            $extra['MacAddress'] = $macAddress

            # STP state
            $stpState = ""
            if ($extra['stpstate']) {
                $stpState = $extra['stpstate']
            } elseif ($msgLower -match 'stp\s+(?:state\s+)?(\w+)') {
                $stpState = $Matches[1]
            }
            $extra['StpState'] = $stpState

            # 802.1X auth result
            $authResult = ""
            if ($extra['authresult']) {
                $authResult = $extra['authresult']
            } elseif ($extra['authstatus']) {
                $authResult = $extra['authstatus']
            } elseif ($msgLower -match '802\.1x\s+auth(?:entication)?\s+(success|fail\w*|reject\w*|timeout)') {
                $authResult = $Matches[1]
            }
            $extra['AuthResult'] = $authResult

            # Enrichment: check FortiSwitchEventLookup if available
            if ($extra['logid'] -and $Script:FortiSwitchEventLookup -and $Script:FortiSwitchEventLookup.ContainsKey($extra['logid'])) {
                $extra['EventDescription'] = $Script:FortiSwitchEventLookup[$extra['logid']]
            }

            # Determine level based on switch event type
            $fgLevel = if ($extra['level']) { $extra['level'].ToLower() } else { "" }
            $actionVal = if ($extra['action']) { $extra['action'].ToLower() } else { "" }

            $level = switch -Wildcard ($fgLevel) {
                "emergency" { "CRITICAL" } "alert" { "CRITICAL" } "critical" { "CRITICAL" }
                "error"     { "ERROR" }
                "warning"   { "WARNING" }
                "notice"    { "INFO" } "information" { "INFO" }
                "debug"     { "DEBUG" }
                default {
                    if ($authResult -and $authResult -match '(?i)fail|reject|denied') {
                        "ERROR"
                    } elseif ($portStatus -eq 'down' -or $msgLower -match 'port\s+down|link\s+down') {
                        "WARNING"
                    } elseif ($msgLower -match 'stp\s+(?:topology\s+change|tcn)' -or $stpState) {
                        "WARNING"
                    } elseif ($portStatus -eq 'up' -or $msgLower -match 'port\s+up|link\s+up') {
                        "INFO"
                    } elseif ($msgLower -match 'mac\s+(?:learn|age|move)') {
                        "INFO"
                    } elseif ($authResult -and $authResult -match '(?i)success') {
                        "INFO"
                    } else {
                        Get-LevelFromText $rawLine
                    }
                }
            }

            $source = if ($extra['devname']) { $extra['devname'] } else { "" }

            # Build switch-specific message
            $msg = ""
            if ($msgLower -match '802\.1x|dot1x' -or $authResult) {
                # 802.1X authentication event
                $parts = [System.Collections.Generic.List[string]]::new()
                $result = if ($authResult) { $authResult } else { "event" }
                $parts.Add("802.1X auth $result")
                if ($macAddress) { $parts.Add("for $macAddress") }
                if ($portName) { $parts.Add("on $portName") }
                $msg = $parts -join ' '
            } elseif ($msgLower -match 'stp|spanning[\s-]tree') {
                # STP event
                $parts = [System.Collections.Generic.List[string]]::new()
                $parts.Add("STP topology change")
                if ($portName) { $parts.Add("on $portName") }
                if ($stpState) { $parts.Add("state=$stpState") }
                $msg = $parts -join ' '
            } elseif ($msgLower -match 'mac\s+(learn|age|move|flush)' -or $macAddress) {
                # MAC event
                $macAction = if ($msgField -match '(?i)mac\s+(learn\w*|age\w*|move\w*|flush\w*)') { $Matches[1].ToLower() }
                             elseif ($actionVal -match 'learn|age|move|flush') { $actionVal }
                             else { "event" }
                $parts = [System.Collections.Generic.List[string]]::new()
                if ($macAddress) { $parts.Add("MAC $macAddress") }
                else { $parts.Add("MAC") }
                $parts.Add($macAction)
                if ($portName) { $parts.Add("on $portName") }
                if ($vlanId) { $parts.Add("VLAN $vlanId") }
                $msg = $parts -join ' '
            } elseif ($portName -and ($portStatus -or $msgLower -match 'port|link|interface')) {
                # Port event
                $status = if ($portStatus) { $portStatus } else { "event" }
                $msg = "Port $portName $status"
                if ($extra['speed']) { $msg += " speed=$($extra['speed'])" }
                if ($extra['duplex']) { $msg += " duplex=$($extra['duplex'])" }
            } elseif ($msgField) {
                $msg = $msgField
            } elseif ($actionVal) {
                $msg = $actionVal
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
