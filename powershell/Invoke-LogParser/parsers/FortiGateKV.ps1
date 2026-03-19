# FortiGate / Fortinet Key=Value Parser
# Handles FortiGate, FortiClient EMS, FortiAnalyzer, FortiSwitch, FortiAP logs

Register-Parser -Id "fortigate-kv" -Name "Fortinet Key=Value" -Extensions @(".log") -SupportsTail $true `
    -AutoDetect {
        param($firstLines, $filePath)
        foreach ($line in $firstLines) {
            if ($line -match 'logid=' -and $line -match 'type=' -and ($line -match 'devname=' -or $line -match 'devid=')) {
                return $true
            }
        }
        return $false
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

            # Device type from devid prefix
            $deviceType = ""
            if ($extra['devid']) {
                $devid = $extra['devid']
                $deviceType = if ($devid.StartsWith('FG')) { 'FortiGate' }
                    elseif ($devid.StartsWith('FTC')) { 'FortiClient' }
                    elseif ($devid.StartsWith('FAZ')) { 'FortiAnalyzer' }
                    elseif ($devid.StartsWith('FSW')) { 'FortiSwitch' }
                    elseif ($devid.StartsWith('FAP')) { 'FortiAP' }
                    else { 'Fortinet' }
                $extra['DeviceType'] = $deviceType
            }

            # Type/subtype enrichment
            $typeSubtype = ""
            if ($extra['type'] -and $extra['subtype']) {
                $typeSubtype = "$($extra['type'])/$($extra['subtype'])"
                if ($Script:FortiSubtypeLookup.ContainsKey($typeSubtype)) {
                    $extra['SubtypeDescription'] = $Script:FortiSubtypeLookup[$typeSubtype]
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
                    $action2 = if ($extra['action']) { $extra['action'].ToLower() } else { '' }
                    if ($action2 -in @('deny','block','dropped')) { "ERROR" }
                    elseif ($action2 -eq 'timeout') { "WARNING" }
                    elseif ($action2 -eq 'accept' -and $extra['type'] -eq 'utm') { "WARNING" }
                    elseif ($action2 -eq 'accept') { "INFO" }
                    else { Get-LevelFromText $rawLine }
                }
            }

            $source = if ($extra['devname']) { $extra['devname'] } elseif ($extra['srcip']) { $extra['srcip'] } else { "" }

            # Build richer message based on log type
            $msg = if ($extra['type'] -eq 'traffic') {
                $parts = [System.Collections.Generic.List[string]]::new()
                if ($extra['action']) { $parts.Add($extra['action']) }
                if ($extra['srcip']) { $parts.Add("srcip=$($extra['srcip'])") }
                if ($extra['dstip']) { $parts.Add("dstip=$($extra['dstip'])") }
                if ($extra['srcport']) { $parts.Add("srcport=$($extra['srcport'])") }
                if ($extra['dstport']) { $parts.Add("dstport=$($extra['dstport'])") }
                if ($extra['policyid']) { $parts.Add("policy=$($extra['policyid'])") }
                $parts -join ' '
            } elseif ($extra['type'] -eq 'utm' -and $extra['subtype'] -eq 'webfilter') {
                $parts = [System.Collections.Generic.List[string]]::new()
                if ($extra['action']) { $parts.Add($extra['action']) }
                if ($extra['url']) { $parts.Add("url=$($extra['url'])") }
                if ($extra['hostname']) { $parts.Add("host=$($extra['hostname'])") }
                if ($extra['catdesc']) { $parts.Add("cat=$($extra['catdesc'])") }
                $parts -join ' '
            } elseif ($extra['type'] -eq 'event' -and $extra['subtype'] -eq 'vpn') {
                $parts = [System.Collections.Generic.List[string]]::new()
                if ($extra['action']) { $parts.Add($extra['action']) }
                if ($extra['tunnelip']) { $parts.Add("tunnel=$($extra['tunnelip'])") }
                if ($extra['tunneltype']) { $parts.Add("type=$($extra['tunneltype'])") }
                if ($extra['remip']) { $parts.Add("remote=$($extra['remip'])") }
                $parts -join ' '
            } elseif ($extra['msg']) { $extra['msg'] }
              elseif ($extra['action']) { $extra['action'] }
              else { $kvLine.Substring(0, [Math]::Min(200, $kvLine.Length)) }

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
