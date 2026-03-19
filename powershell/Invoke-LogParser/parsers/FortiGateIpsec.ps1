# FortiGate IPsec VPN Log Parser
# Handles FortiGate IPsec VPN negotiation, tunnel, and DPD events in KV format

Register-Parser -Id "fortigate-ipsec" -Name "FortiGate IPsec VPN Log" -Extensions @(".log") -SupportsTail $true `
    -AutoDetect {
        param($firstLines, $filePath)
        $matchCount = 0
        $lineCount = 0
        foreach ($line in $firstLines) {
            $lineCount++
            if ($lineCount -gt 20) { break }
            # Must be KV format
            if ($line -notmatch '(\w+)=') { continue }
            if ($line -match 'subtype=ipsec') { $matchCount++ }
            elseif ($line -match 'vpntunnel=') { $matchCount++ }
            elseif ($line -match 'logid=0101') { $matchCount++ }
            elseif ($line -match 'msg=.*(?:phase1|phase2|ike|ipsec|DPD|tunnel)') { $matchCount++ }
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

            # Extract IPsec-specific fields
            $tunnelName = if ($extra['vpntunnel']) { $extra['vpntunnel'] }
                          elseif ($extra['tunnelid']) { $extra['tunnelid'] }
                          elseif ($extra['name']) { $extra['name'] }
                          else { "" }
            $extra['TunnelName'] = $tunnelName

            $remoteGw = if ($extra['remip']) { $extra['remip'] }
                        elseif ($extra['peerip']) { $extra['peerip'] }
                        else { "" }
            $extra['RemoteGw'] = $remoteGw

            # Determine phase from message or logid
            $msgField = if ($extra['msg']) { $extra['msg'] } else { "" }
            $phase = ""
            if ($msgField -match 'phase1|IKE_SA') { $phase = "phase1" }
            elseif ($msgField -match 'phase2|CHILD_SA|IPsec SA') { $phase = "phase2" }
            $extra['Phase'] = $phase

            # Extract crypto suite if available
            $cryptoParts = [System.Collections.Generic.List[string]]::new()
            if ($extra['transform']) { $cryptoParts.Add($extra['transform']) }
            if ($extra['encalgo']) { $cryptoParts.Add($extra['encalgo']) }
            if ($extra['authalgo']) { $cryptoParts.Add($extra['authalgo']) }
            if ($extra['dhgrp']) { $cryptoParts.Add("DH$($extra['dhgrp'])") }
            $extra['CryptoSuite'] = if ($cryptoParts.Count -gt 0) { $cryptoParts -join '/' } else { "" }

            # Enrichment: check IpsecErrorCodes if available
            if ($extra['logid'] -and $Script:IpsecErrorCodes -and $Script:IpsecErrorCodes.ContainsKey($extra['logid'])) {
                $extra['ErrorDescription'] = $Script:IpsecErrorCodes[$extra['logid']]
            }

            # Determine level based on IPsec event type
            $fgLevel = if ($extra['level']) { $extra['level'].ToLower() } else { "" }
            $actionVal = if ($extra['action']) { $extra['action'].ToLower() } else { "" }
            $statusVal = if ($extra['status']) { $extra['status'].ToLower() } else { "" }
            $msgLower = $msgField.ToLower()

            $level = switch -Wildcard ($fgLevel) {
                "emergency" { "CRITICAL" } "alert" { "CRITICAL" } "critical" { "CRITICAL" }
                "error"     { "ERROR" }
                "warning"   { "WARNING" }
                "notice"    { "INFO" } "information" { "INFO" }
                "debug"     { "DEBUG" }
                default {
                    if ($msgLower -match 'negotiation fail|phase[12]\s+error|proposal mismatch|auth.*(fail|error)' -or
                        $actionVal -in @('negotiate-error', 'phase1-error', 'phase2-error') -or
                        $statusVal -in @('failure', 'failed', 'error')) {
                        "ERROR"
                    } elseif ($msgLower -match 'dpd\s+timeout|dead\s+peer' -or $actionVal -eq 'dpd-timeout') {
                        "WARNING"
                    } elseif ($msgLower -match 'tunnel[\s-]up|established|completed' -or
                              $actionVal -in @('tunnel-up', 'phase1-up', 'phase2-up')) {
                        "INFO"
                    } elseif ($msgLower -match 'tunnel[\s-]down|deleted|removed' -or
                              $actionVal -in @('tunnel-down', 'phase1-down', 'phase2-down')) {
                        "WARNING"
                    } else {
                        Get-LevelFromText $rawLine
                    }
                }
            }

            $source = if ($extra['devname']) { $extra['devname'] } elseif ($extra['srcip']) { $extra['srcip'] } else { "" }

            # Build IPsec-specific message
            $msg = ""
            if ($msgLower -match 'dpd\s+timeout|dead\s+peer') {
                # DPD event
                $dpd = "DPD timeout"
                if ($tunnelName) { $dpd += " tunnel=$tunnelName" }
                if ($remoteGw) { $dpd += " remote=$remoteGw" }
                $msg = $dpd
            } elseif ($msgLower -match 'phase[12]|ike|negotiat') {
                # Phase negotiation event
                $parts = [System.Collections.Generic.List[string]]::new()
                if ($actionVal) { $parts.Add($actionVal) } else { $parts.Add("negotiate") }
                if ($tunnelName) { $parts.Add("tunnel=$tunnelName") }
                if ($remoteGw) { $parts.Add("remote=$remoteGw") }
                if ($phase) { $parts.Add("phase=$phase") }
                if ($statusVal) { $parts.Add("result=$statusVal") }
                elseif ($extra['result']) { $parts.Add("result=$($extra['result'])") }
                $msg = $parts -join ' '
            } elseif ($msgLower -match 'tunnel[\s-](up|down)' -or $actionVal -match 'tunnel-(up|down)') {
                # Tunnel up/down
                $parts = [System.Collections.Generic.List[string]]::new()
                if ($actionVal) { $parts.Add($actionVal) } else { $parts.Add("tunnel-event") }
                if ($tunnelName) { $parts.Add("tunnel=$tunnelName") }
                if ($remoteGw) { $parts.Add("remote=$remoteGw") }
                $msg = $parts -join ' '
            } elseif ($msgField) {
                $msg = $msgField
            } elseif ($actionVal) {
                $parts = [System.Collections.Generic.List[string]]::new()
                $parts.Add($actionVal)
                if ($tunnelName) { $parts.Add("tunnel=$tunnelName") }
                if ($remoteGw) { $parts.Add("remote=$remoteGw") }
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
