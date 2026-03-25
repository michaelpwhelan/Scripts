Register-Parser -Id "dhcp-server" -Name "Windows DHCP Server Log" -Extensions @(".log") `
    -AutoDetect {
        param($firstLines, $filePath)
        foreach ($line in $firstLines) {
            if ($line -match 'ID,Date,Time,Description,IP Address') { return $true }
        }
        return $false
    } `
    -Parse {
        param($reader, [int]$startIndex)
        $entries = [System.Collections.Generic.List[object]]::new()
        $idx = $startIndex
        $headersParsed = $false
        $fieldNames = @()

        # DHCP Event ID severity mapping
        $dhcpSeverity = @{
            10 = "INFO"       # New lease
            11 = "INFO"       # Lease renewed
            12 = "INFO"       # Lease released
            13 = "WARNING"    # Lease not found
            14 = "ERROR"      # Duplicate address
            15 = "ERROR"      # Lease denied
            16 = "INFO"       # Lease active
            17 = "INFO"       # Lease not active
            18 = "WARNING"    # Scope full
            20 = "ERROR"      # Scope exhaustion
            24 = "INFO"       # Scope cleanup
            30 = "INFO"       # DNS update request
            31 = "INFO"       # DNS update failed
            32 = "INFO"       # DNS update successful
            50 = "WARNING"    # Rogue server detected
            51 = "WARNING"    # Rogue server authorized
            52 = "WARNING"    # Rogue server not authorized
        }

        while (-not $reader.EndOfStream) {
            $rawLine = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($rawLine)) { continue }

            # Skip header lines until we find the field header
            if (-not $headersParsed) {
                if ($rawLine -match '^ID,Date,Time,') {
                    $fieldNames = $rawLine -split ','
                    $headersParsed = $true
                }
                continue
            }

            $parts = $rawLine -split ','
            if ($parts.Count -lt 5) { continue }

            $eventId = $parts[0].Trim() -as [int]
            $dateStr = $parts[1].Trim()
            $timeStr = $parts[2].Trim()
            $description = $parts[3].Trim()
            $ipAddress = $parts[4].Trim()
            $hostName = if ($parts.Count -gt 5) { $parts[5].Trim() } else { "" }
            $macAddress = if ($parts.Count -gt 6) { $parts[6].Trim() } else { "" }

            $ts = [datetime]::MinValue
            if ($dateStr -and $timeStr) {
                [datetime]::TryParse("$dateStr $timeStr", [ref]$ts) | Out-Null
            }

            $level = if ($dhcpSeverity.ContainsKey($eventId)) { $dhcpSeverity[$eventId] } else { "INFO" }

            $extra = @{
                EventID = $eventId
                IPAddress = $ipAddress
                HostName = $hostName
                MACAddress = $macAddress
            }
            # Add any additional fields
            for ($i = 7; $i -lt [Math]::Min($fieldNames.Count, $parts.Count); $i++) {
                $extra[$fieldNames[$i].Trim()] = $parts[$i].Trim()
            }

            # Event ID description from global lookup
            if ($Script:State.EventIdLookup.ContainsKey($eventId)) {
                $extra['EventIdAnnotation'] = $Script:State.EventIdLookup[$eventId]
            }

            $msg = "[$eventId] $description"
            if ($ipAddress) { $msg += " IP=$ipAddress" }
            if ($hostName) { $msg += " Host=$hostName" }
            if ($macAddress) { $msg += " MAC=$macAddress" }

            $entries.Add((ConvertTo-LogEntry @{
                Index = $idx; Timestamp = $ts; Level = $level
                Source = "DHCP"; Host = $hostName
                Message = $msg; RawLine = $rawLine; Extra = $extra
            }))
            $idx++
        }
        return $entries
    } `
    -SupportsTail $true
