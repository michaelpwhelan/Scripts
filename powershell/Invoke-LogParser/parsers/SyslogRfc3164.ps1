# Syslog RFC 3164 Parser

Register-Parser -Id "syslog-rfc3164" -Name "Syslog RFC 3164" -Extensions @(".log", ".syslog") -SupportsTail $true `
    -AutoDetect {
        param($firstLines, $filePath)
        foreach ($line in $firstLines) {
            if ($line -match '^<\d+>\w{3}\s+\d+\s+\d+:\d+:\d+\s+') { return $true }
            # Also match without PRI: "Jan 15 10:00:45 hostname"
            if ($line -match '^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+') { return $true }
        }
        return $false
    } `
    -Parse {
        param($reader, [int]$startIndex)
        $entries = [System.Collections.Generic.List[object]]::new()
        $idx = $startIndex
        $priPattern = '^<(\d+)>(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)'
        $noPriPattern = '^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)'
        $prevEntry = $null
        while (-not $reader.EndOfStream) {
            $rawLine = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($rawLine)) { continue }

            $matched = $false
            $pri = 0; $facility = 0; $severity = 0
            if ($rawLine -match $priPattern) {
                $matched = $true
                $pri = [int]$Matches[1]; $dateStr = $Matches[2]; $host2 = $Matches[3]
                $process = $Matches[4]; $pid2 = $Matches[5]; $msg = $Matches[6]
                $facility = [math]::Floor($pri / 8); $severity = $pri % 8
            } elseif ($rawLine -match $noPriPattern) {
                $matched = $true
                $dateStr = $Matches[1]; $host2 = $Matches[2]; $process = $Matches[3]
                $pid2 = $Matches[4]; $msg = $Matches[5]; $severity = 6
            }

            if ($matched) {
                $ts = [datetime]::MinValue
                $currentYear = (Get-Date).Year
                try {
                    $ts = [datetime]::ParseExact("$currentYear $dateStr", "yyyy MMM dd HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
                } catch {
                    try {
                        $ts = [datetime]::ParseExact("$currentYear $dateStr", "yyyy MMM  d HH:mm:ss", [System.Globalization.CultureInfo]::InvariantCulture)
                    } catch {
                        try { [datetime]::TryParse($dateStr, [ref]$ts) | Out-Null } catch { }
                    }
                }

                # BUG FIX: Syslog year-wrap - if timestamp is more than 11 months in the future, subtract 1 year
                if ($ts -ne [datetime]::MinValue -and $ts -gt (Get-Date).AddMonths(11)) {
                    $ts = $ts.AddYears(-1)
                }

                $level = switch ($severity) {
                    0 { "CRITICAL" } 1 { "CRITICAL" } 2 { "CRITICAL" }
                    3 { "ERROR" } 4 { "WARNING" } 5 { "INFO" } 6 { "INFO" } 7 { "DEBUG" }
                    default { Get-LevelFromText $rawLine }
                }

                $extra = @{ Priority = $pri; Facility = $facility; Severity = $severity }
                if ($pid2) { $extra['PID'] = $pid2 }

                $prevEntry = ConvertTo-LogEntry @{
                    Index = $idx; Timestamp = $ts; Level = $level; Source = $process
                    Host = $host2; Message = $msg; RawLine = $rawLine; Extra = $extra
                }
                $entries.Add($prevEntry)
                $idx++
            } elseif ($prevEntry -and $startIndex -eq 0) {
                # Multi-line continuation only in full parse mode
                $prevEntry.RawLine += "`n$rawLine"
                $prevEntry.Message += "`n$rawLine"
            }
        }
        return $entries
    }
