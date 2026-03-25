# Syslog RFC 5424 Parser

Register-Parser -Id "syslog-rfc5424" -Name "Syslog RFC 5424" -Extensions @(".log", ".syslog") -SupportsTail $true `
    -AutoDetect {
        param($firstLines, $filePath)
        foreach ($line in $firstLines) {
            if ($line -match '^<\d+>\d\s+\d{4}-\d{2}-\d{2}T') { return $true }
        }
        return $false
    } `
    -Parse {
        param($reader, [int]$startIndex)
        $entries = [System.Collections.Generic.List[object]]::new()
        $idx = $startIndex
        $pattern = '^<(\d+)>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:(\[.*?\])\s*)?(.*)'
        $prevEntry = $null
        while (-not $reader.EndOfStream) {
            $rawLine = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($rawLine)) { continue }
            if ($rawLine -match $pattern) {
                $pri = [int]$Matches[1]; $ver = $Matches[2]; $tsStr = $Matches[3]
                $host2 = $Matches[4]; $app = $Matches[5]; $procId = $Matches[6]
                $msgId = $Matches[7]; $sd = $Matches[8]; $msg = $Matches[9]
                $severity = $pri % 8; $facility = [math]::Floor($pri / 8)

                $ts = [datetime]::MinValue
                [datetime]::TryParse($tsStr, [ref]$ts) | Out-Null

                $level = switch ($severity) {
                    0 { "CRITICAL" } 1 { "CRITICAL" } 2 { "CRITICAL" }
                    3 { "ERROR" } 4 { "WARNING" } 5 { "INFO" } 6 { "INFO" } 7 { "DEBUG" }
                    default { "UNKNOWN" }
                }

                $extra = @{ Priority = $pri; Version = $ver; Facility = $facility; Severity = $severity; ProcID = $procId; MsgID = $msgId }
                if ($sd -and $sd -ne '-') { $extra['StructuredData'] = $sd }

                $prevEntry = ConvertTo-LogEntry @{
                    Index = $idx; Timestamp = $ts; Level = $level; Source = $app
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
