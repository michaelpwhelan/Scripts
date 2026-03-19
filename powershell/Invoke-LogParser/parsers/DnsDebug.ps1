Register-Parser -Id "dns-debug" -Name "Windows DNS Debug Log" -Extensions @(".log", ".txt") `
    -AutoDetect {
        param($firstLines, $filePath)
        $matchCount = 0
        foreach ($line in $firstLines) {
            if ($line -match 'PACKET\s+\w+' -or $line -match '\b(Snd|Rcv)\b.*\b(UDP|TCP)\b') { $matchCount++ }
        }
        return ($matchCount -ge 2)
    } `
    -Parse {
        param($reader, [int]$startIndex)
        $entries = [System.Collections.Generic.List[object]]::new()
        $idx = $startIndex
        # DNS debug log pattern: date time threadId context proto direction remoteIP queryInfo
        $pattern = '^(\d{1,2}/\d{1,2}/\d{4})\s+(\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?)\s+([0-9A-F]+)\s+PACKET\s+([0-9A-F]+)\s+(\w+)\s+(Snd|Rcv)\s+(\S+)\s+([0-9a-f]+)\s+(\w+)\s+(\w+)\s*\[.*?\]\s+(\w+)\s+\((\d+)\)(.*)'
        $simplePattern = '^(\d{1,2}/\d{1,2}/\d{4})\s+(\d{1,2}:\d{2}:\d{2}\s*(?:AM|PM)?)\s+([0-9A-F]+)\s+(.*)'

        # Response code mapping
        $rcodeSeverity = @{
            'NOERROR'  = 'INFO'
            'SERVFAIL' = 'WARNING'
            'NXDOMAIN' = 'WARNING'
            'REFUSED'  = 'WARNING'
            'FORMERR'  = 'ERROR'
        }

        while (-not $reader.EndOfStream) {
            $rawLine = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($rawLine)) { continue }
            if ($rawLine -match '^\s*-{3}') { continue }  # Skip separator lines
            if ($rawLine -match '^DNS Server log') { continue }  # Skip header

            $ts = [datetime]::MinValue
            $extra = @{}
            $level = "INFO"
            $msg = $rawLine
            $source = "DNS"
            $host2 = ""

            if ($rawLine -match $pattern) {
                $dateStr = $Matches[1]; $timeStr = $Matches[2]
                [datetime]::TryParse("$dateStr $timeStr", [ref]$ts) | Out-Null
                $extra['ThreadId'] = $Matches[3]
                $extra['Protocol'] = $Matches[5]
                $extra['Direction'] = $Matches[6]
                $extra['RemoteIP'] = $Matches[7]
                $extra['XID'] = $Matches[8]
                $extra['QueryOp'] = $Matches[9]
                $extra['ResponseCode'] = $Matches[10]
                $extra['QueryType'] = $Matches[11]

                # Decode query name from remaining data
                $queryData = $Matches[13].Trim()
                if ($queryData) {
                    # DNS name is in length-prefixed format: (5)query(3)com(0)
                    $decodedName = $queryData -replace '\(\d+\)', '.' -replace '^\.' , '' -replace '\.$', ''
                    $extra['QueryName'] = $decodedName
                }

                $rcode = $Matches[10]
                $level = if ($rcodeSeverity.ContainsKey($rcode)) { $rcodeSeverity[$rcode] } else { "INFO" }
                $host2 = $Matches[7]
                $direction = if ($Matches[6] -eq 'Rcv') { "Query" } else { "Response" }
                $msg = "$direction $($extra['QueryType']) $($extra['QueryName']) from $($Matches[7]) [$rcode]"
            } elseif ($rawLine -match $simplePattern) {
                [datetime]::TryParse("$($Matches[1]) $($Matches[2])", [ref]$ts) | Out-Null
                $extra['ThreadId'] = $Matches[3]
                $msg = $Matches[4]
                $level = Get-LevelFromText $msg
            } else {
                continue
            }

            $entries.Add((ConvertTo-LogEntry @{
                Index = $idx; Timestamp = $ts; Level = $level
                Source = $source; Host = $host2
                Message = $msg; RawLine = $rawLine; Extra = $extra
            }))
            $idx++
        }
        return $entries
    } `
    -SupportsTail $true
