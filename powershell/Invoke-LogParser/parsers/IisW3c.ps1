# IIS / W3C Extended Log Parser

Register-Parser -Id "iis-w3c" -Name "IIS / W3C Extended Log" -Extensions @(".log") -SupportsTail $true `
    -AutoDetect {
        param($firstLines, $filePath)
        foreach ($line in $firstLines) {
            if ($line -match '^#Software:\s*Microsoft Internet Information') { return $true }
            if ($line -match '^#Fields:' -and $line -match 's-ip|cs-method|sc-status') { return $true }
        }
        return $false
    } `
    -Parse {
        param($reader, [int]$startIndex)
        $entries = [System.Collections.Generic.List[object]]::new()
        $fields = @()

        if ($startIndex -eq 0) {
            # Full parse - read headers from stream
            while (-not $reader.EndOfStream) {
                $rawLine = $reader.ReadLine()
                if ($rawLine -match '^#Fields:\s*(.+)') { $fields = $Matches[1].Trim() -split '\s+'; break }
                if (-not $rawLine.StartsWith('#')) { break }
            }
            $Script:State.ParserState['iis-w3c-fields'] = $fields
        } else {
            # Tail mode - use cached fields
            $fields = $Script:State.ParserState['iis-w3c-fields']
            if (-not $fields) { return $entries }
        }

        $idx = $startIndex
        while (-not $reader.EndOfStream) {
            $rawLine = $reader.ReadLine()
            if ($rawLine.StartsWith('#') -or [string]::IsNullOrWhiteSpace($rawLine)) { continue }
            if ($fields.Count -eq 0) { continue }

            $parts = $rawLine -split '\s+'
            $extra = @{}
            for ($i = 0; $i -lt [Math]::Min($fields.Count, $parts.Count); $i++) {
                $extra[$fields[$i]] = $parts[$i]
            }

            $ts = [datetime]::MinValue
            if ($extra['date'] -and $extra['time']) {
                [datetime]::TryParse("$($extra['date']) $($extra['time'])", [ref]$ts) | Out-Null
            }

            $status = $extra['sc-status']
            $level = if ($status -and [int]$status -ge 500) { "ERROR" }
                     elseif ($status -and [int]$status -ge 400) { "WARNING" }
                     else { "INFO" }

            $msg = "$($extra['cs-method']) $($extra['cs-uri-stem']) $($extra['sc-status'])"
            if ($extra['time-taken']) { $msg += " ($($extra['time-taken'])ms)" }

            $entries.Add((ConvertTo-LogEntry @{
                Index = $idx; Timestamp = $ts; Level = $level
                Source = $extra['c-ip']; Host = $extra['s-ip']
                Message = $msg; RawLine = $rawLine; Extra = $extra
            }))
            $idx++
        }
        return $entries
    }
