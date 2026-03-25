# Apache / Nginx Combined Log Format Parser

Register-Parser -Id "apache-combined" -Name "Apache / Nginx CLF" -Extensions @(".log", ".access") -SupportsTail $true `
    -AutoDetect {
        param($firstLines, $filePath)
        $clfPattern = '^\S+\s+\S+\s+\S+\s+\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+\-]\d{4}\]\s+"'
        foreach ($line in $firstLines) {
            if ($line -match $clfPattern) { return $true }
        }
        return $false
    } `
    -Parse {
        param($reader, [int]$startIndex)
        $entries = [System.Collections.Generic.List[object]]::new()
        $idx = $startIndex
        $pattern = '^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*?)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*?)"\s+"([^"]*?)")?'
        while (-not $reader.EndOfStream) {
            $rawLine = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($rawLine)) { continue }
            if ($rawLine -match $pattern) {
                $ip = $Matches[1]; $ident = $Matches[2]; $user = $Matches[3]
                $dateStr = $Matches[4]; $request = $Matches[5]; $status = $Matches[6]
                $size = $Matches[7]; $referer = $Matches[8]; $ua = $Matches[9]

                $ts = [datetime]::MinValue
                try { $ts = [datetime]::ParseExact($dateStr, 'dd/MMM/yyyy:HH:mm:ss zzz', [System.Globalization.CultureInfo]::InvariantCulture) } catch { }

                $statusInt = [int]$status
                $level = if ($statusInt -ge 500) { "ERROR" } elseif ($statusInt -ge 400) { "WARNING" } else { "INFO" }
                $extra = @{ IP = $ip; Ident = $ident; User = $user; Request = $request; StatusCode = $status; Size = $size; Referer = $referer; UserAgent = $ua }

                $entries.Add((ConvertTo-LogEntry @{
                    Index = $idx; Timestamp = $ts; Level = $level; Source = $ip
                    Host = ""; Message = "$request $status"; RawLine = $rawLine; Extra = $extra
                }))
            } else {
                $entries.Add((ConvertTo-LogEntry @{
                    Index = $idx; Timestamp = [datetime]::MinValue; Level = (Get-LevelFromText $rawLine)
                    Source = ""; Host = ""; Message = $rawLine; RawLine = $rawLine; Extra = @{}
                }))
            }
            $idx++
        }
        return $entries
    }
