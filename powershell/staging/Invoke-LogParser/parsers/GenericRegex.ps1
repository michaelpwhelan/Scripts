# User-Defined Regex Parser

Register-Parser -Id "generic-regex" -Name "User-Defined Regex" -Extensions @() -SupportsTail $false `
    -AutoDetect { param($firstLines, $filePath); return $false } `
    -Parse {
        param($filePath, $encoding)
        $entries = [System.Collections.Generic.List[object]]::new()
        $regexStr = $Script:State.CustomRegex
        if (-not $regexStr) { return $entries }
        $idx = 0
        try {
            $regex = [regex]::new($regexStr, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        } catch { Write-Log "Invalid regex: $_" -Level ERROR; return $entries }
        $reader = [System.IO.StreamReader]::new($filePath, [System.Text.Encoding]::GetEncoding($encoding))
        while (-not $reader.EndOfStream) {
            $rawLine = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($rawLine)) { continue }
            $m = $regex.Match($rawLine)
            if ($m.Success) {
                $extra = @{}
                foreach ($gn in $regex.GetGroupNames()) {
                    if ($gn -ne '0') { $extra[$gn] = $m.Groups[$gn].Value }
                }
                $ts = [datetime]::MinValue
                if ($extra['timestamp']) { [datetime]::TryParse($extra['timestamp'], [ref]$ts) | Out-Null }
                $level = if ($extra['level']) { $extra['level'].ToUpper() } else { Get-LevelFromText $rawLine }
                if ($level -notin @("CRITICAL","ERROR","WARNING","INFO","DEBUG","TRACE")) { $level = Get-LevelFromText $level }
                $entries.Add((ConvertTo-LogEntry @{
                    Index = $idx; Timestamp = $ts; Level = $level
                    Source = $(if ($extra['source']) { $extra['source'] } else { "" })
                    Host = ""; Message = $(if ($extra['message']) { $extra['message'] } else { $rawLine })
                    RawLine = $rawLine; Extra = $extra
                }))
            } else {
                $entries.Add((ConvertTo-LogEntry @{
                    Index = $idx; Timestamp = [datetime]::MinValue; Level = (Get-LevelFromText $rawLine)
                    Source = ""; Host = ""; Message = $rawLine; RawLine = $rawLine; Extra = @{}
                }))
            }
            $idx++
        }
        $reader.Close(); $reader.Dispose()
        return $entries
    }
