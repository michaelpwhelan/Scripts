# FortiClient Local Log Parser

Register-Parser -Id "forticlient-local" -Name "FortiClient Local Log" -Extensions @(".log", ".txt") -SupportsTail $true `
    -AutoDetect {
        param($firstLines, $filePath)
        $matchCount = 0
        foreach ($line in $firstLines) {
            if ($line -match '^\[[\d-]+ [\d:]+\]\s+\[\w+\]\s+\[[\w.-]+\]') { $matchCount++ }
        }
        return ($matchCount -ge 2)
    } `
    -Parse {
        param($reader, [int]$startIndex)
        $entries = [System.Collections.Generic.List[object]]::new()
        $idx = $startIndex
        $pattern = '^\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\]\s+\[(\w+)\]\s+\[([\w.-]+)\]\s+(.*)'
        $prevEntry = $null
        while (-not $reader.EndOfStream) {
            $rawLine = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($rawLine)) { continue }
            if ($rawLine -match $pattern) {
                $ts = [datetime]::MinValue
                [datetime]::TryParse($Matches[1], [ref]$ts) | Out-Null
                $rawLevel = $Matches[2].ToUpper()
                $level = if ($rawLevel -in @("CRITICAL","ERROR","WARNING","INFO","DEBUG","TRACE")) { $rawLevel } else { Get-LevelFromText $rawLevel }
                $module = $Matches[3]
                $msg = $Matches[4]
                $moduleName = if ($Script:FortiClientModuleLookup.ContainsKey($module.ToLower())) { $Script:FortiClientModuleLookup[$module.ToLower()] } else { $module }
                $extra = @{ Module = $module; ModuleName = $moduleName }
                $prevEntry = ConvertTo-LogEntry @{
                    Index = $idx; Timestamp = $ts; Level = $level
                    Source = $moduleName; Host = ""; Message = $msg
                    RawLine = $rawLine; Extra = $extra
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
