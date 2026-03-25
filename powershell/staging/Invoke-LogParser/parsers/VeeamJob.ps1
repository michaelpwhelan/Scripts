Register-Parser -Id "veeam-job" -Name "Veeam Backup Job Log" -Extensions @(".log") `
    -AutoDetect {
        param($firstLines, $filePath)
        $matchCount = 0
        foreach ($line in $firstLines) {
            # Veeam format: [dd.MM.yyyy HH:mm:ss] <thread> (Level) [Module] message
            if ($line -match '^\[\d{2}\.\d{2}\.\d{4}\s+\d{2}:\d{2}:\d{2}\]\s+<\d+>') { $matchCount++ }
        }
        return ($matchCount -ge 2)
    } `
    -Parse {
        param($reader, [int]$startIndex)
        $entries = [System.Collections.Generic.List[object]]::new()
        $idx = $startIndex
        $pattern = '^\[(\d{2})\.(\d{2})\.(\d{4})\s+(\d{2}:\d{2}:\d{2})\]\s+<(\d+)>\s+(\w+)\s+(?:\[([^\]]*)\])?\s*(.*)'
        $prevEntry = $null

        while (-not $reader.EndOfStream) {
            $rawLine = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($rawLine)) { continue }

            if ($rawLine -match $pattern) {
                $day = $Matches[1]; $month = $Matches[2]; $year = $Matches[3]; $time = $Matches[4]
                $thread = $Matches[5]; $rawLevel = $Matches[6]; $module = $Matches[7]; $msg = $Matches[8]

                $ts = [datetime]::MinValue
                [datetime]::TryParse("$year-$month-$day $time", [ref]$ts) | Out-Null

                $level = switch ($rawLevel.ToLower()) {
                    'info' { "INFO" }
                    'warning' { "WARNING" }
                    'error' { "ERROR" }
                    'failed' { "ERROR" }
                    'debug' { "DEBUG" }
                    default { Get-LevelFromText $rawLevel }
                }

                # Check for specific failure patterns
                if ($msg -match 'Failed|Error|Cannot|Unable|Exception') {
                    if ($level -eq "INFO") { $level = "WARNING" }
                }
                if ($msg -match 'Processing finished with errors|Job finished with errors') {
                    $level = "ERROR"
                }

                $extra = @{
                    Thread = $thread
                    Module = $module
                }

                $prevEntry = ConvertTo-LogEntry @{
                    Index = $idx; Timestamp = $ts; Level = $level
                    Source = if ($module) { $module } else { "Veeam" }
                    Host = ""; Message = $msg
                    RawLine = $rawLine; Extra = $extra
                }
                $entries.Add($prevEntry)
                $idx++
            } elseif ($prevEntry -and $startIndex -eq 0) {
                # Multi-line continuation (only in full parse mode)
                $prevEntry.RawLine += "`n$rawLine"
                $prevEntry.Message += "`n$rawLine"
            }
        }
        return $entries
    } `
    -SupportsTail $true
