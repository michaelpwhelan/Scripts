# Plain Text Fallback Parser

Register-Parser -Id "plaintext" -Name "Plain Text (fallback)" -Extensions @(".log", ".txt", "*") -SupportsTail $true `
    -AutoDetect { param($firstLines, $filePath); return $true } `
    -Parse {
        param($reader, [int]$startIndex)
        $entries = [System.Collections.Generic.List[object]]::new()
        $idx = $startIndex
        $tsPatterns = @(
            '(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})',
            '(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})',
            '(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})'
        )
        $prevEntry = $null
        while (-not $reader.EndOfStream) {
            $rawLine = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($rawLine)) { continue }

            # Try to extract timestamp
            $ts = [datetime]::MinValue
            $foundTs = $false
            foreach ($p in $tsPatterns) {
                if ($rawLine -match $p) {
                    if ([datetime]::TryParse($Matches[1], [ref]$ts)) { $foundTs = $true; break }
                }
            }

            # If no timestamp and previous entry exists, treat as continuation (full parse only)
            if (-not $foundTs -and $prevEntry -and $startIndex -eq 0 -and $rawLine -match '^\s') {
                $prevEntry.RawLine += "`n$rawLine"
                $prevEntry.Message += "`n$rawLine"
                continue
            }

            $level = Get-LevelFromText $rawLine
            $prevEntry = ConvertTo-LogEntry @{
                Index = $idx; Timestamp = $ts; Level = $level; Source = ""
                Host = ""; Message = $rawLine; RawLine = $rawLine; Extra = @{}
            }
            $entries.Add($prevEntry)
            $idx++
        }
        return $entries
    }
