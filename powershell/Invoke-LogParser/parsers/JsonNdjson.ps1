# JSON / NDJSON (JSON Lines) Parser

Register-Parser -Id "json-ndjson" -Name "JSON / NDJSON (JSON Lines)" -Extensions @(".json", ".jsonl", ".ndjson") -SupportsTail $true `
    -AutoDetect {
        param($firstLines, $filePath)
        foreach ($line in $firstLines) {
            $trimmed = $line.Trim()
            if ($trimmed.StartsWith('{')) {
                try { $null = $trimmed | ConvertFrom-Json; return $true } catch { }
            }
        }
        return $false
    } `
    -Parse {
        param($reader, [int]$startIndex)
        $entries = [System.Collections.Generic.List[object]]::new()
        $idx = $startIndex
        while (-not $reader.EndOfStream) {
            $rawLine = $reader.ReadLine()
            if ([string]::IsNullOrWhiteSpace($rawLine)) { continue }
            $trimmed = $rawLine.Trim()
            if (-not $trimmed.StartsWith('{')) { continue }
            try {
                $obj = $trimmed | ConvertFrom-Json
                $props = @{}
                $obj.PSObject.Properties | ForEach-Object { $props[$_.Name] = $_.Value }

                $ts = [datetime]::MinValue
                $tsKey = $props.Keys | Where-Object { $_ -match '^(timestamp|time|@timestamp|datetime|date|ts|created_at|logged_at)$' } | Select-Object -First 1
                if ($tsKey) { [datetime]::TryParse([string]$props[$tsKey], [ref]$ts) | Out-Null }

                $lvlKey = $props.Keys | Where-Object { $_ -match '^(level|severity|loglevel|log_level|priority|lvl)$' } | Select-Object -First 1
                $level = if ($lvlKey) { [string]$props[$lvlKey] } else { "UNKNOWN" }
                $level = $level.ToUpper()
                if ($level -notin @("CRITICAL","ERROR","WARNING","INFO","DEBUG","TRACE")) { $level = Get-LevelFromText $level }

                $srcKey = $props.Keys | Where-Object { $_ -match '^(source|logger|service|app|application|host|origin)$' } | Select-Object -First 1
                $source = if ($srcKey) { [string]$props[$srcKey] } else { "" }

                $msgKey = $props.Keys | Where-Object { $_ -match '^(message|msg|text|description|body|log)$' } | Select-Object -First 1
                $msg = if ($msgKey) { [string]$props[$msgKey] } else { $trimmed.Substring(0, [Math]::Min(200, $trimmed.Length)) }

                $extra = @{}; foreach ($k in $props.Keys) { $extra[$k] = [string]$props[$k] }

                $entries.Add((ConvertTo-LogEntry @{
                    Index = $idx; Timestamp = $ts; Level = $level; Source = $source
                    Host = ""; Message = $msg; RawLine = $rawLine; Extra = $extra
                }))
            } catch { }
            $idx++
        }
        return $entries
    }
