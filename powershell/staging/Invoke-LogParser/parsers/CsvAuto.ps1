# CSV with Headers (Auto-detect columns) Parser

Register-Parser -Id "csv-auto" -Name "CSV with Headers" -Extensions @(".csv") -SupportsTail $false `
    -AutoDetect {
        param($firstLines, $filePath)
        if ([System.IO.Path]::GetExtension($filePath).ToLower() -ne '.csv') { return $false }
        if ($firstLines.Count -ge 1 -and ($firstLines[0] -split ',').Count -ge 3) { return $true }
        return $false
    } `
    -Parse {
        param($filePath, $encoding)
        $entries = [System.Collections.Generic.List[object]]::new()
        $idx = 0
        try {
            $csv = Import-Csv -Path $filePath -Encoding $encoding
            $headers = @()
            if ($csv.Count -gt 0) { $headers = $csv[0].PSObject.Properties.Name }
            # Map columns by keyword
            $tsCol = $headers | Where-Object { $_ -match 'time|date|timestamp|@timestamp|created|when' } | Select-Object -First 1
            $lvlCol = $headers | Where-Object { $_ -match 'level|severity|loglevel|priority|type' } | Select-Object -First 1
            $srcCol = $headers | Where-Object { $_ -match 'source|provider|host|computer|server|origin' } | Select-Object -First 1
            $msgCol = $headers | Where-Object { $_ -match 'message|msg|text|description|detail|content' } | Select-Object -First 1

            foreach ($row in $csv) {
                $ts = [datetime]::MinValue
                if ($tsCol) { [datetime]::TryParse($row.$tsCol, [ref]$ts) | Out-Null }
                $level = if ($lvlCol) { $row.$lvlCol.ToUpper() } else { "UNKNOWN" }
                if ($level -notin @("CRITICAL","ERROR","WARNING","INFO","DEBUG","TRACE")) { $level = Get-LevelFromText $level }
                $source = if ($srcCol) { $row.$srcCol } else { "" }
                $msg = if ($msgCol) { $row.$msgCol } else { ($row.PSObject.Properties.Value -join " | ") }
                $extra = @{}
                foreach ($h in $headers) { $extra[$h] = $row.$h }
                $rawLine = ($row.PSObject.Properties.Value -join ",")
                $entries.Add((ConvertTo-LogEntry @{
                    Index = $idx; Timestamp = $ts; Level = $level; Source = $source
                    Host = ""; Message = $msg; RawLine = $rawLine; Extra = $extra
                }))
                $idx++
            }
        } catch {
            Write-Log "CSV parse error: $_" -Level ERROR
        }
        return $entries
    }
