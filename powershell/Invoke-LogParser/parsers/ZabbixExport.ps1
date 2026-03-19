Register-Parser -Id "zabbix-export" -Name "Zabbix Event Export" -Extensions @(".csv", ".json") `
    -AutoDetect {
        param($firstLines, $filePath)
        $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
        $joined = $firstLines -join "`n"
        if ($ext -eq '.json') {
            if (($joined -match '"triggerid"' -or $joined -match '"eventid"') -and $joined -match '"severity"' -and ($joined -match '"acknowledged"' -or $joined -match '"value"' -or $joined -match '"name"')) {
                return $true
            }
        } elseif ($ext -eq '.csv') {
            if ($firstLines.Count -ge 1) {
                $header = $firstLines[0]
                $hasTrigger = ($header -match 'triggerid' -or $header -match 'eventid')
                $hasSeverity = ($header -match 'severity')
                $hasField = ($header -match 'acknowledged' -or $header -match '\bvalue\b' -or $header -match '\bname\b')
                if ($hasTrigger -and $hasSeverity -and $hasField) { return $true }
            }
        }
        return $false
    } `
    -Parse {
        param($filePath, $encoding)
        $entries = [System.Collections.Generic.List[object]]::new()
        $idx = 0
        try {
            $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
            $records = @()

            if ($ext -eq '.json') {
                $content = [System.IO.File]::ReadAllText($filePath, [System.Text.Encoding]::GetEncoding($encoding))
                $json = $content | ConvertFrom-Json

                # Handle both array and {value: [...]} wrapper
                $records = if ($json.value) { $json.value } elseif ($json -is [array]) { $json } else { @($json) }
            } else {
                $records = Import-Csv -Path $filePath -Encoding $encoding
            }

            # Zabbix severity name mapping
            $severityNames = @{
                0 = "Not classified"
                1 = "Information"
                2 = "Warning"
                3 = "Average"
                4 = "High"
                5 = "Disaster"
            }

            foreach ($record in $records) {
                $ts = [datetime]::MinValue
                if ($record.clock) {
                    # Zabbix uses Unix epoch timestamps
                    $epoch = $record.clock -as [long]
                    if ($epoch -gt 0) {
                        $ts = [DateTimeOffset]::FromUnixTimeSeconds($epoch).DateTime
                    }
                } elseif ($record.timestamp) {
                    [datetime]::TryParse([string]$record.timestamp, [ref]$ts) | Out-Null
                }

                $sevNum = $record.severity -as [int]
                $level = switch ($sevNum) {
                    5 { "CRITICAL" }
                    4 { "ERROR" }
                    3 { "WARNING" }
                    2 { "WARNING" }
                    1 { "INFO" }
                    0 { "DEBUG" }
                    default { "INFO" }
                }

                $severityName = if ($severityNames.ContainsKey($sevNum)) { $severityNames[$sevNum] } else { "Unknown" }
                $hostName = if ($record.hostname) { [string]$record.hostname }
                            elseif ($record.host) { [string]$record.host }
                            else { "" }
                $triggerDesc = if ($record.name) { [string]$record.name }
                               elseif ($record.description) { [string]$record.description }
                               else { "" }

                $msg = "[$severityName] $hostName - $triggerDesc"

                $duration = ""
                if ($record.r_clock -and $record.clock) {
                    $startEpoch = $record.clock -as [long]
                    $endEpoch = $record.r_clock -as [long]
                    if ($startEpoch -gt 0 -and $endEpoch -gt 0) {
                        $span = [TimeSpan]::FromSeconds($endEpoch - $startEpoch)
                        $duration = "{0:hh\:mm\:ss}" -f $span
                    }
                } elseif ($record.duration) {
                    $duration = [string]$record.duration
                }

                $extra = @{
                    HostName           = $hostName
                    TriggerId          = [string]$record.triggerid
                    TriggerDescription = $triggerDesc
                    ZabbixSeverity     = $severityName
                    Acknowledged       = [string]$record.acknowledged
                    Duration           = $duration
                    EventId            = [string]$record.eventid
                }

                $rawLine = if ($ext -eq '.json') { $record | ConvertTo-Json -Compress -Depth 5 } else { ($record.PSObject.Properties.Value -join ",") }

                $entries.Add((ConvertTo-LogEntry @{
                    Index = $idx; Timestamp = $ts; Level = $level
                    Source = "Zabbix"; Host = $hostName
                    Message = $msg; RawLine = $rawLine; Extra = $extra
                }))
                $idx++
            }
        } catch {
            Write-Log "Zabbix export parse error: $_" -Level ERROR
        }
        return $entries
    } `
    -SupportsTail $false
