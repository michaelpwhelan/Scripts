Register-Parser -Id "veeam-session" -Name "Veeam Session Detail" -Extensions @(".csv", ".json") `
    -AutoDetect {
        param($firstLines, $filePath)
        $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
        $joined = $firstLines -join "`n"
        if ($ext -eq '.json') {
            if (($joined -match '"JobName"' -or $joined -match '"Name"') -and ($joined -match '"Status"' -or $joined -match '"Result"') -and ($joined -match '"CreationTime"' -or $joined -match '"StartTime"' -or $joined -match '"EndTime"')) {
                return $true
            }
        } elseif ($ext -eq '.csv') {
            if ($firstLines.Count -ge 1) {
                $header = $firstLines[0]
                $hasJob = ($header -match 'JobName' -or $header -match '\bName\b')
                $hasStatus = ($header -match 'Status' -or $header -match 'Result')
                $hasTime = ($header -match 'CreationTime' -or $header -match 'StartTime' -or $header -match 'EndTime')
                if ($hasJob -and $hasStatus -and $hasTime) { return $true }
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

            foreach ($record in $records) {
                $ts = [datetime]::MinValue
                if ($record.CreationTime) {
                    [datetime]::TryParse([string]$record.CreationTime, [ref]$ts) | Out-Null
                } elseif ($record.StartTime) {
                    [datetime]::TryParse([string]$record.StartTime, [ref]$ts) | Out-Null
                }

                $status = if ($record.Status) { [string]$record.Status }
                          elseif ($record.Result) { [string]$record.Result }
                          else { "" }
                $level = switch ($status.ToLower()) {
                    'success'   { "INFO" }
                    'warning'   { "WARNING" }
                    'failed'    { "ERROR" }
                    default     { Get-LevelFromText $status }
                }

                $jobName = if ($record.JobName) { [string]$record.JobName }
                           elseif ($record.Name) { [string]$record.Name }
                           else { "" }
                $sessionType = [string]$record.SessionType

                # Calculate duration
                $duration = ""
                if ($record.Duration) {
                    $duration = [string]$record.Duration
                } elseif ($record.StartTime -and $record.EndTime) {
                    $startTs = [datetime]::MinValue
                    $endTs = [datetime]::MinValue
                    if ([datetime]::TryParse([string]$record.StartTime, [ref]$startTs) -and [datetime]::TryParse([string]$record.EndTime, [ref]$endTs)) {
                        $span = $endTs - $startTs
                        $duration = "{0:hh\:mm\:ss}" -f $span
                    }
                }

                $msg = "$jobName"
                if ($sessionType) { $msg += " ($sessionType)" }
                $msg += " - $status"
                if ($duration) { $msg += " [$duration]" }

                $extra = @{
                    JobName         = $jobName
                    SessionType     = $sessionType
                    Status          = $status
                    Duration        = $duration
                    BackupSize      = [string]$record.BackupSize
                    TransferredData = [string]$record.TransferredData
                    BottleneckType  = [string]$record.BottleneckType
                    VmName          = [string]$record.VmName
                    StartTime       = [string]$record.StartTime
                    EndTime         = [string]$record.EndTime
                }

                $rawLine = if ($ext -eq '.json') { $record | ConvertTo-Json -Compress -Depth 5 } else { ($record.PSObject.Properties.Value -join ",") }

                $entries.Add((ConvertTo-LogEntry @{
                    Index = $idx; Timestamp = $ts; Level = $level
                    Source = "Veeam"; Host = [string]$record.VmName
                    Message = $msg; RawLine = $rawLine; Extra = $extra
                }))
                $idx++
            }
        } catch {
            Write-Log "Veeam session parse error: $_" -Level ERROR
        }
        return $entries
    } `
    -SupportsTail $false
