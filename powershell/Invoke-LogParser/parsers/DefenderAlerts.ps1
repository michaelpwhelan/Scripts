Register-Parser -Id "defender-alerts" -Name "Microsoft Defender Alerts" -Extensions @(".json", ".csv") `
    -AutoDetect {
        param($firstLines, $filePath)
        $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
        $joined = $firstLines -join "`n"
        if ($ext -eq '.json') {
            if ($joined -match '"alertId"' -and ($joined -match '"severity"' -or $joined -match '"detectionSource"') -and $joined -match '"title"') {
                return $true
            }
        } elseif ($ext -eq '.csv') {
            if ($firstLines.Count -ge 1 -and $firstLines[0] -match 'alertId' -and $firstLines[0] -match 'severity' -and $firstLines[0] -match 'title') {
                return $true
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
                if ($record.alertCreationTime) {
                    [datetime]::TryParse([string]$record.alertCreationTime, [ref]$ts) | Out-Null
                } elseif ($record.createdDateTime) {
                    [datetime]::TryParse([string]$record.createdDateTime, [ref]$ts) | Out-Null
                }

                $sev = if ($record.severity) { [string]$record.severity } else { "Informational" }
                $level = switch ($sev.ToLower()) {
                    'critical'      { "CRITICAL" }
                    'high'          { "ERROR" }
                    'medium'        { "WARNING" }
                    'low'           { "INFO" }
                    'informational' { "DEBUG" }
                    default         { "INFO" }
                }

                $title = [string]$record.title
                $deviceName = if ($record.computerDnsName) { [string]$record.computerDnsName } else { "" }
                $msg = "[$sev] $title"
                if ($deviceName) { $msg += " - $deviceName" }

                $mitreTechniques = ""
                if ($record.mitreTechniques -and $record.mitreTechniques -is [array]) {
                    $mitreTechniques = $record.mitreTechniques -join ", "
                }

                $extra = @{
                    AlertId            = [string]$record.alertId
                    Severity           = $sev
                    Category           = [string]$record.category
                    DetectionSource    = [string]$record.detectionSource
                    ThreatName         = [string]$record.threatName
                    DeviceName         = $deviceName
                    UserPrincipalName  = [string]$record.userPrincipalName
                    InvestigationState = [string]$record.investigationState
                    MitreTechniques    = $mitreTechniques
                    FileName           = [string]$record.fileName
                }

                $rawLine = if ($ext -eq '.json') { $record | ConvertTo-Json -Compress -Depth 5 } else { ($record.PSObject.Properties.Value -join ",") }

                $entries.Add((ConvertTo-LogEntry @{
                    Index = $idx; Timestamp = $ts; Level = $level
                    Source = [string]$record.detectionSource; Host = $deviceName
                    Message = $msg; RawLine = $rawLine; Extra = $extra
                }))
                $idx++
            }
        } catch {
            Write-Log "Defender alerts parse error: $_" -Level ERROR
        }
        return $entries
    } `
    -SupportsTail $false
