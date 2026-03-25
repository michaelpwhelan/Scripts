Register-Parser -Id "intune-compliance" -Name "Intune Device Compliance" -Extensions @(".json", ".csv") `
    -AutoDetect {
        param($firstLines, $filePath)
        $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
        $joined = $firstLines -join "`n"
        if ($ext -eq '.json') {
            if ($joined -match '"complianceState"' -or $joined -match '"deviceCompliancePolicyId"') {
                return $true
            }
        } elseif ($ext -eq '.csv') {
            if ($firstLines.Count -ge 1 -and ($firstLines[0] -match 'complianceState' -or $firstLines[0] -match 'deviceCompliancePolicyId')) {
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
                if ($record.lastContactedDateTime) {
                    [datetime]::TryParse([string]$record.lastContactedDateTime, [ref]$ts) | Out-Null
                } elseif ($record.lastSyncDateTime) {
                    [datetime]::TryParse([string]$record.lastSyncDateTime, [ref]$ts) | Out-Null
                }

                $complianceState = if ($record.complianceState) { [string]$record.complianceState } else { "unknown" }
                $level = switch ($complianceState.ToLower()) {
                    'noncompliant'  { "WARNING" }
                    'error'         { "ERROR" }
                    'compliant'     { "INFO" }
                    'ingraceperiod' { "WARNING" }
                    'unknown'       { "DEBUG" }
                    default         { "INFO" }
                }

                $deviceName = if ($record.deviceName) { [string]$record.deviceName } else { "" }
                $policyName = if ($record.policyName) { [string]$record.policyName }
                              elseif ($record.compliancePolicyName) { [string]$record.compliancePolicyName }
                              else { "" }
                $userPrincipalName = [string]$record.userPrincipalName

                $msg = "$deviceName - $complianceState"
                if ($policyName) { $msg += " (policy: $policyName)" }

                $lastContactTime = if ($record.lastContactedDateTime) { [string]$record.lastContactedDateTime }
                                   elseif ($record.lastSyncDateTime) { [string]$record.lastSyncDateTime }
                                   else { "" }

                $extra = @{
                    DeviceName        = $deviceName
                    ComplianceState   = $complianceState
                    PolicyName        = $policyName
                    UserPrincipalName = $userPrincipalName
                    OS                = [string]$record.operatingSystem
                    OSVersion         = [string]$record.osVersion
                    LastContactTime   = $lastContactTime
                }

                $rawLine = if ($ext -eq '.json') { $record | ConvertTo-Json -Compress -Depth 5 } else { ($record.PSObject.Properties.Value -join ",") }

                $entries.Add((ConvertTo-LogEntry @{
                    Index = $idx; Timestamp = $ts; Level = $level
                    Source = "Intune Compliance"; Host = $deviceName
                    Message = $msg; RawLine = $rawLine; Extra = $extra
                }))
                $idx++
            }
        } catch {
            Write-Log "Intune compliance parse error: $_" -Level ERROR
        }
        return $entries
    } `
    -SupportsTail $false
