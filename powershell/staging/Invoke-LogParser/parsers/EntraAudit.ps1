Register-Parser -Id "entra-audit" -Name "Entra ID Audit Logs" -Extensions @(".json") `
    -AutoDetect {
        param($firstLines, $filePath)
        $joined = $firstLines -join "`n"
        if ($joined -match '"activityDisplayName"' -and ($joined -match '"result"' -or $joined -match '"targetResources"')) {
            return $true
        }
        return $false
    } `
    -Parse {
        param($filePath, $encoding)
        $entries = [System.Collections.Generic.List[object]]::new()
        $idx = 0
        try {
            $content = [System.IO.File]::ReadAllText($filePath, [System.Text.Encoding]::GetEncoding($encoding))
            $json = $content | ConvertFrom-Json

            # Handle both array and {value: [...]} wrapper
            $records = if ($json.value) { $json.value } elseif ($json -is [array]) { $json } else { @($json) }

            foreach ($record in $records) {
                $ts = [datetime]::MinValue
                if ($record.activityDateTime) {
                    [datetime]::TryParse([string]$record.activityDateTime, [ref]$ts) | Out-Null
                }

                $result = if ($record.result) { [string]$record.result } else { "" }
                $level = switch ($result.ToLower()) {
                    'failure' { "ERROR" }
                    'success' { "INFO" }
                    'timeout' { "WARNING" }
                    default   { "INFO" }
                }

                $activityDisplayName = [string]$record.activityDisplayName
                $category = [string]$record.category

                # Extract initiatedBy user or app
                $initiatedByUser = ""
                $initiatedByApp = ""
                if ($record.initiatedBy) {
                    if ($record.initiatedBy.user -and $record.initiatedBy.user.userPrincipalName) {
                        $initiatedByUser = [string]$record.initiatedBy.user.userPrincipalName
                    }
                    if ($record.initiatedBy.app -and $record.initiatedBy.app.displayName) {
                        $initiatedByApp = [string]$record.initiatedBy.app.displayName
                    }
                }

                # Extract first target resource displayName
                $targetResource = ""
                if ($record.targetResources -and $record.targetResources.Count -gt 0) {
                    $targetResource = [string]$record.targetResources[0].displayName
                }

                $initiatedBy = if ($initiatedByUser) { $initiatedByUser } elseif ($initiatedByApp) { $initiatedByApp } else { "" }
                $operationType = ""
                if ($record.targetResources -and $record.targetResources.Count -gt 0 -and $record.targetResources[0].modifiedProperties) {
                    $operationType = [string]$record.operationType
                }
                if (-not $operationType -and $record.operationType) {
                    $operationType = [string]$record.operationType
                }

                $msg = "$activityDisplayName"
                if ($targetResource) { $msg += " for $targetResource" }
                if ($initiatedBy) { $msg += " by $initiatedBy" }
                if ($result) { $msg += " ($result)" }

                $extra = @{
                    ActivityDisplayName = $activityDisplayName
                    Category            = $category
                    Result              = $result
                    ResultReason        = [string]$record.resultReason
                    InitiatedByUser     = $initiatedByUser
                    InitiatedByApp      = $initiatedByApp
                    TargetResource      = $targetResource
                    CorrelationId       = [string]$record.correlationId
                    OperationType       = $operationType
                }

                $entries.Add((ConvertTo-LogEntry @{
                    Index = $idx; Timestamp = $ts; Level = $level
                    Source = $category; Host = ""
                    Message = $msg; RawLine = ($record | ConvertTo-Json -Compress -Depth 5)
                    Extra = $extra
                }))
                $idx++
            }
        } catch {
            Write-Log "Entra audit parse error: $_" -Level ERROR
        }
        return $entries
    } `
    -SupportsTail $false
