Register-Parser -Id "entra-signin" -Name "Entra ID Sign-In Logs" -Extensions @(".json") `
    -AutoDetect {
        param($firstLines, $filePath)
        $joined = $firstLines -join "`n"
        # Look for Entra sign-in specific fields
        if ($joined -match '"createdDateTime"' -and ($joined -match '"conditionalAccessStatus"' -or $joined -match '"userPrincipalName"')) {
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
                if ($record.createdDateTime) {
                    [datetime]::TryParse([string]$record.createdDateTime, [ref]$ts) | Out-Null
                }

                $errorCode = 0
                if ($record.status -and $record.status.errorCode) {
                    $errorCode = $record.status.errorCode -as [int]
                }

                $level = if ($errorCode -eq 0) { "INFO" }
                         elseif ($errorCode -in @(50126, 50055, 50056, 50057, 50058, 50059)) { "WARNING" }
                         else { "ERROR" }

                # Risk-based level escalation
                if ($record.riskLevelDuringSignIn -and $record.riskLevelDuringSignIn -ne 'none') {
                    $riskLevel = $record.riskLevelDuringSignIn.ToLower()
                    if ($riskLevel -in @('high', 'critical')) { $level = "CRITICAL" }
                    elseif ($riskLevel -eq 'medium' -and $level -ne "CRITICAL") { $level = "WARNING" }
                }

                $user = [string]$record.userPrincipalName
                $app = [string]$record.appDisplayName
                $ip = [string]$record.ipAddress
                $caStatus = [string]$record.conditionalAccessStatus

                $result = if ($errorCode -eq 0) { "success" } else { "failure (code $errorCode)" }
                $location = ""
                if ($record.location) {
                    $parts = @()
                    if ($record.location.city) { $parts += $record.location.city }
                    if ($record.location.state) { $parts += $record.location.state }
                    if ($record.location.countryOrRegion) { $parts += $record.location.countryOrRegion }
                    $location = $parts -join ", "
                }

                $msg = "Sign-in $result for $user to $app"
                if ($location) { $msg += " from $location" }

                $extra = @{
                    UserPrincipalName = $user
                    AppDisplayName = $app
                    IPAddress = $ip
                    ConditionalAccessStatus = $caStatus
                    ErrorCode = $errorCode
                }
                if ($record.status -and $record.status.failureReason) {
                    $extra['FailureReason'] = [string]$record.status.failureReason
                }
                if ($record.mfaDetail) {
                    if ($record.mfaDetail.authMethod) { $extra['MfaMethod'] = [string]$record.mfaDetail.authMethod }
                    if ($record.mfaDetail.authDetail) { $extra['MfaDetail'] = [string]$record.mfaDetail.authDetail }
                }
                if ($record.deviceDetail) {
                    if ($record.deviceDetail.operatingSystem) { $extra['DeviceOS'] = [string]$record.deviceDetail.operatingSystem }
                    if ($record.deviceDetail.browser) { $extra['Browser'] = [string]$record.deviceDetail.browser }
                    if ($record.deviceDetail.displayName) { $extra['DeviceName'] = [string]$record.deviceDetail.displayName }
                }
                if ($location) { $extra['Location'] = $location }
                if ($record.riskLevelDuringSignIn) { $extra['RiskLevel'] = [string]$record.riskLevelDuringSignIn }
                if ($record.riskState) { $extra['RiskState'] = [string]$record.riskState }
                if ($record.id) { $extra['SignInId'] = [string]$record.id }
                if ($record.correlationId) { $extra['CorrelationId'] = [string]$record.correlationId }

                $entries.Add((ConvertTo-LogEntry @{
                    Index = $idx; Timestamp = $ts; Level = $level
                    Source = $app; Host = $ip
                    Message = $msg; RawLine = ($record | ConvertTo-Json -Compress -Depth 5)
                    Extra = $extra
                }))
                $idx++
            }
        } catch {
            Write-Log "Entra sign-in parse error: $_" -Level ERROR
        }
        return $entries
    } `
    -SupportsTail $false
