# ═══════════════════════════════════════════════════════════════════════════════
# MICROSOFT DEFENDER API CONNECTOR -- Pull alerts and vulnerabilities from MDE
# ═══════════════════════════════════════════════════════════════════════════════

function Connect-Defender {
    <#
    .SYNOPSIS
        Authenticates to the Microsoft Defender for Endpoint API using OAuth2
        client credentials flow and stores the access token.
    .OUTPUTS
        $true on success, $false on failure.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        [System.Security.SecureString]$ClientSecret
    )

    # Retrieve client secret from Credential Manager if not provided
    if (-not $ClientSecret) {
        $stored = Get-StoredApiCredential -TargetName "InvokeLogParser_Defender_$TenantId"
        if (-not $stored) {
            Write-Log "No client secret available for Defender tenant $TenantId" -Level ERROR
            return $false
        }
        $ClientSecret = ConvertTo-SecureString $stored.Password -AsPlainText -Force
    }

    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $plainSecret = ConvertTo-PlainText -SecureString $ClientSecret

    # OAuth2 client credentials -- must use form-encoded body, not JSON
    $tokenBody = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $plainSecret
        scope         = "https://api.securitycenter.microsoft.com/.default"
    }

    try {
        Write-Log "Authenticating to Microsoft Defender API (tenant: $TenantId) ..." -Level INFO

        # Token endpoint expects form-encoded, not JSON
        $response = $null
        $attempt = 0
        $maxRetries = 3
        $lastError = $null

        while ($attempt -lt $maxRetries) {
            $attempt++
            try {
                $response = Invoke-RestMethod -Uri $tokenUrl -Method POST `
                    -Body $tokenBody -ContentType "application/x-www-form-urlencoded" `
                    -TimeoutSec 15 -ErrorAction Stop
                break
            } catch {
                $lastError = $_
                $errMsg = $_.Exception.Message
                $isRetryable = ($errMsg -match 'timed?\s*out|timeout|Unable to connect|connection')
                if ($isRetryable -and $attempt -lt $maxRetries) {
                    $delay = 1000 * $attempt
                    Write-Log "Token request failed (attempt $attempt/$maxRetries): $errMsg -- retrying in ${delay}ms" -Level WARNING
                    Start-Sleep -Milliseconds $delay
                } else {
                    throw $lastError
                }
            }
        }

        if (-not $response -or -not $response.access_token) {
            Write-Log "Defender OAuth2 token request returned no access token" -Level ERROR
            return $false
        }

        $accessToken = $response.access_token
        $expiresIn   = if ($response.expires_in) { [int]$response.expires_in } else { 3600 }

        Register-Connector -Id 'defender' -Name "Microsoft Defender for Endpoint" -Type 'RestApi' -Config @{
            TenantId     = $TenantId
            ClientId     = $ClientId
            AccessToken  = $accessToken
            TokenExpiry  = (Get-Date).AddSeconds($expiresIn - 60)  # 1 min buffer
            BaseUrl      = "https://api.securitycenter.microsoft.com/api"
        }
        Set-ConnectorStatus -Id 'defender' -Status 'Connected'

        Write-Log "Defender API authentication successful (token expires in $expiresIn seconds)" -Level INFO
        return $true
    } catch {
        Write-Log "Defender API authentication failed: $($_.Exception.Message)" -Level ERROR
        Register-Connector -Id 'defender' -Name "Microsoft Defender for Endpoint" -Type 'RestApi' -Config @{
            TenantId = $TenantId; ClientId = $ClientId
        }
        Set-ConnectorStatus -Id 'defender' -Status 'Error' -ErrorMessage $_.Exception.Message
        return $false
    }
}

function Get-DefenderAuthHeaders {
    <#
    .SYNOPSIS
        Returns the Authorization header for Defender API calls. Checks token
        expiry and warns if expired.
    #>
    if (-not $Script:Connectors.ContainsKey('defender') -or
        -not $Script:Connectors['defender'].Config.AccessToken) {
        Write-Log "No active Defender API token. Call Connect-Defender first." -Level ERROR
        return $null
    }

    $config = $Script:Connectors['defender'].Config
    if ($config.TokenExpiry -and (Get-Date) -gt $config.TokenExpiry) {
        Write-Log "Defender API token has expired. Please re-authenticate with Connect-Defender." -Level WARNING
    }

    return @{
        Authorization = "Bearer $($config.AccessToken)"
    }
}

function Get-DefenderAlerts {
    <#
    .SYNOPSIS
        Retrieves alerts from Microsoft Defender for Endpoint API with OData
        filtering and pagination. Converts to standard LogEntry format (same
        schema as DefenderAlerts parser output).
    .OUTPUTS
        [List[object]] of ConvertTo-LogEntry entries.
    #>
    param(
        [datetime]$Since = (Get-Date).AddHours(-24),
        [ValidateSet("", "High", "Medium", "Low", "Informational")]
        [string]$Severity = "",
        [int]$Limit = 500
    )

    # Validate connector
    if (-not $Script:Connectors.ContainsKey('defender') -or
        $Script:Connectors['defender'].Status -ne 'Connected') {
        Write-Log "Defender connector is not connected. Call Connect-Defender first." -Level ERROR
        return [System.Collections.Generic.List[object]]::new()
    }

    # Check cache
    $cached = Get-ConnectorCache -Id 'defender'
    if ($cached) { return $cached }

    Set-ConnectorStatus -Id 'defender' -Status 'Pulling'

    $config  = $Script:Connectors['defender'].Config
    $baseUrl = $config.BaseUrl
    $headers = Get-DefenderAuthHeaders
    if (-not $headers) {
        return [System.Collections.Generic.List[object]]::new()
    }

    $entries = [System.Collections.Generic.List[object]]::new()
    $idx     = 0

    # Build OData filter
    $sinceIso = $Since.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $filter = "alertCreationTime ge $sinceIso"
    if ($Severity) {
        $filter += " and severity eq '$Severity'"
    }

    $uri = "${baseUrl}/alerts?`$filter=$([System.Uri]::EscapeDataString($filter))&`$top=$Limit"

    try {
        Write-Log "Pulling Defender alerts since $sinceIso $(if($Severity){"(severity=$Severity) "})..." -Level INFO

        $pageCount = 0
        $maxPages  = 50  # safety limit

        do {
            $pageCount++
            $response = Invoke-RestWithRetry -Uri $uri -Method GET `
                -Headers $headers -TimeoutSec 30 -MaxRetries 3

            $records = @()
            if ($response.value) {
                $records = $response.value
            } elseif ($response -is [array]) {
                $records = $response
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

                $title      = [string]$record.title
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
                    SourceFormat       = 'defender-alerts'
                    SourceConnector    = 'defender'
                }

                $entries.Add((ConvertTo-LogEntry @{
                    Index     = $idx
                    Timestamp = $ts
                    Level     = $level
                    Source    = [string]$record.detectionSource
                    Host      = $deviceName
                    Message   = $msg
                    RawLine   = ($record | ConvertTo-Json -Compress -Depth 5)
                    Extra     = $extra
                }))
                $idx++

                if ($idx -ge $Limit) { break }
            }

            # Follow @odata.nextLink for pagination
            $uri = $null
            if ($response.'@odata.nextLink' -and $idx -lt $Limit) {
                $uri = $response.'@odata.nextLink'
            }
        } while ($uri -and $pageCount -lt $maxPages)

        Set-ConnectorStatus -Id 'defender' -Status 'Connected'
        if ($entries.Count -gt 0) {
            Set-ConnectorCache -Id 'defender' -Data $entries
        }

        Write-Log "Defender: total $($entries.Count) alerts retrieved" -Level INFO
    } catch {
        Write-Log "Defender alert retrieval failed: $($_.Exception.Message)" -Level ERROR
        Set-ConnectorStatus -Id 'defender' -Status 'Error' -ErrorMessage $_.Exception.Message

        if ($_.Exception.Message -match '401|Unauthorized|token.*expir') {
            Write-Log "Defender API token may have expired -- re-authenticate with Connect-Defender" -Level WARNING
        }
    }

    return $entries
}

function Get-DefenderVulnerabilities {
    <#
    .SYNOPSIS
        Retrieves vulnerability assessments from Microsoft Defender for Endpoint.
        Converts to standard LogEntry format (same schema as DefenderVulnerability
        parser output).
    .OUTPUTS
        [List[object]] of ConvertTo-LogEntry entries.
    #>
    param(
        [ValidateSet("", "Critical", "High", "Medium", "Low")]
        [string]$Severity = ""
    )

    # Validate connector
    if (-not $Script:Connectors.ContainsKey('defender') -or
        $Script:Connectors['defender'].Status -ne 'Connected') {
        Write-Log "Defender connector is not connected. Call Connect-Defender first." -Level ERROR
        return [System.Collections.Generic.List[object]]::new()
    }

    $config  = $Script:Connectors['defender'].Config
    $baseUrl = $config.BaseUrl
    $headers = Get-DefenderAuthHeaders
    if (-not $headers) {
        return [System.Collections.Generic.List[object]]::new()
    }

    $entries = [System.Collections.Generic.List[object]]::new()
    $idx     = 0

    $uri = "${baseUrl}/vulnerabilities/machinesVulnerabilities"
    if ($Severity) {
        $filter = "vulnerabilitySeverityLevel eq '$Severity'"
        $uri += "?`$filter=$([System.Uri]::EscapeDataString($filter))"
    }

    try {
        Write-Log "Pulling Defender vulnerability data $(if($Severity){"(severity=$Severity) "})..." -Level INFO

        $pageCount = 0
        $maxPages  = 100

        do {
            $pageCount++
            $response = Invoke-RestWithRetry -Uri $uri -Method GET `
                -Headers $headers -TimeoutSec 60 -MaxRetries 3

            $records = @()
            if ($response.value) {
                $records = $response.value
            } elseif ($response -is [array]) {
                $records = $response
            }

            foreach ($record in $records) {
                $ts = [datetime]::MinValue
                if ($record.publishedOn) {
                    [datetime]::TryParse([string]$record.publishedOn, [ref]$ts) | Out-Null
                } elseif ($record.updatedOn) {
                    [datetime]::TryParse([string]$record.updatedOn, [ref]$ts) | Out-Null
                }

                $sev = if ($record.vulnerabilitySeverityLevel) {
                    [string]$record.vulnerabilitySeverityLevel
                } else { "Low" }

                $level = switch ($sev.ToLower()) {
                    'critical' { "CRITICAL" }
                    'high'     { "ERROR" }
                    'medium'   { "WARNING" }
                    'low'      { "INFO" }
                    default    { "INFO" }
                }

                $cveId           = [string]$record.cveId
                $softwareName    = [string]$record.softwareName
                $softwareVersion = [string]$record.softwareVersion
                $deviceName      = if ($record.deviceName) { [string]$record.deviceName } else { "" }

                $msg = "$cveId - $softwareName $softwareVersion ($sev)"

                $extra = @{
                    CveId                 = $cveId
                    CvssScore             = [string]$record.cvssScore
                    SoftwareName          = $softwareName
                    SoftwareVersion       = $softwareVersion
                    DeviceName            = $deviceName
                    VulnerabilitySeverity = $sev
                    ExploitAvailable      = [string]$record.exploitAvailable
                    RecommendedAction     = [string]$record.recommendedAction
                    SourceFormat          = 'defender-vulnerability'
                    SourceConnector       = 'defender'
                }

                $entries.Add((ConvertTo-LogEntry @{
                    Index     = $idx
                    Timestamp = $ts
                    Level     = $level
                    Source    = "Defender Vulnerability"
                    Host      = $deviceName
                    Message   = $msg
                    RawLine   = ($record | ConvertTo-Json -Compress -Depth 5)
                    Extra     = $extra
                }))
                $idx++
            }

            # Follow pagination
            $uri = $null
            if ($response.'@odata.nextLink') {
                $uri = $response.'@odata.nextLink'
            }
        } while ($uri -and $pageCount -lt $maxPages)

        Write-Log "Defender: total $($entries.Count) vulnerabilities retrieved" -Level INFO
    } catch {
        Write-Log "Defender vulnerability retrieval failed: $($_.Exception.Message)" -Level ERROR
    }

    return $entries
}
