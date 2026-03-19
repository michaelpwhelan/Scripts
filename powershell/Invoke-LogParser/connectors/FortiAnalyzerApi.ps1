# ═══════════════════════════════════════════════════════════════════════════════
# FORTIANALYZER API CONNECTOR -- Pull logs from FortiAnalyzer via JSON-RPC
# ═══════════════════════════════════════════════════════════════════════════════

function Connect-FortiAnalyzer {
    <#
    .SYNOPSIS
        Authenticates to a FortiAnalyzer appliance via JSON-RPC and stores the
        session token for subsequent API calls.
    .OUTPUTS
        $true on success, $false on failure.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [int]$Port = 443,
        [string]$Username,
        [System.Security.SecureString]$Password,
        [string]$Adom = "root"
    )

    # Retrieve credentials from Credential Manager if not explicitly provided
    if (-not $Username -or -not $Password) {
        $stored = Get-StoredApiCredential -TargetName "InvokeLogParser_FortiAnalyzer_$Server"
        if (-not $stored) {
            Write-Log "No credentials available for FortiAnalyzer $Server" -Level ERROR
            return $false
        }
        if (-not $Username) { $Username = $stored.Username }
        if (-not $Password) {
            $Password = ConvertTo-SecureString $stored.Password -AsPlainText -Force
        }
    }

    $baseUrl = "https://${Server}:${Port}/jsonrpc"
    $plainPass = ConvertTo-PlainText -SecureString $Password

    $loginBody = @{
        id      = 1
        method  = "exec"
        params  = @(
            @{
                url  = "/sys/login/user"
                data = @{
                    user   = $Username
                    passwd = $plainPass
                }
            }
        )
    }

    try {
        Write-Log "Authenticating to FortiAnalyzer $Server as $Username ..." -Level INFO

        $response = Invoke-RestWithRetry -Uri $baseUrl -Method POST `
            -Body $loginBody -TimeoutSec 15 -MaxRetries 2 -SkipCertificateCheck

        # FortiAnalyzer returns session ID in result
        $sessionId = $null
        if ($response.session) {
            $sessionId = $response.session
        } elseif ($response.result -and $response.result[0].status.code -eq 0) {
            $sessionId = $response.session
        }

        if (-not $sessionId) {
            $statusMsg = ""
            if ($response.result -and $response.result[0].status) {
                $statusMsg = $response.result[0].status.message
            }
            Write-Log "FortiAnalyzer authentication failed: $statusMsg" -Level ERROR
            return $false
        }

        Register-Connector -Id 'fortianalyzer' -Name "FortiAnalyzer ($Server)" -Type 'RestApi' -Config @{
            Server    = $Server
            Port      = $Port
            BaseUrl   = $baseUrl
            SessionId = $sessionId
            Adom      = $Adom
            Username  = $Username
        }
        Set-ConnectorStatus -Id 'fortianalyzer' -Status 'Connected'

        Write-Log "FortiAnalyzer authentication successful (session: $($sessionId.Substring(0, [Math]::Min(8, $sessionId.Length)))...)" -Level INFO
        return $true
    } catch {
        Write-Log "FortiAnalyzer connection failed: $($_.Exception.Message)" -Level ERROR
        Register-Connector -Id 'fortianalyzer' -Name "FortiAnalyzer ($Server)" -Type 'RestApi' -Config @{
            Server = $Server; Port = $Port
        }
        Set-ConnectorStatus -Id 'fortianalyzer' -Status 'Error' -ErrorMessage $_.Exception.Message
        return $false
    }
}

function Get-FortiAnalyzerLogs {
    <#
    .SYNOPSIS
        Queries FortiAnalyzer for logs via JSON-RPC with pagination.
        Converts results to the standard LogEntry format (same schema as
        FortiGateKV parser output).
    .OUTPUTS
        [List[object]] of ConvertTo-LogEntry entries.
    #>
    param(
        [string]$Device = "",
        [ValidateSet("traffic", "event", "utm", "dns", "virus", "webfilter",
                     "ips", "app-ctrl", "emailfilter", "dlp", "anomaly")]
        [string]$LogType = "traffic",
        [datetime]$Since = (Get-Date).AddHours(-24),
        [int]$Limit = 10000,
        [string]$Filter = ""
    )

    # Validate connector
    if (-not $Script:Connectors.ContainsKey('fortianalyzer') -or
        $Script:Connectors['fortianalyzer'].Status -ne 'Connected') {
        Write-Log "FortiAnalyzer connector is not connected. Call Connect-FortiAnalyzer first." -Level ERROR
        return [System.Collections.Generic.List[object]]::new()
    }

    # Check cache
    $cacheKey = "fortianalyzer_${LogType}_${Device}"
    $cached = Get-ConnectorCache -Id 'fortianalyzer'
    if ($cached) { return $cached }

    Set-ConnectorStatus -Id 'fortianalyzer' -Status 'Pulling'

    $config    = $Script:Connectors['fortianalyzer'].Config
    $baseUrl   = $config.BaseUrl
    $sessionId = $config.SessionId
    $adom      = $config.Adom

    $entries = [System.Collections.Generic.List[object]]::new()
    $idx     = 0
    $offset  = 0
    $pageSize = 1000  # FortiAnalyzer max per page

    $sinceStr = $Since.ToString("yyyy-MM-dd HH:mm:ss")

    try {
        Write-Log "Pulling FortiAnalyzer $LogType logs since $sinceStr (device: $(if($Device){$Device}else{'all'})) ..." -Level INFO

        do {
            $requestBody = @{
                id      = 2
                method  = "get"
                session = $sessionId
                params  = @(
                    @{
                        url    = "/logview/adom/$adom/logfiles/data"
                        apiver = 3
                        limit  = $pageSize
                        offset = $offset
                        filter = ""
                        logtype = $LogType
                        "time-range" = @{
                            start = $sinceStr
                            end   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        }
                    }
                )
            }

            # Apply device filter
            if ($Device) {
                $requestBody.params[0]['device'] = @(@{ devid = $Device })
            }

            # Apply custom filter
            if ($Filter) {
                $requestBody.params[0]['filter'] = $Filter
            }

            $response = Invoke-RestWithRetry -Uri $baseUrl -Method POST `
                -Body $requestBody -TimeoutSec 60 -MaxRetries 3 -SkipCertificateCheck

            $records = @()
            $totalCount = 0

            if ($response.result -and $response.result[0].data) {
                $records = $response.result[0].data
                if ($response.result[0].'total-count') {
                    $totalCount = $response.result[0].'total-count'
                }
            } elseif ($response.result -and $response.result[0].status.code -ne 0) {
                $errMsg = $response.result[0].status.message
                Write-Log "FortiAnalyzer query error: $errMsg" -Level ERROR
                break
            }

            if (-not $records -or $records.Count -eq 0) { break }

            foreach ($record in $records) {
                # Build timestamp
                $ts = [datetime]::MinValue
                if ($record.date -and $record.time) {
                    [datetime]::TryParse("$($record.date) $($record.time)", [ref]$ts) | Out-Null
                } elseif ($record.itime) {
                    $epoch = $record.itime -as [long]
                    if ($epoch -gt 0) {
                        $ts = [DateTimeOffset]::FromUnixTimeSeconds($epoch).DateTime
                    }
                }

                # Map Fortinet level
                $fgLevel = if ($record.level) { $record.level.ToString().ToLower() } else { "" }
                $level = switch -Wildcard ($fgLevel) {
                    "emergency"   { "CRITICAL" }
                    "alert"       { "CRITICAL" }
                    "critical"    { "CRITICAL" }
                    "error"       { "ERROR" }
                    "warning"     { "WARNING" }
                    "notice"      { "INFO" }
                    "information" { "INFO" }
                    "debug"       { "DEBUG" }
                    default {
                        $action = if ($record.action) { $record.action.ToString().ToLower() } else { '' }
                        if ($action -in @('deny', 'block', 'dropped')) { "ERROR" }
                        elseif ($action -eq 'timeout') { "WARNING" }
                        else { "INFO" }
                    }
                }

                # Build extra hashtable (all KV fields)
                $extra = @{
                    SourceComputer = $config.Server
                    SourceFormat   = 'fortigate-kv'
                    SourceConnector = 'fortianalyzer'
                }
                if ($record -is [PSCustomObject]) {
                    foreach ($prop in $record.PSObject.Properties) {
                        $extra[$prop.Name] = [string]$prop.Value
                    }
                }

                # Build a human-readable message based on log type
                $msg = ""
                if ($LogType -eq 'traffic') {
                    $parts = [System.Collections.Generic.List[string]]::new()
                    if ($record.action) { $parts.Add([string]$record.action) }
                    if ($record.srcip)  { $parts.Add("srcip=$($record.srcip)") }
                    if ($record.dstip)  { $parts.Add("dstip=$($record.dstip)") }
                    if ($record.dstport) { $parts.Add("dstport=$($record.dstport)") }
                    if ($record.policyid) { $parts.Add("policy=$($record.policyid)") }
                    $msg = $parts -join ' '
                } elseif ($record.msg) {
                    $msg = [string]$record.msg
                } elseif ($record.action) {
                    $msg = [string]$record.action
                } else {
                    $msg = ($record | ConvertTo-Json -Compress -Depth 3)
                    if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) }
                }

                $source = if ($record.devname) { [string]$record.devname }
                          elseif ($record.srcip) { [string]$record.srcip }
                          else { $config.Server }

                $entries.Add((ConvertTo-LogEntry @{
                    Index     = $idx
                    Timestamp = $ts
                    Level     = $level
                    Source    = $source
                    Host      = if ($record.devname) { [string]$record.devname } else { "" }
                    Message   = $msg
                    RawLine   = ($record | ConvertTo-Json -Compress -Depth 5)
                    Extra     = $extra
                }))
                $idx++
            }

            $offset += $records.Count
            Write-Log "FortiAnalyzer: fetched $offset / $(if($totalCount){$totalCount}else{'?'}) records" -Level INFO

            # Stop if we have reached our limit or exhausted results
            if ($idx -ge $Limit) { break }
            if ($records.Count -lt $pageSize) { break }

        } while ($true)

        Set-ConnectorStatus -Id 'fortianalyzer' -Status 'Connected'
        if ($entries.Count -gt 0) {
            Set-ConnectorCache -Id 'fortianalyzer' -Data $entries
        }

        Write-Log "FortiAnalyzer: total $($entries.Count) log entries retrieved" -Level INFO
    } catch {
        Write-Log "FortiAnalyzer log retrieval failed: $($_.Exception.Message)" -Level ERROR
        Set-ConnectorStatus -Id 'fortianalyzer' -Status 'Error' -ErrorMessage $_.Exception.Message

        # Check for session expiry and attempt re-auth
        if ($_.Exception.Message -match 'session.*expir|unauthorized|invalid session') {
            Write-Log "FortiAnalyzer session may have expired -- please re-authenticate with Connect-FortiAnalyzer" -Level WARNING
        }
    }

    return $entries
}

function Disconnect-FortiAnalyzer {
    <#
    .SYNOPSIS
        Logs out of the FortiAnalyzer session and cleans up the connector.
    #>
    if (-not $Script:Connectors.ContainsKey('fortianalyzer') -or
        -not $Script:Connectors['fortianalyzer'].Config.SessionId) {
        Write-Log "No active FortiAnalyzer session to disconnect" -Level WARNING
        return
    }

    $config    = $Script:Connectors['fortianalyzer'].Config
    $baseUrl   = $config.BaseUrl
    $sessionId = $config.SessionId

    $logoutBody = @{
        id      = 3
        method  = "exec"
        session = $sessionId
        params  = @(
            @{
                url = "/sys/logout"
            }
        )
    }

    try {
        $null = Invoke-RestWithRetry -Uri $baseUrl -Method POST `
            -Body $logoutBody -TimeoutSec 10 -MaxRetries 1 -SkipCertificateCheck
        Write-Log "FortiAnalyzer session closed" -Level INFO
    } catch {
        Write-Log "FortiAnalyzer logout request failed (session may have already expired): $($_.Exception.Message)" -Level WARNING
    }

    Set-ConnectorStatus -Id 'fortianalyzer' -Status 'Disconnected'
    $Script:Connectors['fortianalyzer'].Config.SessionId = $null
}
