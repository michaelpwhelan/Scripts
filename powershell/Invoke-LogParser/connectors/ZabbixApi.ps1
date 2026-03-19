# ═══════════════════════════════════════════════════════════════════════════════
# ZABBIX API CONNECTOR -- Pull problems and triggers from Zabbix monitoring
# ═══════════════════════════════════════════════════════════════════════════════

function Connect-Zabbix {
    <#
    .SYNOPSIS
        Authenticates to a Zabbix server via the JSON-RPC API (user.login) and
        stores the auth token for subsequent calls.
    .OUTPUTS
        $true on success, $false on failure.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [string]$Username,
        [System.Security.SecureString]$Password
    )

    # Retrieve credentials from Credential Manager if not explicitly provided
    if (-not $Username -or -not $Password) {
        $stored = Get-StoredApiCredential -TargetName "InvokeLogParser_Zabbix_$Server"
        if (-not $stored) {
            Write-Log "No credentials available for Zabbix $Server" -Level ERROR
            return $false
        }
        if (-not $Username) { $Username = $stored.Username }
        if (-not $Password) {
            $Password = ConvertTo-SecureString $stored.Password -AsPlainText -Force
        }
    }

    # Normalize server URL
    $apiUrl = $Server.TrimEnd('/')
    if ($apiUrl -notmatch '/api_jsonrpc\.php$') {
        $apiUrl = "$apiUrl/api_jsonrpc.php"
    }
    if ($apiUrl -notmatch '^https?://') {
        $apiUrl = "https://$apiUrl"
    }

    $plainPass = ConvertTo-PlainText -SecureString $Password

    $loginBody = @{
        jsonrpc = "2.0"
        method  = "user.login"
        params  = @{
            user     = $Username
            password = $plainPass
        }
        id = 1
    }

    try {
        Write-Log "Authenticating to Zabbix at $apiUrl as $Username ..." -Level INFO

        $response = Invoke-RestWithRetry -Uri $apiUrl -Method POST `
            -Body $loginBody -TimeoutSec 15 -MaxRetries 2

        if ($response.error) {
            $errMsg = "$($response.error.code): $($response.error.message) - $($response.error.data)"
            Write-Log "Zabbix authentication failed: $errMsg" -Level ERROR
            return $false
        }

        $authToken = $response.result
        if (-not $authToken) {
            Write-Log "Zabbix authentication returned empty token" -Level ERROR
            return $false
        }

        Register-Connector -Id 'zabbix' -Name "Zabbix ($Server)" -Type 'RestApi' -Config @{
            Server    = $Server
            ApiUrl    = $apiUrl
            AuthToken = $authToken
            Username  = $Username
        }
        Set-ConnectorStatus -Id 'zabbix' -Status 'Connected'

        Write-Log "Zabbix authentication successful" -Level INFO
        return $true
    } catch {
        Write-Log "Zabbix connection failed: $($_.Exception.Message)" -Level ERROR
        Register-Connector -Id 'zabbix' -Name "Zabbix ($Server)" -Type 'RestApi' -Config @{
            Server = $Server; ApiUrl = $apiUrl
        }
        Set-ConnectorStatus -Id 'zabbix' -Status 'Error' -ErrorMessage $_.Exception.Message
        return $false
    }
}

function Get-ZabbixProblems {
    <#
    .SYNOPSIS
        Retrieves current and recent problems from Zabbix with host resolution.
        Converts results to the standard LogEntry format (same schema as
        ZabbixExport parser output).
    .OUTPUTS
        [List[object]] of ConvertTo-LogEntry entries.
    #>
    param(
        [datetime]$Since = (Get-Date).AddHours(-24),
        [ValidateRange(0, 5)]
        [int]$MinSeverity = 0,
        [switch]$IncludeResolved
    )

    # Validate connector
    if (-not $Script:Connectors.ContainsKey('zabbix') -or
        $Script:Connectors['zabbix'].Status -ne 'Connected') {
        Write-Log "Zabbix connector is not connected. Call Connect-Zabbix first." -Level ERROR
        return [System.Collections.Generic.List[object]]::new()
    }

    # Check cache
    $cached = Get-ConnectorCache -Id 'zabbix'
    if ($cached) { return $cached }

    Set-ConnectorStatus -Id 'zabbix' -Status 'Pulling'

    $config    = $Script:Connectors['zabbix'].Config
    $apiUrl    = $config.ApiUrl
    $authToken = $config.AuthToken

    $entries = [System.Collections.Generic.List[object]]::new()
    $idx     = 0

    # Zabbix severity name mapping (mirrors ZabbixExport parser)
    $severityNames = @{
        0 = "Not classified"
        1 = "Information"
        2 = "Warning"
        3 = "Average"
        4 = "High"
        5 = "Disaster"
    }

    # Convert Since to Unix epoch
    $sinceEpoch = [int][double]::Parse(
        (New-TimeSpan -Start ([datetime]'1970-01-01T00:00:00Z') -End $Since.ToUniversalTime()).TotalSeconds.ToString()
    )

    try {
        Write-Log "Pulling Zabbix problems since $($Since.ToString('yyyy-MM-dd HH:mm:ss')) (severity >= $MinSeverity) ..." -Level INFO

        # Step 1: Get problems
        $problemParams = @{
            time_from           = $sinceEpoch
            severities          = @($MinSeverity..5)
            selectAcknowledges  = "extend"
            selectTags          = "extend"
            sortfield           = @("eventid")
            sortorder           = "DESC"
            limit               = 10000
            output              = "extend"
            recent              = $true
        }

        if (-not $IncludeResolved) {
            # Only unresolved problems (value=1 means PROBLEM active)
            # But include recently resolved in the time window for visibility
            $problemParams['suppressed'] = $false
        }

        $problemBody = @{
            jsonrpc = "2.0"
            method  = "problem.get"
            params  = $problemParams
            auth    = $authToken
            id      = 2
        }

        $problemResponse = Invoke-RestWithRetry -Uri $apiUrl -Method POST `
            -Body $problemBody -TimeoutSec 30 -MaxRetries 3

        if ($problemResponse.error) {
            $errMsg = "$($problemResponse.error.code): $($problemResponse.error.message)"
            Write-Log "Zabbix problem.get error: $errMsg" -Level ERROR
            Set-ConnectorStatus -Id 'zabbix' -Status 'Error' -ErrorMessage $errMsg
            return $entries
        }

        $problems = $problemResponse.result
        if (-not $problems -or $problems.Count -eq 0) {
            Write-Log "No Zabbix problems found in the specified time range" -Level INFO
            Set-ConnectorStatus -Id 'zabbix' -Status 'Connected'
            return $entries
        }

        Write-Log "Retrieved $($problems.Count) problems, resolving host names ..." -Level INFO

        # Step 2: Collect trigger IDs for hostname resolution
        $triggerIds = @($problems | ForEach-Object {
            if ($_.objectid) { $_.objectid }
        } | Sort-Object -Unique)

        # Step 3: Get triggers with host info
        $hostMap = @{}  # triggerid -> hostname
        if ($triggerIds.Count -gt 0) {
            $triggerBody = @{
                jsonrpc = "2.0"
                method  = "trigger.get"
                params  = @{
                    triggerids  = $triggerIds
                    selectHosts = @("hostid", "host", "name")
                    output      = @("triggerid", "description")
                }
                auth = $authToken
                id   = 3
            }

            try {
                $triggerResponse = Invoke-RestWithRetry -Uri $apiUrl -Method POST `
                    -Body $triggerBody -TimeoutSec 30 -MaxRetries 2

                if ($triggerResponse.result) {
                    foreach ($trigger in $triggerResponse.result) {
                        $hostname = ""
                        if ($trigger.hosts -and $trigger.hosts.Count -gt 0) {
                            $hostname = if ($trigger.hosts[0].name) {
                                $trigger.hosts[0].name
                            } else {
                                $trigger.hosts[0].host
                            }
                        }
                        $hostMap[$trigger.triggerid] = $hostname
                    }
                }
            } catch {
                Write-Log "Zabbix trigger/host resolution failed: $($_.Exception.Message)" -Level WARNING
            }
        }

        # Step 4: Convert problems to LogEntry format
        foreach ($problem in $problems) {
            $ts = [datetime]::MinValue
            if ($problem.clock) {
                $epoch = $problem.clock -as [long]
                if ($epoch -gt 0) {
                    $ts = [DateTimeOffset]::FromUnixTimeSeconds($epoch).DateTime
                }
            }

            $sevNum = $problem.severity -as [int]
            $level = switch ($sevNum) {
                5 { "CRITICAL" }
                4 { "ERROR" }
                3 { "WARNING" }
                2 { "WARNING" }
                1 { "INFO" }
                0 { "DEBUG" }
                default { "INFO" }
            }

            $severityName = if ($severityNames.ContainsKey($sevNum)) {
                $severityNames[$sevNum]
            } else { "Unknown" }

            $hostName = ""
            if ($problem.objectid -and $hostMap.ContainsKey($problem.objectid)) {
                $hostName = $hostMap[$problem.objectid]
            }

            $triggerDesc = [string]$problem.name

            # Duration calculation
            $duration = ""
            if ($problem.r_clock) {
                $startEpoch = $problem.clock -as [long]
                $endEpoch   = $problem.r_clock -as [long]
                if ($startEpoch -gt 0 -and $endEpoch -gt 0 -and $endEpoch -gt $startEpoch) {
                    $span = [TimeSpan]::FromSeconds($endEpoch - $startEpoch)
                    $duration = "{0:hh\:mm\:ss}" -f $span
                }
            }

            $acknowledged = "No"
            if ($problem.acknowledged -eq "1") {
                $acknowledged = "Yes"
            }

            # Tags as comma-separated string
            $tagStr = ""
            if ($problem.tags -and $problem.tags.Count -gt 0) {
                $tagStr = ($problem.tags | ForEach-Object {
                    "$($_.tag)=$(if($_.value){$_.value}else{''})"
                }) -join ", "
            }

            $msg = "[$severityName] $hostName - $triggerDesc"

            $extra = @{
                HostName           = $hostName
                TriggerId          = [string]$problem.objectid
                TriggerDescription = $triggerDesc
                ZabbixSeverity     = $severityName
                Acknowledged       = $acknowledged
                Duration           = $duration
                EventId            = [string]$problem.eventid
                Tags               = $tagStr
                SourceFormat       = 'zabbix-export'
                SourceConnector    = 'zabbix'
            }

            $entries.Add((ConvertTo-LogEntry @{
                Index     = $idx
                Timestamp = $ts
                Level     = $level
                Source    = "Zabbix"
                Host      = $hostName
                Message   = $msg
                RawLine   = ($problem | ConvertTo-Json -Compress -Depth 5)
                Extra     = $extra
            }))
            $idx++
        }

        Set-ConnectorStatus -Id 'zabbix' -Status 'Connected'
        if ($entries.Count -gt 0) {
            Set-ConnectorCache -Id 'zabbix' -Data $entries
        }

        Write-Log "Zabbix: total $($entries.Count) problem entries retrieved" -Level INFO
    } catch {
        Write-Log "Zabbix problem retrieval failed: $($_.Exception.Message)" -Level ERROR
        Set-ConnectorStatus -Id 'zabbix' -Status 'Error' -ErrorMessage $_.Exception.Message
    }

    return $entries
}

function Get-ZabbixTriggers {
    <#
    .SYNOPSIS
        Retrieves current trigger states from Zabbix. Useful for a quick
        overview of firing triggers without full problem history.
    .OUTPUTS
        Array of trigger objects with host information.
    #>
    param(
        [switch]$ActiveOnly
    )

    # Validate connector
    if (-not $Script:Connectors.ContainsKey('zabbix') -or
        $Script:Connectors['zabbix'].Status -ne 'Connected') {
        Write-Log "Zabbix connector is not connected. Call Connect-Zabbix first." -Level ERROR
        return @()
    }

    $config    = $Script:Connectors['zabbix'].Config
    $apiUrl    = $config.ApiUrl
    $authToken = $config.AuthToken

    $severityNames = @{
        0 = "Not classified"; 1 = "Information"; 2 = "Warning"
        3 = "Average"; 4 = "High"; 5 = "Disaster"
    }

    $triggerParams = @{
        output      = "extend"
        selectHosts = @("hostid", "host", "name")
        sortfield   = "priority"
        sortorder   = "DESC"
        limit       = 5000
    }

    if ($ActiveOnly) {
        $triggerParams['only_true']          = 1
        $triggerParams['skipDependent']      = 1
        $triggerParams['monitored']          = 1
        $triggerParams['active']             = 1
        $triggerParams['withUnacknowledgedEvents'] = 0
    }

    $body = @{
        jsonrpc = "2.0"
        method  = "trigger.get"
        params  = $triggerParams
        auth    = $authToken
        id      = 4
    }

    try {
        Write-Log "Pulling Zabbix triggers (ActiveOnly=$ActiveOnly) ..." -Level INFO

        $response = Invoke-RestWithRetry -Uri $apiUrl -Method POST `
            -Body $body -TimeoutSec 30 -MaxRetries 2

        if ($response.error) {
            $errMsg = "$($response.error.code): $($response.error.message)"
            Write-Log "Zabbix trigger.get error: $errMsg" -Level ERROR
            return @()
        }

        $triggers = $response.result
        if (-not $triggers) { return @() }

        $results = [System.Collections.Generic.List[object]]::new()

        foreach ($trigger in $triggers) {
            $hostName = ""
            if ($trigger.hosts -and $trigger.hosts.Count -gt 0) {
                $hostName = if ($trigger.hosts[0].name) {
                    $trigger.hosts[0].name
                } else {
                    $trigger.hosts[0].host
                }
            }

            $sevNum = $trigger.priority -as [int]
            $severityName = if ($severityNames.ContainsKey($sevNum)) {
                $severityNames[$sevNum]
            } else { "Unknown" }

            $results.Add([PSCustomObject]@{
                TriggerId   = $trigger.triggerid
                Host        = $hostName
                Description = $trigger.description
                Severity    = $severityName
                SeverityNum = $sevNum
                Status      = if ($trigger.value -eq "1") { "PROBLEM" } else { "OK" }
                LastChange  = if ($trigger.lastchange) {
                    $epoch = $trigger.lastchange -as [long]
                    if ($epoch -gt 0) { [DateTimeOffset]::FromUnixTimeSeconds($epoch).DateTime } else { $null }
                } else { $null }
            })
        }

        Write-Log "Zabbix: retrieved $($results.Count) triggers" -Level INFO
        return $results
    } catch {
        Write-Log "Zabbix trigger retrieval failed: $($_.Exception.Message)" -Level ERROR
        return @()
    }
}

function Disconnect-Zabbix {
    <#
    .SYNOPSIS
        Logs out of the Zabbix API session.
    #>
    if (-not $Script:Connectors.ContainsKey('zabbix') -or
        -not $Script:Connectors['zabbix'].Config.AuthToken) {
        Write-Log "No active Zabbix session to disconnect" -Level WARNING
        return
    }

    $config    = $Script:Connectors['zabbix'].Config
    $apiUrl    = $config.ApiUrl
    $authToken = $config.AuthToken

    $body = @{
        jsonrpc = "2.0"
        method  = "user.logout"
        params  = @()
        auth    = $authToken
        id      = 5
    }

    try {
        $null = Invoke-RestWithRetry -Uri $apiUrl -Method POST `
            -Body $body -TimeoutSec 10 -MaxRetries 1
        Write-Log "Zabbix session closed" -Level INFO
    } catch {
        Write-Log "Zabbix logout failed: $($_.Exception.Message)" -Level WARNING
    }

    Set-ConnectorStatus -Id 'zabbix' -Status 'Disconnected'
    $Script:Connectors['zabbix'].Config.AuthToken = $null
}
