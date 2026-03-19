# ═══════════════════════════════════════════════════════════════════════════════
# OSTICKET API CONNECTOR -- Create and query tickets from triage results
# ═══════════════════════════════════════════════════════════════════════════════

function Connect-OsTicket {
    <#
    .SYNOPSIS
        Tests connectivity to an osTicket instance and registers the connector.
    .OUTPUTS
        $true on success, $false on failure.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [string]$ApiKey
    )

    # Retrieve API key from Credential Manager if not provided
    if (-not $ApiKey) {
        $stored = Get-StoredApiCredential -TargetName "InvokeLogParser_OsTicket_$Server"
        if (-not $stored) {
            Write-Log "No API key available for osTicket $Server" -Level ERROR
            return $false
        }
        $ApiKey = $stored.Token
    }

    # Normalize server URL
    $baseUrl = $Server.TrimEnd('/')
    if ($baseUrl -notmatch '^https?://') {
        $baseUrl = "https://$baseUrl"
    }

    $headers = @{
        'X-API-Key' = $ApiKey
    }

    try {
        Write-Log "Testing osTicket connectivity at $baseUrl ..." -Level INFO

        # Test with a lightweight request -- osTicket REST API varies by version
        # Try the tickets endpoint with a limit of 1
        $testUri = "$baseUrl/api/tickets.json"

        # osTicket API may return 405 for GET on some versions, which is still
        # a sign the API is reachable. We accept any non-connection-failure.
        $testSuccess = $false
        try {
            $response = Invoke-RestWithRetry -Uri $testUri -Method GET `
                -Headers $headers -TimeoutSec 15 -MaxRetries 2
            $testSuccess = $true
        } catch {
            $statusCode = 0
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            # 405 (Method Not Allowed) or 501 means the API endpoint exists
            # but does not support GET -- that is acceptable for a connection test
            if ($statusCode -eq 405 -or $statusCode -eq 501) {
                $testSuccess = $true
                Write-Log "osTicket API reachable (GET returned $statusCode, POST should work)" -Level INFO
            }
            # 403 means reachable but bad key
            elseif ($statusCode -eq 403) {
                Write-Log "osTicket API reachable but returned 403 Forbidden -- check API key" -Level WARNING
                $testSuccess = $true  # endpoint is reachable, register anyway
            }
            else {
                throw
            }
        }

        if (-not $testSuccess) {
            Write-Log "osTicket connection test failed" -Level ERROR
            return $false
        }

        Register-Connector -Id 'osticket' -Name "osTicket ($Server)" -Type 'RestApi' -Config @{
            Server  = $Server
            BaseUrl = $baseUrl
            ApiKey  = $ApiKey
            Headers = $headers
        }
        Set-ConnectorStatus -Id 'osticket' -Status 'Connected'

        Write-Log "osTicket connection successful" -Level INFO
        return $true
    } catch {
        Write-Log "osTicket connection failed: $($_.Exception.Message)" -Level ERROR
        Register-Connector -Id 'osticket' -Name "osTicket ($Server)" -Type 'RestApi' -Config @{
            Server = $Server; BaseUrl = $baseUrl
        }
        Set-ConnectorStatus -Id 'osticket' -Status 'Error' -ErrorMessage $_.Exception.Message
        return $false
    }
}

function New-OsTicketFromTriage {
    <#
    .SYNOPSIS
        Creates a new osTicket ticket from triage analysis results. Includes
        duplicate detection to prevent flooding the ticket system.
    .DESCRIPTION
        Builds an HTML-formatted ticket body containing the triage summary,
        contributing events, and severity assessment. Checks for existing
        duplicate tickets before creating.
    .OUTPUTS
        Ticket number (int) on success, $null on failure or duplicate.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Subject,
        [Parameter(Mandatory = $true)]
        [string]$Body,
        [ValidateSet("low", "normal", "high", "emergency")]
        [string]$Priority = "normal",
        [string]$Department = "",
        [string]$Source = "API",
        [hashtable]$CustomFields = @{}
    )

    # Validate connector
    if (-not $Script:Connectors.ContainsKey('osticket') -or
        $Script:Connectors['osticket'].Status -ne 'Connected') {
        Write-Log "osTicket connector is not connected. Call Connect-OsTicket first." -Level ERROR
        return $null
    }

    # Check for duplicates first
    $isDuplicate = Test-OsTicketDuplicate -Subject $Subject -WithinHours 24
    if ($isDuplicate) {
        Write-Log "Duplicate ticket detected for subject '$Subject' -- skipping creation" -Level WARNING
        return $null
    }

    $config  = $Script:Connectors['osticket'].Config
    $baseUrl = $config.BaseUrl
    $headers = $config.Headers

    # Map priority string to osTicket priority ID
    $priorityMap = @{
        'low'       = 1
        'normal'    = 2
        'high'      = 3
        'emergency' = 4
    }
    $priorityId = if ($priorityMap.ContainsKey($Priority)) { $priorityMap[$Priority] } else { 2 }

    # Build HTML body with triage formatting
    $htmlBody = @"
<div style="font-family: Segoe UI, Tahoma, sans-serif; font-size: 13px;">
<h3 style="color: #333;">Automated Triage Alert</h3>
<p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
<p><strong>Priority:</strong> $($Priority.ToUpper())</p>
<p><strong>Source:</strong> $Source</p>
<hr style="border: 1px solid #ccc;" />
$Body
<hr style="border: 1px solid #ccc;" />
<p style="color: #888; font-size: 11px;">
This ticket was auto-generated by Invoke-LogParser triage engine.
Do not reply to this ticket via email.
</p>
</div>
"@

    # Build the ticket payload
    $ticketPayload = @{
        alert   = $true
        autorespond = $true
        source  = $Source
        name    = "LogParser Triage"
        email   = "logparser@localhost"
        subject = $Subject
        message = "data:text/html,$htmlBody"
        ip      = ""
        priorityId = $priorityId
    }

    if ($Department) {
        $ticketPayload['topicId'] = $Department
    }

    # Add custom fields if provided
    if ($CustomFields.Count -gt 0) {
        foreach ($key in $CustomFields.Keys) {
            $ticketPayload[$key] = $CustomFields[$key]
        }
    }

    $uri = "$baseUrl/api/tickets.json"

    try {
        Write-Log "Creating osTicket: '$Subject' (priority=$Priority) ..." -Level INFO

        $response = Invoke-RestWithRetry -Uri $uri -Method POST `
            -Headers $headers -Body $ticketPayload -TimeoutSec 15 -MaxRetries 2

        # osTicket returns the ticket number as a plain integer on success
        $ticketNumber = $null
        if ($response -is [int] -or $response -is [long]) {
            $ticketNumber = [int]$response
        } elseif ($response -is [string] -and $response -match '^\d+$') {
            $ticketNumber = [int]$response
        } elseif ($response.id) {
            $ticketNumber = [int]$response.id
        } elseif ($response.number) {
            $ticketNumber = [int]$response.number
        }

        if ($ticketNumber) {
            Write-Log "osTicket created: #$ticketNumber -- '$Subject'" -Level INFO

            # Track in connector state for duplicate detection
            if (-not $Script:Connectors['osticket'].Config.ContainsKey('RecentTickets')) {
                $Script:Connectors['osticket'].Config['RecentTickets'] = [System.Collections.Generic.List[object]]::new()
            }
            $Script:Connectors['osticket'].Config['RecentTickets'].Add(@{
                Number    = $ticketNumber
                Subject   = $Subject
                CreatedAt = Get-Date
            })

            return $ticketNumber
        } else {
            Write-Log "osTicket creation returned unexpected response: $($response | ConvertTo-Json -Compress -Depth 3)" -Level WARNING
            return $null
        }
    } catch {
        Write-Log "osTicket creation failed: $($_.Exception.Message)" -Level ERROR
        return $null
    }
}

function Get-OsTicketStatus {
    <#
    .SYNOPSIS
        Retrieves the status of an existing osTicket ticket by number.
    .OUTPUTS
        Ticket status object or $null on failure.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [int]$TicketNumber
    )

    # Validate connector
    if (-not $Script:Connectors.ContainsKey('osticket') -or
        $Script:Connectors['osticket'].Status -ne 'Connected') {
        Write-Log "osTicket connector is not connected. Call Connect-OsTicket first." -Level ERROR
        return $null
    }

    $config  = $Script:Connectors['osticket'].Config
    $baseUrl = $config.BaseUrl
    $headers = $config.Headers

    $uri = "$baseUrl/api/tickets/$TicketNumber.json"

    try {
        Write-Log "Querying osTicket #$TicketNumber ..." -Level INFO

        $response = Invoke-RestWithRetry -Uri $uri -Method GET `
            -Headers $headers -TimeoutSec 15 -MaxRetries 2

        if (-not $response) {
            Write-Log "osTicket #$TicketNumber not found or empty response" -Level WARNING
            return $null
        }

        $result = [PSCustomObject]@{
            TicketNumber = $TicketNumber
            Subject      = if ($response.subject) { [string]$response.subject } else { "" }
            Status       = if ($response.status) { [string]$response.status } else { "" }
            Priority     = if ($response.priority) { [string]$response.priority } else { "" }
            Department   = if ($response.department) { [string]$response.department } else { "" }
            Created      = if ($response.created) { [string]$response.created } else { "" }
            Updated      = if ($response.updated) { [string]$response.updated } else { "" }
            Closed       = if ($response.closed) { [string]$response.closed } else { "" }
            AssignedTo   = if ($response.assigned) { [string]$response.assigned } else { "" }
        }

        Write-Log "osTicket #$TicketNumber: status=$($result.Status)" -Level INFO
        return $result
    } catch {
        $statusCode = 0
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        if ($statusCode -eq 404) {
            Write-Log "osTicket #$TicketNumber not found (404)" -Level WARNING
        } else {
            Write-Log "osTicket status query failed: $($_.Exception.Message)" -Level ERROR
        }
        return $null
    }
}

function Test-OsTicketDuplicate {
    <#
    .SYNOPSIS
        Checks whether a ticket with a similar subject has been created within
        the specified time window. Uses both in-memory tracking (from recent
        New-OsTicketFromTriage calls) and the osTicket API.
    .DESCRIPTION
        Prevents duplicate ticket creation for ongoing conditions that may
        trigger multiple triage alerts within a short window.
    .OUTPUTS
        $true if a duplicate ticket is likely to exist, $false otherwise.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Subject,
        [int]$WithinHours = 24
    )

    # Step 1: Check in-memory recent ticket list (fast, no API call)
    if ($Script:Connectors.ContainsKey('osticket') -and
        $Script:Connectors['osticket'].Config.ContainsKey('RecentTickets')) {

        $cutoff = (Get-Date).AddHours(-$WithinHours)
        $recentTickets = $Script:Connectors['osticket'].Config['RecentTickets']

        foreach ($ticket in $recentTickets) {
            if ($ticket.CreatedAt -ge $cutoff) {
                # Fuzzy match: check if the subject is substantially similar
                $existing = $ticket.Subject.ToLower().Trim()
                $incoming = $Subject.ToLower().Trim()

                # Exact match
                if ($existing -eq $incoming) {
                    Write-Log "Duplicate detected (in-memory): ticket #$($ticket.Number) '$($ticket.Subject)'" -Level INFO
                    return $true
                }

                # Substring containment (covers subjects with timestamps appended)
                # Strip trailing timestamp patterns from both
                $existingBase = $existing -replace '\s*[\(\[]\d{4}[-/]\d{2}[-/]\d{2}.*$', ''
                $incomingBase = $incoming -replace '\s*[\(\[]\d{4}[-/]\d{2}[-/]\d{2}.*$', ''

                if ($existingBase -eq $incomingBase -and $existingBase.Length -gt 10) {
                    Write-Log "Duplicate detected (in-memory, base match): ticket #$($ticket.Number)" -Level INFO
                    return $true
                }
            }
        }

        # Clean up old entries while we are here
        $cleanedList = [System.Collections.Generic.List[object]]::new()
        foreach ($ticket in $recentTickets) {
            if ($ticket.CreatedAt -ge $cutoff) {
                $cleanedList.Add($ticket)
            }
        }
        $Script:Connectors['osticket'].Config['RecentTickets'] = $cleanedList
    }

    # Step 2: Query the osTicket API for recent tickets with similar subject
    if ($Script:Connectors.ContainsKey('osticket') -and
        $Script:Connectors['osticket'].Status -eq 'Connected') {

        $config  = $Script:Connectors['osticket'].Config
        $baseUrl = $config.BaseUrl
        $headers = $config.Headers

        # Try to search via the API -- not all osTicket versions support search
        try {
            $searchUri = "$baseUrl/api/tickets.json?search=$([System.Uri]::EscapeDataString($Subject))&limit=5"
            $response = Invoke-RestWithRetry -Uri $searchUri -Method GET `
                -Headers $headers -TimeoutSec 10 -MaxRetries 1

            if ($response -and $response -is [array]) {
                $cutoffStr = (Get-Date).AddHours(-$WithinHours).ToString("yyyy-MM-dd HH:mm:ss")
                foreach ($ticket in $response) {
                    $ticketSubject = ""
                    $ticketCreated = ""
                    if ($ticket.subject) { $ticketSubject = [string]$ticket.subject }
                    if ($ticket.created) { $ticketCreated = [string]$ticket.created }

                    if ($ticketSubject.ToLower().Trim() -eq $Subject.ToLower().Trim()) {
                        if ($ticketCreated -and $ticketCreated -ge $cutoffStr) {
                            Write-Log "Duplicate detected (API): '$ticketSubject' created $ticketCreated" -Level INFO
                            return $true
                        }
                    }
                }
            }
        } catch {
            # API search may not be available -- not a critical failure
            Write-Log "osTicket API search unavailable for duplicate check: $($_.Exception.Message)" -Level WARNING
        }
    }

    return $false
}
