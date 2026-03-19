# ═══════════════════════════════════════════════════════════════════════════════
# WINDOWS EVENT LOG CONNECTOR -- Pull events from remote Windows machines
# ═══════════════════════════════════════════════════════════════════════════════

function Connect-WindowsEventLog {
    <#
    .SYNOPSIS
        Tests connectivity to one or more remote Windows machines and verifies
        event log access.
    .OUTPUTS
        Hashtable: @{ Connected = @(); Failed = @(); Credential = $cred }
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ComputerNames,
        [string[]]$LogNames = @("Security", "System", "Application"),
        [pscredential]$Credential = $null
    )

    $connected = [System.Collections.Generic.List[string]]::new()
    $failed    = [System.Collections.Generic.List[string]]::new()

    # Prompt for credential if not supplied and accessing remote machines
    if (-not $Credential) {
        $stored = Get-StoredApiCredential -TargetName "InvokeLogParser_WinEventLog"
        if ($stored) {
            $secPass = ConvertTo-SecureString $stored.Password -AsPlainText -Force
            $Credential = New-Object System.Management.Automation.PSCredential($stored.Username, $secPass)
        }
    }

    foreach ($computer in $ComputerNames) {
        try {
            Write-Log "Testing event log connectivity to $computer ..." -Level INFO
            $splatParams = @{
                LogName     = $LogNames[0]
                MaxEvents   = 1
                ErrorAction = 'Stop'
            }
            # Only add ComputerName for non-local targets
            $isLocal = ($computer -eq $env:COMPUTERNAME) -or
                       ($computer -eq 'localhost') -or
                       ($computer -eq '127.0.0.1') -or
                       ($computer -eq '.')
            if (-not $isLocal) {
                $splatParams['ComputerName'] = $computer
                if ($Credential) {
                    # Get-WinEvent does not accept -Credential natively;
                    # use Invoke-Command to test remote access
                    try {
                        $testResult = Invoke-Command -ComputerName $computer -Credential $Credential -ScriptBlock {
                            param($logName)
                            Get-WinEvent -LogName $logName -MaxEvents 1 -ErrorAction Stop | Select-Object -First 1
                        } -ArgumentList $LogNames[0] -ErrorAction Stop
                        $connected.Add($computer)
                        Write-Log "Connected to $computer (via WinRM)" -Level INFO
                        continue
                    } catch {
                        # Fall through to direct Get-WinEvent attempt
                    }
                }
            }

            $null = Get-WinEvent @splatParams
            $connected.Add($computer)
            Write-Log "Connected to $computer" -Level INFO
        } catch {
            $failed.Add($computer)
            Write-Log "Failed to connect to ${computer}: $($_.Exception.Message)" -Level ERROR
        }
    }

    # Register connector
    Register-Connector -Id 'windows-eventlog' -Name 'Windows Event Log' -Type 'WindowsEventLog' -Config @{
        ComputerNames = $ComputerNames
        LogNames      = $LogNames
        Credential    = $Credential
    }

    if ($connected.Count -gt 0) {
        Set-ConnectorStatus -Id 'windows-eventlog' -Status 'Connected'
    } else {
        Set-ConnectorStatus -Id 'windows-eventlog' -Status 'Error' -ErrorMessage 'No computers accessible'
    }

    return @{
        Connected  = $connected.ToArray()
        Failed     = $failed.ToArray()
        Credential = $Credential
    }
}

function Get-RemoteEvents {
    <#
    .SYNOPSIS
        Pulls Windows events from remote computers and converts them to the
        standard LogEntry format (same schema as the WindowsEvtx parser).
    .OUTPUTS
        [List[object]] of ConvertTo-LogEntry entries.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ComputerNames,
        [string[]]$LogNames = @("Security"),
        [int[]]$EventIds = @(),
        [datetime]$Since = (Get-Date).AddHours(-24),
        [int]$MaxEvents = 10000,
        [pscredential]$Credential = $null
    )

    # Check for cached results
    $cached = Get-ConnectorCache -Id 'windows-eventlog'
    if ($cached) { return $cached }

    Set-ConnectorStatus -Id 'windows-eventlog' -Status 'Pulling'

    $entries = [System.Collections.Generic.List[object]]::new()
    $idx = 0

    foreach ($computer in $ComputerNames) {
        foreach ($logName in $LogNames) {
            try {
                Write-Log "Pulling $logName events from $computer since $($Since.ToString('yyyy-MM-dd HH:mm:ss')) ..." -Level INFO

                $filterHash = @{
                    LogName   = $logName
                    StartTime = $Since
                }
                if ($EventIds.Count -gt 0) {
                    $filterHash['ID'] = $EventIds
                }

                $splatParams = @{
                    FilterHashtable = $filterHash
                    MaxEvents       = $MaxEvents
                    ErrorAction     = 'Stop'
                }

                $isLocal = ($computer -eq $env:COMPUTERNAME) -or
                           ($computer -eq 'localhost') -or
                           ($computer -eq '127.0.0.1') -or
                           ($computer -eq '.')

                $events = $null
                if (-not $isLocal -and $Credential) {
                    # Remote with explicit credential -- use Invoke-Command
                    try {
                        $events = Invoke-Command -ComputerName $computer -Credential $Credential -ScriptBlock {
                            param($fh, $max)
                            Get-WinEvent -FilterHashtable $fh -MaxEvents $max -ErrorAction Stop
                        } -ArgumentList $filterHash, $MaxEvents -ErrorAction Stop
                    } catch {
                        Write-Log "WinRM pull failed for ${computer}/${logName}, trying direct: $($_.Exception.Message)" -Level WARNING
                        $splatParams['ComputerName'] = $computer
                        $events = Get-WinEvent @splatParams
                    }
                } else {
                    if (-not $isLocal) {
                        $splatParams['ComputerName'] = $computer
                    }
                    $events = Get-WinEvent @splatParams
                }

                if (-not $events) { continue }

                foreach ($evt in $events) {
                    $extra = @{
                        EventID         = $evt.Id
                        ProviderName    = $evt.ProviderName
                        LogName         = $evt.LogName
                        SourceComputer  = $computer
                        SourceFormat    = 'windows-evtx'
                    }

                    # EventId annotation enrichment
                    if ($evt.Id -and $Script:State -and $Script:State.EventIdLookup -and
                        $Script:State.EventIdLookup.ContainsKey([int]$evt.Id)) {
                        $extra['EventIdAnnotation'] = $Script:State.EventIdLookup[[int]$evt.Id]
                    }

                    # MITRE ATT&CK enrichment
                    if ($Script:MitreEventIdMap -and $Script:MitreEventIdMap.ContainsKey([int]$evt.Id)) {
                        $mitre = $Script:MitreEventIdMap[[int]$evt.Id]
                        $extra['MitreTechniqueId']   = $mitre.TechniqueId
                        $extra['MitreTechniqueName'] = $mitre.TechniqueName
                        $extra['MitreTactic']        = $mitre.Tactic
                        $extra['MitreAnnotation']    = "MITRE: $($mitre.TechniqueId) - $($mitre.TechniqueName) ($($mitre.Tactic))"
                    }

                    # Extract EventData / UserData from XML
                    try {
                        $evtXml = [xml]$evt.ToXml()
                        $eventData = $evtXml.Event.EventData
                        if ($eventData) {
                            foreach ($data in $eventData.Data) {
                                if ($data.Name) { $extra[$data.Name] = $data.'#text' }
                            }
                        }
                        $userData = $evtXml.Event.UserData
                        if ($userData) {
                            foreach ($child in $userData.ChildNodes) {
                                foreach ($sub in $child.ChildNodes) {
                                    if ($sub.LocalName -and $sub.InnerText) {
                                        $extra[$sub.LocalName] = $sub.InnerText
                                    }
                                }
                            }
                        }
                    } catch { }

                    $level = switch ($evt.Level) {
                        1 { "CRITICAL" }
                        2 { "ERROR" }
                        3 { "WARNING" }
                        4 { "INFO" }
                        5 { "DEBUG" }
                        0 { if ($evt.Id -eq 1102) { "WARNING" } else { "INFO" } }
                        default { "INFO" }
                    }

                    $entries.Add((ConvertTo-LogEntry @{
                        Index   = $idx
                        Timestamp = $evt.TimeCreated
                        Level   = $level
                        Source  = $evt.ProviderName
                        Host    = $computer
                        Message = $evt.Message
                        RawLine = $evt.ToXml()
                        Extra   = $extra
                    }))
                    $idx++
                }

                Write-Log "Pulled $($events.Count) events from ${computer}/$logName" -Level INFO
            } catch {
                Write-Log "Failed to pull events from ${computer}/${logName}: $($_.Exception.Message)" -Level ERROR
            }
        }
    }

    if ($entries.Count -gt 0) {
        Set-ConnectorStatus -Id 'windows-eventlog' -Status 'Connected'
        Set-ConnectorCache -Id 'windows-eventlog' -Data $entries
    } else {
        Set-ConnectorStatus -Id 'windows-eventlog' -Status 'Connected'
    }

    Write-Log "Total remote events pulled: $($entries.Count)" -Level INFO
    return $entries
}
