# Hyper-V Event Log (.evtx) Parser

Register-Parser -Id "hyperv-event" -Name "Hyper-V Event Log" -Extensions @(".evtx") -SupportsTail $false `
    -AutoDetect {
        param($firstLines, $filePath)
        if ([System.IO.Path]::GetExtension($filePath).ToLower() -ne '.evtx') { return $false }
        # Use filename heuristic to avoid Get-WinEvent overhead in AutoDetect
        $fileName = [System.IO.Path]::GetFileNameWithoutExtension($filePath)
        if ($fileName -match 'hyper|VMMS') {
            return $true
        }
        return $false
    } `
    -Parse {
        param($filePath, $encoding)
        $entries = [System.Collections.Generic.List[object]]::new()
        $idx = 0
        try {
            $events = Get-WinEvent -Path $filePath -ErrorAction Stop
            foreach ($evt in $events) {
                # Filter to Hyper-V providers
                if ($evt.ProviderName -notlike 'Microsoft-Windows-Hyper-V*') { continue }

                $extra = @{
                    EventID        = $evt.Id
                    ProviderName   = $evt.ProviderName
                    LogName        = $evt.LogName
                    VmName         = ""
                    VmId           = ""
                }

                if ($evt.Id -and $Script:State.EventIdLookup.ContainsKey([int]$evt.Id)) {
                    $extra['EventIdAnnotation'] = $Script:State.EventIdLookup[[int]$evt.Id]
                }

                # Extract EventData fields from XML
                $vmName = ""
                $vmId = ""
                try {
                    $evtXml = [xml]$evt.ToXml()
                    $eventData = $evtXml.Event.EventData
                    if ($eventData) {
                        foreach ($data in $eventData.Data) {
                            if ($data.Name) {
                                $extra[$data.Name] = $data.'#text'
                                if ($data.Name -eq 'VmName') { $vmName = $data.'#text' }
                                if ($data.Name -eq 'VmId') { $vmId = $data.'#text' }
                            }
                        }
                    }
                    $userData = $evtXml.Event.UserData
                    if ($userData) {
                        foreach ($child in $userData.ChildNodes) {
                            foreach ($sub in $child.ChildNodes) {
                                if ($sub.LocalName -and $sub.InnerText) {
                                    $extra[$sub.LocalName] = $sub.InnerText
                                    if ($sub.LocalName -eq 'VmName') { $vmName = $sub.InnerText }
                                    if ($sub.LocalName -eq 'VmId') { $vmId = $sub.InnerText }
                                }
                            }
                        }
                    }
                } catch { }

                $extra['VmName'] = $vmName
                $extra['VmId'] = $vmId

                $level = switch ($evt.Level) {
                    1 { "CRITICAL" } 2 { "ERROR" } 3 { "WARNING" } 4 { "INFO" } 5 { "DEBUG" }
                    0 { if ($evt.Id -eq 1102) { "WARNING" } else { "INFO" } }
                    default { "INFO" }
                }

                $msg = [string]$evt.Message
                if ($vmName) { $msg = "[VM: $vmName] $msg" }

                $entries.Add((ConvertTo-LogEntry @{
                    Index = $idx; Timestamp = $evt.TimeCreated; Level = $level
                    Source = $evt.ProviderName; Host = $evt.MachineName
                    Message = $msg; RawLine = $evt.ToXml(); Extra = $extra
                }))
                $idx++
            }
        } catch {
            Write-Log "Hyper-V EVTX parse error: $_" -Level ERROR
        }
        return $entries
    }
