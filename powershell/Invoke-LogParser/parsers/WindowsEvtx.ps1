# Windows Event Log (.evtx) Parser

Register-Parser -Id "windows-evtx" -Name "Windows Event Log (.evtx)" -Extensions @(".evtx") -SupportsTail $false `
    -AutoDetect {
        param($firstLines, $filePath)
        return ([System.IO.Path]::GetExtension($filePath).ToLower() -eq '.evtx')
    } `
    -Parse {
        param($filePath, $encoding)
        $entries = [System.Collections.Generic.List[object]]::new()
        $idx = 0
        try {
            $events = Get-WinEvent -Path $filePath -ErrorAction Stop
            foreach ($evt in $events) {
                $extra = @{ EventID = $evt.Id; ProviderName = $evt.ProviderName; LogName = $evt.LogName }
                if ($evt.Id -and $Script:State.EventIdLookup.ContainsKey([int]$evt.Id)) {
                    $extra['EventIdAnnotation'] = $Script:State.EventIdLookup[[int]$evt.Id]
                }
                # MITRE ATT&CK enrichment
                if ($Script:MitreEventIdMap -and $Script:MitreEventIdMap.ContainsKey([int]$evt.Id)) {
                    $mitre = $Script:MitreEventIdMap[[int]$evt.Id]
                    $extra['MitreTechniqueId'] = $mitre.TechniqueId
                    $extra['MitreTechniqueName'] = $mitre.TechniqueName
                    $extra['MitreTactic'] = $mitre.Tactic
                    $extra['MitreAnnotation'] = "MITRE: $($mitre.TechniqueId) - $($mitre.TechniqueName) ($($mitre.Tactic))"
                }
                # Extract EventData fields from XML
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
                                if ($sub.LocalName -and $sub.InnerText) { $extra[$sub.LocalName] = $sub.InnerText }
                            }
                        }
                    }
                } catch { }

                $level = switch ($evt.Level) {
                    1 { "CRITICAL" } 2 { "ERROR" } 3 { "WARNING" } 4 { "INFO" } 5 { "DEBUG" }
                    0 { if ($evt.Id -eq 1102) { "WARNING" } else { "INFO" } }
                    default { "INFO" }
                }

                $entries.Add((ConvertTo-LogEntry @{
                    Index = $idx; Timestamp = $evt.TimeCreated; Level = $level
                    Source = $evt.ProviderName; Host = $evt.MachineName
                    Message = $evt.Message; RawLine = $evt.ToXml(); Extra = $extra
                }))
                $idx++
            }
        } catch {
            Write-Log "EVTX parse error: $_" -Level ERROR
        }
        return $entries
    }
