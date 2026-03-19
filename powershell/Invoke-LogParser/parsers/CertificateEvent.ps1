Register-Parser -Id "certificate-event" -Name "Certificate Lifecycle Event" -Extensions @(".evtx", ".csv", ".json") `
    -AutoDetect {
        param($firstLines, $filePath)
        $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
        if ($ext -eq '.evtx') {
            # Use filename heuristic to avoid Get-WinEvent overhead
            $fileName = [System.IO.Path]::GetFileNameWithoutExtension($filePath)
            if ($fileName -match 'cert|CAPI') {
                return $true
            }
            return $false
        }
        $joined = $firstLines -join "`n"
        if ($ext -eq '.json') {
            if ($joined -match '"thumbprint"' -and ($joined -match '"notAfter"' -or $joined -match '"expiryDate"' -or $joined -match '"subject"' -or $joined -match '"template"')) {
                return $true
            }
        } elseif ($ext -eq '.csv') {
            if ($firstLines.Count -ge 1) {
                $header = $firstLines[0]
                if ($header -match 'thumbprint' -and ($header -match 'notAfter' -or $header -match 'expiryDate' -or $header -match 'subject' -or $header -match 'template')) {
                    return $true
                }
            }
        }
        return $false
    } `
    -Parse {
        param($filePath, $encoding)
        $entries = [System.Collections.Generic.List[object]]::new()
        $idx = 0
        $ext = [System.IO.Path]::GetExtension($filePath).ToLower()
        try {
            if ($ext -eq '.evtx') {
                $events = Get-WinEvent -Path $filePath -ErrorAction Stop
                foreach ($evt in $events) {
                    $extra = @{
                        EventID      = $evt.Id
                        ProviderName = $evt.ProviderName
                        LogName      = $evt.LogName
                        Thumbprint   = ""
                        Subject      = ""
                        Issuer       = ""
                        NotAfter     = ""
                        NotBefore    = ""
                        DaysToExpiry = ""
                        Store        = ""
                        Template     = ""
                        SerialNumber = ""
                    }

                    if ($evt.Id -and $Script:State.EventIdLookup.ContainsKey([int]$evt.Id)) {
                        $extra['EventIdAnnotation'] = $Script:State.EventIdLookup[[int]$evt.Id]
                    }

                    # Extract EventData fields from XML
                    try {
                        $evtXml = [xml]$evt.ToXml()
                        $eventData = $evtXml.Event.EventData
                        if ($eventData) {
                            foreach ($data in $eventData.Data) {
                                if ($data.Name) {
                                    $extra[$data.Name] = $data.'#text'
                                }
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

                    # Map known cert event data fields to standard names
                    if ($extra.ContainsKey('CertificateThumbprint')) { $extra['Thumbprint'] = $extra['CertificateThumbprint'] }
                    if ($extra.ContainsKey('CertificateSubject')) { $extra['Subject'] = $extra['CertificateSubject'] }
                    if ($extra.ContainsKey('CertificateIssuer')) { $extra['Issuer'] = $extra['CertificateIssuer'] }
                    if ($extra.ContainsKey('CertificateTemplateName')) { $extra['Template'] = $extra['CertificateTemplateName'] }
                    if ($extra.ContainsKey('CertificateSerialNumber')) { $extra['SerialNumber'] = $extra['CertificateSerialNumber'] }

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
            } else {
                # JSON or CSV certificate inventory
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
                    if ($record.notBefore) {
                        [datetime]::TryParse([string]$record.notBefore, [ref]$ts) | Out-Null
                    }

                    $subject = [string]$record.subject
                    $notAfterStr = if ($record.notAfter) { [string]$record.notAfter }
                                   elseif ($record.expiryDate) { [string]$record.expiryDate }
                                   else { "" }

                    # Calculate DaysToExpiry
                    $daysToExpiry = ""
                    $expiryDate = [datetime]::MinValue
                    if ($notAfterStr -and [datetime]::TryParse($notAfterStr, [ref]$expiryDate)) {
                        $daysToExpiry = ($expiryDate - (Get-Date)).Days
                    }

                    # Level based on DaysToExpiry
                    $level = if ($daysToExpiry -ne "" -and $daysToExpiry -le 0) { "CRITICAL" }
                             elseif ($daysToExpiry -ne "" -and $daysToExpiry -le 30) { "ERROR" }
                             elseif ($daysToExpiry -ne "" -and $daysToExpiry -le 90) { "WARNING" }
                             else { "INFO" }

                    $msg = "Certificate $subject"
                    if ($notAfterStr) { $msg += " expires $notAfterStr" }
                    if ($daysToExpiry -ne "") { $msg += " ($daysToExpiry days)" }

                    $extra = @{
                        Thumbprint   = [string]$record.thumbprint
                        Subject      = $subject
                        Issuer       = [string]$record.issuer
                        NotAfter     = $notAfterStr
                        NotBefore    = [string]$record.notBefore
                        DaysToExpiry = if ($daysToExpiry -ne "") { $daysToExpiry } else { "" }
                        Store        = [string]$record.store
                        Template     = [string]$record.template
                        SerialNumber = [string]$record.serialNumber
                    }

                    $rawLine = if ($ext -eq '.json') { $record | ConvertTo-Json -Compress -Depth 5 } else { ($record.PSObject.Properties.Value -join ",") }

                    $entries.Add((ConvertTo-LogEntry @{
                        Index = $idx; Timestamp = $ts; Level = $level
                        Source = "Certificate"; Host = ""
                        Message = $msg; RawLine = $rawLine; Extra = $extra
                    }))
                    $idx++
                }
            }
        } catch {
            Write-Log "Certificate event parse error: $_" -Level ERROR
        }
        return $entries
    } `
    -SupportsTail $false
