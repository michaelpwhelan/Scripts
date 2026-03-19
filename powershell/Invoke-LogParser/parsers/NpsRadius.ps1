# NPS/RADIUS DTS XML Parser

Register-Parser -Id "nps-radius" -Name "NPS/RADIUS DTS XML" -Extensions @(".xml", ".log") -SupportsTail $false `
    -AutoDetect {
        param($firstLines, $filePath)
        $joined = $firstLines -join "`n"
        if ($joined -match '<Event>' -and ($joined -match '<Computer-Name>' -or $joined -match '<Packet-Type>')) { return $true }
        if ([System.IO.Path]::GetExtension($filePath).ToLower() -eq '.xml' -and $joined -match 'Acct-Session-Id|NAS-IP-Address|Packet-Type') { return $true }
        return $false
    } `
    -Parse {
        param($filePath, $encoding)
        $entries = [System.Collections.Generic.List[object]]::new()
        $idx = 0
        try {
            $content = [System.IO.File]::ReadAllText($filePath)
            # Wrap in root if needed
            if ($content -notmatch '^\s*<\?xml') { $content = "<?xml version='1.0'?><Root>$content</Root>" }
            elseif ($content -notmatch '<Root>') { $content = $content -replace '(<\?xml[^?]*\?>)', '$1<Root>'; $content += '</Root>' }
            $xml = [xml]$content
            $events = $xml.SelectNodes('//Event')
            foreach ($event in $events) {
                $extra = @{}
                foreach ($child in $event.ChildNodes) {
                    if ($child.NodeType -eq 'Element') {
                        $extra[$child.LocalName] = $child.InnerText
                    }
                }
                $ts = [datetime]::MinValue
                $tsField = $extra['Timestamp'] , $extra['Event-Timestamp'] , $extra['timestamp'] | Where-Object { $_ } | Select-Object -First 1
                if ($tsField) { [datetime]::TryParse($tsField, [ref]$ts) | Out-Null }

                $reasonCode = $extra['Reason-Code'] -as [int]
                $reasonText = if ($null -ne $reasonCode -and $Script:State.NpsReasonLookup.ContainsKey($reasonCode)) {
                    $Script:State.NpsReasonLookup[$reasonCode]
                } else { "" }
                if ($reasonText) { $extra['ReasonCodeTranslation'] = $reasonText }

                $packetType = $extra['Packet-Type'] -as [int]
                $packetName = switch ($packetType) {
                    1 { "Access-Request" } 2 { "Access-Accept" } 3 { "Access-Reject" }
                    4 { "Accounting-Request" } 5 { "Accounting-Response" }
                    11 { "Access-Challenge" } default { "Type-$packetType" }
                }
                $extra['PacketTypeName'] = $packetName

                $level = if ($packetType -eq 3) { "WARNING" }
                         elseif ($reasonCode -and $reasonCode -ne 0) { "ERROR" }
                         else { "INFO" }

                $user = $extra['User-Name'] , $extra['SAM-Account-Name'] , $extra['Fully-Qualifed-User-Name'] | Where-Object { $_ } | Select-Object -First 1
                $msg = "$packetName"
                if ($user) { $msg += " for $user" }
                if ($reasonText) { $msg += " - $reasonText" }

                $entries.Add((ConvertTo-LogEntry @{
                    Index = $idx; Timestamp = $ts; Level = $level
                    Source = $(if ($extra['NAS-IP-Address']) { $extra['NAS-IP-Address'] } else { $extra['Client-IP-Address'] })
                    Host = $extra['Computer-Name']; Message = $msg; RawLine = $event.OuterXml; Extra = $extra
                }))
                $idx++
            }
        } catch {
            Write-Log "NPS XML parse error: $_" -Level ERROR
        }
        return $entries
    }
