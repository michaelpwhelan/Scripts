# FortiGate Configuration File Parser

Register-Parser -Id "fortigate-conf" -Name "FortiGate Config File" -Extensions @(".conf") -SupportsTail $false `
    -AutoDetect {
        param($firstLines, $filePath)
        foreach ($line in $firstLines) {
            if ($line -match '^#config-version=FG') { return $true }
            if ($line -match '^\s*config system global\s*$') { return $true }
        }
        return $false
    } `
    -Parse {
        param($filePath, $encoding)
        $entries = [System.Collections.Generic.List[object]]::new()
        $idx = 0
        $lines = [System.IO.File]::ReadAllLines($filePath, [System.Text.Encoding]::GetEncoding($encoding))
        $hostname = ""; $firmware = ""; $model = ""
        $headerExtra = @{}

        # Parse config header
        foreach ($line in $lines) {
            if ($line -match '^#config-version=(\w+)-([^:]+):') {
                $model = $Matches[1]; $firmware = $Matches[2]
                $headerExtra['Model'] = $model; $headerExtra['Firmware'] = $firmware
            }
            if ($line -match '^#buildno=(\d+)') { $headerExtra['BuildNo'] = $Matches[1] }
            if (-not $line.StartsWith('#')) { break }
        }

        $sectionStack = [System.Collections.Generic.List[string]]::new()
        $currentSection = ""
        $editId = ""
        $editSettings = [ordered]@{}
        $editRawLines = [System.Collections.Generic.List[string]]::new()
        $inEdit = $false
        $nestDepth = 0

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i].Trim()
            if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }

            if ($line -match '^config\s+(.+)$') {
                if ($inEdit) {
                    $nestDepth++
                    $editRawLines.Add($lines[$i])
                } else {
                    $sectionStack.Add($Matches[1])
                    $currentSection = $sectionStack -join ' > '
                }
                continue
            }

            if ($line -eq 'end') {
                if ($inEdit -and $nestDepth -gt 0) {
                    $nestDepth--
                    $editRawLines.Add($lines[$i])
                    continue
                }
                if ($inEdit) {
                    # Shouldn't happen - 'next' closes edit blocks. Treat as implicit next + end.
                    $inEdit = $false
                }
                if ($sectionStack.Count -gt 0) {
                    $sectionStack.RemoveAt($sectionStack.Count - 1)
                    $currentSection = if ($sectionStack.Count -gt 0) { $sectionStack -join ' > ' } else { "" }
                }
                continue
            }

            if ($line -match '^edit\s+"?([^"]+)"?$') {
                $editId = $Matches[1]
                $editSettings = [ordered]@{}
                $editRawLines = [System.Collections.Generic.List[string]]::new()
                $editRawLines.Add($lines[$i])
                $inEdit = $true
                $nestDepth = 0
                continue
            }

            if ($line -eq 'next' -and $inEdit) {
                $editRawLines.Add($lines[$i])
                $inEdit = $false

                # Extract hostname from system global
                if ($currentSection -match 'system global' -and $editSettings['hostname']) {
                    $hostname = $editSettings['hostname']
                }

                # Determine level and flags
                $entryLevel = "INFO"
                $flags = [System.Collections.Generic.List[string]]::new()

                if ($editSettings['status'] -and $editSettings['status'] -eq 'disable') {
                    $entryLevel = "WARNING"; $flags.Add("DISABLED")
                }
                if ($currentSection -match 'firewall policy') {
                    $sa = if ($editSettings['srcaddr']) { $editSettings['srcaddr'] } else { "" }
                    $da = if ($editSettings['dstaddr']) { $editSettings['dstaddr'] } else { "" }
                    $svc = if ($editSettings['service']) { $editSettings['service'] } else { "" }
                    if ($sa -match '\ball\b' -and $da -match '\ball\b' -and $svc -match '\bALL\b') {
                        $entryLevel = "WARNING"; $flags.Add("PERMISSIVE")
                    }
                    $act = if ($editSettings['action']) { $editSettings['action'] } else { "deny" }
                    if ($act -eq 'accept') {
                        $hasUtm = $editSettings.Keys | Where-Object { $_ -match 'utm-status|av-profile|webfilter-profile|ips-sensor|application-list|ssl-ssh-profile' }
                        if (-not $hasUtm) { $flags.Add("NO-UTM") }
                        # Check for missing IPS sensor
                        if (-not $editSettings['ips-sensor']) { $entryLevel = "WARNING"; $flags.Add("NO-IPS") }
                    }
                    # Check for disabled logging
                    $logTraffic = $editSettings['logtraffic']
                    if ($logTraffic -eq 'disable' -or (-not $logTraffic -and $act -eq 'accept')) {
                        $entryLevel = "WARNING"; $flags.Add("NO-LOGGING")
                    }
                    # Check SSL inspection mode
                    $sslProfile = $editSettings['ssl-ssh-profile']
                    if ($sslProfile -and $sslProfile -match 'certificate-inspection') {
                        $flags.Add("WEAK-SSL-INSPECT")
                    }
                }
                # Check system interface for insecure management access
                if ($currentSection -match 'system interface') {
                    $allowAccess = $editSettings['allowaccess']
                    if ($allowAccess -and $allowAccess -match '\b(http|telnet)\b') {
                        $entryLevel = "ERROR"; $flags.Add("INSECURE-MGMT")
                    }
                }
                # Check system password policy
                if ($currentSection -match 'system password-policy') {
                    $minLength = $editSettings['minimum-length'] -as [int]
                    if ($minLength -and $minLength -lt 8) {
                        $entryLevel = "WARNING"; $flags.Add("WEAK-PASSWD-POLICY")
                    }
                    $status2 = $editSettings['status']
                    if ($status2 -eq 'disable') {
                        $entryLevel = "WARNING"; $flags.Add("WEAK-PASSWD-POLICY")
                    }
                }

                # Build message
                $msgParts = [System.Collections.Generic.List[string]]::new()
                $name = if ($editSettings['name']) { $editSettings['name'] } else { $editId }
                $msgParts.Add("[$($currentSection.Split('>')[-1].Trim()) $editId] $name")

                if ($currentSection -match 'firewall policy') {
                    $si = if ($editSettings['srcintf']) { $editSettings['srcintf'] } else { "?" }
                    $di = if ($editSettings['dstintf']) { $editSettings['dstintf'] } else { "?" }
                    $msgParts.Add("${si}`u{2192}${di}")
                    if ($editSettings['srcaddr']) { $msgParts.Add("srcaddr=$($editSettings['srcaddr'])") }
                    if ($editSettings['dstaddr']) { $msgParts.Add("dstaddr=$($editSettings['dstaddr'])") }
                    if ($editSettings['action']) { $msgParts.Add("action=$($editSettings['action'])") }
                }
                if ($flags.Count -gt 0) { $msgParts.Add("[$($flags -join ',')]") }

                $extra = [ordered]@{}
                foreach ($k in $editSettings.Keys) { $extra[$k] = $editSettings[$k] }
                foreach ($k in $headerExtra.Keys) { $extra["Config_$k"] = $headerExtra[$k] }
                $extra['Section'] = $currentSection

                $entries.Add((ConvertTo-LogEntry @{
                    Index = $idx; Timestamp = [datetime]::MinValue; Level = $entryLevel
                    Source = $currentSection.Split('>')[-1].Trim()
                    Host = $hostname; Message = ($msgParts -join ': ')
                    RawLine = ($editRawLines -join "`n"); Extra = $extra
                }))
                $idx++
                continue
            }

            if ($inEdit -and $line -match '^set\s+(\S+)\s+(.+)$') {
                $editRawLines.Add($lines[$i])
                $setKey = $Matches[1]
                $setVal = $Matches[2].Trim('"')
                $editSettings[$setKey] = $setVal
                continue
            }

            if ($inEdit -and $line -match '^unset\s+(\S+)') {
                $editRawLines.Add($lines[$i])
                continue
            }

            if ($inEdit) { $editRawLines.Add($lines[$i]) }

            # Handle set in top-level config (no edit block, e.g., config system global)
            if (-not $inEdit -and $line -match '^set\s+(\S+)\s+(.+)$') {
                $setKey = $Matches[1]
                $setVal = $Matches[2].Trim('"')
                if ($currentSection -match 'system global' -and $setKey -eq 'hostname') {
                    $hostname = $setVal
                }
            }
        }
        return $entries
    }
