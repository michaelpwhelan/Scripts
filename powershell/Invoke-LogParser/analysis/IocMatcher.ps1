function Import-IocFile {
    param([string]$FilePath)

    if (-not (Test-Path $FilePath)) {
        Write-Log "IOC file not found: $FilePath" -Level ERROR
        return
    }

    $Script:State.IocSet = @{
        IPs      = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        Domains  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        Hashes   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        All      = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        Descriptions = @{}
        MatchCount = 0
    }

    $ipPattern = '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    $hashPattern = '^[0-9a-fA-F]{32,128}$'

    try {
        $csv = Import-Csv -Path $FilePath
        foreach ($row in $csv) {
            $value = $null
            # Try 'value' column, then 'indicator', then 'ioc'
            foreach ($col in @('value', 'indicator', 'ioc', 'Value', 'Indicator', 'IOC')) {
                if ($row.PSObject.Properties.Name -contains $col) {
                    $value = $row.$col
                    break
                }
            }
            if (-not $value) { continue }
            $value = $value.Trim()
            if ([string]::IsNullOrWhiteSpace($value)) { continue }

            # Auto-detect type
            $type = $null
            foreach ($col in @('type', 'Type', 'indicator_type')) {
                if ($row.PSObject.Properties.Name -contains $col) {
                    $type = $row.$col
                    break
                }
            }
            if (-not $type) {
                if ($value -match $ipPattern) { $type = "ip" }
                elseif ($value -match $hashPattern) { $type = "hash" }
                else { $type = "domain" }
            }

            switch ($type.ToLower()) {
                'ip'     { $Script:State.IocSet.IPs.Add($value) | Out-Null }
                'hash'   { $Script:State.IocSet.Hashes.Add($value) | Out-Null }
                default  { $Script:State.IocSet.Domains.Add($value) | Out-Null }
            }
            $Script:State.IocSet.All.Add($value) | Out-Null

            # Store description if available
            $desc = $null
            foreach ($col in @('description', 'Description', 'desc', 'note')) {
                if ($row.PSObject.Properties.Name -contains $col) {
                    $desc = $row.$col
                    break
                }
            }
            if ($desc) { $Script:State.IocSet.Descriptions[$value] = $desc }
        }

        Write-Log "Loaded $($Script:State.IocSet.All.Count) IOCs ($($Script:State.IocSet.IPs.Count) IPs, $($Script:State.IocSet.Domains.Count) domains, $($Script:State.IocSet.Hashes.Count) hashes)"
    } catch {
        Write-Log "Failed to load IOC file: $_" -Level ERROR
    }
}

function Invoke-IocMatch {
    param([System.Collections.Generic.List[object]]$Entries)

    if (-not $Script:State.IocSet -or $Script:State.IocSet.All.Count -eq 0) { return }

    $matchCount = 0
    $iocAll = $Script:State.IocSet.All
    $iocIPs = $Script:State.IocSet.IPs
    $iocDomains = $Script:State.IocSet.Domains

    foreach ($entry in $Entries) {
        $matched = $false
        $matchedValue = ""

        # Check IP fields
        foreach ($field in @('srcip', 'dstip', 'IPAddress', 'RemoteIP', 'IP', 'c-ip', 's-ip', 'ipAddress')) {
            if ($entry.Extra -and $entry.Extra.ContainsKey($field)) {
                $val = [string]$entry.Extra[$field]
                if ($iocIPs.Contains($val)) {
                    $matched = $true; $matchedValue = $val; break
                }
            }
        }

        # Check hostname/domain fields
        if (-not $matched) {
            foreach ($field in @('hostname', 'url', 'Host', 'QueryName', 'dstname')) {
                if ($entry.Extra -and $entry.Extra.ContainsKey($field)) {
                    $val = [string]$entry.Extra[$field]
                    foreach ($ioc in $iocDomains) {
                        if ($val -like "*$ioc*") {
                            $matched = $true; $matchedValue = $ioc; break
                        }
                    }
                    if ($matched) { break }
                }
            }
        }

        # Check Message, Source, Host
        if (-not $matched) {
            $searchFields = @($entry.Message, $entry.Source, $entry.Host)
            foreach ($sf in $searchFields) {
                if (-not $sf) { continue }
                foreach ($ioc in $iocAll) {
                    if ($sf.IndexOf($ioc, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                        $matched = $true; $matchedValue = $ioc; break
                    }
                }
                if ($matched) { break }
            }
        }

        if ($matched) {
            $entry.Extra['IocMatch'] = $true
            $entry.Extra['IocMatchedValue'] = $matchedValue
            if ($Script:State.IocSet.Descriptions.ContainsKey($matchedValue)) {
                $entry.Extra['IocDescription'] = $Script:State.IocSet.Descriptions[$matchedValue]
            }
            $matchCount++
        }
    }

    $Script:State.IocSet.MatchCount = $matchCount
    Write-Log "IOC matching complete: $matchCount matches found"
}
