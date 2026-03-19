# ═══════════════════════════════════════════════════════════════════════════════
# ASSET ENGINE — Asset enrichment and context for log events
# ═══════════════════════════════════════════════════════════════════════════════

$Script:AssetCache = $null
$Script:AssetCriticality = $null

function Initialize-AssetEngine {
    # Load asset cache from data/asset-cache.json
    $cachePath = Join-Path $Config.ScriptRoot "data" "asset-cache.json"
    if (Test-Path $cachePath) {
        try {
            $content = [System.IO.File]::ReadAllText($cachePath)
            $raw = $content | ConvertFrom-Json
            $Script:AssetCache = @{
                Assets      = [System.Collections.Generic.List[object]]::new()
                ByIP        = @{}
                ByHostname  = @{}
                ByMAC       = @{}
                BySerial    = @{}
                ByUser      = @{}
                LastUpdated = [datetime]::MinValue
            }

            if ($raw.LastUpdated) {
                $ts = [datetime]::MinValue
                if ([datetime]::TryParse([string]$raw.LastUpdated, [ref]$ts)) {
                    $Script:AssetCache.LastUpdated = $ts
                }
            }

            $assetIndex = 0
            foreach ($a in $raw.Assets) {
                $asset = @{
                    Id            = if ($null -ne $a.Id) { [int]$a.Id } else { $assetIndex }
                    Name          = if ($a.Name) { [string]$a.Name } else { "" }
                    AssetTag      = if ($a.AssetTag) { [string]$a.AssetTag } else { "" }
                    Serial        = if ($a.Serial) { [string]$a.Serial } else { "" }
                    Model         = if ($a.Model) { [string]$a.Model } else { "" }
                    Category      = if ($a.Category) { [string]$a.Category } else { "" }
                    Status        = if ($a.Status) { [string]$a.Status } else { "" }
                    AssignedTo    = if ($a.AssignedTo) { [string]$a.AssignedTo } else { "" }
                    Location      = if ($a.Location) { [string]$a.Location } else { "" }
                    IPAddress     = if ($a.IPAddress) { [string]$a.IPAddress } else { "" }
                    MACAddress    = if ($a.MACAddress) { [string]$a.MACAddress } else { "" }
                    OS            = if ($a.OS) { [string]$a.OS } else { "" }
                    PurchaseDate  = if ($a.PurchaseDate) { [string]$a.PurchaseDate } else { "" }
                    WarrantyExpiry = if ($a.WarrantyExpiry) { [string]$a.WarrantyExpiry } else { "" }
                    ServiceRole   = if ($a.ServiceRole) { [string]$a.ServiceRole } else { "" }
                    Notes         = if ($a.Notes) { [string]$a.Notes } else { "" }
                }
                $Script:AssetCache.Assets.Add($asset)
                Build-AssetIndex -Asset $asset -Index $assetIndex
                $assetIndex++
            }

            Write-Log "Loaded asset cache ($($Script:AssetCache.Assets.Count) assets)"
        } catch {
            Write-Log "Failed to load asset cache: $_" -Level WARNING
            $Script:AssetCache = $null
        }
    }

    # Load criticality rules from data/asset-criticality.json
    $critPath = Join-Path $Config.ScriptRoot "data" "asset-criticality.json"
    if (Test-Path $critPath) {
        try {
            $content = [System.IO.File]::ReadAllText($critPath)
            $Script:AssetCriticality = $content | ConvertFrom-Json
            Write-Log "Loaded asset criticality rules"
        } catch {
            Write-Log "Failed to load asset criticality rules: $_" -Level WARNING
            $Script:AssetCriticality = $null
        }
    }
}

function Build-AssetIndex {
    param($Asset, [int]$Index)

    if (-not $Script:AssetCache) { return }

    # Index by IP address
    if ($Asset.IPAddress) {
        $ipKey = $Asset.IPAddress.Trim().ToLower()
        if ($ipKey) {
            $Script:AssetCache.ByIP[$ipKey] = $Index
        }
    }

    # Index by hostname
    if ($Asset.Name) {
        $hostKey = $Asset.Name.Trim().ToLower()
        if ($hostKey) {
            $Script:AssetCache.ByHostname[$hostKey] = $Index
        }
    }

    # Index by MAC address (normalize to lowercase, colon-separated)
    if ($Asset.MACAddress) {
        $macNorm = $Asset.MACAddress.Trim().ToLower() -replace '[-\.]', ':'
        if ($macNorm) {
            $Script:AssetCache.ByMAC[$macNorm] = $Index
        }
    }

    # Index by serial number
    if ($Asset.Serial) {
        $serialKey = $Asset.Serial.Trim().ToLower()
        if ($serialKey) {
            $Script:AssetCache.BySerial[$serialKey] = $Index
        }
    }

    # Index by assigned user (one user can have multiple assets)
    if ($Asset.AssignedTo) {
        $userKey = $Asset.AssignedTo.Trim().ToLower()
        if ($userKey) {
            if (-not $Script:AssetCache.ByUser.ContainsKey($userKey)) {
                $Script:AssetCache.ByUser[$userKey] = [System.Collections.Generic.List[int]]::new()
            }
            $Script:AssetCache.ByUser[$userKey].Add($Index)
        }
    }
}

function Get-AssetByField {
    param([string]$Field, [string]$Value)

    if (-not $Script:AssetCache -or -not $Value) { return $null }

    $lookupKey = $Value.Trim().ToLower()
    if (-not $lookupKey) { return $null }

    switch ($Field.ToLower()) {
        'ip' {
            if ($Script:AssetCache.ByIP.ContainsKey($lookupKey)) {
                return $Script:AssetCache.Assets[$Script:AssetCache.ByIP[$lookupKey]]
            }
        }
        'ipaddress' {
            if ($Script:AssetCache.ByIP.ContainsKey($lookupKey)) {
                return $Script:AssetCache.Assets[$Script:AssetCache.ByIP[$lookupKey]]
            }
        }
        'hostname' {
            if ($Script:AssetCache.ByHostname.ContainsKey($lookupKey)) {
                return $Script:AssetCache.Assets[$Script:AssetCache.ByHostname[$lookupKey]]
            }
        }
        'name' {
            if ($Script:AssetCache.ByHostname.ContainsKey($lookupKey)) {
                return $Script:AssetCache.Assets[$Script:AssetCache.ByHostname[$lookupKey]]
            }
        }
        'mac' {
            $macNorm = $lookupKey -replace '[-\.]', ':'
            if ($Script:AssetCache.ByMAC.ContainsKey($macNorm)) {
                return $Script:AssetCache.Assets[$Script:AssetCache.ByMAC[$macNorm]]
            }
        }
        'macaddress' {
            $macNorm = $lookupKey -replace '[-\.]', ':'
            if ($Script:AssetCache.ByMAC.ContainsKey($macNorm)) {
                return $Script:AssetCache.Assets[$Script:AssetCache.ByMAC[$macNorm]]
            }
        }
        'serial' {
            if ($Script:AssetCache.BySerial.ContainsKey($lookupKey)) {
                return $Script:AssetCache.Assets[$Script:AssetCache.BySerial[$lookupKey]]
            }
        }
        'username' {
            if ($Script:AssetCache.ByUser.ContainsKey($lookupKey)) {
                $indices = $Script:AssetCache.ByUser[$lookupKey]
                if ($indices.Count -eq 1) {
                    return $Script:AssetCache.Assets[$indices[0]]
                }
                # Multiple assets for this user — return the first one
                return $Script:AssetCache.Assets[$indices[0]]
            }
        }
        'user' {
            if ($Script:AssetCache.ByUser.ContainsKey($lookupKey)) {
                $indices = $Script:AssetCache.ByUser[$lookupKey]
                return $Script:AssetCache.Assets[$indices[0]]
            }
        }
    }

    return $null
}

function Enrich-EventWithAsset {
    param($Entry)

    if (-not $Script:AssetCache -or -not $Entry) { return $Entry }
    if (-not $Entry.Extra) { $Entry.Extra = @{} }

    $asset = $null

    # Try lookup by IP address from various Extra fields
    if (-not $asset -and $Entry.Extra['srcip']) {
        $asset = Get-AssetByField -Field 'ip' -Value ([string]$Entry.Extra['srcip'])
    }
    if (-not $asset -and $Entry.Extra['dstip']) {
        $asset = Get-AssetByField -Field 'ip' -Value ([string]$Entry.Extra['dstip'])
    }
    if (-not $asset -and $Entry.Extra['IPAddress']) {
        $asset = Get-AssetByField -Field 'ip' -Value ([string]$Entry.Extra['IPAddress'])
    }
    if (-not $asset -and $Entry.Extra['IpAddress']) {
        $asset = Get-AssetByField -Field 'ip' -Value ([string]$Entry.Extra['IpAddress'])
    }

    # Try lookup by hostname
    if (-not $asset -and $Entry.Host) {
        $asset = Get-AssetByField -Field 'hostname' -Value $Entry.Host
    }
    if (-not $asset -and $Entry.Extra['devname']) {
        $asset = Get-AssetByField -Field 'hostname' -Value ([string]$Entry.Extra['devname'])
    }
    if (-not $asset -and $Entry.Extra['ComputerName']) {
        $asset = Get-AssetByField -Field 'hostname' -Value ([string]$Entry.Extra['ComputerName'])
    }

    # Try lookup by MAC address
    if (-not $asset -and $Entry.Extra['srcmac']) {
        $asset = Get-AssetByField -Field 'mac' -Value ([string]$Entry.Extra['srcmac'])
    }
    if (-not $asset -and $Entry.Extra['Calling-Station-Id']) {
        $callId = [string]$Entry.Extra['Calling-Station-Id']
        if ($callId -match '^([0-9A-Fa-f]{2}[:\-\.]{0,1}){5}[0-9A-Fa-f]{2}$') {
            $asset = Get-AssetByField -Field 'mac' -Value $callId
        }
    }

    # Try lookup by username
    if (-not $asset) {
        $username = $null
        if ($Entry.Extra['user']) { $username = [string]$Entry.Extra['user'] }
        elseif ($Entry.Extra['User-Name']) { $username = [string]$Entry.Extra['User-Name'] }
        elseif ($Entry.Extra['TargetUserName']) { $username = [string]$Entry.Extra['TargetUserName'] }
        elseif ($Entry.Extra['SubjectUserName']) { $username = [string]$Entry.Extra['SubjectUserName'] }
        elseif ($Entry.Extra['UserPrincipalName']) { $username = [string]$Entry.Extra['UserPrincipalName'] }

        if ($username) {
            # Strip domain prefix if present (DOMAIN\user -> user)
            if ($username.Contains('\')) {
                $username = $username.Split('\')[-1]
            }
            # Strip UPN suffix if present (user@domain -> user)
            if ($username.Contains('@')) {
                $username = $username.Split('@')[0]
            }
            $asset = Get-AssetByField -Field 'username' -Value $username
        }
    }

    # Enrich the entry if we found a matching asset
    if ($asset) {
        $Entry.Extra['AssetName'] = $asset.Name
        $Entry.Extra['AssetType'] = $asset.Category
        $Entry.Extra['AssetOwner'] = $asset.AssignedTo
        $Entry.Extra['AssetSite'] = $asset.Location

        # Calculate and attach criticality
        try {
            $crit = Get-AssetCriticality -Asset $asset
            $Entry.Extra['AssetCriticality'] = $crit.Level
        } catch {
            # Silently continue if criticality calculation fails
        }
    }

    return $Entry
}

function Get-AssetCriticality {
    param($Asset)

    $score = 0
    $factors = [System.Collections.Generic.List[string]]::new()

    if (-not $Asset) {
        return @{ Score = 0; Level = "Low"; Factors = @() }
    }

    # Load weights from criticality rules or use defaults
    $typeWeights = @{
        'Server' = 10; 'Domain Controller' = 15; 'Network Device' = 8; 'Firewall' = 12
        'Switch' = 6; 'Access Point' = 4; 'Workstation' = 5; 'Laptop' = 5
        'Printer' = 2; 'Phone' = 2; 'Virtual Machine' = 7; 'Unknown' = 3
    }
    $roleWeights = @{
        'DC' = 15; 'NPS' = 12; 'CA' = 12; 'HyperV' = 10; 'Veeam' = 8
        'DNS' = 10; 'DHCP' = 8; 'FileServer' = 6; 'PrintServer' = 3
        'WebServer' = 7; 'DatabaseServer' = 10; 'FortiManager' = 10
        'FortiAnalyzer' = 8; 'Zabbix' = 7; 'Exchange' = 9
    }
    $siteRoleWeights = @{ 'hub' = 10; 'dr_hub' = 8; 'spoke' = 5 }
    $critLevels = @(
        @{ Name = 'Critical'; MinScore = 25 }
        @{ Name = 'High'; MinScore = 15 }
        @{ Name = 'Medium'; MinScore = 8 }
        @{ Name = 'Low'; MinScore = 0 }
    )

    # Override from loaded criticality rules if available
    if ($Script:AssetCriticality) {
        if ($Script:AssetCriticality.assetTypeWeights) {
            $typeWeights = @{}
            foreach ($prop in $Script:AssetCriticality.assetTypeWeights.PSObject.Properties) {
                $typeWeights[$prop.Name] = [int]$prop.Value
            }
        }
        if ($Script:AssetCriticality.serviceRoleWeights) {
            $roleWeights = @{}
            foreach ($prop in $Script:AssetCriticality.serviceRoleWeights.PSObject.Properties) {
                $roleWeights[$prop.Name] = [int]$prop.Value
            }
        }
        if ($Script:AssetCriticality.siteRoleWeights) {
            $siteRoleWeights = @{}
            foreach ($prop in $Script:AssetCriticality.siteRoleWeights.PSObject.Properties) {
                $siteRoleWeights[$prop.Name] = [int]$prop.Value
            }
        }
        if ($Script:AssetCriticality.criticalityLevels) {
            $critLevels = [System.Collections.Generic.List[object]]::new()
            foreach ($prop in $Script:AssetCriticality.criticalityLevels.PSObject.Properties) {
                $critLevels.Add(@{ Name = $prop.Name; MinScore = [int]$prop.Value.minScore })
            }
            # Sort descending by MinScore so we match highest first
            $critLevels = @($critLevels | Sort-Object { $_.MinScore } -Descending)
        }
    }

    # Check special asset name/role pattern overrides first
    if ($Script:AssetCriticality -and $Script:AssetCriticality.specialAssets -and $Script:AssetCriticality.specialAssets.patterns) {
        foreach ($pattern in $Script:AssetCriticality.specialAssets.patterns) {
            $fieldName = if ($pattern -is [PSCustomObject]) { $pattern.field } else { $pattern['field'] }
            $patternStr = if ($pattern -is [PSCustomObject]) { $pattern.pattern } else { $pattern['pattern'] }
            $overrideLevel = if ($pattern -is [PSCustomObject]) { $pattern.level } else { $pattern['level'] }
            $reason = if ($pattern -is [PSCustomObject]) { $pattern.reason } else { $pattern['reason'] }

            $fieldValue = $null
            if ($fieldName -eq 'Name') { $fieldValue = $Asset.Name }
            elseif ($fieldName -eq 'ServiceRole') { $fieldValue = $Asset.ServiceRole }
            elseif ($fieldName -eq 'Category') { $fieldValue = $Asset.Category }
            elseif ($fieldName -eq 'AssetTag') { $fieldValue = $Asset.AssetTag }

            if ($fieldValue) {
                # Convert wildcard pattern to regex for matching
                $regexPattern = '^' + [regex]::Escape($patternStr).Replace('\*', '.*').Replace('\?', '.') + '$'
                if ($fieldValue -match $regexPattern) {
                    $factors.Add("Special override: $reason")
                    return @{
                        Score   = 100
                        Level   = $overrideLevel
                        Factors = @($factors)
                    }
                }
            }
        }
    }

    # Score by asset type/category
    $category = if ($Asset.Category) { $Asset.Category } else { "Unknown" }
    $typeScore = 0
    foreach ($tKey in $typeWeights.Keys) {
        if ($category -eq $tKey) {
            $typeScore = $typeWeights[$tKey]
            break
        }
    }
    if ($typeScore -eq 0 -and $typeWeights.ContainsKey('Unknown')) {
        $typeScore = $typeWeights['Unknown']
    }
    if ($typeScore -gt 0) {
        $score += $typeScore
        $factors.Add("AssetType '$category' (+$typeScore)")
    }

    # Score by service role
    if ($Asset.ServiceRole) {
        $role = $Asset.ServiceRole
        $roleScore = 0
        foreach ($rKey in $roleWeights.Keys) {
            if ($role -eq $rKey) {
                $roleScore = $roleWeights[$rKey]
                break
            }
        }
        if ($roleScore -gt 0) {
            $score += $roleScore
            $factors.Add("ServiceRole '$role' (+$roleScore)")
        }
    }

    # Score by site role (uses TopologyEngine if available)
    if ($Asset.Location) {
        $siteRole = $null
        # Try to resolve site role via TopologyEngine if loaded
        if (Get-Command -Name 'Get-SiteRole' -ErrorAction SilentlyContinue) {
            try {
                $siteRole = Get-SiteRole -SiteCode $Asset.Location
            } catch {
                # TopologyEngine not available or site not found
            }
        }
        if ($siteRole -and $siteRoleWeights.ContainsKey($siteRole)) {
            $siteScore = $siteRoleWeights[$siteRole]
            $score += $siteScore
            $factors.Add("SiteRole '$siteRole' (+$siteScore)")
        }
    }

    # Determine criticality level from score
    $level = "Low"
    foreach ($cl in $critLevels) {
        if ($score -ge $cl.MinScore) {
            $level = $cl.Name
            break
        }
    }

    return @{
        Score   = $score
        Level   = $level
        Factors = @($factors)
    }
}

function Sync-AssetCacheFromFile {
    param([string]$FilePath)

    if (-not $FilePath -or -not (Test-Path $FilePath)) {
        Write-Log "Asset file not found: $FilePath" -Level ERROR
        return
    }

    # Initialize empty cache
    $Script:AssetCache = @{
        Assets      = [System.Collections.Generic.List[object]]::new()
        ByIP        = @{}
        ByHostname  = @{}
        ByMAC       = @{}
        BySerial    = @{}
        ByUser      = @{}
        LastUpdated = Get-Date
    }

    $ext = [System.IO.Path]::GetExtension($FilePath).ToLower()
    $assetIndex = 0

    try {
        if ($ext -eq '.json') {
            $content = [System.IO.File]::ReadAllText($FilePath)
            $rawAssets = $content | ConvertFrom-Json

            # Handle both array and object-with-Assets-property formats
            $assetList = $null
            if ($rawAssets -is [System.Array]) {
                $assetList = $rawAssets
            } elseif ($rawAssets.Assets) {
                $assetList = $rawAssets.Assets
            } else {
                Write-Log "Unrecognized JSON asset format in $FilePath" -Level WARNING
                return
            }

            foreach ($a in $assetList) {
                $asset = @{
                    Id            = if ($null -ne $a.Id) { [int]$a.Id } else { $assetIndex }
                    Name          = if ($a.Name) { [string]$a.Name } else { "" }
                    AssetTag      = if ($a.AssetTag) { [string]$a.AssetTag } else { "" }
                    Serial        = if ($a.Serial) { [string]$a.Serial } else { "" }
                    Model         = if ($a.Model) { [string]$a.Model } else { "" }
                    Category      = if ($a.Category) { [string]$a.Category } else { "" }
                    Status        = if ($a.Status) { [string]$a.Status } else { "" }
                    AssignedTo    = if ($a.AssignedTo) { [string]$a.AssignedTo } else { "" }
                    Location      = if ($a.Location) { [string]$a.Location } else { "" }
                    IPAddress     = if ($a.IPAddress) { [string]$a.IPAddress } else { "" }
                    MACAddress    = if ($a.MACAddress) { [string]$a.MACAddress } else { "" }
                    OS            = if ($a.OS) { [string]$a.OS } else { "" }
                    PurchaseDate  = if ($a.PurchaseDate) { [string]$a.PurchaseDate } else { "" }
                    WarrantyExpiry = if ($a.WarrantyExpiry) { [string]$a.WarrantyExpiry } else { "" }
                    ServiceRole   = if ($a.ServiceRole) { [string]$a.ServiceRole } else { "" }
                    Notes         = if ($a.Notes) { [string]$a.Notes } else { "" }
                }
                $Script:AssetCache.Assets.Add($asset)
                Build-AssetIndex -Asset $asset -Index $assetIndex
                $assetIndex++
            }
        } elseif ($ext -eq '.csv') {
            $csvData = Import-Csv -Path $FilePath

            foreach ($row in $csvData) {
                $asset = @{
                    Id            = if ($row.Id) { [int]$row.Id } else { $assetIndex }
                    Name          = if ($row.Name) { [string]$row.Name } else { "" }
                    AssetTag      = if ($row.AssetTag) { [string]$row.AssetTag } else { "" }
                    Serial        = if ($row.Serial) { [string]$row.Serial } else { "" }
                    Model         = if ($row.Model) { [string]$row.Model } else { "" }
                    Category      = if ($row.Category) { [string]$row.Category } else { "" }
                    Status        = if ($row.Status) { [string]$row.Status } else { "" }
                    AssignedTo    = if ($row.AssignedTo) { [string]$row.AssignedTo } else { "" }
                    Location      = if ($row.Location) { [string]$row.Location } else { "" }
                    IPAddress     = if ($row.IPAddress) { [string]$row.IPAddress } else { "" }
                    MACAddress    = if ($row.MACAddress) { [string]$row.MACAddress } else { "" }
                    OS            = if ($row.OS) { [string]$row.OS } else { "" }
                    PurchaseDate  = if ($row.PurchaseDate) { [string]$row.PurchaseDate } else { "" }
                    WarrantyExpiry = if ($row.WarrantyExpiry) { [string]$row.WarrantyExpiry } else { "" }
                    ServiceRole   = if ($row.ServiceRole) { [string]$row.ServiceRole } else { "" }
                    Notes         = if ($row.Notes) { [string]$row.Notes } else { "" }
                }
                $Script:AssetCache.Assets.Add($asset)
                Build-AssetIndex -Asset $asset -Index $assetIndex
                $assetIndex++
            }
        } else {
            Write-Log "Unsupported asset file format: $ext (use .json or .csv)" -Level ERROR
            return
        }

        Write-Log "Imported $assetIndex assets from $FilePath"

        # Save to data/asset-cache.json for future use
        $savePath = Join-Path $Config.ScriptRoot "data" "asset-cache.json"
        try {
            $saveObj = @{
                Assets      = @($Script:AssetCache.Assets)
                LastUpdated = $Script:AssetCache.LastUpdated.ToString('o')
            }
            $json = $saveObj | ConvertTo-Json -Depth 5
            [System.IO.File]::WriteAllText($savePath, $json)
            Write-Log "Saved asset cache to $savePath"
        } catch {
            Write-Log "Failed to save asset cache: $_" -Level WARNING
        }
    } catch {
        Write-Log "Failed to import assets from ${FilePath}: $_" -Level ERROR
    }
}

function Get-AssetSummary {
    if (-not $Script:AssetCache -or $Script:AssetCache.Assets.Count -eq 0) {
        return @{
            TotalAssets    = 0
            ByCategory     = @{}
            ByLocation     = @{}
            ByStatus       = @{}
            IndexedIPs     = 0
            IndexedHosts   = 0
            IndexedMACs    = 0
            IndexedSerials = 0
            IndexedUsers   = 0
            LastUpdated    = $null
            CriticalCount  = 0
            HighCount      = 0
            MediumCount    = 0
            LowCount       = 0
        }
    }

    $byCategory = @{}
    $byLocation = @{}
    $byStatus = @{}
    $criticalCount = 0
    $highCount = 0
    $mediumCount = 0
    $lowCount = 0

    foreach ($asset in $Script:AssetCache.Assets) {
        # Count by category
        $cat = if ($asset.Category) { $asset.Category } else { "Unknown" }
        if (-not $byCategory.ContainsKey($cat)) { $byCategory[$cat] = 0 }
        $byCategory[$cat]++

        # Count by location
        $loc = if ($asset.Location) { $asset.Location } else { "Unknown" }
        if (-not $byLocation.ContainsKey($loc)) { $byLocation[$loc] = 0 }
        $byLocation[$loc]++

        # Count by status
        $st = if ($asset.Status) { $asset.Status } else { "Unknown" }
        if (-not $byStatus.ContainsKey($st)) { $byStatus[$st] = 0 }
        $byStatus[$st]++

        # Count by criticality level
        try {
            $crit = Get-AssetCriticality -Asset $asset
            switch ($crit.Level) {
                'Critical' { $criticalCount++ }
                'High'     { $highCount++ }
                'Medium'   { $mediumCount++ }
                'Low'      { $lowCount++ }
            }
        } catch {
            $lowCount++
        }
    }

    return @{
        TotalAssets    = $Script:AssetCache.Assets.Count
        ByCategory     = $byCategory
        ByLocation     = $byLocation
        ByStatus       = $byStatus
        IndexedIPs     = $Script:AssetCache.ByIP.Count
        IndexedHosts   = $Script:AssetCache.ByHostname.Count
        IndexedMACs    = $Script:AssetCache.ByMAC.Count
        IndexedSerials = $Script:AssetCache.BySerial.Count
        IndexedUsers   = $Script:AssetCache.ByUser.Count
        LastUpdated    = $Script:AssetCache.LastUpdated
        CriticalCount  = $criticalCount
        HighCount      = $highCount
        MediumCount    = $mediumCount
        LowCount       = $lowCount
    }
}
