# ═══════════════════════════════════════════════════════════════════════════════
# SNIPE-IT API CONNECTOR -- Pull asset inventory from Snipe-IT
# ═══════════════════════════════════════════════════════════════════════════════

function Connect-SnipeIt {
    <#
    .SYNOPSIS
        Tests connectivity to a Snipe-IT instance using a Personal Access Token
        and registers the connector.
    .OUTPUTS
        $true on success, $false on failure.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [string]$ApiToken
    )

    # Retrieve token from Credential Manager if not provided
    if (-not $ApiToken) {
        $stored = Get-StoredApiCredential -TargetName "InvokeLogParser_SnipeIt_$Server"
        if (-not $stored) {
            Write-Log "No API token available for Snipe-IT $Server" -Level ERROR
            return $false
        }
        $ApiToken = $stored.Token
    }

    # Normalize server URL
    $baseUrl = $Server.TrimEnd('/')
    if ($baseUrl -notmatch '^https?://') {
        $baseUrl = "https://$baseUrl"
    }

    $headers = @{
        Authorization = "Bearer $ApiToken"
        Accept        = "application/json"
    }

    try {
        Write-Log "Testing Snipe-IT connectivity at $baseUrl ..." -Level INFO

        $testUri = "$baseUrl/api/v1/statuslabels?limit=1"
        $response = Invoke-RestWithRetry -Uri $testUri -Method GET `
            -Headers $headers -TimeoutSec 15 -MaxRetries 2

        # A successful response contains 'total' or 'rows'
        if ($null -eq $response) {
            Write-Log "Snipe-IT returned empty response -- check API token permissions" -Level ERROR
            return $false
        }

        Register-Connector -Id 'snipeit' -Name "Snipe-IT ($Server)" -Type 'RestApi' -Config @{
            Server   = $Server
            BaseUrl  = $baseUrl
            ApiToken = $ApiToken
            Headers  = $headers
        }
        Set-ConnectorStatus -Id 'snipeit' -Status 'Connected'

        $total = if ($response.total) { $response.total } else { "?" }
        Write-Log "Snipe-IT connection successful ($total status labels found)" -Level INFO
        return $true
    } catch {
        Write-Log "Snipe-IT connection failed: $($_.Exception.Message)" -Level ERROR
        Register-Connector -Id 'snipeit' -Name "Snipe-IT ($Server)" -Type 'RestApi' -Config @{
            Server = $Server; BaseUrl = $baseUrl
        }
        Set-ConnectorStatus -Id 'snipeit' -Status 'Error' -ErrorMessage $_.Exception.Message
        return $false
    }
}

function Get-SnipeItAssets {
    <#
    .SYNOPSIS
        Retrieves hardware assets from Snipe-IT with pagination.
    .OUTPUTS
        Array of standardized asset objects.
    #>
    param(
        [int]$Limit = 500,
        [string]$Search = "",
        [int]$LocationId = 0
    )

    # Validate connector
    if (-not $Script:Connectors.ContainsKey('snipeit') -or
        $Script:Connectors['snipeit'].Status -ne 'Connected') {
        Write-Log "Snipe-IT connector is not connected. Call Connect-SnipeIt first." -Level ERROR
        return @()
    }

    # Check cache
    $cached = Get-ConnectorCache -Id 'snipeit'
    if ($cached -and -not $Search -and $LocationId -eq 0) { return $cached }

    $config  = $Script:Connectors['snipeit'].Config
    $baseUrl = $config.BaseUrl
    $headers = $config.Headers

    $assets  = [System.Collections.Generic.List[object]]::new()
    $offset  = 0
    $pageSize = 100  # Snipe-IT default page size

    try {
        Write-Log "Pulling Snipe-IT assets $(if($Search){"(search='$Search') "})$(if($LocationId){"(location=$LocationId) "})..." -Level INFO

        do {
            $uri = "$baseUrl/api/v1/hardware?limit=$pageSize&offset=$offset&sort=id&order=asc"
            if ($Search) {
                $uri += "&search=$([System.Uri]::EscapeDataString($Search))"
            }
            if ($LocationId -gt 0) {
                $uri += "&location_id=$LocationId"
            }

            $response = Invoke-RestWithRetry -Uri $uri -Method GET `
                -Headers $headers -TimeoutSec 30 -MaxRetries 3

            if (-not $response -or -not $response.rows) { break }

            $totalAvailable = if ($response.total) { [int]$response.total } else { 0 }

            foreach ($hw in $response.rows) {
                # Extract standard fields
                $assignedTo = ""
                if ($hw.assigned_to) {
                    if ($hw.assigned_to.name) {
                        $assignedTo = [string]$hw.assigned_to.name
                    } elseif ($hw.assigned_to.username) {
                        $assignedTo = [string]$hw.assigned_to.username
                    }
                }

                $locationName = ""
                if ($hw.location -and $hw.location.name) {
                    $locationName = [string]$hw.location.name
                } elseif ($hw.rtd_location -and $hw.rtd_location.name) {
                    $locationName = [string]$hw.rtd_location.name
                }

                $statusLabel = ""
                if ($hw.status_label -and $hw.status_label.name) {
                    $statusLabel = [string]$hw.status_label.name
                }

                $modelName = ""
                if ($hw.model -and $hw.model.name) {
                    $modelName = [string]$hw.model.name
                }

                $categoryName = ""
                if ($hw.category -and $hw.category.name) {
                    $categoryName = [string]$hw.category.name
                }

                # Extract IP and MAC from custom fields if present
                $ipAddress  = ""
                $macAddress = ""
                if ($hw.custom_fields) {
                    # Custom fields can be a hashtable or PSCustomObject
                    $cfProps = $null
                    if ($hw.custom_fields -is [PSCustomObject]) {
                        $cfProps = $hw.custom_fields.PSObject.Properties
                    }
                    if ($cfProps) {
                        foreach ($prop in $cfProps) {
                            $fieldName = $prop.Name.ToLower()
                            $fieldVal  = ""
                            if ($prop.Value -and $prop.Value.value) {
                                $fieldVal = [string]$prop.Value.value
                            }
                            if ($fieldName -match 'ip.?address|ipv4' -and $fieldVal) {
                                $ipAddress = $fieldVal
                            }
                            if ($fieldName -match 'mac.?address' -and $fieldVal) {
                                $macAddress = $fieldVal
                            }
                        }
                    }
                }

                $purchaseDate   = if ($hw.purchase_date -and $hw.purchase_date.date) {
                    [string]$hw.purchase_date.date
                } elseif ($hw.purchase_date -is [string]) {
                    $hw.purchase_date
                } else { "" }

                $warrantyExpiry = if ($hw.warranty_expires -and $hw.warranty_expires.date) {
                    [string]$hw.warranty_expires.date
                } elseif ($hw.warranty_expires -is [string]) {
                    $hw.warranty_expires
                } else { "" }

                $assets.Add([PSCustomObject]@{
                    Id             = [int]$hw.id
                    Name           = [string]$hw.name
                    AssetTag       = [string]$hw.asset_tag
                    Serial         = [string]$hw.serial
                    Model          = $modelName
                    Category       = $categoryName
                    Status         = $statusLabel
                    AssignedTo     = $assignedTo
                    Location       = $locationName
                    IPAddress      = $ipAddress
                    MACAddress     = $macAddress
                    PurchaseDate   = $purchaseDate
                    WarrantyExpiry = $warrantyExpiry
                    Notes          = if ($hw.notes) { [string]$hw.notes } else { "" }
                })
            }

            $offset += $response.rows.Count
            Write-Log "Snipe-IT: fetched $offset / $totalAvailable assets" -Level INFO

            if ($offset -ge $Limit) { break }
            if ($response.rows.Count -lt $pageSize) { break }

        } while ($true)

        # Cache results for unfiltered queries
        if (-not $Search -and $LocationId -eq 0 -and $assets.Count -gt 0) {
            Set-ConnectorCache -Id 'snipeit' -Data $assets
        }

        Write-Log "Snipe-IT: total $($assets.Count) assets retrieved" -Level INFO
    } catch {
        Write-Log "Snipe-IT asset retrieval failed: $($_.Exception.Message)" -Level ERROR
    }

    return $assets
}

function Get-SnipeItAssetByField {
    <#
    .SYNOPSIS
        Searches for a specific asset by serial number, asset tag, or name.
    .OUTPUTS
        Single asset object or $null if not found.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("serial", "asset_tag", "name")]
        [string]$Field,
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    # Validate connector
    if (-not $Script:Connectors.ContainsKey('snipeit') -or
        $Script:Connectors['snipeit'].Status -ne 'Connected') {
        Write-Log "Snipe-IT connector is not connected. Call Connect-SnipeIt first." -Level ERROR
        return $null
    }

    $config  = $Script:Connectors['snipeit'].Config
    $baseUrl = $config.BaseUrl
    $headers = $config.Headers

    try {
        Write-Log "Searching Snipe-IT for $Field = '$Value' ..." -Level INFO

        $uri = ""
        switch ($Field) {
            "serial" {
                $uri = "$baseUrl/api/v1/hardware/byserial/$([System.Uri]::EscapeDataString($Value))"
            }
            "asset_tag" {
                $uri = "$baseUrl/api/v1/hardware/bytag/$([System.Uri]::EscapeDataString($Value))"
            }
            "name" {
                $uri = "$baseUrl/api/v1/hardware?search=$([System.Uri]::EscapeDataString($Value))&limit=1"
            }
        }

        $response = Invoke-RestWithRetry -Uri $uri -Method GET `
            -Headers $headers -TimeoutSec 15 -MaxRetries 2

        $hw = $null
        if ($Field -eq "name" -and $response.rows -and $response.rows.Count -gt 0) {
            $hw = $response.rows[0]
        } elseif ($Field -eq "serial" -and $response.rows -and $response.rows.Count -gt 0) {
            $hw = $response.rows[0]
        } elseif ($response.id) {
            $hw = $response
        }

        if (-not $hw) {
            Write-Log "Snipe-IT: no asset found for $Field = '$Value'" -Level WARNING
            return $null
        }

        # Build standardized object (same format as Get-SnipeItAssets)
        $assignedTo = ""
        if ($hw.assigned_to -and $hw.assigned_to.name) {
            $assignedTo = [string]$hw.assigned_to.name
        }
        $locationName = ""
        if ($hw.location -and $hw.location.name) {
            $locationName = [string]$hw.location.name
        }

        $result = [PSCustomObject]@{
            Id             = [int]$hw.id
            Name           = [string]$hw.name
            AssetTag       = [string]$hw.asset_tag
            Serial         = [string]$hw.serial
            Model          = if ($hw.model -and $hw.model.name) { [string]$hw.model.name } else { "" }
            Category       = if ($hw.category -and $hw.category.name) { [string]$hw.category.name } else { "" }
            Status         = if ($hw.status_label -and $hw.status_label.name) { [string]$hw.status_label.name } else { "" }
            AssignedTo     = $assignedTo
            Location       = $locationName
            IPAddress      = ""
            MACAddress     = ""
            PurchaseDate   = if ($hw.purchase_date) { [string]$hw.purchase_date } else { "" }
            WarrantyExpiry = if ($hw.warranty_expires) { [string]$hw.warranty_expires } else { "" }
            Notes          = if ($hw.notes) { [string]$hw.notes } else { "" }
        }

        Write-Log "Snipe-IT: found asset '$($result.Name)' (tag: $($result.AssetTag))" -Level INFO
        return $result
    } catch {
        Write-Log "Snipe-IT asset lookup failed: $($_.Exception.Message)" -Level ERROR
        return $null
    }
}

function Sync-AssetCache {
    <#
    .SYNOPSIS
        Pulls all Snipe-IT assets and saves them to data/asset-cache.json
        for offline enrichment use. Call manually or on a schedule.
    #>

    # Validate connector
    if (-not $Script:Connectors.ContainsKey('snipeit') -or
        $Script:Connectors['snipeit'].Status -ne 'Connected') {
        Write-Log "Snipe-IT connector is not connected. Call Connect-SnipeIt first." -Level ERROR
        return
    }

    try {
        Write-Log "Starting full Snipe-IT asset cache sync ..." -Level INFO

        # Pull all assets (high limit)
        $assets = Get-SnipeItAssets -Limit 50000

        if (-not $assets -or $assets.Count -eq 0) {
            Write-Log "No assets returned from Snipe-IT -- cache not updated" -Level WARNING
            return
        }

        # Determine cache file path
        $scriptRoot = $PSScriptRoot
        if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
        $projectRoot = Split-Path -Parent $scriptRoot  # up from connectors/
        $dataDir     = Join-Path $projectRoot "data"

        if (-not (Test-Path $dataDir)) {
            New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
        }

        $cacheFile = Join-Path $dataDir "asset-cache.json"

        $cacheObj = @{
            SyncTime   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Server     = $Script:Connectors['snipeit'].Config.Server
            AssetCount = $assets.Count
            Assets     = $assets
        }

        $cacheObj | ConvertTo-Json -Depth 5 | Set-Content -Path $cacheFile -Encoding UTF8 -Force

        Write-Log "Asset cache saved to $cacheFile ($($assets.Count) assets)" -Level INFO
    } catch {
        Write-Log "Asset cache sync failed: $($_.Exception.Message)" -Level ERROR
    }
}
