# ═══════════════════════════════════════════════════════════════════════════════
# TOPOLOGY ENGINE — Network topology awareness for correlation and analysis
# ═══════════════════════════════════════════════════════════════════════════════

$Script:Topology = $null

function Initialize-Topology {
    $topoPath = Join-Path $Config.ScriptRoot "data" "topology.json"
    if (Test-Path $topoPath) {
        try {
            $content = [System.IO.File]::ReadAllText($topoPath)
            $Script:Topology = $content | ConvertFrom-Json
            Write-Log "Loaded network topology ($($Script:Topology.sites.PSObject.Properties.Count) sites)"
        } catch {
            Write-Log "Failed to load topology: $_" -Level WARNING
        }
    }
}

function Get-SiteInfo {
    param([string]$SiteCode)
    if (-not $Script:Topology -or -not $Script:Topology.sites) { return $null }
    $site = $Script:Topology.sites.PSObject.Properties | Where-Object { $_.Name -eq $SiteCode } | Select-Object -First 1
    if ($site) {
        return @{
            Code          = $SiteCode
            Role          = $site.Value.role
            Description   = $site.Value.description
            WanLinks      = @($site.Value.wan_links)
            HasServerInfra = [bool]$site.Value.has_server_infra
            IsDrSite      = [bool]$site.Value.is_dr_site
            Notes         = $site.Value.notes
        }
    }
    return $null
}

function Get-SiteRole {
    param([string]$SiteCode)
    $info = Get-SiteInfo $SiteCode
    if ($info) { return $info.Role }
    return "unknown"
}

function Get-AllSites {
    if (-not $Script:Topology -or -not $Script:Topology.sites) {
        return @{ Hubs = @(); DrHubs = @(); Spokes = @() }
    }

    $hubs = [System.Collections.Generic.List[string]]::new()
    $drHubs = [System.Collections.Generic.List[string]]::new()
    $spokes = [System.Collections.Generic.List[string]]::new()

    foreach ($prop in $Script:Topology.sites.PSObject.Properties) {
        $code = $prop.Name
        $role = $prop.Value.role
        switch ($role) {
            'hub'     { $hubs.Add($code) }
            'dr_hub'  { $drHubs.Add($code) }
            'spoke'   { $spokes.Add($code) }
            default   { $spokes.Add($code) }
        }
    }

    return @{
        Hubs   = @($hubs)
        DrHubs = @($drHubs)
        Spokes = @($spokes)
    }
}

function Get-TrafficPath {
    param(
        [string]$FromSite,
        [string]$ToSite
    )

    if (-not $Script:Topology -or -not $Script:Topology.sites) {
        return @{ Path = @($FromSite, $ToSite); Tunnels = @(); Notes = @("Topology not loaded") }
    }

    $fromRole = Get-SiteRole $FromSite
    $toRole = Get-SiteRole $ToSite

    $path = [System.Collections.Generic.List[string]]::new()
    $tunnels = [System.Collections.Generic.List[string]]::new()
    $notes = [System.Collections.Generic.List[string]]::new()

    # Determine the primary hub for transit routing
    $allSites = Get-AllSites
    $primaryHub = if ($allSites.Hubs.Count -gt 0) { $allSites.Hubs[0] } else { $null }

    if ($FromSite -eq $ToSite) {
        $path.Add($FromSite)
        $notes.Add("Same site - local traffic")
    }
    elseif ($fromRole -eq 'hub' -and $toRole -eq 'spoke') {
        # Hub to spoke: direct tunnel
        $path.Add($FromSite)
        $path.Add($ToSite)
        $tunnelKey = Get-TunnelKeyForPair $ToSite $FromSite
        if ($tunnelKey) { $tunnels.Add($tunnelKey) }
    }
    elseif ($fromRole -eq 'spoke' -and $toRole -eq 'hub') {
        # Spoke to hub: direct tunnel
        $path.Add($FromSite)
        $path.Add($ToSite)
        $tunnelKey = Get-TunnelKeyForPair $FromSite $ToSite
        if ($tunnelKey) { $tunnels.Add($tunnelKey) }
    }
    elseif ($fromRole -eq 'spoke' -and $toRole -eq 'spoke') {
        # Spoke to spoke: via primary hub
        $path.Add($FromSite)
        if ($primaryHub) {
            $path.Add($primaryHub)
            $tunnelFrom = Get-TunnelKeyForPair $FromSite $primaryHub
            $tunnelTo = Get-TunnelKeyForPair $ToSite $primaryHub
            if ($tunnelFrom) { $tunnels.Add($tunnelFrom) }
            if ($tunnelTo) { $tunnels.Add($tunnelTo) }
            $notes.Add("Spoke-to-spoke traffic transits hub $primaryHub")
        }
        $path.Add($ToSite)
    }
    elseif ($fromRole -eq 'hub' -and $toRole -eq 'dr_hub') {
        # Hub to DR hub: direct tunnel
        $path.Add($FromSite)
        $path.Add($ToSite)
        $tunnelKey = Get-TunnelKeyForPair $ToSite $FromSite
        if ($tunnelKey) { $tunnels.Add($tunnelKey) }
    }
    elseif ($fromRole -eq 'dr_hub' -and $toRole -eq 'hub') {
        # DR hub to hub: direct tunnel
        $path.Add($FromSite)
        $path.Add($ToSite)
        $tunnelKey = Get-TunnelKeyForPair $FromSite $ToSite
        if ($tunnelKey) { $tunnels.Add($tunnelKey) }
    }
    elseif ($fromRole -eq 'dr_hub' -and $toRole -eq 'spoke') {
        # DR hub to spoke: via primary hub
        $path.Add($FromSite)
        if ($primaryHub) {
            $path.Add($primaryHub)
            $tunnelDr = Get-TunnelKeyForPair $FromSite $primaryHub
            $tunnelSpoke = Get-TunnelKeyForPair $ToSite $primaryHub
            if ($tunnelDr) { $tunnels.Add($tunnelDr) }
            if ($tunnelSpoke) { $tunnels.Add($tunnelSpoke) }
            $notes.Add("DR-to-spoke traffic transits hub $primaryHub")
        }
        $path.Add($ToSite)
    }
    elseif ($fromRole -eq 'spoke' -and $toRole -eq 'dr_hub') {
        # Spoke to DR hub: via primary hub
        $path.Add($FromSite)
        if ($primaryHub) {
            $path.Add($primaryHub)
            $tunnelSpoke = Get-TunnelKeyForPair $FromSite $primaryHub
            $tunnelDr = Get-TunnelKeyForPair $ToSite $primaryHub
            if ($tunnelSpoke) { $tunnels.Add($tunnelSpoke) }
            if ($tunnelDr) { $tunnels.Add($tunnelDr) }
            $notes.Add("Spoke-to-DR traffic transits hub $primaryHub")
        }
        $path.Add($ToSite)
    }
    else {
        # Fallback: unknown topology relationship
        $path.Add($FromSite)
        $path.Add($ToSite)
        $notes.Add("Unknown topology relationship ($fromRole to $toRole)")
    }

    # Check each tunnel for transport-level notes
    foreach ($tKey in $tunnels) {
        $tInfo = Get-TunnelInfo -TunnelKey $tKey
        if ($tInfo -and $tInfo.Transport -eq 'tcp') {
            $notes.Add("TCP transport required on tunnel $tKey")
        }
    }

    return @{
        Path    = @($path)
        Tunnels = @($tunnels)
        Notes   = @($notes)
    }
}

function Get-TunnelKeyForPair {
    param(
        [string]$Site1,
        [string]$Site2
    )
    if (-not $Script:Topology -or -not $Script:Topology.tunnels) { return $null }

    foreach ($prop in $Script:Topology.tunnels.PSObject.Properties) {
        $endpoints = @($prop.Value.endpoints)
        if (($endpoints -contains $Site1) -and ($endpoints -contains $Site2)) {
            return $prop.Name
        }
    }
    return $null
}

function Get-TunnelInfo {
    param(
        [string]$Site1,
        [string]$Site2,
        [string]$TunnelKey
    )
    if (-not $Script:Topology -or -not $Script:Topology.tunnels) { return $null }

    # If a direct tunnel key was provided, look it up
    if ($TunnelKey) {
        $tunnel = $Script:Topology.tunnels.PSObject.Properties | Where-Object { $_.Name -eq $TunnelKey } | Select-Object -First 1
        if ($tunnel) {
            return @{
                Key       = $TunnelKey
                Type      = $tunnel.Value.type
                Endpoints = @($tunnel.Value.endpoints)
                Transport = $tunnel.Value.transport
                Members   = $tunnel.Value.members
                Notes     = $tunnel.Value.notes
            }
        }
        return $null
    }

    # Otherwise search by site pair
    if (-not $Site1 -or -not $Site2) { return $null }

    foreach ($prop in $Script:Topology.tunnels.PSObject.Properties) {
        $endpoints = @($prop.Value.endpoints)
        if (($endpoints -contains $Site1) -and ($endpoints -contains $Site2)) {
            return @{
                Key       = $prop.Name
                Type      = $prop.Value.type
                Endpoints = @($prop.Value.endpoints)
                Transport = $prop.Value.transport
                Members   = $prop.Value.members
                Notes     = $prop.Value.notes
            }
        }
    }
    return $null
}

function Get-AffectedSites {
    param([string]$SiteCode)

    if (-not $Script:Topology -or -not $Script:Topology.sites) { return @($SiteCode) }

    $role = Get-SiteRole $SiteCode
    if ($role -eq 'spoke') {
        return @($SiteCode)
    }

    # For hub or dr_hub, find all spokes that route through this site
    $affected = [System.Collections.Generic.List[string]]::new()
    $affected.Add($SiteCode)

    if ($role -eq 'hub') {
        # A hub outage affects all spokes that tunnel through it
        if ($Script:Topology.tunnels) {
            foreach ($prop in $Script:Topology.tunnels.PSObject.Properties) {
                $endpoints = @($prop.Value.endpoints)
                if ($endpoints -contains $SiteCode) {
                    foreach ($ep in $endpoints) {
                        if ($ep -ne $SiteCode -and -not $affected.Contains($ep)) {
                            $affected.Add($ep)
                        }
                    }
                }
            }
        }
    }
    elseif ($role -eq 'dr_hub') {
        # A DR hub outage affects the hub-to-DR tunnel and any DR-dependent services
        if ($Script:Topology.tunnels) {
            foreach ($prop in $Script:Topology.tunnels.PSObject.Properties) {
                $endpoints = @($prop.Value.endpoints)
                if ($endpoints -contains $SiteCode) {
                    foreach ($ep in $endpoints) {
                        if ($ep -ne $SiteCode -and -not $affected.Contains($ep)) {
                            $affected.Add($ep)
                        }
                    }
                }
            }
        }
    }

    return @($affected)
}

function Resolve-SiteFromEvent {
    param($Entry)

    if (-not $Entry) { return $null }
    if (-not $Script:Topology -or -not $Script:Topology.sites) { return $null }

    # Collect all known site codes for validation
    $knownSites = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($prop in $Script:Topology.sites.PSObject.Properties) {
        $knownSites.Add($prop.Name) | Out-Null
    }

    # 1. Try Entry.Extra['devname'] - FortiGate device names contain site codes (e.g., "FG-009", "FG009", "FW-009")
    if ($Entry.Extra -and $Entry.Extra['devname']) {
        $devname = [string]$Entry.Extra['devname']
        if ($devname -match '(?:FG|FW|SW|AP|FS)[-_]?(\d{3})') {
            $candidate = $Matches[1]
            if ($knownSites.Contains($candidate)) { return $candidate }
        }
    }

    # 2. Try Entry.Extra['srcip'] or Entry.Host - IP subnet to site mapping
    $ipCandidates = @()
    if ($Entry.Extra -and $Entry.Extra['srcip']) { $ipCandidates += [string]$Entry.Extra['srcip'] }
    if ($Entry.Host) { $ipCandidates += [string]$Entry.Host }
    if ($Entry.Extra -and $Entry.Extra['dstip']) { $ipCandidates += [string]$Entry.Extra['dstip'] }

    foreach ($ip in $ipCandidates) {
        if (-not $ip) { continue }
        $resolved = Resolve-SiteFromIp $ip
        if ($resolved) { return $resolved }
    }

    # 3. Try Entry.Extra['TunnelName'] - tunnel names contain site codes (e.g., "H012-H009", "S001-H009")
    if ($Entry.Extra -and $Entry.Extra['TunnelName']) {
        $tunnelName = [string]$Entry.Extra['TunnelName']
        $tunnelMatches = [regex]::Matches($tunnelName, '[HShs](\d{3})')
        foreach ($m in $tunnelMatches) {
            $candidate = $m.Groups[1].Value
            if ($knownSites.Contains($candidate)) { return $candidate }
        }
        # Also try bare 3-digit codes in tunnel names
        $bareMatches = [regex]::Matches($tunnelName, '(\d{3})')
        foreach ($m in $bareMatches) {
            $candidate = $m.Groups[1].Value
            if ($knownSites.Contains($candidate)) { return $candidate }
        }
    }

    # 4. Try Entry.Source - source field may contain device or site identifiers
    if ($Entry.Source) {
        $source = [string]$Entry.Source
        if ($source -match '(?:FG|FW|SW|AP|FS|site)[-_]?(\d{3})') {
            $candidate = $Matches[1]
            if ($knownSites.Contains($candidate)) { return $candidate }
        }
    }

    # 5. Fallback: scan Message for device name patterns with 3-digit site codes
    if ($Entry.Message) {
        $msg = [string]$Entry.Message
        if ($msg -match '(?:FG|FW|SW|AP|FS|site)[-_]?(\d{3})') {
            $candidate = $Matches[1]
            if ($knownSites.Contains($candidate)) { return $candidate }
        }
    }

    return $null
}

function Resolve-SiteFromIp {
    param([string]$IpAddress)

    if (-not $IpAddress -or -not $Script:Topology -or -not $Script:Topology.ip_subnets) { return $null }

    # Parse the IP address into octets for subnet matching
    $parts = $IpAddress.Split('.')
    if ($parts.Count -ne 4) { return $null }

    try {
        $octet1 = [int]$parts[0]
        $octet2 = [int]$parts[1]
    } catch {
        return $null
    }

    # Check each site's subnets
    foreach ($prop in $Script:Topology.ip_subnets.PSObject.Properties) {
        $siteCode = $prop.Name
        foreach ($subnetProp in $prop.Value.PSObject.Properties) {
            $subnet = $subnetProp.Value
            if (-not $subnet) { continue }

            # Parse CIDR notation (e.g., "10.9.0.0/16", "10.9.1.0/24")
            $cidrParts = $subnet.Split('/')
            if ($cidrParts.Count -ne 2) { continue }

            $netParts = $cidrParts[0].Split('.')
            if ($netParts.Count -ne 4) { continue }

            try {
                $mask = [int]$cidrParts[1]
                $netOctet1 = [int]$netParts[0]
                $netOctet2 = [int]$netParts[1]
                $netOctet3 = [int]$netParts[2]
            } catch {
                continue
            }

            $match = $false
            if ($mask -le 8) {
                $match = ($octet1 -eq $netOctet1)
            }
            elseif ($mask -le 16) {
                $match = ($octet1 -eq $netOctet1 -and $octet2 -eq $netOctet2)
            }
            elseif ($mask -le 24) {
                $octet3 = [int]$parts[2]
                $match = ($octet1 -eq $netOctet1 -and $octet2 -eq $netOctet2 -and $octet3 -eq $netOctet3)
            }

            if ($match) { return $siteCode }
        }
    }

    return $null
}

function Get-TopologySummary {
    if (-not $Script:Topology) {
        return @{
            SiteCount    = 0
            HubCount     = 0
            SpokeCount   = 0
            TunnelCount  = 0
            BgpPeerCount = 0
        }
    }

    $allSites = Get-AllSites
    $tunnelCount = 0
    $bgpPeerCount = 0

    if ($Script:Topology.tunnels) {
        $tunnelCount = @($Script:Topology.tunnels.PSObject.Properties).Count
    }

    if ($Script:Topology.bgp) {
        foreach ($prop in $Script:Topology.bgp.PSObject.Properties) {
            $bgpPeerCount += @($prop.Value.peers).Count
        }
    }

    return @{
        SiteCount    = $allSites.Hubs.Count + $allSites.DrHubs.Count + $allSites.Spokes.Count
        HubCount     = $allSites.Hubs.Count + $allSites.DrHubs.Count
        SpokeCount   = $allSites.Spokes.Count
        TunnelCount  = $tunnelCount
        BgpPeerCount = $bgpPeerCount
    }
}

function Get-SiteHealthFromEntries {
    param([System.Collections.Generic.List[object]]$Entries)

    $siteHealth = @{}

    if (-not $Entries -or $Entries.Count -eq 0) { return $siteHealth }

    # Group entries by resolved site code
    $siteEntries = @{}
    foreach ($entry in $Entries) {
        $siteCode = Resolve-SiteFromEvent $entry
        if (-not $siteCode) { continue }

        if (-not $siteEntries.ContainsKey($siteCode)) {
            $siteEntries[$siteCode] = [System.Collections.Generic.List[object]]::new()
        }
        $siteEntries[$siteCode].Add($entry)
    }

    foreach ($siteCode in $siteEntries.Keys) {
        $entries = $siteEntries[$siteCode]
        $role = Get-SiteRole $siteCode

        $criticalCount = 0
        $errorCount = 0
        $warningCount = 0
        $tunnelUpCount = 0
        $tunnelDownCount = 0
        $tunnelFlapCount = 0

        foreach ($entry in $entries) {
            switch ($entry.Level) {
                'CRITICAL' { $criticalCount++ }
                'ERROR'    { $errorCount++ }
                'WARNING'  { $warningCount++ }
            }

            # Check for tunnel status indicators in messages
            if ($entry.Message) {
                $msg = $entry.Message
                if ($msg -match 'tunnel.*up|SA.*established|phase[12].*completed') {
                    $tunnelUpCount++
                }
                elseif ($msg -match 'tunnel.*down|SA.*deleted|SA.*expired') {
                    $tunnelDownCount++
                }
            }

            # Check for tunnel flap indicators via action field
            if ($entry.Extra) {
                $action = $entry.Extra['action']
                if ($action -match 'tunnel-up') { $tunnelUpCount++ }
                elseif ($action -match 'tunnel-down') { $tunnelDownCount++ }
            }
        }

        # Determine tunnel status
        $tunnelStatus = "Unknown"
        if ($tunnelUpCount -gt 0 -or $tunnelDownCount -gt 0) {
            # Check for flapping: both up and down events with rapid alternation
            if ($tunnelUpCount -gt 2 -and $tunnelDownCount -gt 2) {
                $tunnelStatus = "Flapping"
                $tunnelFlapCount = [Math]::Min($tunnelUpCount, $tunnelDownCount)
            }
            elseif ($tunnelDownCount -gt $tunnelUpCount) {
                $tunnelStatus = "Down"
            }
            else {
                $tunnelStatus = "Up"
            }
        }

        # Calculate health score: GREEN / YELLOW / RED
        $health = "GREEN"
        if ($criticalCount -gt 0 -or $tunnelStatus -eq 'Down') {
            $health = "RED"
        }
        elseif ($errorCount -gt 5 -or $warningCount -gt 20 -or $tunnelStatus -eq 'Flapping') {
            $health = "RED"
        }
        elseif ($errorCount -gt 0 -or $warningCount -gt 5) {
            $health = "YELLOW"
        }

        # Hub health is more critical - lower thresholds
        if ($role -eq 'hub' -or $role -eq 'dr_hub') {
            if ($health -eq 'GREEN' -and ($errorCount -gt 0 -or $warningCount -gt 3)) {
                $health = "YELLOW"
            }
        }

        $siteHealth[$siteCode] = @{
            SiteCode      = $siteCode
            Role          = $role
            TotalEvents   = $entries.Count
            CriticalCount = $criticalCount
            ErrorCount    = $errorCount
            WarningCount  = $warningCount
            TunnelStatus  = $tunnelStatus
            Health        = $health
        }
    }

    return $siteHealth
}
