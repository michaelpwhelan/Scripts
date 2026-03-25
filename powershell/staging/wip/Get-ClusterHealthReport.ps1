<#
.SYNOPSIS
    Checks Windows Failover Cluster health and exports node, resource,
    quorum, and CSV status to CSV.

.DESCRIPTION
    Queries one or more Windows Failover Clusters using the FailoverClusters
    module. Reports cluster node status and uptime, resource groups and their
    owner nodes, quorum configuration and witness health, and Cluster Shared
    Volume (CSV) capacity. Flags degraded nodes, failed or pending resources,
    and resources running on unexpected owner nodes. Results are exported to
    timestamped CSVs. A color-coded console summary is printed at the end.

.PARAMETER Clusters
    One or more cluster names to check. Overrides $Config.Clusters.

.NOTES
    Author:       Michael Whelan
    Created:      2026-03-14
    Dependencies: Requires FailoverClusters module (RSAT - Failover Clustering Tools).

.EXAMPLE
    .\Get-ClusterHealthReport.ps1
    Checks cluster health for clusters in $Config.Clusters and exports results to
    $PSScriptRoot\output\ClusterHealth_*_<timestamp>.csv

.EXAMPLE
    .\Get-ClusterHealthReport.ps1 -Clusters "cluster01.contoso.com","cluster02.contoso.com"
    Checks the two specified clusters.
#>
#Requires -Version 5.1
param(
    [string[]]$Clusters
)

# =============================================================================
# CONFIGURATION
# =============================================================================
$Config = @{
    ScriptName          = "Get-ClusterHealthReport"
    LogDir              = "$PSScriptRoot\logs"
    OutputDir           = "$PSScriptRoot\output"

    # --- Cluster names to check ---
    Clusters            = @(
        "cluster01.contoso.com"
        # "cluster02.contoso.com"
    )

    # --- CSV free space warning threshold (percent free) ---
    CsvFreeSpaceWarnPct = 20

    # --- Expected owner nodes per resource group (optional) ---
    # Format: @{ "SQL-Group" = "NODE01"; "FileServer-Group" = "NODE02" }
    ExpectedOwners      = @{}
}
# =============================================================================

# --- Parameter overrides ---
if ($PSBoundParameters.ContainsKey('Clusters')) { $Config.Clusters = $Clusters }

# --- Logging setup ---

$Script:LogFile = $null

if ($Config.LogDir) {
    if (-not (Test-Path $Config.LogDir)) { New-Item -ItemType Directory -Path $Config.LogDir | Out-Null }
    $Script:LogFile = Join-Path $Config.LogDir (
        "{0}_{1}.log" -f $Config.ScriptName, (Get-Date -Format "yyyyMMdd_HHmmss")
    )
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR")][string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"
    switch ($Level) {
        "INFO"    { Write-Host $line -ForegroundColor Cyan }
        "WARNING" { Write-Host $line -ForegroundColor Yellow }
        "ERROR"   { Write-Host $line -ForegroundColor Red }
    }
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $line }
}

# Write-Summary: colored console output + plain text to log file
function Write-Summary {
    param([string]$Line, [string]$Color = "White")
    Write-Host $Line -ForegroundColor $Color
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $Line }
}


# --- Functions ---

function Get-ClusterNodeHealth {
    param([string]$ClusterName)

    $rows = [System.Collections.Generic.List[PSCustomObject]]::new()
    $nodes = Get-ClusterNode -Cluster $ClusterName -ErrorAction Stop
    Write-Log "Found $($nodes.Count) node(s) in $ClusterName"

    foreach ($node in $nodes) {
        $isDegraded = ($node.State -ne "Up")
        $uptimeDays = -1

        try {
            $os = Get-CimInstance Win32_OperatingSystem -ComputerName $node.Name -ErrorAction Stop
            $uptimeDays = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
        } catch {
            Write-Log "Could not query uptime for node $($node.Name): $_" -Level WARNING
        }

        if ($isDegraded) {
            Write-Log "Node $($node.Name) is $($node.State)" -Level WARNING
        }

        $rows.Add([PSCustomObject]@{
            Cluster    = $ClusterName
            NodeName   = $node.Name
            State      = $node.State.ToString()
            NodeWeight = $node.NodeWeight
            UptimeDays = $uptimeDays
            IsDegraded = $isDegraded
            ReportedAt = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        })
    }

    return $rows
}

function Get-ClusterResourceHealth {
    param([string]$ClusterName, [hashtable]$ExpectedOwners)

    $rows = [System.Collections.Generic.List[PSCustomObject]]::new()
    $resources = Get-ClusterResource -Cluster $ClusterName -ErrorAction Stop
    Write-Log "Found $($resources.Count) resource(s) in $ClusterName"

    foreach ($resource in $resources) {
        $isFailed = ($resource.State -notin @("Online", "Offline"))
        $expectedOwner = $ExpectedOwners[$resource.OwnerGroup.ToString()]
        $isUnexpectedOwner = ($expectedOwner -and $resource.OwnerNode.ToString() -ne $expectedOwner)

        if ($isFailed) {
            Write-Log "Resource '$($resource.Name)' is $($resource.State)" -Level WARNING
        }
        if ($isUnexpectedOwner) {
            Write-Log "Resource '$($resource.Name)' on $($resource.OwnerNode) (expected $expectedOwner)" -Level WARNING
        }

        $rows.Add([PSCustomObject]@{
            Cluster           = $ClusterName
            ResourceName      = $resource.Name
            ResourceType      = $resource.ResourceType.ToString()
            State             = $resource.State.ToString()
            OwnerGroup        = $resource.OwnerGroup.ToString()
            OwnerNode         = $resource.OwnerNode.ToString()
            ExpectedOwner     = if ($expectedOwner) { $expectedOwner } else { "" }
            IsFailed          = $isFailed
            IsUnexpectedOwner = $isUnexpectedOwner
            ReportedAt        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        })
    }

    return $rows
}

function Get-ClusterQuorumHealth {
    param([string]$ClusterName)

    $rows = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $quorum = Get-ClusterQuorum -Cluster $ClusterName -ErrorAction Stop
        $witnessName  = if ($quorum.QuorumResource) { $quorum.QuorumResource.Name } else { "None" }
        $witnessState = if ($quorum.QuorumResource) { $quorum.QuorumResource.State.ToString() } else { "N/A" }
        $witnessType  = if ($quorum.QuorumResource) { $quorum.QuorumResource.ResourceType.ToString() } else { "N/A" }
        $isWitnessHealthy = ($witnessName -eq "None" -or $witnessState -eq "Online")

        if (-not $isWitnessHealthy) {
            Write-Log "Quorum witness '$witnessName' is $witnessState" -Level WARNING
        }

        $rows.Add([PSCustomObject]@{
            Cluster          = $ClusterName
            QuorumType       = $quorum.QuorumType.ToString()
            WitnessName      = $witnessName
            WitnessType      = $witnessType
            WitnessState     = $witnessState
            IsWitnessHealthy = $isWitnessHealthy
            ReportedAt       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        })
    } catch {
        Write-Log "Failed to query quorum for $ClusterName : $_" -Level ERROR
    }

    return $rows
}

function Get-ClusterCsvHealth {
    param([string]$ClusterName, [int]$FreeSpaceWarnPct)

    $rows = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $csvs = Get-ClusterSharedVolume -Cluster $ClusterName -ErrorAction SilentlyContinue
        if ($csvs) {
            Write-Log "Found $($csvs.Count) CSV(s) in $ClusterName"

            foreach ($csv in $csvs) {
                $volInfo   = $csv.SharedVolumeInfo[0]
                $partition = $volInfo.Partition

                $totalGB = [math]::Round($partition.Size / 1GB, 2)
                $freeGB  = [math]::Round($partition.FreeSpace / 1GB, 2)
                $usedGB  = [math]::Round(($partition.Size - $partition.FreeSpace) / 1GB, 2)
                $freePct = if ($partition.Size -gt 0) {
                    [math]::Round(($partition.FreeSpace / $partition.Size) * 100, 1)
                } else { 0 }

                $isLowSpace = ($freePct -lt $FreeSpaceWarnPct)

                if ($isLowSpace) {
                    Write-Log "CSV '$($csv.Name)' low space: $freePct% free ($freeGB GB)" -Level WARNING
                }

                $rows.Add([PSCustomObject]@{
                    Cluster    = $ClusterName
                    CsvName    = $csv.Name
                    CsvPath    = $volInfo.FriendlyVolumeName
                    OwnerNode  = $csv.OwnerNode.ToString()
                    State      = $csv.State.ToString()
                    TotalGB    = $totalGB
                    UsedGB     = $usedGB
                    FreeGB     = $freeGB
                    FreePct    = $freePct
                    IsLowSpace = $isLowSpace
                    ReportedAt = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
                })
            }
        } else {
            Write-Log "No Cluster Shared Volumes found in $ClusterName"
        }
    } catch {
        Write-Log "Failed to query CSVs for $ClusterName : $_" -Level ERROR
    }

    return $rows
}


# --- Main ---

try {
    Write-Log "Starting $($Config.ScriptName)"
    Write-Log "CSV free space warn threshold: $($Config.CsvFreeSpaceWarnPct)%"

    $nodeRows     = [System.Collections.Generic.List[PSCustomObject]]::new()
    $resourceRows = [System.Collections.Generic.List[PSCustomObject]]::new()
    $quorumRows   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $csvRows      = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($clusterName in $Config.Clusters) {
        Write-Log "Checking cluster: $clusterName"
        try {
            $clusterNodes = Get-ClusterNodeHealth -ClusterName $clusterName
            $clusterNodes | ForEach-Object { $nodeRows.Add($_) }

            $clusterResources = Get-ClusterResourceHealth -ClusterName $clusterName -ExpectedOwners $Config.ExpectedOwners
            $clusterResources | ForEach-Object { $resourceRows.Add($_) }

            $clusterQuorum = Get-ClusterQuorumHealth -ClusterName $clusterName
            $clusterQuorum | ForEach-Object { $quorumRows.Add($_) }

            $clusterCsvs = Get-ClusterCsvHealth -ClusterName $clusterName -FreeSpaceWarnPct $Config.CsvFreeSpaceWarnPct
            $clusterCsvs | ForEach-Object { $csvRows.Add($_) }
        } catch {
            Write-Log "Failed to query cluster $clusterName : $_" -Level ERROR
        }
    }

    if ($nodeRows.Count -eq 0) {
        Write-Log "No cluster data collected. Exiting." -Level WARNING
        exit 0
    }

    if (-not (Test-Path $Config.OutputDir)) { New-Item -ItemType Directory -Path $Config.OutputDir | Out-Null }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    # Export Nodes
    $nodesFile = Join-Path $Config.OutputDir "ClusterHealth_Nodes_${timestamp}.csv"
    $nodeRows | Export-Csv -Path $nodesFile -NoTypeInformation -Encoding UTF8
    Write-Log "Exported $($nodeRows.Count) node row(s) to $nodesFile"

    # Export Resources
    $resourcesFile = $null
    if ($resourceRows.Count -gt 0) {
        $resourcesFile = Join-Path $Config.OutputDir "ClusterHealth_Resources_${timestamp}.csv"
        $resourceRows | Export-Csv -Path $resourcesFile -NoTypeInformation -Encoding UTF8
        Write-Log "Exported $($resourceRows.Count) resource row(s) to $resourcesFile"
    }

    # Export Quorum
    $quorumFile = $null
    if ($quorumRows.Count -gt 0) {
        $quorumFile = Join-Path $Config.OutputDir "ClusterHealth_Quorum_${timestamp}.csv"
        $quorumRows | Export-Csv -Path $quorumFile -NoTypeInformation -Encoding UTF8
        Write-Log "Exported $($quorumRows.Count) quorum row(s) to $quorumFile"
    }

    # Export CSVs
    $csvFile = $null
    if ($csvRows.Count -gt 0) {
        $csvFile = Join-Path $Config.OutputDir "ClusterHealth_CSV_${timestamp}.csv"
        $csvRows | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
        Write-Log "Exported $($csvRows.Count) CSV row(s) to $csvFile"
    }

    # --- Console summary ---

    $separator    = [string]::new([char]0x2550, 60)
    $divider      = [string]::new([char]0x2500, 60)
    $displayTime  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $nodesUp      = @($nodeRows | Where-Object { $_.IsDegraded -eq $false }).Count
    $failedRes    = @($resourceRows | Where-Object { $_.IsFailed -eq $true }).Count
    $unexpectedOwn = @($resourceRows | Where-Object { $_.IsUnexpectedOwner -eq $true }).Count
    $lowSpaceCsv  = @($csvRows | Where-Object { $_.IsLowSpace -eq $true }).Count
    $quorumHealthy = @($quorumRows | Where-Object { $_.IsWitnessHealthy -eq $true }).Count

    Write-Summary ""
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary "  Cluster Health Report  —  $displayTime"                        -Color Yellow
    Write-Summary "  Clusters: $($Config.Clusters.Count)"                           -Color Yellow
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary ""

    # NODE STATUS — per-cluster
    Write-Summary "  NODE STATUS"                                                   -Color Cyan
    Write-Summary $divider                                                          -Color Cyan
    $nodesByCluster = $nodeRows | Group-Object -Property Cluster
    foreach ($cg in $nodesByCluster) {
        $up   = @($cg.Group | Where-Object { $_.IsDegraded -eq $false }).Count
        $down = @($cg.Group | Where-Object { $_.IsDegraded -eq $true }).Count
        $color = if ($down -gt 0) { "Red" } else { "Green" }
        $line = "  {0,-35}  up:{1,3}  down:{2,3}" -f $cg.Name, $up, $down
        Write-Summary $line                                                         -Color $color
    }
    Write-Summary ""

    # DEGRADED NODES
    $degradedNodes = @($nodeRows | Where-Object { $_.IsDegraded -eq $true })
    if ($degradedNodes.Count -gt 0) {
        Write-Summary "  DEGRADED NODES ($($degradedNodes.Count))"                  -Color Cyan
        Write-Summary $divider                                                      -Color Cyan
        foreach ($n in $degradedNodes) {
            $line = "  {0,-20}  state: {1,-12}  cluster: {2}" -f $n.NodeName, $n.State, $n.Cluster
            Write-Summary $line                                                     -Color Red
        }
        Write-Summary ""
    }

    # FAILED RESOURCES
    $failedResources = @($resourceRows | Where-Object { $_.IsFailed -eq $true })
    if ($failedResources.Count -gt 0) {
        Write-Summary "  FAILED RESOURCES ($($failedResources.Count))"              -Color Cyan
        Write-Summary $divider                                                      -Color Cyan
        foreach ($r in $failedResources) {
            $line = "  {0,-25}  state: {1,-12}  cluster: {2}" -f $r.ResourceName, $r.State, $r.Cluster
            Write-Summary $line                                                     -Color Red
        }
        Write-Summary ""
    }

    # LOW SPACE CSVs
    $lowSpaceCsvs = @($csvRows | Where-Object { $_.IsLowSpace -eq $true })
    if ($lowSpaceCsvs.Count -gt 0) {
        Write-Summary "  LOW SPACE CSVs ($($lowSpaceCsvs.Count))"                   -Color Cyan
        Write-Summary $divider                                                      -Color Cyan
        foreach ($c in $lowSpaceCsvs) {
            $line = "  {0,-25}  {1,5}% free  ({2} GB / {3} GB)  cluster: {4}" -f
                $c.CsvName, $c.FreePct, $c.FreeGB, $c.TotalGB, $c.Cluster
            Write-Summary $line                                                     -Color Red
        }
        Write-Summary ""
    }

    # QUORUM
    Write-Summary "  QUORUM"                                                        -Color Cyan
    Write-Summary $divider                                                          -Color Cyan
    foreach ($q in $quorumRows) {
        $color = if ($q.IsWitnessHealthy) { "Green" } else { "Red" }
        $line = "  {0,-35}  type: {1,-20}  witness: {2} ({3})" -f
            $q.Cluster, $q.QuorumType, $q.WitnessName, $q.WitnessState
        Write-Summary $line                                                         -Color $color
    }
    Write-Summary ""

    # Final totals
    Write-Summary $separator                                                        -Color Cyan
    Write-Summary ("  TOTAL: nodes {0}/{1} up  |  {2} failed resources  |  {3} low-space CSVs  |  quorum {4}/{5} healthy" -f
        $nodesUp, $nodeRows.Count, $failedRes, $lowSpaceCsv,
        $quorumHealthy, $quorumRows.Count)                                          -Color Cyan
    Write-Summary "  Nodes CSV:     $nodesFile"                                     -Color Cyan
    if ($resourcesFile) { Write-Summary "  Resources CSV: $resourcesFile"           -Color Cyan }
    if ($quorumFile)    { Write-Summary "  Quorum CSV:    $quorumFile"               -Color Cyan }
    if ($csvFile)       { Write-Summary "  CSV Volumes:   $csvFile"                  -Color Cyan }
    Write-Summary $separator                                                        -Color Cyan
    Write-Summary ""

    Write-Log "Completed $($Config.ScriptName) successfully"
    $hasIssues = ($degradedNodes.Count -gt 0 -or $failedRes -gt 0 -or $lowSpaceCsv -gt 0)
    if ($hasIssues) { exit 1 } else { exit 0 }
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    exit 1
}
