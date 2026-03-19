# Test-TopologyEngine.ps1 — Tests for the Topology Engine

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"

$Config = @{ ScriptRoot = $appRoot }
. "$appRoot\lib\TopologyEngine.ps1"

Invoke-Test "TopologyEngine: Initialize-Topology loads without error" {
    # This may or may not find a topology.json, but should not throw
    Initialize-Topology
    # If topology file exists, $Script:Topology should be loaded
    $topoPath = Join-Path $appRoot "data" "topology.json"
    if (Test-Path $topoPath) {
        Assert-NotNull $Script:Topology "Topology should be loaded when file exists"
    }
}

Invoke-Test "TopologyEngine: Get-AllSites returns structured result" {
    Initialize-Topology
    $sites = Get-AllSites
    Assert-NotNull $sites "Sites result should not be null"
    Assert-True ($sites.ContainsKey('Hubs')) "Should have Hubs key"
    Assert-True ($sites.ContainsKey('DrHubs')) "Should have DrHubs key"
    Assert-True ($sites.ContainsKey('Spokes')) "Should have Spokes key"
}

Invoke-Test "TopologyEngine: Get-SiteInfo returns null for unknown site" {
    Initialize-Topology
    $result = Get-SiteInfo -SiteCode "NONEXISTENT-XYZ"
    Assert-Null $result "Unknown site should return null"
}

Invoke-Test "TopologyEngine: Get-SiteRole returns 'unknown' for missing site" {
    Initialize-Topology
    $role = Get-SiteRole -SiteCode "NONEXISTENT-XYZ"
    Assert-Equal "unknown" $role "Missing site should return 'unknown' role"
}

Invoke-Test "TopologyEngine: Get-TrafficPath returns path structure" {
    Initialize-Topology
    $path = Get-TrafficPath -FromSite "SITE-A" -ToSite "SITE-B"
    Assert-NotNull $path "Traffic path should not be null"
    Assert-True ($path.ContainsKey('Path')) "Should have Path key"
    Assert-True ($path.ContainsKey('Tunnels')) "Should have Tunnels key"
}

Invoke-Test "TopologyEngine: Get-TopologySummary returns summary" {
    Initialize-Topology
    $summary = Get-TopologySummary
    Assert-NotNull $summary "Topology summary should not be null"
}

Invoke-Test "TopologyEngine: Get-SiteInfo returns site details when topology loaded" {
    Initialize-Topology
    if (-not $Script:Topology -or -not $Script:Topology.sites) {
        $Script:TestResults.Skipped++; return
    }
    $firstSite = $Script:Topology.sites.PSObject.Properties | Select-Object -First 1
    if ($firstSite) {
        $info = Get-SiteInfo -SiteCode $firstSite.Name
        Assert-NotNull $info "Should return site info for known site"
        Assert-Equal $firstSite.Name $info.Code
    }
}

Write-TestSummary
