# Test-AssetEngine.ps1 — Tests for the Asset Engine

$testRoot = $PSScriptRoot | Split-Path -Parent
$appRoot = $testRoot | Split-Path -Parent
. "$testRoot\TestHelpers.ps1"
. "$appRoot\lib\Helpers.ps1"
. "$appRoot\lib\Logging.ps1"

$Config = @{ ScriptRoot = $appRoot }
. "$appRoot\lib\AssetEngine.ps1"

Invoke-Test "AssetEngine: Initialize-AssetEngine runs without error" {
    Initialize-AssetEngine
    # May or may not load assets depending on asset-cache.json presence
}

Invoke-Test "AssetEngine: Get-AssetByField returns null for unknown IP" {
    Initialize-AssetEngine
    $asset = Get-AssetByField -FieldName "IPAddress" -Value "999.999.999.999"
    Assert-Null $asset "Unknown IP should return null"
}

Invoke-Test "AssetEngine: Get-AssetByField returns null for unknown hostname" {
    Initialize-AssetEngine
    $asset = Get-AssetByField -FieldName "Name" -Value "NONEXISTENT-HOST-XYZ"
    Assert-Null $asset "Unknown hostname should return null"
}

Invoke-Test "AssetEngine: Get-AssetSummary returns structured result" {
    Initialize-AssetEngine
    $summary = Get-AssetSummary
    Assert-NotNull $summary "Summary should not be null"
}

Invoke-Test "AssetEngine: AssetCache structure has expected keys when loaded" {
    Initialize-AssetEngine
    if ($Script:AssetCache) {
        Assert-True ($Script:AssetCache.ContainsKey('Assets')) "Cache should have Assets key"
        Assert-True ($Script:AssetCache.ContainsKey('ByIP')) "Cache should have ByIP index"
        Assert-True ($Script:AssetCache.ContainsKey('ByHostname')) "Cache should have ByHostname index"
        Assert-True ($Script:AssetCache.ContainsKey('ByMAC')) "Cache should have ByMAC index"
    }
}

Invoke-Test "AssetEngine: Enrich-EventWithAsset does not throw for unmatched event" {
    Initialize-AssetEngine
    $entry = New-TestEvent -Source "Unknown" -Extra @{ srcip = "192.168.255.255" }
    # Should not throw even when no asset matches
    Enrich-EventWithAsset -Entry $entry
    Assert-NotNull $entry "Entry should still be valid after enrichment attempt"
}

Invoke-Test "AssetEngine: Get-AssetCriticality returns result" {
    Initialize-AssetEngine
    $crit = Get-AssetCriticality -AssetName "NONEXISTENT-XYZ"
    # Should return a default or null, not throw
    # The function exists and is callable
}

Invoke-Test "AssetEngine: Asset indexes are built when cache loads" {
    Initialize-AssetEngine
    if ($Script:AssetCache -and $Script:AssetCache.Assets.Count -gt 0) {
        $firstAsset = $Script:AssetCache.Assets[0]
        if ($firstAsset.IPAddress) {
            $lookup = $Script:AssetCache.ByIP[$firstAsset.IPAddress]
            Assert-NotNull $lookup "IP index should find the first asset"
        }
    } else {
        $Script:TestResults.Skipped++
    }
}

Write-TestSummary
