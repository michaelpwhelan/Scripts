<#
.SYNOPSIS
    Lists members of one or more Entra ID groups via Microsoft Graph and exports to CSV.

.DESCRIPTION
    Authenticates to Microsoft Graph using client credentials, looks up each
    configured group by display name or object ID, retrieves all direct members
    (with transitive member support optional), and exports to a timestamped CSV.
    One output file is produced per group, plus a combined file when querying
    multiple groups.

.NOTES
    Author:       Your Name
    Created:      YYYY-MM-DD
    Version:      1.0.0
    Dependencies: None. Uses Invoke-RestMethod (built-in).
                  Requires an Entra ID app registration with:
                    - Group.Read.All
                    - User.Read.All

.EXAMPLE
    .\Get-GroupMembers.ps1
    Exports members of all configured groups to .\output\.
#>
#Requires -Version 5.1

# =============================================================================
# CONFIGURATION — Edit these variables before running
# =============================================================================
$Config = @{
    # --- General ---
    ScriptName = "Get-GroupMembers"
    LogDir     = ".\logs"
    OutputDir  = ".\output"

    # --- Entra ID / Graph API credentials ---
    TenantId     = if ($env:ENTRA_TENANT_ID)     { $env:ENTRA_TENANT_ID }     else { "<YOUR_TENANT_ID>" }
    ClientId     = if ($env:ENTRA_CLIENT_ID)     { $env:ENTRA_CLIENT_ID }     else { "<YOUR_CLIENT_ID>" }
    ClientSecret = if ($env:ENTRA_CLIENT_SECRET) { $env:ENTRA_CLIENT_SECRET } else { "<YOUR_CLIENT_SECRET>" }

    # --- Groups to query ---
    # Use display names or object IDs. Mix is supported.
    Groups = @(
        "IT Admins"
        # "00000000-0000-0000-0000-000000000000"
    )

    # Set to $true to expand nested groups (transitive members)
    TransitiveMembers = $false
}
# =============================================================================


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


# --- Functions ---

function Get-GraphToken {
    param([string]$TenantId, [string]$ClientId, [string]$ClientSecret)
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }
    $r = Invoke-RestMethod -Method POST `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Body $body -ContentType "application/x-www-form-urlencoded"
    return $r.access_token
}

function Get-PagedResults {
    param([string]$Token, [string]$Url)
    $headers = @{ Authorization = "Bearer $Token" }
    $items   = [System.Collections.Generic.List[object]]::new()
    while ($Url) {
        $r = Invoke-RestMethod -Method GET -Uri $Url -Headers $headers
        $items.AddRange($r.value)
        $Url = $r.'@odata.nextLink'
    }
    return $items
}

function Resolve-GroupId {
    param([string]$Token, [string]$GroupRef)
    $headers = @{ Authorization = "Bearer $Token" }
    # Try as GUID first
    if ($GroupRef -match '^[0-9a-fA-F-]{36}$') { return $GroupRef }
    # Otherwise search by displayName
    $encoded = [uri]::EscapeDataString($GroupRef)
    $r = Invoke-RestMethod -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$encoded'&`$select=id,displayName" `
        -Headers $headers
    if ($r.value.Count -eq 0) { throw "Group not found: '$GroupRef'" }
    return $r.value[0].id
}


# --- Main ---

try {
    Write-Log "Starting $($Config.ScriptName)"

    foreach ($key in @("TenantId", "ClientId", "ClientSecret")) {
        if ($Config[$key] -like "<*>") { throw "Config '$key' is not set." }
    }

    Write-Log "Acquiring Graph API token..."
    $token = Get-GraphToken -TenantId $Config.TenantId -ClientId $Config.ClientId -ClientSecret $Config.ClientSecret

    if (-not (Test-Path $Config.OutputDir)) { New-Item -ItemType Directory -Path $Config.OutputDir | Out-Null }
    $ts         = Get-Date -Format "yyyyMMdd_HHmmss"
    $allMembers = [System.Collections.Generic.List[PSCustomObject]]::new()
    $memberEndpoint = if ($Config.TransitiveMembers) { "transitiveMembers" } else { "members" }

    foreach ($groupRef in $Config.Groups) {
        Write-Log "Resolving group: $groupRef"
        try {
            $groupId = Resolve-GroupId -Token $token -GroupRef $groupRef

            $select  = "id,displayName,userPrincipalName,mail,department,jobTitle,accountEnabled"
            $url     = "https://graph.microsoft.com/v1.0/groups/$groupId/$memberEndpoint/microsoft.graph.user?`$select=$select&`$top=999"
            $members = Get-PagedResults -Token $token -Url $url

            Write-Log "Group '$groupRef' — $($members.Count) member(s)"

            $rows = $members | ForEach-Object {
                [PSCustomObject]@{
                    GroupRef          = $groupRef
                    GroupId           = $groupId
                    DisplayName       = $_.displayName
                    UserPrincipalName = $_.userPrincipalName
                    Mail              = $_.mail
                    Department        = $_.department
                    JobTitle          = $_.jobTitle
                    AccountEnabled    = $_.accountEnabled
                }
            }

            # Per-group file
            $safeName   = $groupRef -replace '[\\/:*?"<>|]', '_'
            $groupFile  = Join-Path $Config.OutputDir "GroupMembers_${safeName}_${ts}.csv"
            $rows | Export-Csv -Path $groupFile -NoTypeInformation -Encoding UTF8
            Write-Log "Exported '$groupRef' to $groupFile"

            $allMembers.AddRange($rows)
        } catch {
            Write-Log "Failed for group '$groupRef': $_" -Level ERROR
        }
    }

    # Combined file (only written when querying multiple groups)
    if ($Config.Groups.Count -gt 1 -and $allMembers.Count -gt 0) {
        $combinedFile = Join-Path $Config.OutputDir "GroupMembers_All_${ts}.csv"
        $allMembers | Export-Csv -Path $combinedFile -NoTypeInformation -Encoding UTF8
        Write-Log "Combined export: $combinedFile"
    }

    Write-Log "Completed $($Config.ScriptName) successfully"
    exit 0
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    exit 1
}
