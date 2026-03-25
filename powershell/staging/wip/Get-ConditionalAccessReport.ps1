<#
.SYNOPSIS
    Exports all Conditional Access policies with state, conditions, and grant controls.

.DESCRIPTION
    Authenticates to Microsoft Graph using client credentials (app registration),
    retrieves all Conditional Access policies with pagination, flattens conditions
    and controls into a tabular format, and exports the result to a CSV file.
    A color-coded console summary is printed at the end highlighting policies
    without grant controls and policies targeting all users.

.NOTES
    Author:       Michael Whelan
    Created:      2026-03-14
    Dependencies: None. Uses Invoke-RestMethod (built-in).
                  Requires an Entra ID app registration with Policy.Read.All permission.

.EXAMPLE
    .\Get-ConditionalAccessReport.ps1
    Retrieves all CA policies and exports to
    $PSScriptRoot\output\ConditionalAccessReport_<timestamp>.csv

.EXAMPLE
    .\Get-ConditionalAccessReport.ps1
    Runs with default configuration; override tenant credentials via environment
    variables ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET.
#>
#Requires -Version 5.1

# =============================================================================
# CONFIGURATION
# =============================================================================
$Config = @{
    ScriptName   = "Get-ConditionalAccessReport"
    LogDir       = "$PSScriptRoot\logs"
    OutputDir    = "$PSScriptRoot\output"

    # --- Entra ID / Graph API credentials ---
    TenantId     = if ($env:ENTRA_TENANT_ID)     { $env:ENTRA_TENANT_ID }     else { "<YOUR_TENANT_ID>" }
    ClientId     = if ($env:ENTRA_CLIENT_ID)     { $env:ENTRA_CLIENT_ID }     else { "<YOUR_CLIENT_ID>" }
    ClientSecret = if ($env:ENTRA_CLIENT_SECRET) { $env:ENTRA_CLIENT_SECRET } else { "<YOUR_CLIENT_SECRET>" }
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

# Write-Summary: colored console output + plain text to log file
function Write-Summary {
    param([string]$Line, [string]$Color = "White")
    Write-Host $Line -ForegroundColor $Color
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $Line }
}


# --- Functions ---

function Get-GraphToken {
    param([string]$TenantId, [string]$ClientId, [string]$ClientSecret)

    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }
    $response = Invoke-RestMethod -Method POST -Uri $tokenUrl -Body $body -ContentType "application/x-www-form-urlencoded"
    return $response.access_token
}

function Get-PagedResults {
    param([string]$Url, [string]$Token)

    $headers = @{ Authorization = "Bearer $Token" }
    $results = [System.Collections.Generic.List[object]]::new()

    while ($Url) {
        $response = $null
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                $response = Invoke-RestMethod -Method GET -Uri $Url -Headers $headers
                break
            } catch {
                $statusCode = $_.Exception.Response.StatusCode.value__
                if ($statusCode -eq 429 -or ($statusCode -ge 500 -and $statusCode -le 599)) {
                    if ($attempt -eq 3) { throw }
                    $retryAfter = 5
                    if ($statusCode -eq 429) {
                        $retryHeader = $_.Exception.Response.Headers['Retry-After']
                        if ($retryHeader) { $retryAfter = [int]$retryHeader }
                    }
                    Write-Log "HTTP $statusCode on attempt $attempt/3 — retrying in ${retryAfter}s..." -Level WARNING
                    Start-Sleep -Seconds $retryAfter
                } else {
                    throw
                }
            }
        }
        $results.AddRange($response.value)
        $Url = $response.'@odata.nextLink'
        if ($Url) { Write-Log "Fetching next page ($($results.Count) policies so far)..." }
    }

    return $results
}


# --- Main ---

try {
    Write-Log "Starting $($Config.ScriptName)"

    # Validate placeholders
    foreach ($key in @("TenantId", "ClientId", "ClientSecret")) {
        if ($Config[$key] -like "<*>") {
            throw "Config '$key' is not set. Set the environment variable or edit the config block."
        }
    }

    Write-Log "Acquiring Graph API token..."
    $token = Get-GraphToken -TenantId $Config.TenantId -ClientId $Config.ClientId -ClientSecret $Config.ClientSecret

    Write-Log "Retrieving Conditional Access policies..."
    $policies = Get-PagedResults -Url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Token $token

    Write-Log "Retrieved $($policies.Count) policy(ies)"

    if ($policies.Count -eq 0) {
        Write-Log "No policies found. Exiting." -Level WARNING
        exit 0
    }

    # Flatten policies into tabular format
    $results = $policies | ForEach-Object {
        $policy = $_

        # Conditions — Users
        $includeUsers      = ($policy.conditions.users.includeUsers      -join ";")
        $excludeUsers      = ($policy.conditions.users.excludeUsers      -join ";")
        $includeGroups     = ($policy.conditions.users.includeGroups     -join ";")
        $excludeGroups     = ($policy.conditions.users.excludeGroups     -join ";")

        # Conditions — Applications
        $includeApps       = ($policy.conditions.applications.includeApplications -join ";")
        $excludeApps       = ($policy.conditions.applications.excludeApplications -join ";")

        # Conditions — Client app types
        $clientAppTypes    = ($policy.conditions.clientAppTypes -join ";")

        # Conditions — Platforms
        $platforms = if ($policy.conditions.platforms -and $policy.conditions.platforms.includePlatforms) {
            ($policy.conditions.platforms.includePlatforms -join ";")
        } else { "" }

        # Conditions — Locations
        $locations = if ($policy.conditions.locations -and $policy.conditions.locations.includeLocations) {
            ($policy.conditions.locations.includeLocations -join ";")
        } else { "" }

        # Grant controls
        $grantControls = if ($policy.grantControls -and $policy.grantControls.builtInControls) {
            ($policy.grantControls.builtInControls -join ";")
        } else { "" }

        # Session controls
        $sessionControls = if ($policy.sessionControls -and (
            $policy.sessionControls.applicationEnforcedRestrictions -or
            $policy.sessionControls.cloudAppSecurity -or
            $policy.sessionControls.signInFrequency -or
            $policy.sessionControls.persistentBrowser
        )) { "Present" } else { "None" }

        # Report-only flag
        $isReportOnly = $policy.state -eq "enabledForReportingButNotEnforced"

        [PSCustomObject]@{
            DisplayName           = $policy.displayName
            State                 = $policy.state
            IsReportOnly          = $isReportOnly
            CreatedDateTime       = $policy.createdDateTime
            ModifiedDateTime      = $policy.modifiedDateTime
            IncludeUsers          = $includeUsers
            ExcludeUsers          = $excludeUsers
            IncludeGroups         = $includeGroups
            ExcludeGroups         = $excludeGroups
            IncludeApplications   = $includeApps
            ExcludeApplications   = $excludeApps
            ClientAppTypes        = $clientAppTypes
            Platforms             = $platforms
            Locations             = $locations
            GrantControls         = $grantControls
            SessionControls       = $sessionControls
        }
    }

    # Calculate summary stats
    $enabledCount    = @($policies | Where-Object { $_.state -eq "enabled" }).Count
    $disabledCount   = @($policies | Where-Object { $_.state -eq "disabled" }).Count
    $reportOnlyCount = @($policies | Where-Object { $_.state -eq "enabledForReportingButNotEnforced" }).Count

    Write-Log "Total policies: $($policies.Count)"
    Write-Log "Enabled: $enabledCount, Disabled: $disabledCount, Report-only: $reportOnlyCount"

    # Export to CSV
    if (-not (Test-Path $Config.OutputDir)) { New-Item -ItemType Directory -Path $Config.OutputDir | Out-Null }
    $outputFile = Join-Path $Config.OutputDir (
        "ConditionalAccessReport_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss")
    )
    $results | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8

    Write-Log "Exported to $outputFile"

    # --- Console summary ---

    $separator    = [string]::new([char]0x2550, 60)
    $divider      = [string]::new([char]0x2500, 60)
    $displayTime  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    Write-Summary ""
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary "  Conditional Access Report  —  $displayTime"                    -Color Yellow
    Write-Summary "  Tenant: $($Config.TenantId)"                                   -Color Yellow
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary ""

    # POLICY STATE BREAKDOWN
    Write-Summary "  POLICY STATE BREAKDOWN"                                        -Color Cyan
    Write-Summary $divider                                                          -Color Cyan
    Write-Summary ("  Enabled:      {0,5}" -f $enabledCount)                        -Color Green
    Write-Summary ("  Disabled:     {0,5}" -f $disabledCount)                       -Color $(if ($disabledCount -gt 0) { "DarkGray" } else { "Green" })
    Write-Summary ("  Report-only:  {0,5}" -f $reportOnlyCount)
    Write-Summary ""

    # POLICIES WITHOUT GRANT CONTROLS
    $noGrantPolicies = @($results | Where-Object { $_.GrantControls -eq "" })
    if ($noGrantPolicies.Count -gt 0) {
        Write-Summary "  POLICIES WITHOUT GRANT CONTROLS ($($noGrantPolicies.Count))" -Color Cyan
        Write-Summary $divider                                                      -Color Cyan
        foreach ($p in $noGrantPolicies) {
            $line = "  [{0,-10}]  {1}" -f $p.State, $p.DisplayName
            Write-Summary $line                                                     -Color Red
        }
        Write-Summary ""
    }

    # ALL-USERS POLICIES
    $allUsersPolicies = @($results | Where-Object { $_.IncludeUsers -match "All" })
    if ($allUsersPolicies.Count -gt 0) {
        Write-Summary "  ALL-USERS POLICIES ($($allUsersPolicies.Count))"           -Color Cyan
        Write-Summary $divider                                                      -Color Cyan
        foreach ($p in $allUsersPolicies) {
            $controls = if ($p.GrantControls) { $p.GrantControls } else { "(none)" }
            $line = "  [{0,-10}]  {1,-35}  grants: {2}" -f $p.State, $p.DisplayName, $controls
            Write-Summary $line
        }
        Write-Summary ""
    }

    # Final totals
    Write-Summary $separator                                                        -Color Cyan
    Write-Summary ("  TOTAL: {0} policies  |  {1} enabled  |  {2} disabled  |  {3} report-only" -f
        $policies.Count, $enabledCount, $disabledCount, $reportOnlyCount)           -Color Cyan
    Write-Summary "  CSV: $outputFile"                                              -Color Cyan
    Write-Summary $separator                                                        -Color Cyan
    Write-Summary ""

    Write-Log "Completed $($Config.ScriptName) successfully"
    exit 0
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    exit 1
}
