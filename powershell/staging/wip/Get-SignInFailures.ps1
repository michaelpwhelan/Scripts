<#
.SYNOPSIS
    Audits failed sign-in attempts from Entra ID sign-in logs via Microsoft Graph API.

.DESCRIPTION
    Authenticates to Microsoft Graph using client credentials (app registration),
    retrieves failed sign-in events from the audit logs within a configurable
    lookback window, exports a detail CSV of all failures, then produces a
    summary CSV grouping failures by user and flagging those who exceed the
    configured failure threshold. A color-coded console summary is printed
    at the end.

.PARAMETER LookbackHours
    Number of hours to look back for failed sign-ins. Overrides $Config.LookbackHours.
    Default: 24

.PARAMETER FailureThreshold
    Flag users with failure count at or above this value. Overrides $Config.FailureThreshold.
    Default: 10

.NOTES
    Author:       Michael Whelan
    Created:      2026-03-11
    Dependencies: None. Uses Invoke-RestMethod (built-in).
                  Requires an Entra ID app registration with
                  AuditLog.Read.All and Directory.Read.All permissions.
                  Requires Entra ID P1/P2 license.

.EXAMPLE
    .\Get-SignInFailures.ps1
    Retrieves failed sign-ins from the last 24 hours and exports to
    .\output\SignInFailures_<timestamp>.csv and .\output\SignInFailures_Summary_<timestamp>.csv

.EXAMPLE
    .\Get-SignInFailures.ps1 -LookbackHours 48 -FailureThreshold 5
    Looks back 48 hours and flags users with 5 or more failures.
#>
#Requires -Version 5.1
param(
    [int]$LookbackHours,
    [int]$FailureThreshold
)

# =============================================================================
# CONFIGURATION
# =============================================================================
$Config = @{
    ScriptName   = "Get-SignInFailures"
    LogDir       = "$PSScriptRoot\logs"    # Set to $null to disable file logging
    OutputDir    = "$PSScriptRoot\output"

    # --- Entra ID / Graph API credentials ---
    # Set environment variables, or replace the placeholders below.
    TenantId     = if ($env:ENTRA_TENANT_ID)     { $env:ENTRA_TENANT_ID }     else { "<YOUR_TENANT_ID>" }
    ClientId     = if ($env:ENTRA_CLIENT_ID)     { $env:ENTRA_CLIENT_ID }     else { "<YOUR_CLIENT_ID>" }
    ClientSecret = if ($env:ENTRA_CLIENT_SECRET) { $env:ENTRA_CLIENT_SECRET } else { "<YOUR_CLIENT_SECRET>" }

    # --- Script-specific settings ---
    # Number of hours to look back for failed sign-ins
    LookbackHours    = 24

    # Flag users with failure count at or above this threshold
    FailureThreshold = 10
}
# =============================================================================

# --- Parameter overrides ---
if ($PSBoundParameters.ContainsKey('LookbackHours'))    { $Config.LookbackHours    = $LookbackHours }
if ($PSBoundParameters.ContainsKey('FailureThreshold')) { $Config.FailureThreshold = $FailureThreshold }

# --- Logging setup ---

$Script:LogFile = $null

if ($Config.LogDir) {
    if (-not (Test-Path $Config.LogDir)) {
        New-Item -ItemType Directory -Path $Config.LogDir | Out-Null
    }
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
        if ($Url) { Write-Log "Fetching next page ($($results.Count) records so far)..." }
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

    # Build lookback filter
    $lookbackTime = (Get-Date).AddHours(-$Config.LookbackHours).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $filter = "status/errorCode ne 0 and createdDateTime ge $lookbackTime"
    $select = "userPrincipalName,userDisplayName,ipAddress,clientAppUsed,resourceDisplayName,status,createdDateTime,location"
    $url = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$filter&`$select=$select&`$top=500"

    Write-Log "Retrieving failed sign-ins from the last $($Config.LookbackHours) hour(s)..."
    $signIns = Get-PagedResults -Url $url -Token $token

    Write-Log "Retrieved $($signIns.Count) failed sign-in event(s)"

    if ($signIns.Count -eq 0) {
        Write-Log "No failed sign-ins found. Exiting." -Level WARNING
        exit 0
    }

    # Build detail report
    $detailReport = foreach ($entry in $signIns) {
        $location = @($entry.location.city, $entry.location.countryOrRegion) |
            Where-Object { $_ } | ForEach-Object { "$_" }
        $location = $location -join ", "

        [PSCustomObject]@{
            UserPrincipalName   = $entry.userPrincipalName
            UserDisplayName     = $entry.userDisplayName
            IPAddress           = $entry.ipAddress
            ClientAppUsed       = $entry.clientAppUsed
            ResourceDisplayName = $entry.resourceDisplayName
            ErrorCode           = $entry.status.errorCode
            FailureReason       = $entry.status.failureReason
            CreatedDateTime     = $entry.createdDateTime
            Location            = $location
        }
    }

    # Export detail CSV
    if (-not (Test-Path $Config.OutputDir)) { New-Item -ItemType Directory -Path $Config.OutputDir | Out-Null }
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    $detailFile = Join-Path $Config.OutputDir ("SignInFailures_{0}.csv" -f $timestamp)
    $detailReport | Export-Csv -Path $detailFile -NoTypeInformation -Encoding UTF8
    Write-Log "Exported detail report to $detailFile"

    # Build summary report grouped by user
    $grouped = $detailReport | Group-Object -Property UserPrincipalName
    $summaryReport = foreach ($group in $grouped) {
        $failureCount = $group.Count
        $flagged      = $failureCount -ge $Config.FailureThreshold

        # Determine most frequent error code
        $topErrorCode = ($group.Group | Group-Object -Property ErrorCode |
            Sort-Object -Property Count -Descending | Select-Object -First 1).Name

        # Determine most frequent IP address
        $topIPAddress = ($group.Group | Group-Object -Property IPAddress |
            Sort-Object -Property Count -Descending | Select-Object -First 1).Name

        if ($flagged) {
            Write-Log "User $($group.Name) has $failureCount failed sign-in(s) (exceeds threshold of $($Config.FailureThreshold))" -Level WARNING
        }

        [PSCustomObject]@{
            UserPrincipalName = $group.Name
            FailureCount      = $failureCount
            Flagged           = $flagged
            TopErrorCode      = $topErrorCode
            TopIPAddress      = $topIPAddress
        }
    }

    $summaryFile = Join-Path $Config.OutputDir ("SignInFailures_Summary_{0}.csv" -f $timestamp)
    $summaryReport | Export-Csv -Path $summaryFile -NoTypeInformation -Encoding UTF8
    Write-Log "Exported summary report to $summaryFile"

    # --- Console summary ---

    $separator    = "═" * 60
    $divider      = "─" * 60
    $displayTime  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $flaggedUsers = @($summaryReport | Where-Object { $_.Flagged -eq $true })
    $flaggedCount = $flaggedUsers.Count

    Write-Summary ""
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary "  Sign-In Failure Audit  —  $displayTime"                        -Color Yellow
    Write-Summary "  Tenant: $($Config.TenantId)"                                   -Color Yellow
    Write-Summary "  Lookback: $($Config.LookbackHours) hour(s)  |  Threshold: $($Config.FailureThreshold) failures" -Color Yellow
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary ""

    # TOP OFFENDERS — users exceeding the failure threshold
    if ($flaggedCount -gt 0) {
        Write-Summary "  TOP OFFENDERS ($flaggedCount user(s) exceeding threshold)" -Color Cyan
        Write-Summary $divider                                                      -Color Cyan
        $ranked = $flaggedUsers | Sort-Object { [int]$_.FailureCount } -Descending |
            Select-Object -First 15
        foreach ($entry in $ranked) {
            $line = "  {0,5} failures  {1,-35}  err:{2,-8}  ip:{3}" -f
                $entry.FailureCount, $entry.UserPrincipalName,
                $entry.TopErrorCode, $entry.TopIPAddress
            Write-Summary $line -Color Red
        }
        if ($flaggedCount -gt 15) {
            Write-Summary "          ... and $($flaggedCount - 15) more"            -Color DarkGray
        }
        Write-Summary ""
    }

    # ERROR CODE BREAKDOWN
    $errorGroups = $detailReport | Group-Object -Property ErrorCode | Sort-Object Count -Descending
    if ($errorGroups.Count -gt 0) {
        Write-Summary "  ERROR CODE BREAKDOWN"                                      -Color Cyan
        Write-Summary $divider                                                      -Color Cyan
        foreach ($eg in $errorGroups) {
            # Grab the first failure reason for this error code as a label
            $reason = ($eg.Group | Select-Object -First 1).FailureReason
            if (-not $reason) { $reason = "(unknown)" }
            $line = "  {0,5}x  {1,-8}  {2}" -f $eg.Count, $eg.Name, $reason
            Write-Summary $line
        }
        Write-Summary ""
    }

    # GEOGRAPHIC SPREAD — top locations (if location data exists)
    $locEntries = @($detailReport | Where-Object { $_.Location -ne "" })
    if ($locEntries.Count -gt 0) {
        $locGroups = $locEntries | Group-Object -Property Location | Sort-Object Count -Descending |
            Select-Object -First 10
        Write-Summary "  GEOGRAPHIC SPREAD"                                         -Color Cyan
        Write-Summary $divider                                                      -Color Cyan
        foreach ($lg in $locGroups) {
            $line = "  {0,5}x  {1}" -f $lg.Count, $lg.Name
            Write-Summary $line
        }
        $totalLocations = ($locEntries | Group-Object -Property Location).Count
        if ($totalLocations -gt 10) {
            Write-Summary "          ... and $($totalLocations - 10) more location(s)" -Color DarkGray
        }
        Write-Summary ""
    }

    # Final totals
    $uniqueIPs = ($detailReport | Select-Object -Property IPAddress -Unique).Count
    Write-Summary $separator                                                        -Color Cyan
    Write-Summary ("  TOTAL: {0} failures  |  {1} unique users  |  {2} flagged  |  {3} unique IPs" -f
        $signIns.Count, $grouped.Count, $flaggedCount, $uniqueIPs)                  -Color Cyan
    Write-Summary "  Detail CSV:  $detailFile"                                      -Color Cyan
    Write-Summary "  Summary CSV: $summaryFile"                                     -Color Cyan
    Write-Summary $separator                                                        -Color Cyan
    Write-Summary ""

    Write-Log "Completed $($Config.ScriptName) successfully"
    if ($flaggedCount -gt 0) { exit 1 } else { exit 0 }
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    exit 1
}
