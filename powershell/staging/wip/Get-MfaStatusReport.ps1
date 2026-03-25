<#
.SYNOPSIS
    Reports MFA registration status for all Entra ID users via Microsoft Graph API.

.DESCRIPTION
    Authenticates to Microsoft Graph using client credentials (app registration),
    retrieves user MFA registration details from the authenticationMethods report
    endpoint, flags users who have not registered MFA, highlights admin accounts
    without MFA, and exports the full report to a CSV file. A color-coded console
    summary is printed at the end.

.NOTES
    Author:       Michael Whelan
    Created:      2026-03-14
    Dependencies: None. Uses Invoke-RestMethod (built-in).
                  Requires an Entra ID app registration with
                  UserAuthenticationMethod.Read.All and AuditLog.Read.All permissions.

.EXAMPLE
    .\Get-MfaStatusReport.ps1
    Retrieves MFA status for all users and exports to
    $PSScriptRoot\output\MfaStatusReport_<timestamp>.csv

.EXAMPLE
    .\Get-MfaStatusReport.ps1
    Runs with default configuration; override tenant credentials via environment
    variables ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET.
#>
#Requires -Version 5.1

# =============================================================================
# CONFIGURATION
# =============================================================================
$Config = @{
    ScriptName   = "Get-MfaStatusReport"
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

    Write-Log "Retrieving MFA registration details from Entra ID..."
    $url = "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails"
    $registrationDetails = Get-PagedResults -Url $url -Token $token

    Write-Log "Retrieved $($registrationDetails.Count) user record(s)"

    if ($registrationDetails.Count -eq 0) {
        Write-Log "No users found. Exiting." -Level WARNING
        exit 0
    }

    # Build report objects
    $report = foreach ($user in $registrationDetails) {
        [PSCustomObject]@{
            UserPrincipalName = $user.userPrincipalName
            UserDisplayName   = $user.userDisplayName
            IsMfaRegistered   = $user.isMfaRegistered
            IsMfaCapable      = $user.isMfaCapable
            MethodsRegistered = ($user.methodsRegistered -join ";")
            IsAdmin           = $user.isAdmin
            DefaultMfaMethod  = $user.defaultMfaMethod
        }
    }

    # Summary counts
    $totalUsers       = $report.Count
    $mfaRegistered    = @($report | Where-Object { $_.IsMfaRegistered -eq $true }).Count
    $mfaNotRegistered = @($report | Where-Object { $_.IsMfaRegistered -eq $false }).Count

    Write-Log "MFA Summary: Total=$totalUsers, Registered=$mfaRegistered, NotRegistered=$mfaNotRegistered"

    if ($mfaNotRegistered -gt 0) {
        Write-Log "$mfaNotRegistered user(s) do not have MFA registered" -Level WARNING
    }

    # Export to CSV
    if (-not (Test-Path $Config.OutputDir)) { New-Item -ItemType Directory -Path $Config.OutputDir | Out-Null }
    $outputFile = Join-Path $Config.OutputDir (
        "MfaStatusReport_{0}.csv" -f (Get-Date -Format "yyyyMMdd_HHmmss")
    )
    $report | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8

    Write-Log "Exported to $outputFile"

    # --- Console summary ---

    $separator    = [string]::new([char]0x2550, 60)
    $divider      = [string]::new([char]0x2500, 60)
    $displayTime  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    Write-Summary ""
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary "  MFA Status Report  —  $displayTime"                            -Color Yellow
    Write-Summary "  Tenant: $($Config.TenantId)"                                   -Color Yellow
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary ""

    # MFA REGISTRATION
    Write-Summary "  MFA REGISTRATION"                                              -Color Cyan
    Write-Summary $divider                                                          -Color Cyan
    Write-Summary ("  Registered:       {0,5}" -f $mfaRegistered)                   -Color Green
    Write-Summary ("  Not registered:   {0,5}" -f $mfaNotRegistered)                -Color $(if ($mfaNotRegistered -gt 0) { "Red" } else { "Green" })
    Write-Summary ""

    # ADMIN ACCOUNTS WITHOUT MFA
    $adminsNoMfa = @($report | Where-Object { $_.IsAdmin -eq $true -and $_.IsMfaRegistered -eq $false })
    if ($adminsNoMfa.Count -gt 0) {
        Write-Summary "  ADMIN ACCOUNTS WITHOUT MFA ($($adminsNoMfa.Count))"        -Color Cyan
        Write-Summary $divider                                                      -Color Cyan
        foreach ($admin in $adminsNoMfa) {
            Write-Summary "  $($admin.UserPrincipalName)"                           -Color Red
        }
        Write-Summary ""
    }

    # METHOD BREAKDOWN
    $allMethods = $report | Where-Object { $_.MethodsRegistered -ne "" } |
        ForEach-Object { $_.MethodsRegistered -split ";" } |
        Group-Object | Sort-Object Count -Descending
    if ($allMethods.Count -gt 0) {
        Write-Summary "  METHOD BREAKDOWN"                                          -Color Cyan
        Write-Summary $divider                                                      -Color Cyan
        foreach ($method in $allMethods) {
            $line = "  {0,5}x  {1}" -f $method.Count, $method.Name
            Write-Summary $line
        }
        Write-Summary ""
    }

    # Final totals
    Write-Summary $separator                                                        -Color Cyan
    Write-Summary ("  TOTAL: {0} users  |  {1} registered  |  {2} not registered" -f
        $totalUsers, $mfaRegistered, $mfaNotRegistered)                             -Color Cyan
    Write-Summary "  CSV: $outputFile"                                              -Color Cyan
    Write-Summary $separator                                                        -Color Cyan
    Write-Summary ""

    Write-Log "Completed $($Config.ScriptName) successfully"
    if ($adminsNoMfa.Count -gt 0) { exit 1 } else { exit 0 }
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    exit 1
}
