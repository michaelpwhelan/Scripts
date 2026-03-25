<#
.SYNOPSIS
    Revokes access for a compromised Entra ID user and exports a forensic timeline.

.DESCRIPTION
    Takes a user principal name and performs incident response actions: disables the
    Entra ID account, revokes all refresh tokens, retrieves recent sign-in logs,
    and optionally bans source IPs on a FortiGate firewall. All actions and sign-in
    events are exported to a forensic timeline CSV. Runs in DryRun mode by default.

.NOTES
    Author:       Michael Whelan
    Created:      2026-03-11
    Dependencies: None. Uses Invoke-RestMethod (built-in).
                  Requires an Entra ID app registration with:
                    - User.Read.All          (read user details + sign-in data)
                    - AuditLog.Read.All      (read sign-in logs)
                    - User.EnableDisableAll  (disable account — only needed when DryRun = $false)
                  Optional FortiGate REST API token for IP banning.

.EXAMPLE
    .\Revoke-CompromisedUser.ps1
    Runs in DryRun mode — reports what actions would be taken without making changes.
#>
#Requires -Version 5.1

# =============================================================================
# CONFIGURATION
# =============================================================================
$Config = @{
    ScriptName   = "Revoke-CompromisedUser"
    LogDir       = "$PSScriptRoot\logs"    # Set to $null to disable file logging
    OutputDir    = "$PSScriptRoot\output"

    # --- Target user ---
    UserUpn      = "user@contoso.com"

    # --- Entra ID / Graph API credentials ---
    # Set environment variables, or replace the placeholders below.
    TenantId     = if ($env:ENTRA_TENANT_ID)     { $env:ENTRA_TENANT_ID }     else { "<YOUR_TENANT_ID>" }
    ClientId     = if ($env:ENTRA_CLIENT_ID)     { $env:ENTRA_CLIENT_ID }     else { "<YOUR_CLIENT_ID>" }
    ClientSecret = if ($env:ENTRA_CLIENT_SECRET) { $env:ENTRA_CLIENT_SECRET } else { "<YOUR_CLIENT_SECRET>" }

    # --- FortiGate (optional — leave empty to skip) ---
    FgtHost      = if ($env:FGT_HOST)  { $env:FGT_HOST }  else { "" }
    FgtToken     = if ($env:FGT_TOKEN) { $env:FGT_TOKEN } else { "" }
    FgtPort      = 443

    # --- Settings ---
    LookbackHours = 72

    # --- Safety ---
    # $true  → report only, do NOT take any actions
    # $false → disable account, revoke tokens, ban IPs
    DryRun        = $true
}
# =============================================================================


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
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }
    $response = Invoke-RestMethod -Method POST `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Body $body -ContentType "application/x-www-form-urlencoded"
    return $response.access_token
}

function Get-PagedResults {
    param([string]$Url, [string]$Token)
    $headers = @{ Authorization = "Bearer $Token" }
    $results = [System.Collections.Generic.List[object]]::new()
    while ($Url) {
        $response = Invoke-RestMethod -Method GET -Uri $Url -Headers $headers
        $results.AddRange($response.value)
        $Url = $response.'@odata.nextLink'
        if ($Url) { Write-Log "Fetching next page ($($results.Count) records so far)..." }
    }
    return $results
}

function Get-UserByUpn {
    param([string]$Token, [string]$Upn)
    $headers = @{ Authorization = "Bearer $Token" }
    $url = "https://graph.microsoft.com/v1.0/users/$Upn"
    return Invoke-RestMethod -Method GET -Uri $url -Headers $headers
}

function Get-UserSignInLogs {
    param([string]$Token, [string]$Upn, [int]$LookbackHours)
    $lookbackTime = (Get-Date).AddHours(-$LookbackHours).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $filter = "userPrincipalName eq '$Upn' and createdDateTime ge $lookbackTime"
    $url = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$filter&`$top=999"
    return Get-PagedResults -Url $url -Token $Token
}

function Disable-UserAccount {
    param([string]$Token, [string]$UserId)
    $headers = @{
        Authorization  = "Bearer $Token"
        "Content-Type" = "application/json"
    }
    $body = '{"accountEnabled": false}'
    Invoke-RestMethod -Method PATCH `
        -Uri "https://graph.microsoft.com/v1.0/users/$UserId" `
        -Headers $headers -Body $body | Out-Null
}

function Revoke-UserSessions {
    param([string]$Token, [string]$UserId)
    $headers = @{ Authorization = "Bearer $Token" }
    Invoke-RestMethod -Method POST `
        -Uri "https://graph.microsoft.com/v1.0/users/$UserId/revokeSignInSessions" `
        -Headers $headers | Out-Null
}

function Initialize-FgtConnection {
    add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAll : ICertificatePolicy {
            public bool CheckValidationResult(ServicePoint sp, X509Certificate cert,
                WebRequest req, int problem) { return true; }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAll
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
}

function Ban-FgtAddress {
    param([string]$Host, [int]$Port, [string]$Token, [string]$IPAddress)
    $url = "https://${Host}:${Port}/api/v2/monitor/user/banned/add_users"
    $headers = @{ Authorization = "Bearer $Token"; "Content-Type" = "application/json" }
    $body = @{ ip_addresses = @($IPAddress) } | ConvertTo-Json
    Invoke-RestMethod -Method POST -Uri $url -Headers $headers -Body $body | Out-Null
}

function Test-PrivateIP {
    param([string]$IPAddress)
    try {
        $octets = $IPAddress.Split('.') | ForEach-Object { [int]$_ }
        if ($octets[0] -eq 10) { return $true }
        if ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) { return $true }
        if ($octets[0] -eq 192 -and $octets[1] -eq 168) { return $true }
        return $false
    } catch { return $false }
}


# --- Helper: create an action timeline row ---

function New-TimelineAction {
    param(
        [string]$Detail,
        [string]$ActionTaken,
        [string]$UPN = "",
        [string]$IPAddress = ""
    )
    $now = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    return [PSCustomObject]@{
        Timestamp   = $now
        EventType   = "Action"
        Source       = "Script"
        Detail       = $Detail
        UPN          = $UPN
        IPAddress    = $IPAddress
        Location     = ""
        AppUsed      = ""
        Resource     = ""
        Status       = ""
        ErrorCode    = ""
        ActionTaken  = $ActionTaken
    }
}


# --- Main ---

try {
    Write-Log "Starting $($Config.ScriptName)"
    if ($Config.DryRun) { Write-Log "DRY RUN MODE — no changes will be made" -Level WARNING }

    # Validate Entra ID credential placeholders
    foreach ($key in @("TenantId", "ClientId", "ClientSecret")) {
        if ($Config[$key] -like "<*>") {
            throw "Config '$key' is not set. Set the environment variable or edit the config block."
        }
    }

    # Validate target user
    if ([string]::IsNullOrWhiteSpace($Config.UserUpn)) {
        throw "Config 'UserUpn' is not set. Specify the compromised user's UPN."
    }

    Write-Log "Target user: $($Config.UserUpn)"
    Write-Log "Lookback window: $($Config.LookbackHours) hour(s)"

    # --- Acquire Graph API token ---

    Write-Log "Acquiring Graph API token..."
    $token = Get-GraphToken -TenantId $Config.TenantId `
        -ClientId $Config.ClientId -ClientSecret $Config.ClientSecret
    Write-Log "Graph API token acquired"

    # --- Retrieve user object ---

    Write-Log "Looking up user: $($Config.UserUpn)..."
    $user = Get-UserByUpn -Token $token -Upn $Config.UserUpn
    Write-Log "Found user: $($user.displayName) ($($user.id))"

    # --- Build forensic timeline ---

    $timeline = [System.Collections.Generic.List[PSCustomObject]]::new()

    # --- Disable the account ---

    if (-not $Config.DryRun) {
        Write-Log "Disabling account for $($user.userPrincipalName)..."
        Disable-UserAccount -Token $token -UserId $user.id
        Write-Log "Account disabled successfully"
    } else {
        Write-Log "[DRY RUN] Would disable account for $($user.userPrincipalName)" -Level WARNING
    }
    $timeline.Add((New-TimelineAction `
        -Detail "Account disabled for $($user.userPrincipalName)" `
        -ActionTaken "AccountDisabled" `
        -UPN $user.userPrincipalName))

    # --- Revoke all sessions / refresh tokens ---

    if (-not $Config.DryRun) {
        Write-Log "Revoking all sessions for $($user.userPrincipalName)..."
        Revoke-UserSessions -Token $token -UserId $user.id
        Write-Log "All sessions revoked successfully"
    } else {
        Write-Log "[DRY RUN] Would revoke all sessions for $($user.userPrincipalName)" -Level WARNING
    }
    $timeline.Add((New-TimelineAction `
        -Detail "All refresh tokens and sessions revoked for $($user.userPrincipalName)" `
        -ActionTaken "TokensRevoked" `
        -UPN $user.userPrincipalName))

    # --- Retrieve sign-in logs ---

    Write-Log "Retrieving sign-in logs for the last $($Config.LookbackHours) hour(s)..."
    $signIns = Get-UserSignInLogs -Token $token -Upn $Config.UserUpn `
        -LookbackHours $Config.LookbackHours
    Write-Log "Retrieved $($signIns.Count) sign-in event(s)"

    # --- Add sign-in events to timeline ---

    foreach ($entry in $signIns) {
        $city    = if ($entry.location.city)            { $entry.location.city }            else { "" }
        $country = if ($entry.location.countryOrRegion) { $entry.location.countryOrRegion } else { "" }
        $location = if ($city -and $country) { "$city, $country" } elseif ($country) { $country } else { $city }

        $timeline.Add([PSCustomObject]@{
            Timestamp   = $entry.createdDateTime
            EventType   = "SignIn"
            Source       = "Graph"
            Detail       = $entry.status.failureReason
            UPN          = $entry.userPrincipalName
            IPAddress    = $entry.ipAddress
            Location     = $location
            AppUsed      = $entry.clientAppUsed
            Resource     = $entry.resourceDisplayName
            Status       = if ($entry.status.errorCode -eq 0) { "Success" } else { "Failure" }
            ErrorCode    = $entry.status.errorCode
            ActionTaken  = ""
        })
    }

    # --- Extract and deduplicate source IPs ---

    $sourceIPs = @($signIns | Where-Object { $_.ipAddress } |
        Select-Object -ExpandProperty ipAddress -Unique)
    Write-Log "Unique source IPs: $($sourceIPs.Count)"

    # Separate public vs private IPs
    $publicIPs  = @($sourceIPs | Where-Object { -not (Test-PrivateIP $_) })
    $privateIPs = @($sourceIPs | Where-Object { Test-PrivateIP $_ })

    if ($publicIPs.Count -gt 0) {
        Write-Log "Public IPs: $($publicIPs.Count)"
    }
    if ($privateIPs.Count -gt 0) {
        Write-Log "Private/RFC1918 IPs: $($privateIPs.Count)" -Level WARNING
    }

    # --- FortiGate IP banning ---

    $fgtEnabled       = ($Config.FgtHost -ne "" -and $Config.FgtToken -ne "")
    $bannedIPs        = [System.Collections.Generic.List[string]]::new()
    $fgtSkippedPrivate = [System.Collections.Generic.List[string]]::new()
    $fgtErrors        = [System.Collections.Generic.List[string]]::new()

    if ($fgtEnabled) {
        Write-Log "FortiGate integration enabled: $($Config.FgtHost):$($Config.FgtPort)"

        # Initialize TLS trust for self-signed certs
        Initialize-FgtConnection
        Write-Log "TLS trust initialized for FortiGate connection"

        # Ban each public IP
        foreach ($ip in $publicIPs) {
            if (-not $Config.DryRun) {
                try {
                    Ban-FgtAddress -Host $Config.FgtHost -Port $Config.FgtPort `
                        -Token $Config.FgtToken -IPAddress $ip
                    $bannedIPs.Add($ip)
                    Write-Log "Banned IP on FortiGate: $ip"
                } catch {
                    Write-Log "Failed to ban IP $ip on FortiGate: $_" -Level ERROR
                    $fgtErrors.Add($ip)
                }
            } else {
                Write-Log "[DRY RUN] Would ban IP on FortiGate: $ip" -Level WARNING
                $bannedIPs.Add($ip)
            }

            $timeline.Add((New-TimelineAction `
                -Detail "IP address banned on FortiGate ($($Config.FgtHost))" `
                -ActionTaken "IPBanned" `
                -UPN $Config.UserUpn `
                -IPAddress $ip))
        }

        # Log skipped private IPs
        foreach ($ip in $privateIPs) {
            $fgtSkippedPrivate.Add($ip)
            Write-Log "Skipped private IP (RFC1918): $ip" -Level WARNING
        }
    } else {
        Write-Log "FortiGate integration not configured — skipping IP bans"
    }

    # --- Sort timeline by timestamp ---

    $sortedTimeline = $timeline | Sort-Object Timestamp

    # --- Export forensic timeline CSV ---

    if (-not (Test-Path $Config.OutputDir)) { New-Item -ItemType Directory -Path $Config.OutputDir | Out-Null }

    $timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeUpn    = $Config.UserUpn -replace '[^a-zA-Z0-9]', '_'
    $outputFile = Join-Path $Config.OutputDir (
        "IncidentTimeline_{0}_{1}.csv" -f $safeUpn, $timestamp
    )

    $sortedTimeline | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
    Write-Log "Exported forensic timeline to $outputFile"

    # --- Console summary ---

    $separator = "═" * 60
    $divider   = "─" * 60
    $now       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $mode      = if ($Config.DryRun) { "DRY RUN" } else { "LIVE" }

    Write-Summary ""
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary "  Incident Response  [$mode]  —  $now"                           -Color Yellow
    Write-Summary "  User: $($Config.UserUpn)"                                      -Color Yellow
    Write-Summary "  Tenant: $($Config.TenantId)"                                   -Color Yellow
    Write-Summary "  Lookback: $($Config.LookbackHours) hours"                      -Color Yellow
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary ""

    # Account status section
    Write-Summary "  ACCOUNT STATUS"                                                -Color Cyan
    Write-Summary $divider                                                          -Color Cyan
    Write-Summary "  Display Name:    $($user.displayName)"
    Write-Summary "  User ID:         $($user.id)"
    Write-Summary "  UPN:             $($user.userPrincipalName)"
    $acctAction  = if ($Config.DryRun) { "Would disable (dry run)" } else { "Disabled" }
    $tokenAction = if ($Config.DryRun) { "Would revoke (dry run)" } else { "Revoked" }
    $acctColor   = if ($Config.DryRun) { "Yellow" } else { "Red" }
    $tokenColor  = if ($Config.DryRun) { "Yellow" } else { "Red" }
    Write-Summary "  Account:         $acctAction"                                  -Color $acctColor
    Write-Summary "  Tokens:          $tokenAction"                                 -Color $tokenColor
    Write-Summary ""

    # Sign-in activity section
    $successCount = @($signIns | Where-Object { $_.status.errorCode -eq 0 }).Count
    $failureCount = $signIns.Count - $successCount

    Write-Summary "  SIGN-IN ACTIVITY (last $($Config.LookbackHours) hours)"        -Color Cyan
    Write-Summary $divider                                                          -Color Cyan
    Write-Summary "  Total events:    $($signIns.Count)"
    Write-Summary "  Successful:      $successCount"
    Write-Summary "  Failed:          $failureCount"
    Write-Summary ""

    # Source IPs table ranked by frequency
    if ($sourceIPs.Count -gt 0) {
        $ipGroups = $signIns | Where-Object { $_.ipAddress } |
            Group-Object -Property ipAddress | Sort-Object Count -Descending

        Write-Summary "  SOURCE IPs ($($sourceIPs.Count) unique)"                   -Color Cyan
        Write-Summary $divider                                                      -Color Cyan
        foreach ($ipg in $ipGroups) {
            $isPrivate = Test-PrivateIP $ipg.Name
            $banStatus = if (-not $fgtEnabled) { "n/a" }
                         elseif ($isPrivate) { "skipped (private)" }
                         else { if ($Config.DryRun) { "would ban" } else { "banned" } }
            $line = "  {0,5}x  {1,-18}  {2}" -f $ipg.Count, $ipg.Name, $banStatus
            $color = if ($isPrivate) { "DarkGray" } else { "White" }
            Write-Summary $line -Color $color
        }
        Write-Summary ""
    }

    # Geographic spread of sign-in events
    $locEntries = @($signIns | Where-Object { $_.location.city -or $_.location.countryOrRegion })
    if ($locEntries.Count -gt 0) {
        $locGroups = foreach ($entry in $locEntries) {
            $city    = if ($entry.location.city)            { $entry.location.city }            else { "" }
            $country = if ($entry.location.countryOrRegion) { $entry.location.countryOrRegion } else { "" }
            if ($city -and $country) { "$city, $country" } elseif ($country) { $country } else { $city }
        }
        $locGrouped = $locGroups | Group-Object | Sort-Object Count -Descending | Select-Object -First 10

        Write-Summary "  GEOGRAPHIC SPREAD"                                         -Color Cyan
        Write-Summary $divider                                                      -Color Cyan
        foreach ($lg in $locGrouped) {
            $line = "  {0,5}x  {1}" -f $lg.Count, $lg.Name
            Write-Summary $line
        }
        $totalLocations = ($locGroups | Group-Object).Count
        if ($totalLocations -gt 10) {
            Write-Summary "          ... and $($totalLocations - 10) more location(s)" -Color DarkGray
        }
        Write-Summary ""
    }

    # Application breakdown
    $appEntries = @($signIns | Where-Object { $_.clientAppUsed })
    if ($appEntries.Count -gt 0) {
        $appGroups = $appEntries | Group-Object -Property clientAppUsed |
            Sort-Object Count -Descending | Select-Object -First 10

        Write-Summary "  CLIENT APPLICATIONS"                                       -Color Cyan
        Write-Summary $divider                                                      -Color Cyan
        foreach ($ag in $appGroups) {
            $line = "  {0,5}x  {1}" -f $ag.Count, $ag.Name
            Write-Summary $line
        }
        Write-Summary ""
    }

    # Resource breakdown
    $resEntries = @($signIns | Where-Object { $_.resourceDisplayName })
    if ($resEntries.Count -gt 0) {
        $resGroups = $resEntries | Group-Object -Property resourceDisplayName |
            Sort-Object Count -Descending | Select-Object -First 10

        Write-Summary "  TARGET RESOURCES"                                          -Color Cyan
        Write-Summary $divider                                                      -Color Cyan
        foreach ($rg in $resGroups) {
            $line = "  {0,5}x  {1}" -f $rg.Count, $rg.Name
            Write-Summary $line
        }
        Write-Summary ""
    }

    # FortiGate section
    if ($fgtEnabled) {
        Write-Summary "  FORTIGATE ACTIONS ($($Config.FgtHost))"                    -Color Cyan
        Write-Summary $divider                                                      -Color Cyan
        Write-Summary "  IPs banned:      $($bannedIPs.Count)"
        Write-Summary "  IPs skipped:     $($fgtSkippedPrivate.Count) (private/RFC1918)"
        if ($fgtErrors.Count -gt 0) {
            Write-Summary "  IPs failed:      $($fgtErrors.Count)"                  -Color Red
        }
        Write-Summary ""
    }

    # Final totals
    Write-Summary $separator                                                        -Color Cyan
    Write-Summary ("  TOTAL: {0} sign-ins  |  {1} IPs  |  {2} banned  |  Mode: {3}" -f
        $signIns.Count, $sourceIPs.Count, $bannedIPs.Count, $mode)                 -Color Cyan
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
