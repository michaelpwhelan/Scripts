<#
.SYNOPSIS
    Finds and optionally disables Entra ID accounts that have been inactive for N or more days.

.DESCRIPTION
    Authenticates to Microsoft Graph, retrieves all users with their last sign-in
    activity, and identifies stale accounts — those inactive for InactiveDays or more.
    Accounts that have never signed in are optionally included.

    By default the script runs in dry-run mode — it reports what would be disabled
    without making changes. Pass -Live to actually disable accounts; the script
    will require interactive confirmation before proceeding.

    Requires an Entra ID app registration with:
      - User.Read.All         (read users + sign-in data)
      - AuditLog.Read.All     (read signInActivity)
      - User.EnableDisableAll (disable accounts — only needed with -Live)

.PARAMETER InactiveDays
    Number of days without sign-in before an account is considered stale.
    Overrides $Config.InactiveDays. Default: 90.

.PARAMETER Live
    Opt-in switch for destructive mode. When specified, the script will disable
    stale accounts (after confirmation). Without this switch, the script runs
    in dry-run mode.

.EXAMPLE
    .\Disable-StaleAccounts.ps1
    Runs in DryRun mode — reports stale accounts without disabling them.

.EXAMPLE
    .\Disable-StaleAccounts.ps1 -InactiveDays 60 -Live
    Disables accounts inactive for 60+ days (after confirmation prompt).
#>
#Requires -Version 5.1
param(
    [int]$InactiveDays,
    [switch]$Live
)

# =============================================================================
# CONFIGURATION
# =============================================================================
$Config = @{
    ScriptName   = "Disable-StaleAccounts"
    LogDir       = "$PSScriptRoot\logs"
    OutputDir    = "$PSScriptRoot\output"

    # --- Entra ID / Graph API credentials ---
    TenantId     = if ($env:ENTRA_TENANT_ID)     { $env:ENTRA_TENANT_ID }     else { "<YOUR_TENANT_ID>" }
    ClientId     = if ($env:ENTRA_CLIENT_ID)     { $env:ENTRA_CLIENT_ID }     else { "<YOUR_CLIENT_ID>" }
    ClientSecret = if ($env:ENTRA_CLIENT_SECRET) { $env:ENTRA_CLIENT_SECRET } else { "<YOUR_CLIENT_SECRET>" }

    # --- Stale-account criteria ---
    InactiveDays         = 90
    IncludeNeverSignedIn = $true

    # --- Safety ---
    DryRun = $true

    # UPNs to always skip (e.g. break-glass / emergency accounts)
    ExcludeUpns = @(
        # "admin@contoso.onmicrosoft.com"
    )
}
# =============================================================================

# --- Parameter overrides ---
if ($PSBoundParameters.ContainsKey('InactiveDays')) { $Config.InactiveDays = $InactiveDays }
if ($Live) { $Config.DryRun = $false }

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

function Write-Summary {
    <# Writes colored console output and appends to the log file. #>
    param([string]$Line, [string]$Color = "White")
    Write-Host $Line -ForegroundColor $Color
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $Line }
}


# =============================================================================
# FUNCTIONS
# =============================================================================

function Get-GraphToken {
    <# Acquires an OAuth2 access token for Microsoft Graph using client credentials. #>
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

function Invoke-GraphRequest {
    <# Makes a single Graph API GET request with retry logic for 429 and 5xx errors. #>
    param([string]$Token, [string]$Url, [string]$Method = "GET", [string]$Body)
    $headers = @{ Authorization = "Bearer $Token" }
    if ($Body) { $headers["Content-Type"] = "application/json" }
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $params = @{ Method = $Method; Uri = $Url; Headers = $headers }
            if ($Body) { $params.Body = $Body }
            return Invoke-RestMethod @params
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
}

function Get-PagedGraphResults {
    <# Retrieves all pages from a Microsoft Graph endpoint using Invoke-GraphRequest. #>
    param([string]$Token, [string]$Url)
    $items = [System.Collections.Generic.List[object]]::new()
    while ($Url) {
        $r = Invoke-GraphRequest -Token $Token -Url $Url
        $items.AddRange($r.value)
        $Url = $r.'@odata.nextLink'
        if ($Url) { Write-Log "Fetching next page ($($items.Count) users so far)..." }
    }
    return $items
}


# =============================================================================
# MAIN
# =============================================================================

try {
    Write-Log "Starting $($Config.ScriptName)"
    if ($Config.DryRun) { Write-Log "DRY RUN MODE — no accounts will be disabled" -Level WARNING }

    foreach ($key in @("TenantId", "ClientId", "ClientSecret")) {
        if ($Config[$key] -like "<*>") { throw "Config '$key' is not set." }
    }

    $now    = Get-Date
    $cutoff = $now.AddDays(-$Config.InactiveDays)
    Write-Log "Stale threshold: $($Config.InactiveDays) day(s) — cutoff $($cutoff.ToString('yyyy-MM-dd'))"

    Write-Log "Acquiring Graph API token..."
    $token = Get-GraphToken -TenantId $Config.TenantId -ClientId $Config.ClientId -ClientSecret $Config.ClientSecret
    $tokenAcquiredAt = Get-Date

    Write-Log "Retrieving users..."
    $select  = "id,displayName,userPrincipalName,department,jobTitle,accountEnabled,createdDateTime,signInActivity"
    $allUsers = Get-PagedGraphResults -Token $token -Url "https://graph.microsoft.com/v1.0/users?`$select=$select&`$top=999"
    Write-Log "Total users retrieved: $($allUsers.Count)"

    # --- Identify stale accounts ---

    $stale          = [System.Collections.Generic.List[PSCustomObject]]::new()
    $alreadyDisabled = 0
    $exclude        = @($Config.ExcludeUpns)

    foreach ($user in $allUsers) {
        if ($user.userPrincipalName -in $exclude) { continue }
        if (-not $user.accountEnabled) {
            $alreadyDisabled++
            continue
        }

        $lastSignIn        = $user.signInActivity.lastSignInDateTime
        $isStale           = $false
        $lastSignInDisplay = "Never"
        $daysSince         = "N/A"

        if ($null -eq $lastSignIn -or $lastSignIn -eq '') {
            $isStale = $Config.IncludeNeverSignedIn
        } else {
            $signInDate = [datetime]$lastSignIn
            if ($signInDate -lt $cutoff) {
                $isStale           = $true
                $lastSignInDisplay = $signInDate.ToString("yyyy-MM-dd HH:mm:ss")
                $daysSince         = [int]($now - $signInDate).TotalDays
            }
        }

        if ($isStale) {
            $stale.Add([PSCustomObject]@{
                UserId             = $user.id
                DisplayName        = $user.displayName
                UserPrincipalName  = $user.userPrincipalName
                Department         = $user.department
                JobTitle           = $user.jobTitle
                CreatedDateTime    = $user.createdDateTime
                LastSignInDateTime = $lastSignInDisplay
                DaysSinceSignIn    = $daysSince
                Action             = if ($Config.DryRun) { "WouldDisable" } else { "Pending" }
            })
        }
    }

    Write-Log "Stale accounts found: $($stale.Count)"
    Write-Log "Already-disabled accounts skipped: $alreadyDisabled"

    if ($stale.Count -eq 0) {
        Write-Log "No stale accounts found. Exiting."
        exit 0
    }

    # --- Disable accounts (or dry-run) ---

    $disabledCount = 0
    $errorCount    = 0

    if (-not $Config.DryRun) {
        Write-Host ""
        Write-Host "WARNING: You are about to disable $($stale.Count) account(s)." -ForegroundColor Red
        Write-Host "Type YES to proceed, or anything else to abort: " -ForegroundColor Yellow -NoNewline
        $confirmation = Read-Host
        if ($confirmation -ne 'YES') {
            Write-Log "User aborted — no accounts were disabled." -Level WARNING
            exit 0
        }

        for ($i = 0; $i -lt $stale.Count; $i++) {
            $entry    = $stale[$i]
            $progress = "[{0}/{1}]" -f ($i + 1), $stale.Count
            Write-Log "$progress Disabling: $($entry.UserPrincipalName)"

            # Refresh token if approaching expiry
            if (((Get-Date) - $tokenAcquiredAt).TotalMinutes -gt 50) {
                Write-Log "Token approaching expiry — refreshing..."
                $token = Get-GraphToken -TenantId $Config.TenantId -ClientId $Config.ClientId -ClientSecret $Config.ClientSecret
                $tokenAcquiredAt = Get-Date
            }

            try {
                Invoke-GraphRequest -Token $token -Url "https://graph.microsoft.com/v1.0/users/$($entry.UserId)" `
                    -Method PATCH -Body '{"accountEnabled": false}' | Out-Null
                $entry.Action = "Disabled"
                $disabledCount++
            } catch {
                Write-Log "$progress Failed to disable $($entry.UserPrincipalName): $_" -Level ERROR
                $entry.Action = "Error"
                $errorCount++
            }
        }
    }

    # --- Export audit CSV ---

    if (-not (Test-Path $Config.OutputDir)) { New-Item -ItemType Directory -Path $Config.OutputDir | Out-Null }
    $prefix     = if ($Config.DryRun) { "StaleAccounts_DryRun" } else { "StaleAccounts_Disabled" }
    $outputFile = Join-Path $Config.OutputDir (
        "{0}_{1}.csv" -f $prefix, (Get-Date -Format "yyyyMMdd_HHmmss")
    )
    $stale | Select-Object DisplayName, UserPrincipalName, Department, JobTitle,
        CreatedDateTime, LastSignInDateTime, DaysSinceSignIn, Action |
        Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8

    # --- Console summary ---

    $separator = [string]::new([char]0x2550, 60)
    $divider   = [string]::new([char]0x2500, 60)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $mode      = if ($Config.DryRun) { "DRY RUN" } else { "LIVE" }

    $neverCount   = @($stale | Where-Object { $_.LastSignInDateTime -eq "Never" }).Count
    $expiredCount = $stale.Count - $neverCount

    $deptGroups = $stale | Group-Object -Property Department | Sort-Object Count -Descending

    Write-Summary ""
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary "  Stale Account Audit  [$mode]  —  $timestamp"                  -Color Yellow
    Write-Summary "  Threshold: $($Config.InactiveDays) days  |  Cutoff: $($cutoff.ToString('yyyy-MM-dd'))" -Color Yellow
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary ""

    $ranked = $stale | Where-Object { $_.DaysSinceSignIn -ne "N/A" } |
        Sort-Object { [int]$_.DaysSinceSignIn } -Descending |
        Select-Object -First 10

    if ($ranked.Count -gt 0) {
        Write-Summary "  MOST STALE ACCOUNTS"                                       -Color Cyan
        Write-Summary $divider                                                      -Color Cyan
        foreach ($entry in $ranked) {
            $line = "  {0,-6}  {1,-40}  {2}" -f "$($entry.DaysSinceSignIn)d", $entry.UserPrincipalName, $entry.Department
            Write-Summary $line                                                     -Color Red
        }
        Write-Summary ""
    }

    if ($neverCount -gt 0) {
        $neverAccounts = $stale | Where-Object { $_.LastSignInDateTime -eq "Never" } | Select-Object -First 10
        Write-Summary "  NEVER SIGNED IN ($neverCount total)"                       -Color Cyan
        Write-Summary $divider                                                      -Color Cyan
        foreach ($entry in $neverAccounts) {
            Write-Summary ("          {0,-40}  {1}" -f $entry.UserPrincipalName, $entry.Department) -Color Red
        }
        if ($neverCount -gt 10) {
            Write-Summary "          ... and $($neverCount - 10) more"              -Color DarkGray
        }
        Write-Summary ""
    }

    if ($deptGroups.Count -gt 1) {
        Write-Summary "  BY DEPARTMENT"                                             -Color Cyan
        Write-Summary $divider                                                      -Color Cyan
        foreach ($group in $deptGroups) {
            $deptName = if ($group.Name) { $group.Name } else { "(none)" }
            Write-Summary ("  {0,4}  {1}" -f $group.Count, $deptName)
        }
        Write-Summary ""
    }

    Write-Summary $separator                                                        -Color Cyan
    if ($Config.DryRun) {
        Write-Summary ("  TOTAL: {0} stale  |  {1} expired  |  {2} never signed in  |  {3} already disabled  |  Action: NONE (dry run)" -f
            $stale.Count, $expiredCount, $neverCount, $alreadyDisabled)             -Color Cyan
    } else {
        Write-Summary ("  TOTAL: {0} stale  |  Disabled: {1}  |  Errors: {2}  |  Already disabled: {3}" -f
            $stale.Count, $disabledCount, $errorCount, $alreadyDisabled)            -Color Cyan
    }
    Write-Summary "  CSV: $outputFile"                                              -Color Cyan
    Write-Summary $separator                                                        -Color Cyan
    Write-Summary ""

    Write-Log "Audit log exported to $outputFile"
    Write-Log "Completed $($Config.ScriptName) successfully"
    exit 0
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    exit 1
}
