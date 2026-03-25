<#
.SYNOPSIS
    Unlocks a locked-out user account and diagnoses the lockout cause.

.DESCRIPTION
    Checks lockout status in on-premises Active Directory across all domain
    controllers, unlocks the account (unless -DiagnosticOnly is specified), and
    retrieves recent failed sign-in attempts from Entra ID sign-in logs via the
    Microsoft Graph API.

    Diagnostic output includes per-DC lockout state, bad password counts, lockout
    timestamps, and a pattern analysis of recent Entra ID sign-in failures (top
    offending applications and source IPs). All diagnostic data is exported to a
    timestamped CSV and a summary block is copied to the clipboard.

    On-prem AD operations require the ActiveDirectory PowerShell module (RSAT).
    Entra ID diagnostics require an app registration with AuditLog.Read.All and
    User.Read.All application permissions, with credentials supplied via
    environment variables or the Config block.

.PARAMETER UserPrincipalName
    User principal name of the locked-out user (e.g. jane.doe@contoso.com).

.PARAMETER DiagnosticOnly
    Show lockout diagnostics without unlocking the account. Useful for
    investigating the lockout source before deciding to unlock.

.EXAMPLE
    .\Unlock-UserAccount.ps1 -UserPrincipalName "john.smith@contoso.com"

    Unlocks the account in on-prem AD and displays lockout diagnostics from
    all domain controllers and Entra ID sign-in logs.

.EXAMPLE
    .\Unlock-UserAccount.ps1 -UPN "john.smith@contoso.com" -DiagnosticOnly

    Shows lockout status across all DCs and recent Entra ID sign-in failures
    without unlocking the account.
#>
#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, Position = 0, HelpMessage = "User principal name of the locked-out user.")]
    [ValidateNotNullOrEmpty()]
    [Alias("UPN")]
    [string]$UserPrincipalName,

    [Parameter(HelpMessage = "Show lockout diagnostics without unlocking the account.")]
    [switch]$DiagnosticOnly
)

# ── Strict mode & preference ────────────────────────────────────────────────
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =============================================================================
# CONFIGURATION
# =============================================================================

$Config = @{
    ScriptName        = "Unlock-UserAccount"
    LogDir            = "$PSScriptRoot\logs"
    OutputDir         = "$PSScriptRoot\output"

    TenantId          = if ($env:ENTRA_TENANT_ID)     { $env:ENTRA_TENANT_ID }     else { "<YOUR_TENANT_ID>" }
    ClientId          = if ($env:ENTRA_CLIENT_ID)     { $env:ENTRA_CLIENT_ID }     else { "<YOUR_CLIENT_ID>" }
    ClientSecret      = if ($env:ENTRA_CLIENT_SECRET) { $env:ENTRA_CLIENT_SECRET } else { "<YOUR_CLIENT_SECRET>" }

    RequireAD         = $false
    SignInLogsToShow  = 15       # Max recent failed sign-ins to display
    SignInLookbackHours = 24     # How far back to query sign-in logs
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile   = Join-Path $Config.LogDir "$($Config.ScriptName)_$timestamp.log"

# ── Shared toolkit ──────────────────────────────────────────────────────────
$_toolkitPath = Join-Path (Split-Path $PSScriptRoot -Parent) "HelpdeskToolkit.ps1"
$_toolkitLoaded = $false
if (Test-Path $_toolkitPath) {
    try {
        . $_toolkitPath
        $_toolkitLoaded = $true
    } catch { }
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

if (-not $_toolkitLoaded) {
function Write-Log {
    <#
    .SYNOPSIS
        Writes a timestamped, color-coded message to the console and a log file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [Parameter()]
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO"
    )

    $ts    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] $Message"

    # Ensure log directory exists
    $logDir = Split-Path $logFile -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue

    $color = switch ($Level) {
        "INFO"    { "Cyan" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
        "DEBUG"   { "Gray" }
    }
    Write-Host $entry -ForegroundColor $color
}
}

function Write-Summary {
    <#
    .SYNOPSIS
        Builds a plain-text summary block suitable for clipboard or log output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter()]
        [object]$ADUser,

        [Parameter()]
        [bool]$WasUnlocked = $false,

        [Parameter()]
        [object[]]$DCLockoutSources,

        [Parameter()]
        [object[]]$SignInFailures
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("=== Unlock-UserAccount Summary ===")
    $lines.Add("User:      $UserPrincipalName")
    $lines.Add("Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $lines.Add("")

    if ($ADUser) {
        $lines.Add("[On-Prem AD]")
        $lines.Add("  Display Name:    $($ADUser.DisplayName)")
        $lines.Add("  Enabled:         $($ADUser.Enabled)")
        $lockedText = if ($ADUser.LockedOut) { "YES" } else { "No" }
        $lines.Add("  Locked Out:      $lockedText")
        $lines.Add("  Bad Pwd Count:   $($ADUser.BadPwdCount)")
        if ($WasUnlocked) {
            $lines.Add("  Action:          Account UNLOCKED")
        }
        $lines.Add("")
    }

    if ($DCLockoutSources -and $DCLockoutSources.Count -gt 0) {
        $lines.Add("[DC Lockout Sources]")
        foreach ($src in $DCLockoutSources) {
            $lines.Add("  $($src.DC) (Site: $($src.Site)) — BadPwd: $($src.BadPwdCount), Lockout: $($src.LockoutTime)")
        }
        $lines.Add("")
    }

    if ($SignInFailures -and $SignInFailures.Count -gt 0) {
        $lines.Add("[Entra Sign-In Failures: $($SignInFailures.Count) recent]")
        $appGroups = $SignInFailures | Group-Object { $_.appDisplayName } | Sort-Object Count -Descending | Select-Object -First 3
        foreach ($app in $appGroups) {
            $lines.Add("  App: $($app.Name) — $($app.Count) failure(s)")
        }
        $ipGroups = $SignInFailures | Group-Object { $_.ipAddress } | Sort-Object Count -Descending | Select-Object -First 3
        foreach ($ip in $ipGroups) {
            $lines.Add("  IP:  $($ip.Name) — $($ip.Count) failure(s)")
        }
        $lines.Add("")
    }

    return ($lines -join "`n")
}

if (-not $_toolkitLoaded) {
function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Invokes a script block with retry logic and exponential backoff.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [int]$MaxAttempts = 3,

        [Parameter()]
        [string]$OperationName = "operation"
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            return (& $ScriptBlock)
        }
        catch {
            if ($attempt -ge $MaxAttempts) {
                Write-Log "All $MaxAttempts attempts failed for $OperationName. Last error: $_" -Level ERROR
                throw
            }
            $delay = [math]::Pow(2, $attempt)
            Write-Log "Attempt $attempt/$MaxAttempts for $OperationName failed: $_ — retrying in ${delay}s" -Level WARN
            Start-Sleep -Seconds $delay
        }
    }
}

function Get-GraphToken {
    <#
    .SYNOPSIS
        Obtains an OAuth2 access token from Microsoft Identity Platform using client credentials.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$ClientSecret
    )

    # Validate TenantId is a GUID
    if ($TenantId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
        throw "TenantId '$TenantId' is not a valid GUID. Set the ENTRA_TENANT_ID environment variable."
    }

    $tokenUri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }

    $response = Invoke-WithRetry -OperationName "Graph token acquisition" -ScriptBlock {
        Invoke-RestMethod -Method Post -Uri $tokenUri -ContentType "application/x-www-form-urlencoded" -Body $body
    }

    if (-not $response.access_token) {
        throw "Token response did not contain an access_token."
    }

    Write-Log "Graph API token acquired successfully." -Level SUCCESS
    return $response.access_token
}

function Get-PagedResults {
    <#
    .SYNOPSIS
        Retrieves paginated results from the Microsoft Graph API with retry on 429/5xx.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter(Mandatory)]
        [string]$Token,

        [Parameter()]
        [int]$MaxResults = 0
    )

    $headers = @{ Authorization = "Bearer $Token" }
    $results = [System.Collections.Generic.List[object]]::new()

    while ($Url) {
        $response = $null
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                $response = Invoke-RestMethod -Method Get -Uri $Url -Headers $headers -ErrorAction Stop
                break
            }
            catch {
                $statusCode = $null
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }
                if ($statusCode -eq 429 -or ($statusCode -ge 500 -and $statusCode -le 599)) {
                    if ($attempt -eq 3) { throw }
                    $retryAfter = [math]::Pow(2, $attempt) * 2
                    if ($statusCode -eq 429) {
                        $retryHeader = $_.Exception.Response.Headers['Retry-After']
                        if ($retryHeader) { $retryAfter = [int]$retryHeader }
                    }
                    Write-Log "HTTP $statusCode on attempt $attempt/3 — retrying in ${retryAfter}s..." -Level WARN
                    Start-Sleep -Seconds $retryAfter
                }
                else {
                    throw
                }
            }
        }

        if ($response.value) {
            $results.AddRange($response.value)
        }
        if ($MaxResults -gt 0 -and $results.Count -ge $MaxResults) {
            break
        }
        $Url = $response.'@odata.nextLink'
    }

    return $results
}
}

function Show-Section {
    <#
    .SYNOPSIS
        Displays a formatted section header to the console.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Title
    )

    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor White
    Write-Host "  $Title" -ForegroundColor White
    Write-Host ("=" * 60) -ForegroundColor White
}

function Show-Property {
    <#
    .SYNOPSIS
        Displays a label-value pair with consistent alignment and color coding.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Label,

        [Parameter(Position = 1)]
        $Value,

        [Parameter()]
        [string]$Color = "Gray"
    )

    $displayValue = if ($null -eq $Value -or $Value -eq "") { "(not set)" } else { $Value }
    Write-Host ("  {0,-28} " -f "${Label}:") -NoNewline -ForegroundColor DarkGray
    Write-Host $displayValue -ForegroundColor $Color
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

try {
    Write-Log "=== $($Config.ScriptName) started ===" -Level INFO
    Write-Log "Target user: '$UserPrincipalName'" -Level INFO
    if ($DiagnosticOnly) {
        Write-Log "Running in diagnostic-only mode (no unlock will be performed)." -Level INFO
    }

    $diagnostics       = [System.Collections.Generic.List[PSCustomObject]]::new()
    $adUser            = $null
    $wasUnlocked       = $false
    $dcLockoutSources  = @()
    $signInFailures    = @()

    # ── Module / credential dependency check ────────────────────────────────
    $adAvailable    = $null -ne (Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue)
    $entraAvailable = ($Config.TenantId -notlike "<*>")

    if (-not $adAvailable -and $Config.RequireAD) {
        Write-Log "ActiveDirectory module required but not found. Install with: Install-WindowsFeature RSAT-AD-PowerShell" -Level ERROR
        exit 1
    }
    if (-not $adAvailable) {
        Write-Log "ActiveDirectory module not found — on-prem AD checks will be skipped." -Level WARN
    }
    if (-not $entraAvailable) {
        Write-Log "Entra ID credentials not configured — sign-in diagnostics will be skipped." -Level WARN
    }
    if (-not $adAvailable -and -not $entraAvailable) {
        Write-Log "Neither AD module nor Entra credentials available. Configure at least one source." -Level ERROR
        exit 1
    }

    # =========================================================================
    # ON-PREMISES AD LOCKOUT DIAGNOSTICS
    # =========================================================================

    if ($adAvailable) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
        }
        catch {
            Write-Log "Failed to import ActiveDirectory module: $_" -Level ERROR
            if ($Config.RequireAD) { exit 1 }
        }

        Write-Log "Checking on-prem AD lockout status..." -Level INFO

        $adProperties = @(
            "DisplayName", "LockedOut", "LockoutTime", "BadPwdCount",
            "BadPasswordTime", "LastLogonDate", "Enabled",
            "PasswordLastSet", "PasswordExpired"
        )

        $safeUpn = $UserPrincipalName -replace "['\*\\]", ""

        try {
            $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$safeUpn'" `
                -Properties $adProperties -ErrorAction Stop
        }
        catch {
            Write-Log "AD user lookup failed: $_" -Level ERROR
        }

        if (-not $adUser) {
            Write-Log "User '$UserPrincipalName' not found in on-prem Active Directory." -Level WARN
        }
        else {
            # ── Display account properties ──────────────────────────────────
            Show-Section "On-Prem AD — Account & Lockout Status"

            Show-Property "Display Name"       $adUser.DisplayName
            Show-Property "Account Enabled"    $adUser.Enabled -Color $(if ($adUser.Enabled) { "Green" } else { "Red" })

            $lockedColor = if ($adUser.LockedOut) { "Red" } else { "Green" }
            $lockedText  = if ($adUser.LockedOut) { "YES — LOCKED" } else { "No" }
            Show-Property "Locked Out"         $lockedText -Color $lockedColor

            if ($adUser.LockoutTime -and $adUser.LockoutTime -gt 0) {
                try {
                    $lockoutTimeReadable = [DateTime]::FromFileTime($adUser.LockoutTime)
                    Show-Property "Lockout Time" $lockoutTimeReadable -Color "Yellow"
                }
                catch {
                    Show-Property "Lockout Time" $adUser.LockoutTime -Color "Yellow"
                }
            }

            Show-Property "Bad Password Count" $adUser.BadPwdCount

            if ($adUser.BadPasswordTime -and $adUser.BadPasswordTime -gt 0) {
                try {
                    $badPwdTimeReadable = [DateTime]::FromFileTime($adUser.BadPasswordTime)
                    Show-Property "Last Bad Password" $badPwdTimeReadable -Color "Yellow"
                }
                catch {
                    Show-Property "Last Bad Password" $adUser.BadPasswordTime -Color "Yellow"
                }
            }

            Show-Property "Password Last Set"  $adUser.PasswordLastSet
            Show-Property "Password Expired"   $adUser.PasswordExpired -Color $(if ($adUser.PasswordExpired) { "Red" } else { "Green" })
            Show-Property "Last Logon"         $adUser.LastLogonDate

            # ── DC reachability pre-check & per-DC lockout query ────────────
            Write-Log "Querying domain controllers for lockout status..." -Level INFO

            try {
                $allDCs = Get-ADDomainController -Filter * -ErrorAction Stop
                Write-Log "Found $($allDCs.Count) domain controller(s)." -Level INFO

                $reachableDCs   = [System.Collections.Generic.List[object]]::new()
                $unreachableDCs = [System.Collections.Generic.List[string]]::new()

                foreach ($dc in $allDCs) {
                    try {
                        $reachable = Test-Connection -ComputerName $dc.HostName -Count 1 -Quiet -ErrorAction SilentlyContinue
                        if ($reachable) {
                            $reachableDCs.Add($dc)
                        }
                        else {
                            $unreachableDCs.Add($dc.HostName)
                            Write-Log "DC '$($dc.HostName)' is unreachable — skipping." -Level WARN
                        }
                    }
                    catch {
                        $unreachableDCs.Add($dc.HostName)
                        Write-Log "DC '$($dc.HostName)' connectivity test failed: $_ — skipping." -Level WARN
                    }
                }

                if ($unreachableDCs.Count -gt 0) {
                    Write-Host ""
                    Write-Host "  Unreachable DCs (skipped): $($unreachableDCs -join ', ')" -ForegroundColor Yellow
                }

                $dcLockoutSources = [System.Collections.Generic.List[PSCustomObject]]::new()
                $dcStatusRows     = [System.Collections.Generic.List[PSCustomObject]]::new()

                foreach ($dc in $reachableDCs) {
                    try {
                        $dcUser = Get-ADUser -Identity $adUser.DistinguishedName `
                            -Server $dc.HostName `
                            -Properties LockedOut, BadPwdCount, LockoutTime -ErrorAction Stop

                        $lockoutTimeDisplay = "N/A"
                        if ($dcUser.LockoutTime -and $dcUser.LockoutTime -gt 0) {
                            try {
                                $lockoutTimeDisplay = [DateTime]::FromFileTime($dcUser.LockoutTime)
                            }
                            catch {
                                $lockoutTimeDisplay = $dcUser.LockoutTime
                            }
                        }

                        $row = [PSCustomObject]@{
                            DC          = $dc.HostName
                            Site        = $dc.Site
                            LockedOut   = $dcUser.LockedOut
                            BadPwdCount = $dcUser.BadPwdCount
                            LockoutTime = $lockoutTimeDisplay
                        }
                        $dcStatusRows.Add($row)

                        if ($dcUser.LockedOut) {
                            $dcLockoutSources.Add($row)
                        }
                    }
                    catch {
                        Write-Log "Could not query DC '$($dc.HostName)': $_" -Level WARN
                    }
                }

                # Display DC status
                if ($dcStatusRows.Count -gt 0) {
                    Write-Host ""
                    Write-Host "  Domain Controller Lockout Status:" -ForegroundColor White
                    $dcStatusRows | Format-Table -Property DC, Site, LockedOut, BadPwdCount, LockoutTime -AutoSize |
                        Out-String | ForEach-Object { Write-Host $_ }
                }

                if ($dcLockoutSources.Count -gt 0) {
                    Write-Host "  Lockout detected on $($dcLockoutSources.Count) DC(s)." -ForegroundColor Red
                }
                else {
                    Write-Host "  No lockout detected across domain controllers." -ForegroundColor Green
                }

                # Add DC lockout sources to diagnostics export
                foreach ($src in $dcLockoutSources) {
                    $diagnostics.Add([PSCustomObject]@{
                        Source       = "AD Domain Controller"
                        Detail       = $src.DC
                        Site         = $src.Site
                        BadPwdCount  = $src.BadPwdCount
                        LockoutTime  = $src.LockoutTime
                        IPAddress    = ""
                        ErrorCode    = ""
                        Application  = ""
                        Timestamp    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    })
                }
            }
            catch {
                Write-Log "Could not enumerate domain controllers: $_" -Level WARN
            }

            # ── Unlock the account ──────────────────────────────────────────
            if ($adUser.LockedOut -and -not $DiagnosticOnly) {
                if ($PSCmdlet.ShouldProcess($adUser.DistinguishedName, "Unlock account")) {
                    try {
                        Write-Log "Unlocking account in on-prem AD..." -Level INFO
                        Unlock-ADAccount -Identity $adUser.DistinguishedName -ErrorAction Stop

                        # Verify unlock
                        $adUserAfter = Get-ADUser -Identity $adUser.DistinguishedName `
                            -Properties LockedOut -ErrorAction Stop

                        if (-not $adUserAfter.LockedOut) {
                            $wasUnlocked = $true
                            Write-Host ""
                            Write-Host "  >> ACCOUNT UNLOCKED SUCCESSFULLY" -ForegroundColor Green
                            Write-Host ""
                            Write-Log "Account unlocked successfully." -Level SUCCESS
                        }
                        else {
                            Write-Log "Account may still be locked — verify manually." -Level WARN
                        }
                    }
                    catch {
                        Write-Log "Failed to unlock account: $_" -Level ERROR
                    }
                }
            }
            elseif ($adUser.LockedOut -and $DiagnosticOnly) {
                Write-Host ""
                Write-Host "  >> Account is LOCKED — run without -DiagnosticOnly to unlock." -ForegroundColor Yellow
                Write-Host ""
            }
            elseif (-not $adUser.LockedOut) {
                Write-Host ""
                Write-Host "  >> Account is NOT locked out." -ForegroundColor Green
                Write-Host ""
            }
        }
    }

    # =========================================================================
    # ENTRA ID SIGN-IN DIAGNOSTICS
    # =========================================================================

    if ($entraAvailable) {
        try {
            Write-Log "Acquiring Graph API token..." -Level INFO
            $token = Get-GraphToken -TenantId $Config.TenantId -ClientId $Config.ClientId -ClientSecret $Config.ClientSecret

            Show-Section "Entra ID — Recent Failed Sign-Ins"

            $escapedUpn  = $UserPrincipalName -replace "'", "''"
            $top         = $Config.SignInLogsToShow
            $lookbackISO = (Get-Date).AddHours(-$Config.SignInLookbackHours).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

            $signInUrl = "https://graph.microsoft.com/v1.0/auditLogs/signIns?" +
                "`$filter=userPrincipalName eq '$escapedUpn' " +
                "and status/errorCode ne 0 " +
                "and createdDateTime ge $lookbackISO" +
                "&`$top=$top" +
                "&`$orderby=createdDateTime desc"

            try {
                $signInFailures = Get-PagedResults -Url $signInUrl -Token $token -MaxResults $top

                if (-not $signInFailures -or $signInFailures.Count -eq 0) {
                    Write-Host "  No failed sign-ins in the last $($Config.SignInLookbackHours) hour(s)." -ForegroundColor Green
                }
                else {
                    Write-Log "Found $($signInFailures.Count) recent failed sign-in(s)." -Level INFO

                    # Display table
                    $table = foreach ($entry in $signInFailures) {
                        $appName = $entry.appDisplayName
                        if ($appName -and $appName.Length -gt 30) {
                            $appName = $appName.Substring(0, 27) + "..."
                        }

                        $reason = $entry.status.failureReason
                        if ($reason -and $reason.Length -gt 45) {
                            $reason = $reason.Substring(0, 42) + "..."
                        }

                        $location = ""
                        if ($entry.location) {
                            $city    = $entry.location.city
                            $country = $entry.location.countryOrRegion
                            if ($city -and $country) { $location = "$city, $country" }
                            elseif ($country)        { $location = $country }
                            elseif ($city)           { $location = $city }
                        }

                        [PSCustomObject]@{
                            Timestamp     = ([DateTime]$entry.createdDateTime).ToString("yyyy-MM-dd HH:mm:ss")
                            Application   = $appName
                            IPAddress     = $entry.ipAddress
                            Location      = $location
                            ErrorCode     = $entry.status.errorCode
                            FailureReason = $reason
                        }
                    }

                    $table | Format-Table -AutoSize | Out-String | ForEach-Object { Write-Host $_ }

                    # Pattern analysis
                    $appCounts = $signInFailures |
                        Group-Object { $_.appDisplayName } |
                        Sort-Object Count -Descending |
                        Select-Object -First 3
                    $ipCounts = $signInFailures |
                        Group-Object { $_.ipAddress } |
                        Sort-Object Count -Descending |
                        Select-Object -First 3

                    Write-Host "  Top apps with failures:" -ForegroundColor Yellow
                    foreach ($app in $appCounts) {
                        Write-Host "    - $($app.Name): $($app.Count) failure(s)" -ForegroundColor Yellow
                    }
                    Write-Host ""
                    Write-Host "  Top source IPs:" -ForegroundColor Yellow
                    foreach ($ip in $ipCounts) {
                        Write-Host "    - $($ip.Name): $($ip.Count) failure(s)" -ForegroundColor Yellow
                    }
                    Write-Host ""

                    # Add sign-in failures to diagnostics export
                    foreach ($entry in $signInFailures) {
                        $location = ""
                        if ($entry.location) {
                            $city    = $entry.location.city
                            $country = $entry.location.countryOrRegion
                            if ($city -and $country) { $location = "$city, $country" }
                            elseif ($country)        { $location = $country }
                            elseif ($city)           { $location = $city }
                        }

                        $diagnostics.Add([PSCustomObject]@{
                            Source      = "Entra Sign-In Log"
                            Detail      = $entry.appDisplayName
                            Site        = $location
                            BadPwdCount = ""
                            LockoutTime = ""
                            IPAddress   = $entry.ipAddress
                            ErrorCode   = $entry.status.errorCode
                            Application = $entry.appDisplayName
                            Timestamp   = ([DateTime]$entry.createdDateTime).ToString("yyyy-MM-dd HH:mm:ss")
                        })
                    }
                }
            }
            catch {
                Write-Log "Could not retrieve sign-in logs (requires AuditLog.Read.All permission): $_" -Level WARN
            }
        }
        catch {
            Write-Log "Entra ID diagnostics could not be completed: $_" -Level ERROR
        }
    }

    # =========================================================================
    # CSV EXPORT
    # =========================================================================

    if ($diagnostics.Count -gt 0) {
        if (-not (Test-Path $Config.OutputDir)) {
            New-Item -Path $Config.OutputDir -ItemType Directory -Force | Out-Null
        }

        $safeId    = $UserPrincipalName -replace '[^a-zA-Z0-9]', '_'
        $csvPath   = Join-Path $Config.OutputDir (
            "{0}_{1}_{2}.csv" -f $Config.ScriptName, $safeId, $timestamp
        )
        $diagnostics | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log "Exported $($diagnostics.Count) diagnostic record(s) to: $csvPath" -Level SUCCESS
    }

    # =========================================================================
    # CLIPBOARD SUMMARY
    # =========================================================================

    $summaryText = Write-Summary `
        -UserPrincipalName $UserPrincipalName `
        -ADUser $adUser `
        -WasUnlocked $wasUnlocked `
        -DCLockoutSources $dcLockoutSources `
        -SignInFailures $signInFailures

    try {
        $summaryText | Set-Clipboard -ErrorAction Stop
        Write-Log "Summary copied to clipboard." -Level SUCCESS
    }
    catch {
        Write-Log "Could not copy summary to clipboard (Set-Clipboard not available): $_" -Level WARN
    }

    Write-Host ""
    Write-Host $summaryText -ForegroundColor DarkGray
    Write-Host ""

    # =========================================================================
    # DONE
    # =========================================================================

    Write-Log "=== $($Config.ScriptName) completed ===" -Level SUCCESS
    exit 0
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    Write-Log $_.ScriptStackTrace -Level ERROR
    exit 1
}
