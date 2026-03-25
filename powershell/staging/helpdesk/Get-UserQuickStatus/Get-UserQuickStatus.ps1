<#
.SYNOPSIS
    Retrieves a comprehensive status summary for a single Entra ID user.

.DESCRIPTION
    Queries Microsoft Graph for identity details, account status, password info,
    MFA registration, assigned licenses, group memberships, and mailbox settings.
    Produces a color-coded console dashboard, exports a CSV report, and copies a
    ticket-ready text block to the clipboard.

    Requires an Entra ID app registration with the following application permissions:
      - User.Read.All
      - UserAuthenticationMethod.Read.All
      - AuditLog.Read.All  (optional — sign-in activity degrades gracefully)
      - GroupMember.Read.All
      - MailboxSettings.Read

.PARAMETER UserIdentity
    The user principal name (UPN) or display name to look up.
    If the value contains '@' it is treated as a UPN; otherwise a displayName
    search is performed.

.EXAMPLE
    .\Get-UserQuickStatus.ps1 -UserIdentity "jsmith@contoso.com"
    Retrieves full status for jsmith@contoso.com and displays a console dashboard
    with a clipboard-ready block for pasting into a ticket.

.EXAMPLE
    .\Get-UserQuickStatus.ps1 -User "John Smith"
    Searches by display name, retrieves full status, exports to CSV, and copies
    a summary to the clipboard.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0, HelpMessage = "User principal name or display name to look up.")]
    [ValidateNotNullOrEmpty()]
    [Alias("UPN", "User")]
    [string]$UserIdentity
)

# =============================================================================
# CONFIGURATION
# =============================================================================
$Config = @{
    ScriptName   = "Get-UserQuickStatus"
    LogDir       = "$PSScriptRoot\logs"
    OutputDir    = "$PSScriptRoot\output"

    TenantId     = if ($env:ENTRA_TENANT_ID)     { $env:ENTRA_TENANT_ID }     else { "<YOUR_TENANT_ID>" }
    ClientId     = if ($env:ENTRA_CLIENT_ID)     { $env:ENTRA_CLIENT_ID }     else { "<YOUR_CLIENT_ID>" }
    ClientSecret = if ($env:ENTRA_CLIENT_SECRET) { $env:ENTRA_CLIENT_SECRET } else { "<YOUR_CLIENT_SECRET>" }

    # SKU friendly-name mapping — add your tenant's SKUs here
    SkuFriendlyNames = @{
        "ENTERPRISEPACK"        = "Office 365 E3"
        "ENTERPRISEPREMIUM"     = "Office 365 E5"
        "SPE_E3"                = "Microsoft 365 E3"
        "SPE_E5"                = "Microsoft 365 E5"
        "SPE_F1"                = "Microsoft 365 F3"
        "EXCHANGESTANDARD"      = "Exchange Online Plan 1"
        "EXCHANGEENTERPRISE"    = "Exchange Online Plan 2"
        "EMS"                   = "EMS E3"
        "EMSPREMIUM"            = "EMS E5"
        "AAD_PREMIUM"           = "Entra ID P1"
        "AAD_PREMIUM_P2"        = "Entra ID P2"
        "POWER_BI_STANDARD"     = "Power BI Free"
        "POWER_BI_PRO"          = "Power BI Pro"
        "PROJECTPREMIUM"        = "Project Plan 5"
        "VISIOCLIENT"           = "Visio Plan 2"
        "WIN_DEF_ATP"           = "Defender for Endpoint"
        "THREAT_INTELLIGENCE"   = "Defender for Office 365 P2"
    }

    DefaultPasswordExpiryDays = 90
}
# =============================================================================

# =============================================================================
# LOGGING SETUP
# =============================================================================

$Script:LogFile = $null

if ($Config.LogDir) {
    if (-not (Test-Path $Config.LogDir)) {
        New-Item -ItemType Directory -Path $Config.LogDir -Force | Out-Null
    }
    $Script:LogFile = Join-Path $Config.LogDir (
        "{0}_{1}.log" -f $Config.ScriptName, (Get-Date -Format "yyyyMMdd_HHmmss")
    )
}

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
# FUNCTIONS
# =============================================================================

if (-not $_toolkitLoaded) {
function Write-Log {
    <#
    .SYNOPSIS
        Timestamped, color-coded console + log file writer.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"
    switch ($Level) {
        "INFO"    { Write-Host $line -ForegroundColor Cyan }
        "WARN"    { Write-Host $line -ForegroundColor Yellow }
        "ERROR"   { Write-Host $line -ForegroundColor Red }
        "SUCCESS" { Write-Host $line -ForegroundColor Green }
        "DEBUG"   { Write-Host $line -ForegroundColor Gray }
    }
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $line }
}
}

function Write-Summary {
    <#
    .SYNOPSIS
        Colored console output + plain text to log file.
    #>
    param(
        [string]$Line,
        [string]$Color = "White"
    )
    Write-Host $Line -ForegroundColor $Color
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $Line }
}

if (-not $_toolkitLoaded) {
function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Retries a scriptblock up to MaxAttempts times with exponential backoff.
    #>
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,
        [int]$MaxAttempts = 3,
        [int]$DelaySeconds = 2,
        [string]$OperationName = "Operation"
    )
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            return (& $ScriptBlock)
        } catch {
            if ($attempt -ge $MaxAttempts) { throw }
            $wait = $DelaySeconds * [math]::Pow(2, $attempt - 1)
            Write-Log "$OperationName failed (attempt $attempt/$MaxAttempts): $_. Retrying in ${wait}s..." -Level WARN
            Start-Sleep -Seconds $wait
        }
    }
}

function Get-GraphToken {
    <#
    .SYNOPSIS
        Acquires an OAuth2 client-credentials token for Microsoft Graph.
    #>
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$ClientSecret
    )

    if ($TenantId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
        throw "TenantId '$TenantId' is not a valid GUID format."
    }

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
    <#
    .SYNOPSIS
        Follows @odata.nextLink pagination with retry on 429/5xx.
    #>
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$Token
    )

    $headers = @{ Authorization = "Bearer $Token" }
    $results = [System.Collections.Generic.List[object]]::new()

    while ($Url) {
        $response = $null
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                $response = Invoke-RestMethod -Method GET -Uri $Url -Headers $headers
                break
            } catch {
                $statusCode = $null
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }
                if ($statusCode -eq 429 -or ($statusCode -ge 500 -and $statusCode -le 599)) {
                    if ($attempt -eq 3) { throw }
                    $retryAfter = 5
                    if ($statusCode -eq 429) {
                        try {
                            $retryHeader = $_.Exception.Response.Headers |
                                Where-Object { $_.Key -eq 'Retry-After' } |
                                Select-Object -ExpandProperty Value -First 1
                            if ($retryHeader) { $retryAfter = [int]$retryHeader }
                        } catch { }
                    }
                    Write-Log "HTTP $statusCode on attempt $attempt/3 -- retrying in ${retryAfter}s..." -Level WARN
                    Start-Sleep -Seconds $retryAfter
                } else {
                    throw
                }
            }
        }
        if ($response.value) {
            $results.AddRange(@($response.value))
        }
        $Url = $response.'@odata.nextLink'
        if ($Url) { Write-Log "Fetching next page ($($results.Count) records so far)..." }
    }

    return $results
}

function Protect-ODataValue {
    <#
    .SYNOPSIS
        Escapes single quotes for OData $filter expressions.
    #>
    param(
        [Parameter(Mandatory)][string]$Value
    )
    return $Value -replace "'", "''"
}
}

function Get-UserDetails {
    <#
    .SYNOPSIS
        Looks up a user by UPN or displayName. Falls back to excluding signInActivity
        if AuditLog.Read.All is not granted.
    #>
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][string]$Identity
    )

    $headers = @{ Authorization = "Bearer $Token" }
    $selectFull = "id,displayName,userPrincipalName,department,jobTitle,accountEnabled,signInActivity,passwordPolicies,lastPasswordChangeDateTime,userType,onPremisesSyncEnabled,createdDateTime"
    $selectFallback = "id,displayName,userPrincipalName,department,jobTitle,accountEnabled,passwordPolicies,lastPasswordChangeDateTime,userType,onPremisesSyncEnabled,createdDateTime"

    if ($Identity -match '@') {
        # Treat as UPN — direct lookup
        $encodedIdentity = [System.Uri]::EscapeDataString($Identity)
        $url = "https://graph.microsoft.com/v1.0/users/$encodedIdentity`?`$select=$selectFull"
        try {
            return Invoke-RestMethod -Method GET -Uri $url -Headers $headers
        } catch {
            # Retry without signInActivity in case AuditLog.Read.All is missing
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            if ($statusCode -eq 403) {
                Write-Log "signInActivity requires AuditLog.Read.All -- retrying without it" -Level WARN
                $url = "https://graph.microsoft.com/v1.0/users/$encodedIdentity`?`$select=$selectFallback"
                return Invoke-RestMethod -Method GET -Uri $url -Headers $headers
            }
            throw
        }
    } else {
        # Search by displayName
        $safeIdentity = Protect-ODataValue -Value $Identity
        $filter = [System.Uri]::EscapeDataString("displayName eq '$safeIdentity'")
        $url = "https://graph.microsoft.com/v1.0/users?`$filter=$filter&`$select=$selectFull"
        try {
            $response = Invoke-RestMethod -Method GET -Uri $url -Headers $headers
        } catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            if ($statusCode -eq 403) {
                Write-Log "signInActivity requires AuditLog.Read.All -- retrying without it" -Level WARN
                $url = "https://graph.microsoft.com/v1.0/users?`$filter=$filter&`$select=$selectFallback"
                $response = Invoke-RestMethod -Method GET -Uri $url -Headers $headers
            } else {
                throw
            }
        }
        if ($response.value.Count -eq 0) {
            throw "No user found with display name '$Identity'."
        }
        if ($response.value.Count -gt 1) {
            Write-Log "Multiple users found for '$Identity' -- using first match." -Level WARN
        }
        return $response.value[0]
    }
}

function Get-UserManager {
    <#
    .SYNOPSIS
        Returns the user's manager display name, or "(none)".
    #>
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][string]$UserId
    )

    $headers = @{ Authorization = "Bearer $Token" }
    try {
        $url = "https://graph.microsoft.com/v1.0/users/$UserId/manager?`$select=displayName,userPrincipalName"
        $manager = Invoke-RestMethod -Method GET -Uri $url -Headers $headers
        if ($manager.displayName) {
            return $manager.displayName
        }
        return "(none)"
    } catch {
        return "(none)"
    }
}

function Get-UserMfaMethods {
    <#
    .SYNOPSIS
        Retrieves authentication methods, categorises each, and counts strong methods.
    #>
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][string]$UserId
    )

    $headers = @{ Authorization = "Bearer $Token" }
    $url = "https://graph.microsoft.com/v1.0/users/$UserId/authentication/methods"
    $response = Invoke-RestMethod -Method GET -Uri $url -Headers $headers
    $allMethods = @($response.value)

    # Categorise each method
    $categorised = foreach ($method in $allMethods) {
        $type = $method.'@odata.type'
        $strong = $false
        $name = switch ($type) {
            '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod' {
                $strong = $true
                "Authenticator App"
            }
            '#microsoft.graph.phoneAuthenticationMethod' {
                $strong = $true
                $phoneType = if ($method.phoneType) { $method.phoneType } else { "SMS" }
                "Phone ($phoneType)"
            }
            '#microsoft.graph.fido2AuthenticationMethod' {
                $strong = $true
                "FIDO2 Security Key"
            }
            '#microsoft.graph.emailAuthenticationMethod' {
                "Email"
            }
            '#microsoft.graph.windowsHelloForBusinessAuthenticationMethod' {
                $strong = $true
                "Windows Hello for Business"
            }
            '#microsoft.graph.softwareOathAuthenticationMethod' {
                $strong = $true
                "Software OATH Token"
            }
            '#microsoft.graph.temporaryAccessPassAuthenticationMethod' {
                "Temporary Access Pass"
            }
            '#microsoft.graph.passwordAuthenticationMethod' {
                "Password"
            }
            default {
                $type -replace '#microsoft\.graph\.', '' -replace 'AuthenticationMethod', ''
            }
        }
        [PSCustomObject]@{
            Name     = $name
            ODataType = $type
            IsStrong = $strong
            IsPassword = ($type -eq '#microsoft.graph.passwordAuthenticationMethod')
        }
    }

    return $categorised
}

function Get-UserLicenses {
    <#
    .SYNOPSIS
        Returns license details with friendly names mapped from config.
    #>
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][string]$UserId,
        [Parameter(Mandatory)][hashtable]$SkuMap
    )

    $headers = @{ Authorization = "Bearer $Token" }
    $url = "https://graph.microsoft.com/v1.0/users/$UserId/licenseDetails"
    $response = Invoke-RestMethod -Method GET -Uri $url -Headers $headers

    $names = foreach ($lic in $response.value) {
        $friendly = $SkuMap[$lic.skuPartNumber]
        if ($friendly) {
            "$friendly ($($lic.skuPartNumber))"
        } else {
            $lic.skuPartNumber
        }
    }
    return @($names)
}

function Get-UserGroups {
    <#
    .SYNOPSIS
        Returns paginated list of direct group membership display names.
    #>
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][string]$UserId
    )

    $url = "https://graph.microsoft.com/v1.0/users/$UserId/memberOf?`$select=displayName,@odata.type&`$top=999"
    $members = Get-PagedResults -Url $url -Token $Token
    $groupNames = @(
        $members |
            Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' } |
            Select-Object -ExpandProperty displayName |
            Sort-Object
    )
    return $groupNames
}

function Get-UserMailboxSettings {
    <#
    .SYNOPSIS
        Returns mailbox settings (auto-reply status, timezone), or $null on failure.
    #>
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][string]$UserId
    )

    $headers = @{ Authorization = "Bearer $Token" }
    try {
        $url = "https://graph.microsoft.com/v1.0/users/$UserId/mailboxSettings"
        return Invoke-RestMethod -Method GET -Uri $url -Headers $headers
    } catch {
        Write-Log "Could not retrieve mailbox settings: $_" -Level WARN
        return $null
    }
}

function Show-Section {
    <#
    .SYNOPSIS
        Displays a section header with divider line.
    #>
    param(
        [Parameter(Mandatory)][string]$Title
    )
    $divider = [string]::new([char]0x2500, 60)   # ─
    Write-Summary ""
    Write-Summary "  $Title" -Color Cyan
    Write-Summary "  $divider" -Color DarkGray
}

function Show-Property {
    <#
    .SYNOPSIS
        Displays a label/value pair with optional color for the value.
    #>
    param(
        [Parameter(Mandatory)][string]$Label,
        [string]$Value,
        [string]$Color = "White"
    )
    $padded = $Label.PadRight(22)
    $line = "    $padded $Value"
    Write-Summary $line -Color $Color
}

function Format-ClipboardBlock {
    <#
    .SYNOPSIS
        Builds a plain-text, ticket-ready summary block.
    #>
    param(
        [hashtable]$Data
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("--- USER QUICK STATUS ---")
    $lines.Add("Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $lines.Add("")
    $lines.Add("IDENTITY")
    $lines.Add("  Display Name:    $($Data.DisplayName)")
    $lines.Add("  UPN:             $($Data.UserPrincipalName)")
    $lines.Add("  Department:      $($Data.Department)")
    $lines.Add("  Job Title:       $($Data.JobTitle)")
    $lines.Add("  Manager:         $($Data.Manager)")
    $lines.Add("  User Type:       $($Data.UserType)")
    $lines.Add("  Sync Status:     $($Data.SyncStatus)")
    $lines.Add("  Created:         $($Data.CreatedDateTime)")
    $lines.Add("")
    $lines.Add("ACCOUNT STATUS")
    $lines.Add("  Enabled:         $(if ($Data.AccountEnabled) { 'Yes' } else { 'No' })")
    $lines.Add("  Last Interactive:     $($Data.LastInteractiveSignIn)")
    $lines.Add("  Last Non-Interactive: $($Data.LastNonInteractiveSignIn)")
    $lines.Add("")
    $lines.Add("PASSWORD")
    $lines.Add("  Last Changed:    $($Data.PasswordLastChanged)")
    $lines.Add("  Expires:         $($Data.PasswordExpiry)")
    $lines.Add("  Days Until:      $($Data.DaysUntilExpiry)")
    $lines.Add("")
    $lines.Add("MFA")
    $lines.Add("  Status:          $($Data.MfaStatus)")
    $lines.Add("  Strong Methods:  $($Data.StrongMethodCount)")
    $lines.Add("  Methods:         $($Data.MfaMethods)")
    $lines.Add("")
    $lines.Add("LICENSES")
    if ($Data.Licenses.Count -eq 0) {
        $lines.Add("  (none)")
    } else {
        foreach ($lic in $Data.Licenses) { $lines.Add("  - $lic") }
    }
    $lines.Add("")
    $lines.Add("GROUPS")
    if ($Data.Groups.Count -eq 0) {
        $lines.Add("  (none)")
    } else {
        foreach ($grp in $Data.Groups) { $lines.Add("  - $grp") }
    }
    $lines.Add("")
    $lines.Add("MAILBOX")
    $lines.Add("  Auto-Reply:      $($Data.AutoReplyStatus)")
    $lines.Add("  Timezone:        $($Data.Timezone)")
    $lines.Add("--- END ---")

    return ($lines -join "`n")
}

# =============================================================================
# MAIN
# =============================================================================

try {
    Write-Log "Starting $($Config.ScriptName)"

    # --- Validate configuration placeholders ---
    foreach ($key in @("TenantId", "ClientId", "ClientSecret")) {
        if ($Config[$key] -like "<*>") {
            throw "Config '$key' is not set. Set the corresponding ENTRA_* environment variable or edit the config block."
        }
    }

    Write-Log "Target user: $UserIdentity"

    # --- Acquire Graph API token ---

    Write-Log "Acquiring Graph API token..."
    $token = Invoke-WithRetry -OperationName "Graph token acquisition" -ScriptBlock {
        Get-GraphToken -TenantId $Config.TenantId -ClientId $Config.ClientId -ClientSecret $Config.ClientSecret
    }
    Write-Log "Graph API token acquired."

    # --- Retrieve user details ---

    Write-Log "Looking up user: $UserIdentity..."
    $user = Get-UserDetails -Token $token -Identity $UserIdentity
    Write-Log "Found user: $($user.displayName) ($($user.id))"

    # --- Retrieve manager ---

    Write-Log "Retrieving manager..."
    $manager = Get-UserManager -Token $token -UserId $user.id

    # --- Retrieve MFA methods ---

    Write-Log "Retrieving MFA methods..."
    try {
        $mfaCategorised = Get-UserMfaMethods -Token $token -UserId $user.id
    } catch {
        Write-Log "Failed to retrieve MFA methods: $_" -Level WARN
        $mfaCategorised = @()
    }

    $realMfaMethods = @($mfaCategorised | Where-Object { -not $_.IsPassword })
    $strongMethods  = @($realMfaMethods | Where-Object { $_.IsStrong })
    $mfaRegistered  = $realMfaMethods.Count -gt 0
    $mfaStatus      = if ($mfaRegistered) { "Registered" } else { "Not Registered" }
    $methodNames    = @($realMfaMethods | ForEach-Object { $_.Name })
    $methodsStr     = if ($methodNames.Count -gt 0) { $methodNames -join ", " } else { "(none)" }
    $strongCount    = $strongMethods.Count

    # --- Retrieve licenses ---

    Write-Log "Retrieving licenses..."
    try {
        $licenses = Get-UserLicenses -Token $token -UserId $user.id -SkuMap $Config.SkuFriendlyNames
    } catch {
        Write-Log "Failed to retrieve licenses: $_" -Level WARN
        $licenses = @()
    }
    if (-not $licenses) { $licenses = @() }

    # --- Retrieve groups ---

    Write-Log "Retrieving group memberships..."
    try {
        $groups = Get-UserGroups -Token $token -UserId $user.id
    } catch {
        Write-Log "Failed to retrieve groups: $_" -Level WARN
        $groups = @()
    }

    # --- Retrieve mailbox settings ---

    Write-Log "Retrieving mailbox settings..."
    $mailboxSettings = Get-UserMailboxSettings -Token $token -UserId $user.id

    $autoReplyStatus = "(none)"
    $timezone = "(unknown)"
    if ($mailboxSettings) {
        $timezone = if ($mailboxSettings.timeZone) { $mailboxSettings.timeZone } else { "(unknown)" }
        if ($mailboxSettings.automaticRepliesSetting) {
            $arStatus = $mailboxSettings.automaticRepliesSetting.status
            if ($arStatus -eq "alwaysEnabled" -or $arStatus -eq "scheduled") {
                $autoReplyStatus = "Enabled ($arStatus)"
            } else {
                $autoReplyStatus = "Disabled"
            }
        }
    }

    # --- Derive account status fields ---

    $accountEnabled = [bool]$user.accountEnabled
    $department     = if ($user.department)  { $user.department }  else { "(none)" }
    $title          = if ($user.jobTitle)    { $user.jobTitle }    else { "(none)" }
    $userType       = if ($user.userType)    { $user.userType }    else { "(unknown)" }
    $createdDT      = if ($user.createdDateTime) { $user.createdDateTime } else { "(unknown)" }

    $syncStatus = if ($user.onPremisesSyncEnabled -eq $true) {
        "Synced from on-premises"
    } elseif ($user.onPremisesSyncEnabled -eq $false) {
        "Cloud-only"
    } else {
        "Cloud-only"
    }

    # Sign-in activity
    $lastInteractive    = "(never)"
    $lastNonInteractive = "(never)"
    if ($user.signInActivity) {
        if ($user.signInActivity.lastSignInDateTime) {
            $lastInteractive = $user.signInActivity.lastSignInDateTime
        }
        if ($user.signInActivity.lastNonInteractiveSignInDateTime) {
            $lastNonInteractive = $user.signInActivity.lastNonInteractiveSignInDateTime
        }
    }

    # Password info
    $pwdLastChanged = if ($user.lastPasswordChangeDateTime) { $user.lastPasswordChangeDateTime } else { "(unknown)" }

    $pwdExpiry      = "(unknown)"
    $daysUntilExpiry = "(unknown)"
    if ($user.passwordPolicies -match "DisablePasswordExpiration") {
        $pwdExpiry       = "Never (policy: no expiration)"
        $daysUntilExpiry = "N/A"
    } elseif ($user.lastPasswordChangeDateTime) {
        $lastChange = [DateTime]::Parse($user.lastPasswordChangeDateTime)
        $expiryDate = $lastChange.AddDays($Config.DefaultPasswordExpiryDays)
        $daysLeft   = [math]::Ceiling(($expiryDate - (Get-Date)).TotalDays)
        $pwdExpiry  = $expiryDate.ToString("yyyy-MM-dd HH:mm:ss")
        if ($daysLeft -le 0) {
            $pwdExpiry       += " (EXPIRED)"
            $daysUntilExpiry = "$daysLeft (EXPIRED)"
        } else {
            $daysUntilExpiry = "$daysLeft days"
        }
    }

    # --- Ensure output directory exists ---

    if (-not (Test-Path $Config.OutputDir)) {
        New-Item -ItemType Directory -Path $Config.OutputDir -Force | Out-Null
    }

    # --- Build result object ---

    $resultData = @{
        DisplayName            = $user.displayName
        UserPrincipalName      = $user.userPrincipalName
        Department             = $department
        JobTitle               = $title
        Manager                = $manager
        UserType               = $userType
        SyncStatus             = $syncStatus
        CreatedDateTime        = $createdDT
        AccountEnabled         = $accountEnabled
        LastInteractiveSignIn  = $lastInteractive
        LastNonInteractiveSignIn = $lastNonInteractive
        PasswordLastChanged    = $pwdLastChanged
        PasswordExpiry         = $pwdExpiry
        DaysUntilExpiry        = $daysUntilExpiry
        MfaStatus              = $mfaStatus
        MfaMethods             = $methodsStr
        StrongMethodCount      = $strongCount
        Licenses               = $licenses
        Groups                 = $groups
        AutoReplyStatus        = $autoReplyStatus
        Timezone               = $timezone
    }

    # --- Console dashboard ---

    $separator = [string]::new([char]0x2550, 64)   # ═

    Write-Summary ""
    Write-Summary "  $separator" -Color Yellow
    Write-Summary "    User Quick Status  --  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Color Yellow
    Write-Summary "    $($user.displayName) ($($user.userPrincipalName))" -Color Yellow
    Write-Summary "  $separator" -Color Yellow

    # -- Section 1: Identity --
    Show-Section "IDENTITY"
    Show-Property "Display Name"   $user.displayName
    Show-Property "UPN"            $user.userPrincipalName
    Show-Property "Department"     $department
    Show-Property "Job Title"      $title
    Show-Property "Manager"        $manager
    Show-Property "User Type"      $userType
    Show-Property "Sync Status"    $syncStatus
    Show-Property "Created"        $createdDT

    # -- Section 2: Account Status --
    Show-Section "ACCOUNT STATUS"
    $enabledLabel = if ($accountEnabled) { "Enabled" } else { "Disabled" }
    $enabledColor = if ($accountEnabled) { "Green" } else { "Red" }
    Show-Property "Account"             $enabledLabel         -Color $enabledColor
    Show-Property "Last Interactive"     $lastInteractive
    Show-Property "Last Non-Interactive" $lastNonInteractive

    # -- Section 3: Password --
    Show-Section "PASSWORD"
    Show-Property "Last Changed" $pwdLastChanged

    $expiryColor = "White"
    if ($pwdExpiry -match "EXPIRED") {
        $expiryColor = "Red"
    } elseif ($pwdExpiry -eq "Never (policy: no expiration)") {
        $expiryColor = "DarkGray"
    }
    Show-Property "Expires" $pwdExpiry -Color $expiryColor

    $daysColor = "White"
    if ($daysUntilExpiry -match "EXPIRED") {
        $daysColor = "Red"
    } elseif ($daysUntilExpiry -match '^\d+' -and [int]($daysUntilExpiry -replace '\D.*') -le 14) {
        $daysColor = "Yellow"
    }
    Show-Property "Days Until Expiry" $daysUntilExpiry -Color $daysColor

    # -- Section 4: MFA --
    Show-Section "MFA"
    $mfaColor = if ($mfaRegistered) { "Green" } else { "Red" }
    Show-Property "Status"         $mfaStatus       -Color $mfaColor
    Show-Property "Strong Methods" "$strongCount"
    foreach ($m in $realMfaMethods) {
        $indicator = if ($m.IsStrong) { "[strong]" } else { "[basic]" }
        Show-Property "  -" "$($m.Name) $indicator"
    }

    # -- Section 5: Licenses --
    Show-Section "LICENSES ($($licenses.Count))"
    if ($licenses.Count -eq 0) {
        Show-Property " " "(none)" -Color DarkGray
    } else {
        foreach ($lic in $licenses) {
            Show-Property "  -" $lic
        }
    }

    # -- Section 6: Groups --
    Show-Section "GROUPS ($($groups.Count))"
    if ($groups.Count -eq 0) {
        Show-Property " " "(none)" -Color DarkGray
    } else {
        foreach ($grp in $groups) {
            Show-Property "  -" $grp
        }
    }

    # -- Section 7: Mailbox --
    Show-Section "MAILBOX"
    Show-Property "Auto-Reply" $autoReplyStatus
    Show-Property "Timezone"   $timezone

    Write-Summary ""
    Write-Summary "  $separator" -Color Cyan

    # --- CSV export ---

    $timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeUpn    = ($user.userPrincipalName) -replace '[^a-zA-Z0-9]', '_'
    $outputFile = Join-Path $Config.OutputDir ("UserQuickStatus_{0}_{1}.csv" -f $safeUpn, $timestamp)

    $csvObject = [PSCustomObject]@{
        DisplayName            = $user.displayName
        UserPrincipalName      = $user.userPrincipalName
        Department             = $department
        JobTitle               = $title
        Manager                = $manager
        UserType               = $userType
        SyncStatus             = $syncStatus
        CreatedDateTime        = $createdDT
        AccountEnabled         = $accountEnabled
        LastInteractiveSignIn  = $lastInteractive
        LastNonInteractiveSignIn = $lastNonInteractive
        PasswordLastChanged    = $pwdLastChanged
        PasswordExpiry         = $pwdExpiry
        DaysUntilExpiry        = $daysUntilExpiry
        MfaStatus              = $mfaStatus
        MfaMethods             = $methodsStr
        StrongMethodCount      = $strongCount
        Licenses               = ($licenses -join "; ")
        Groups                 = ($groups -join "; ")
        AutoReplyStatus        = $autoReplyStatus
        Timezone               = $timezone
        ReportedAt             = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }
    $csvObject | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
    Write-Log "Exported CSV to $outputFile"
    Write-Summary "    CSV: $outputFile" -Color Cyan
    Write-Summary "  $separator" -Color Cyan
    Write-Summary ""

    # --- Clipboard block ---

    $clipBlock = Format-ClipboardBlock -Data $resultData

    try {
        $clipBlock | Set-Clipboard
        Write-Log "Summary copied to clipboard."
    } catch {
        Write-Log "Could not copy to clipboard (Set-Clipboard not available): $_" -Level WARN
    }

    # --- Write-Output: PSCustomObject for pipeline ---

    Write-Output $csvObject

    Write-Log "Completed $($Config.ScriptName) successfully."
    exit 0
} catch {
    Write-Log "Fatal error: $_" -Level ERROR
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level ERROR
    exit 1
}
