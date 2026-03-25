<#
.SYNOPSIS
    Verifies that a newly onboarded user has all required Entra ID provisioning items.

.DESCRIPTION
    Takes a user principal name and runs a series of PASS/FAIL/WARN checks against
    Microsoft Graph to confirm the user's Entra ID account is properly set up:
    account exists, is enabled, sign-in not blocked, sync status, required groups
    assigned, required licenses assigned, mailbox provisioned, MFA registered,
    manager set, correct OU, and first sign-in. Produces a color-coded checklist
    summary, a CSV export, and a clipboard-ready block for pasting into a ticket.

    Supports named onboarding templates (e.g., 'Standard', 'ITStaff') that override
    the default required groups and licenses per role.

.PARAMETER UserIdentity
    The user principal name (UPN) of the newly onboarded user.

.PARAMETER Template
    Named onboarding profile from the config block (e.g., 'Standard', 'ITStaff').
    When specified, overrides the default RequiredGroups and RequiredLicenses with
    the values defined in $Config.Templates. If the template name is not found,
    a warning is logged and the defaults are used.

.EXAMPLE
    .\Test-OnboardComplete.ps1 -UserIdentity "jsmith@contoso.com"
    Runs all onboard verification checks for jsmith@contoso.com using the default
    requirements and displays a PASS/FAIL/WARN checklist.

.EXAMPLE
    .\Test-OnboardComplete.ps1 -UserIdentity "jdoe@contoso.com" -Template ITStaff
    Runs onboard verification for jdoe@contoso.com using the ITStaff template,
    which requires membership in IT Department and VPN Users groups plus an E5 license.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0, HelpMessage = "User principal name of the newly onboarded user.")]
    [ValidateNotNullOrEmpty()]
    [Alias("UPN")]
    [string]$UserIdentity,

    [Parameter(HelpMessage = "Named onboarding profile from config (e.g., 'Standard', 'ITStaff'). Overrides default requirements.")]
    [string]$Template
)

# =============================================================================
# CONFIGURATION
# =============================================================================
$Config = @{
    ScriptName   = "Test-OnboardComplete"
    LogDir       = "$PSScriptRoot\logs"
    OutputDir    = "$PSScriptRoot\output"

    TenantId     = if ($env:ENTRA_TENANT_ID)     { $env:ENTRA_TENANT_ID }     else { "<YOUR_TENANT_ID>" }
    ClientId     = if ($env:ENTRA_CLIENT_ID)     { $env:ENTRA_CLIENT_ID }     else { "<YOUR_CLIENT_ID>" }
    ClientSecret = if ($env:ENTRA_CLIENT_SECRET) { $env:ENTRA_CLIENT_SECRET } else { "<YOUR_CLIENT_SECRET>" }

    # --- Default onboarding requirements ---
    RequiredGroups   = @("All Staff")
    RequiredLicenses = @("ENTERPRISEPACK")    # SKU part numbers
    RequiredOU       = ""                      # AD OU path (blank = skip check)
    MfaGracePeriodDays = 14                    # WARN (not FAIL) if MFA not registered within this many days of account creation

    # --- Named onboarding templates ---
    # Override RequiredGroups and RequiredLicenses per role
    Templates = @{
        "Standard" = @{
            RequiredGroups   = @("All Staff")
            RequiredLicenses = @("ENTERPRISEPACK")
        }
        "ITStaff" = @{
            RequiredGroups   = @("All Staff", "IT Department", "VPN Users")
            RequiredLicenses = @("SPE_E5")
        }
    }
}
# =============================================================================

# --- Template override ---
if ($PSBoundParameters.ContainsKey('Template')) {
    if ($Config.Templates.ContainsKey($Template)) {
        $Config.RequiredGroups   = $Config.Templates[$Template].RequiredGroups
        $Config.RequiredLicenses = $Config.Templates[$Template].RequiredLicenses
        # Note: logged after Write-Log is defined
    } else {
        # Deferred warning — logged after Write-Log is defined
        $Script:TemplateWarning = "Template '$Template' not found in config. Using default requirements."
    }
}

# --- Logging setup ---

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
    param(
        [Parameter(Mandatory)]
        [string]$Line,
        [string]$Color = "White"
    )
    Write-Host $Line -ForegroundColor $Color
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $Line }
}

if (-not $_toolkitLoaded) {
function Invoke-WithRetry {
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
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,
        [Parameter(Mandatory)]
        [string]$ClientId,
        [Parameter(Mandatory)]
        [string]$ClientSecret
    )

    if ($TenantId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
        throw "TenantId '$TenantId' is not a valid GUID format."
    }
    if ($ClientId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
        throw "ClientId '$ClientId' is not a valid GUID format."
    }

    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }

    $response = Invoke-WithRetry -OperationName "Graph token acquisition" -ScriptBlock {
        Invoke-RestMethod -Method POST -Uri $tokenUrl -Body $body -ContentType "application/x-www-form-urlencoded"
    }

    return $response.access_token
}

function Get-PagedResults {
    param(
        [Parameter(Mandatory)]
        [string]$Url,
        [Parameter(Mandatory)]
        [string]$Token
    )

    $headers = @{ Authorization = "Bearer $Token" }
    $results = [System.Collections.Generic.List[object]]::new()

    while ($Url) {
        $response = Invoke-WithRetry -OperationName "Graph API paged request" -ScriptBlock {
            Invoke-RestMethod -Method GET -Uri $Url -Headers $headers
        }

        if ($response.value) {
            $results.AddRange($response.value)
        }

        $Url = $response.'@odata.nextLink'
        if ($Url) { Write-Log "Fetching next page ($($results.Count) records so far)..." }
    }

    return $results
}
}

function New-CheckResult {
    param(
        [Parameter(Mandatory)]
        [string]$Check,
        [Parameter(Mandatory)]
        [ValidateSet("PASS", "FAIL", "WARN", "SKIP")]
        [string]$Status,
        [Parameter(Mandatory)]
        [string]$Detail
    )
    return [PSCustomObject]@{
        Check  = $Check
        Status = $Status
        Detail = $Detail
    }
}

function Write-CheckResult {
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Result
    )
    $tag   = "[$($Result.Status)]"
    $color = switch ($Result.Status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "WARN" { "Yellow" }
        "SKIP" { "DarkGray" }
        default { "White" }
    }
    $line = "  {0,-6}  {1,-30}  {2}" -f $tag, $Result.Check, $Result.Detail
    Write-Summary -Line $line -Color $color
}

# =============================================================================
# MAIN
# =============================================================================

try {
    Write-Log "Starting $($Config.ScriptName)"

    # Log deferred template messages now that Write-Log is available
    if ($PSBoundParameters.ContainsKey('Template')) {
        if ($Script:TemplateWarning) {
            Write-Log $Script:TemplateWarning -Level WARN
        } else {
            Write-Log "Using onboarding template: $Template"
        }
    }

    # Validate placeholders
    foreach ($key in @("TenantId", "ClientId", "ClientSecret")) {
        if ($Config[$key] -like "<*>") {
            throw "Config '$key' is not set. Set the environment variable or edit the config block."
        }
    }

    Write-Log "Target user: $UserIdentity"
    Write-Log "Required groups: $($Config.RequiredGroups -join ', ')"
    Write-Log "Required licenses: $($Config.RequiredLicenses -join ', ')"

    # --- Acquire Graph API token ---

    Write-Log "Acquiring Graph API token..."
    $token = Get-GraphToken -TenantId $Config.TenantId -ClientId $Config.ClientId -ClientSecret $Config.ClientSecret
    $headers = @{ Authorization = "Bearer $token" }
    Write-Log "Graph API token acquired"

    # --- Results collection ---

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # =========================================================================
    # CHECK 1: Account exists
    # =========================================================================

    Write-Log "Checking if account exists..."
    $user = $null
    try {
        $select = "id,displayName,userPrincipalName,accountEnabled,createdDateTime,onPremisesSyncEnabled,onPremisesDistinguishedName,signInActivity"
        $url = "https://graph.microsoft.com/v1.0/users/$($UserIdentity)?`$select=$select"
        $user = Invoke-WithRetry -OperationName "Get user" -ScriptBlock {
            Invoke-RestMethod -Method GET -Uri $url -Headers $headers
        }
        $results.Add((New-CheckResult -Check "Account exists" -Status "PASS" -Detail "$($user.displayName) ($($user.userPrincipalName))"))
    } catch {
        $results.Add((New-CheckResult -Check "Account exists" -Status "FAIL" -Detail "User not found: $UserIdentity"))
        # Cannot continue checks without a user object
        throw "User account not found -- cannot continue onboard verification."
    }

    # =========================================================================
    # CHECK 2: Account enabled
    # =========================================================================

    if ($user.accountEnabled) {
        $results.Add((New-CheckResult -Check "Account enabled" -Status "PASS" -Detail "Account is enabled"))
    } else {
        $results.Add((New-CheckResult -Check "Account enabled" -Status "FAIL" -Detail "Account is disabled"))
    }

    # =========================================================================
    # CHECK 3: Sign-in not blocked
    # =========================================================================

    if ($user.accountEnabled) {
        $results.Add((New-CheckResult -Check "Sign-in allowed" -Status "PASS" -Detail "Sign-in is not blocked"))
    } else {
        $results.Add((New-CheckResult -Check "Sign-in allowed" -Status "FAIL" -Detail "Sign-in is blocked (account disabled)"))
    }

    # =========================================================================
    # CHECK 4: Sync status (informational -- always PASS)
    # =========================================================================

    if ($user.onPremisesSyncEnabled) {
        $results.Add((New-CheckResult -Check "Sync status" -Status "PASS" -Detail "Directory-synced (hybrid)"))
    } else {
        $results.Add((New-CheckResult -Check "Sync status" -Status "PASS" -Detail "Cloud-only"))
    }

    # =========================================================================
    # CHECK 5: Required groups
    # =========================================================================

    Write-Log "Checking group memberships..."
    $groupUrl = "https://graph.microsoft.com/v1.0/users/$($user.id)/memberOf?`$select=displayName,`@odata.type&`$top=999"
    $members = Get-PagedResults -Url $groupUrl -Token $token
    $groupNames = @($members |
        Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' } |
        Select-Object -ExpandProperty displayName)

    foreach ($reqGroup in $Config.RequiredGroups) {
        if ($groupNames -contains $reqGroup) {
            $results.Add((New-CheckResult -Check "Group: $reqGroup" -Status "PASS" -Detail "Member of '$reqGroup'"))
        } else {
            $results.Add((New-CheckResult -Check "Group: $reqGroup" -Status "FAIL" -Detail "Not a member of '$reqGroup'"))
        }
    }

    # =========================================================================
    # CHECK 6: Required licenses
    # =========================================================================

    Write-Log "Checking licenses..."
    $licUrl = "https://graph.microsoft.com/v1.0/users/$($user.id)/licenseDetails"
    $licResponse = Invoke-WithRetry -OperationName "Get license details" -ScriptBlock {
        Invoke-RestMethod -Method GET -Uri $licUrl -Headers $headers
    }
    $assignedSkus = @($licResponse.value | Select-Object -ExpandProperty skuPartNumber)

    foreach ($reqLic in $Config.RequiredLicenses) {
        if ($assignedSkus -contains $reqLic) {
            $results.Add((New-CheckResult -Check "License: $reqLic" -Status "PASS" -Detail "License '$reqLic' assigned"))
        } else {
            $results.Add((New-CheckResult -Check "License: $reqLic" -Status "FAIL" -Detail "License '$reqLic' not assigned"))
        }
    }

    # =========================================================================
    # CHECK 7: Mailbox provisioned
    # =========================================================================

    Write-Log "Checking mailbox..."
    try {
        $mailUrl = "https://graph.microsoft.com/v1.0/users/$($user.id)/mailboxSettings"
        Invoke-WithRetry -OperationName "Get mailbox settings" -ScriptBlock {
            Invoke-RestMethod -Method GET -Uri $mailUrl -Headers $headers
        } | Out-Null
        $results.Add((New-CheckResult -Check "Mailbox provisioned" -Status "PASS" -Detail "Mailbox is accessible"))
    } catch {
        $results.Add((New-CheckResult -Check "Mailbox provisioned" -Status "WARN" -Detail "Mailbox not accessible -- may not be provisioned yet"))
    }

    # =========================================================================
    # CHECK 8: MFA registered
    # =========================================================================

    Write-Log "Checking MFA registration..."
    $mfaUrl = "https://graph.microsoft.com/v1.0/users/$($user.id)/authentication/methods"
    $mfaResponse = Invoke-WithRetry -OperationName "Get authentication methods" -ScriptBlock {
        Invoke-RestMethod -Method GET -Uri $mfaUrl -Headers $headers
    }
    $strongMethods = @($mfaResponse.value | Where-Object {
        $_.'@odata.type' -ne '#microsoft.graph.passwordAuthenticationMethod'
    })

    if ($strongMethods.Count -gt 0) {
        $results.Add((New-CheckResult -Check "MFA registered" -Status "PASS" -Detail "$($strongMethods.Count) strong method(s) registered"))
    } else {
        # Determine if within grace period
        $withinGrace = $false
        if ($user.createdDateTime -and $Config.MfaGracePeriodDays -gt 0) {
            $createdDate = [datetime]$user.createdDateTime
            $graceEnd    = $createdDate.AddDays($Config.MfaGracePeriodDays)
            if ((Get-Date) -le $graceEnd) {
                $withinGrace = $true
            }
        }

        if ($withinGrace) {
            $daysLeft = [math]::Ceiling(($graceEnd - (Get-Date)).TotalDays)
            $results.Add((New-CheckResult -Check "MFA registered" -Status "WARN" -Detail "No strong MFA methods -- $daysLeft day(s) left in grace period"))
        } else {
            $results.Add((New-CheckResult -Check "MFA registered" -Status "FAIL" -Detail "No strong MFA methods registered and grace period has expired"))
        }
    }

    # =========================================================================
    # CHECK 9: Manager set
    # =========================================================================

    Write-Log "Checking manager assignment..."
    try {
        $mgrUrl = "https://graph.microsoft.com/v1.0/users/$($user.id)/manager?`$select=displayName,userPrincipalName"
        $manager = Invoke-WithRetry -OperationName "Get manager" -ScriptBlock {
            Invoke-RestMethod -Method GET -Uri $mgrUrl -Headers $headers
        }
        $results.Add((New-CheckResult -Check "Manager set" -Status "PASS" -Detail "Manager: $($manager.displayName) ($($manager.userPrincipalName))"))
    } catch {
        $results.Add((New-CheckResult -Check "Manager set" -Status "WARN" -Detail "No manager assigned"))
    }

    # =========================================================================
    # CHECK 10: Correct OU
    # =========================================================================

    if ([string]::IsNullOrWhiteSpace($Config.RequiredOU)) {
        $results.Add((New-CheckResult -Check "Correct OU" -Status "SKIP" -Detail "RequiredOU not configured -- skipping"))
    } elseif (-not $user.onPremisesSyncEnabled) {
        $results.Add((New-CheckResult -Check "Correct OU" -Status "SKIP" -Detail "Cloud-only user -- OU check not applicable"))
    } else {
        $dn = $user.onPremisesDistinguishedName
        if ($dn -and $dn -like "*$($Config.RequiredOU)") {
            $results.Add((New-CheckResult -Check "Correct OU" -Status "PASS" -Detail "DN matches required OU"))
        } else {
            $actualOU = if ($dn) { $dn } else { "(not available)" }
            $results.Add((New-CheckResult -Check "Correct OU" -Status "FAIL" -Detail "Expected OU '$($Config.RequiredOU)' but found '$actualOU'"))
        }
    }

    # =========================================================================
    # CHECK 11: First sign-in
    # =========================================================================

    if ($user.signInActivity.lastSignInDateTime) {
        $lastSignIn = [datetime]$user.signInActivity.lastSignInDateTime
        $results.Add((New-CheckResult -Check "First sign-in" -Status "PASS" -Detail "Last sign-in: $($lastSignIn.ToString('yyyy-MM-dd HH:mm:ss')) UTC"))
    } else {
        $results.Add((New-CheckResult -Check "First sign-in" -Status "WARN" -Detail "User has not signed in yet"))
    }

    # =========================================================================
    # EXPORT CSV
    # =========================================================================

    if (-not (Test-Path $Config.OutputDir)) {
        New-Item -ItemType Directory -Path $Config.OutputDir -Force | Out-Null
    }
    $timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeUpn    = $UserIdentity -replace '[^a-zA-Z0-9]', '_'
    $outputFile = Join-Path $Config.OutputDir ("OnboardCheck_{0}_{1}.csv" -f $safeUpn, $timestamp)

    $results | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
    Write-Log "Exported to $outputFile"

    # =========================================================================
    # CONSOLE SUMMARY
    # =========================================================================

    $separator   = "=" * 60
    $divider     = "-" * 60
    $displayTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $passCount = @($results | Where-Object { $_.Status -eq "PASS" }).Count
    $failCount = @($results | Where-Object { $_.Status -eq "FAIL" }).Count
    $warnCount = @($results | Where-Object { $_.Status -eq "WARN" }).Count
    $skipCount = @($results | Where-Object { $_.Status -eq "SKIP" }).Count
    $totalCount = $results.Count

    Write-Summary -Line ""
    Write-Summary -Line $separator                                                     -Color Yellow
    Write-Summary -Line "  Onboard Verification  --  $displayTime"                     -Color Yellow
    Write-Summary -Line "  User: $($user.displayName) ($($user.userPrincipalName))"    -Color Yellow
    if ($PSBoundParameters.ContainsKey('Template') -and -not $Script:TemplateWarning) {
        Write-Summary -Line "  Template: $Template"                                    -Color Yellow
    }
    Write-Summary -Line $separator                                                     -Color Yellow
    Write-Summary -Line ""

    Write-Summary -Line "  CHECKLIST"                                                  -Color Cyan
    Write-Summary -Line $divider                                                       -Color Cyan
    foreach ($result in $results) {
        Write-CheckResult -Result $result
    }
    Write-Summary -Line ""

    # Totals line
    $totalColor = if ($failCount -gt 0) { "Red" } elseif ($warnCount -gt 0) { "Yellow" } else { "Green" }
    Write-Summary -Line $separator                                                     -Color $totalColor
    Write-Summary -Line ("  RESULT: {0}/{1} passed | {2} failed | {3} warnings" -f
        $passCount, $totalCount, $failCount, $warnCount)                               -Color $totalColor
    Write-Summary -Line "  CSV: $outputFile"                                           -Color Cyan
    Write-Summary -Line $separator                                                     -Color $totalColor
    Write-Summary -Line ""

    # =========================================================================
    # CLIPBOARD BLOCK
    # =========================================================================

    $clipLines = [System.Collections.Generic.List[string]]::new()
    $clipLines.Add("--- COPY FOR TICKET ---")
    $clipLines.Add("Onboard Verification: $($user.displayName) ($($user.userPrincipalName))")
    $clipLines.Add("Generated: $displayTime")
    if ($PSBoundParameters.ContainsKey('Template') -and -not $Script:TemplateWarning) {
        $clipLines.Add("Template: $Template")
    }
    $clipLines.Add("")
    foreach ($result in $results) {
        $clipLines.Add("[$($result.Status)]  $($result.Check): $($result.Detail)")
    }
    $clipLines.Add("")
    $clipLines.Add("Result: $passCount/$totalCount passed, $failCount failed, $warnCount warnings")
    $clipLines.Add("--- END COPY ---")

    $clipBlock = $clipLines -join "`n"

    # Attempt to copy to clipboard (non-fatal if unavailable)
    try {
        $clipBlock | Set-Clipboard -ErrorAction Stop
        Write-Log "Results copied to clipboard"
    } catch {
        Write-Log "Could not copy to clipboard (Set-Clipboard not available)" -Level WARN
    }

    Write-Summary -Line $clipBlock
    Write-Summary -Line ""

    Write-Log "Completed $($Config.ScriptName) successfully"
    if ($failCount -gt 0) { exit 1 } else { exit 0 }
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level ERROR
    exit 1
}
