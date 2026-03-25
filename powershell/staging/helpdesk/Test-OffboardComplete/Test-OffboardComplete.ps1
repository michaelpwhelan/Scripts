<#
.SYNOPSIS
    Verifies that an offboarded user has been fully cleaned up in Entra ID.

.DESCRIPTION
    Takes a user principal name and runs a series of PASS/FAIL/WARN checks against
    Microsoft Graph to confirm the offboarding process is complete: account exists
    (required for verification), is disabled, sign-in blocked, licenses removed,
    non-default group memberships cleaned up, manager field cleared, mail auto-reply
    configured, MFA methods removed, and devices disassociated. Produces a color-coded
    checklist summary, CSV export, and a plain-text clipboard block for pasting into
    osTicket.

.PARAMETER UserIdentity
    The user principal name (UPN) of the offboarded user to verify.

.PARAMETER SkipMailboxCheck
    Skip mailbox-related checks (auto-reply / forwarding) for accounts that never
    had a mailbox.

.EXAMPLE
    .\Test-OffboardComplete.ps1 -UserIdentity "jsmith@contoso.com"
    Runs all offboard verification checks for jsmith@contoso.com and displays
    a pass/fail checklist with a clipboard-ready block.

.EXAMPLE
    .\Test-OffboardComplete.ps1 -UserIdentity "svc-print@contoso.com" -SkipMailboxCheck
    Runs offboard verification but skips the mailbox auto-reply check, useful for
    service accounts or users that were never mailbox-enabled.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0, HelpMessage = "User principal name of the offboarded user.")]
    [ValidateNotNullOrEmpty()]
    [Alias("UPN")]
    [string]$UserIdentity,

    [Parameter(HelpMessage = "Skip mailbox-related checks for accounts that never had a mailbox.")]
    [switch]$SkipMailboxCheck
)

# =============================================================================
# CONFIGURATION
# =============================================================================
$Config = @{
    ScriptName     = "Test-OffboardComplete"
    LogDir         = "$PSScriptRoot\logs"
    OutputDir      = "$PSScriptRoot\output"

    TenantId       = if ($env:ENTRA_TENANT_ID)     { $env:ENTRA_TENANT_ID }     else { "<YOUR_TENANT_ID>" }
    ClientId       = if ($env:ENTRA_CLIENT_ID)     { $env:ENTRA_CLIENT_ID }     else { "<YOUR_CLIENT_ID>" }
    ClientSecret   = if ($env:ENTRA_CLIENT_SECRET) { $env:ENTRA_CLIENT_SECRET } else { "<YOUR_CLIENT_SECRET>" }

    # Groups that are OK to remain after offboarding (e.g., auto-assigned groups)
    DefaultGroups  = @("Domain Users", "All Users")
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

# ── Shared toolkit ──────────────────────────────────────────────────────────
$_toolkitPath = Join-Path (Split-Path $PSScriptRoot -Parent) "HelpdeskToolkit.ps1"
$_toolkitLoaded = $false
if (Test-Path $_toolkitPath) {
    try {
        . $_toolkitPath
        $_toolkitLoaded = $true
    } catch { }
}

if (-not $_toolkitLoaded) {
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG")][string]$Level = "INFO"
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

# Write-Summary: colored console output + plain text to log file
function Write-Summary {
    param([string]$Line, [string]$Color = "White")
    Write-Host $Line -ForegroundColor $Color
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $Line }
}


# --- Functions ---

if (-not $_toolkitLoaded) {
function Get-GraphToken {
    param([string]$TenantId, [string]$ClientId, [string]$ClientSecret)

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
                    Write-Log "HTTP $statusCode on attempt $attempt/3 — retrying in ${retryAfter}s..." -Level WARN
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

function Invoke-WithRetry {
    param(
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
}

function New-CheckResult {
    param(
        [string]$Check,
        [string]$Status,    # PASS, FAIL, WARN, SKIP
        [string]$Detail
    )
    return [PSCustomObject]@{
        Check  = $Check
        Status = $Status
        Detail = $Detail
    }
}

function Write-CheckResult {
    param([PSCustomObject]$Result)
    $tag   = "[$($Result.Status)]"
    $color = switch ($Result.Status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "WARN" { "Yellow" }
        "SKIP" { "DarkGray" }
    }
    $line = "  {0,-6}  {1,-40}  {2}" -f $tag, $Result.Check, $Result.Detail
    Write-Summary $line -Color $color
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

    Write-Log "Target user: $UserIdentity"

    # --- Acquire Graph API token ---

    Write-Log "Acquiring Graph API token..."
    $token = Invoke-WithRetry -OperationName "Graph token acquisition" -ScriptBlock {
        Get-GraphToken -TenantId $Config.TenantId -ClientId $Config.ClientId -ClientSecret $Config.ClientSecret
    }
    Write-Log "Graph API token acquired"

    $headers = @{ Authorization = "Bearer $token" }

    # --- Results collection ---

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    # =========================================================================
    # Check 1: Account exists
    # =========================================================================

    Write-Log "Checking if account exists..."
    $user = $null
    try {
        $select = "id,displayName,userPrincipalName,accountEnabled"
        $url = "https://graph.microsoft.com/v1.0/users/$($UserIdentity)?`$select=$select"
        $user = Invoke-RestMethod -Method GET -Uri $url -Headers $headers
        $results.Add((New-CheckResult -Check "Account exists" -Status "PASS" -Detail "$($user.displayName) ($($user.userPrincipalName)) — account present for verification"))
    } catch {
        $results.Add((New-CheckResult -Check "Account exists" -Status "FAIL" -Detail "User not found: $UserIdentity — cannot verify offboarding"))
        # Cannot continue checks without a user object
        throw "User account not found — cannot continue offboard verification."
    }

    # =========================================================================
    # Check 2: Account disabled
    # =========================================================================

    Write-Log "Checking if account is disabled..."
    if (-not $user.accountEnabled) {
        $results.Add((New-CheckResult -Check "Account disabled" -Status "PASS" -Detail "Account is disabled"))
    } else {
        $results.Add((New-CheckResult -Check "Account disabled" -Status "FAIL" -Detail "Account is still enabled"))
    }

    # =========================================================================
    # Check 3: Sign-in blocked
    # =========================================================================

    if (-not $user.accountEnabled) {
        $results.Add((New-CheckResult -Check "Sign-in blocked" -Status "PASS" -Detail "Sign-in is blocked (account disabled)"))
    } else {
        $results.Add((New-CheckResult -Check "Sign-in blocked" -Status "FAIL" -Detail "Sign-in is not blocked — account still enabled"))
    }

    # =========================================================================
    # Check 4: Licenses removed
    # =========================================================================

    Write-Log "Checking licenses..."
    $licUrl = "https://graph.microsoft.com/v1.0/users/$($user.id)/licenseDetails"
    $licResponse = Invoke-RestMethod -Method GET -Uri $licUrl -Headers $headers
    $assignedLicenses = @($licResponse.value)

    if ($assignedLicenses.Count -eq 0) {
        $results.Add((New-CheckResult -Check "Licenses removed" -Status "PASS" -Detail "No licenses assigned"))
    } else {
        $licNames = @($assignedLicenses | ForEach-Object {
            $sku = $_.skuPartNumber
            $id  = $_.skuId
            "$sku ($id)"
        })
        $remaining = $licNames -join "; "
        $results.Add((New-CheckResult -Check "Licenses removed" -Status "FAIL" -Detail "Still has $($assignedLicenses.Count) license(s): $remaining"))
    }

    # =========================================================================
    # Check 5: Groups cleaned up
    # =========================================================================

    Write-Log "Checking group memberships..."
    $groupUrl = "https://graph.microsoft.com/v1.0/users/$($user.id)/memberOf?`$select=displayName,`@odata.type&`$top=999"
    $members = Get-PagedResults -Url $groupUrl -Token $token
    $groupNames = @($members | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' } |
        Select-Object -ExpandProperty displayName)

    $nonDefaultGroups = @($groupNames | Where-Object { $_ -notin $Config.DefaultGroups })

    if ($nonDefaultGroups.Count -eq 0) {
        $detail = if ($groupNames.Count -gt 0) {
            "Only default/allowed groups remain: $($groupNames -join ', ')"
        } else {
            "No group memberships"
        }
        $results.Add((New-CheckResult -Check "Groups cleaned up" -Status "PASS" -Detail $detail))
    } else {
        $groupList = $nonDefaultGroups -join "; "
        $results.Add((New-CheckResult -Check "Groups cleaned up" -Status "FAIL" -Detail "Still in $($nonDefaultGroups.Count) non-default group(s): $groupList"))
    }

    # =========================================================================
    # Check 6: Manager field cleared
    # =========================================================================

    Write-Log "Checking manager assignment..."
    $managerSet = $false
    $managerDetail = ""
    try {
        $mgrUrl = "https://graph.microsoft.com/v1.0/users/$($user.id)/manager?`$select=displayName,userPrincipalName"
        $manager = Invoke-RestMethod -Method GET -Uri $mgrUrl -Headers $headers
        $managerSet = $true
        $managerDetail = "$($manager.displayName) ($($manager.userPrincipalName))"
    } catch {
        # 404 means no manager set, which is expected
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -ne 404) {
            Write-Log "Unexpected error checking manager: $_" -Level WARN
        }
    }

    if (-not $managerSet) {
        $results.Add((New-CheckResult -Check "Manager cleared" -Status "PASS" -Detail "No manager assigned"))
    } else {
        $results.Add((New-CheckResult -Check "Manager cleared" -Status "WARN" -Detail "Manager still set: $managerDetail — may be intentional for delegation"))
    }

    # =========================================================================
    # Check 7: Mail forwarding / auto-reply
    # =========================================================================

    if ($SkipMailboxCheck) {
        Write-Log "Skipping mailbox check (-SkipMailboxCheck specified)"
        $results.Add((New-CheckResult -Check "Mail auto-reply" -Status "SKIP" -Detail "Skipped — -SkipMailboxCheck specified"))
    } else {
        Write-Log "Checking mailbox auto-reply settings..."
        try {
            $mailUrl = "https://graph.microsoft.com/v1.0/users/$($user.id)/mailboxSettings"
            $mailbox = Invoke-RestMethod -Method GET -Uri $mailUrl -Headers $headers

            if ($mailbox.automaticRepliesSetting.status -eq "AlwaysEnabled" -or
                $mailbox.automaticRepliesSetting.status -eq "Scheduled") {
                $results.Add((New-CheckResult -Check "Mail auto-reply" -Status "PASS" -Detail "Auto-reply is enabled ($($mailbox.automaticRepliesSetting.status))"))
            } else {
                $results.Add((New-CheckResult -Check "Mail auto-reply" -Status "WARN" -Detail "Auto-reply is not configured — may be intentional"))
            }
        } catch {
            $results.Add((New-CheckResult -Check "Mail auto-reply" -Status "WARN" -Detail "Mailbox not accessible — may not be provisioned"))
        }
    }

    # =========================================================================
    # Check 8: MFA methods
    # =========================================================================

    Write-Log "Checking MFA methods..."
    $mfaUrl = "https://graph.microsoft.com/v1.0/users/$($user.id)/authentication/methods"
    $mfaResponse = Invoke-RestMethod -Method GET -Uri $mfaUrl -Headers $headers
    $realMfaMethods = @($mfaResponse.value | Where-Object { $_.'@odata.type' -ne '#microsoft.graph.passwordAuthenticationMethod' })

    if ($realMfaMethods.Count -eq 0) {
        $results.Add((New-CheckResult -Check "MFA methods removed" -Status "PASS" -Detail "No MFA methods registered"))
    } else {
        $methodTypes = @($realMfaMethods | ForEach-Object {
            ($_.'@odata.type' -replace '#microsoft\.graph\.', '') -replace 'AuthenticationMethod$', ''
        })
        $methodList = $methodTypes -join ", "
        $results.Add((New-CheckResult -Check "MFA methods removed" -Status "WARN" -Detail "$($realMfaMethods.Count) method(s) still registered: $methodList — may be intentional"))
    }

    # =========================================================================
    # Check 9: Devices removed
    # =========================================================================

    Write-Log "Checking device associations..."
    $ownedUrl = "https://graph.microsoft.com/v1.0/users/$($user.id)/ownedDevices?`$select=displayName,deviceId&`$top=999"
    $registeredUrl = "https://graph.microsoft.com/v1.0/users/$($user.id)/registeredDevices?`$select=displayName,deviceId&`$top=999"

    $ownedDevices = @()
    $registeredDevices = @()
    try {
        $ownedDevices = @(Get-PagedResults -Url $ownedUrl -Token $token)
    } catch {
        Write-Log "Error fetching owned devices: $_" -Level WARN
    }
    try {
        $registeredDevices = @(Get-PagedResults -Url $registeredUrl -Token $token)
    } catch {
        Write-Log "Error fetching registered devices: $_" -Level WARN
    }

    # Deduplicate by deviceId
    $allDevices = @{}
    foreach ($dev in $ownedDevices) {
        $key = if ($dev.deviceId) { $dev.deviceId } else { $dev.id }
        $allDevices[$key] = $dev.displayName
    }
    foreach ($dev in $registeredDevices) {
        $key = if ($dev.deviceId) { $dev.deviceId } else { $dev.id }
        if (-not $allDevices.ContainsKey($key)) {
            $allDevices[$key] = $dev.displayName
        }
    }

    $deviceCount = $allDevices.Count
    if ($deviceCount -eq 0) {
        $results.Add((New-CheckResult -Check "Devices removed" -Status "PASS" -Detail "No devices associated"))
    } else {
        $deviceNames = ($allDevices.Values | Sort-Object) -join "; "
        $results.Add((New-CheckResult -Check "Devices removed" -Status "WARN" -Detail "$deviceCount device(s) still associated: $deviceNames"))
    }

    # =========================================================================
    # Export CSV
    # =========================================================================

    if (-not (Test-Path $Config.OutputDir)) { New-Item -ItemType Directory -Path $Config.OutputDir | Out-Null }
    $timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeUpn    = $UserIdentity -replace '[^a-zA-Z0-9]', '_'
    $outputFile = Join-Path $Config.OutputDir ("OffboardCheck_{0}_{1}.csv" -f $safeUpn, $timestamp)

    $results | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
    Write-Log "Exported to $outputFile"

    # =========================================================================
    # Console summary
    # =========================================================================

    $separator   = "=" * 60
    $divider     = "-" * 60
    $displayTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $passCount  = @($results | Where-Object { $_.Status -eq "PASS" }).Count
    $failCount  = @($results | Where-Object { $_.Status -eq "FAIL" }).Count
    $warnCount  = @($results | Where-Object { $_.Status -eq "WARN" }).Count
    $skipCount  = @($results | Where-Object { $_.Status -eq "SKIP" }).Count
    $totalCount = $results.Count

    Write-Summary ""
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary "  Offboard Verification  --  $displayTime"                       -Color Yellow
    Write-Summary "  User: $($user.displayName) ($($user.userPrincipalName))"       -Color Yellow
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary ""

    Write-Summary "  CHECKLIST"                                                     -Color Cyan
    Write-Summary $divider                                                          -Color Cyan
    foreach ($result in $results) {
        Write-CheckResult -Result $result
    }
    Write-Summary ""

    # Totals
    $totalColor = if ($failCount -gt 0) { "Red" } elseif ($warnCount -gt 0) { "Yellow" } else { "Green" }
    $summaryLine = "  RESULT: {0}/{1} passed  |  {2} failed  |  {3} warnings" -f $passCount, $totalCount, $failCount, $warnCount
    if ($skipCount -gt 0) { $summaryLine += "  |  $skipCount skipped" }

    Write-Summary $separator                                                        -Color $totalColor
    Write-Summary $summaryLine                                                      -Color $totalColor
    Write-Summary "  CSV: $outputFile"                                              -Color Cyan
    Write-Summary $separator                                                        -Color $totalColor
    Write-Summary ""

    # =========================================================================
    # Clipboard block
    # =========================================================================

    $clipLines = [System.Collections.Generic.List[string]]::new()
    $clipLines.Add("--- COPY FOR TICKET ---")
    $clipLines.Add("Offboard Verification: $($user.displayName) ($($user.userPrincipalName))")
    $clipLines.Add("Generated: $displayTime")
    $clipLines.Add("")
    foreach ($result in $results) {
        $clipLines.Add("[$($result.Status)]  $($result.Check): $($result.Detail)")
    }
    $clipLines.Add("")
    $clipLines.Add("Result: $passCount/$totalCount passed, $failCount failed, $warnCount warnings")
    $clipLines.Add("--- END COPY ---")

    Write-Summary ($clipLines -join "`n")
    Write-Summary ""

    Write-Log "Completed $($Config.ScriptName) successfully"
    if ($failCount -gt 0) { exit 1 } else { exit 0 }
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    exit 1
}
