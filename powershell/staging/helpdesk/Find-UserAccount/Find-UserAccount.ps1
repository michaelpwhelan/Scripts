<#
.SYNOPSIS
    Searches for user accounts across on-premises Active Directory and Entra ID (Microsoft Graph).

.DESCRIPTION
    Find-UserAccount performs a unified user lookup against both on-premises Active Directory
    and Entra ID (via the Microsoft Graph API). Results are returned as standardized
    PSCustomObject instances, displayed in the console, and exported to a timestamped CSV.

    The script supports flexible input — UPN, SamAccountName, display name, or partial match —
    and can optionally include disabled accounts.

    On-prem AD lookups require the ActiveDirectory PowerShell module (RSAT).
    Entra ID lookups require a registered app with User.Read.All (application) permissions
    and credentials supplied via environment variables or the Config block.

.PARAMETER Identity
    User identifier to search for. Accepts a UPN, SamAccountName, display name, or partial
    string. Wildcards are applied automatically for AD queries; Entra uses startsWith for
    display-name searches and exact match for UPN-style input.

.PARAMETER IncludeDisabled
    When specified, disabled accounts are included in the results. By default only enabled
    accounts are returned.

.EXAMPLE
    .\Find-UserAccount.ps1 -Identity "jane.doe@contoso.com"

    Searches both AD and Entra ID for the exact UPN jane.doe@contoso.com.

.EXAMPLE
    .\Find-UserAccount.ps1 -Identity "Jane" -IncludeDisabled

    Searches both directories for any user whose name, UPN, SAM, or email contains "Jane",
    including disabled accounts.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0, HelpMessage = "User identifier: UPN, SamAccountName, display name, or partial match.")]
    [ValidateNotNullOrEmpty()]
    [string]$Identity,

    [Parameter(HelpMessage = "Include disabled accounts in results.")]
    [switch]$IncludeDisabled
)

# ── Strict mode & preference ────────────────────────────────────────────────
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Configuration ───────────────────────────────────────────────────────────
$Config = @{
    ScriptName   = "Find-UserAccount"
    LogDir       = "$PSScriptRoot\logs"
    OutputDir    = "$PSScriptRoot\output"

    # --- Entra ID / Graph API credentials ---
    TenantId     = if ($env:ENTRA_TENANT_ID)     { $env:ENTRA_TENANT_ID }     else { "<YOUR_TENANT_ID>" }
    ClientId     = if ($env:ENTRA_CLIENT_ID)     { $env:ENTRA_CLIENT_ID }     else { "<YOUR_CLIENT_ID>" }
    ClientSecret = if ($env:ENTRA_CLIENT_SECRET) { $env:ENTRA_CLIENT_SECRET } else { "<YOUR_CLIENT_SECRET>" }

    # --- Behavior ---
    RequireAD    = $false   # $true = hard-fail if AD module missing; $false = skip with warning
    MaxResults   = 25       # Max results per directory
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

# ── Helper Functions ────────────────────────────────────────────────────────

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

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
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

function Protect-ODataValue {
    <#
    .SYNOPSIS
        Escapes single quotes for safe use in OData filter expressions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )
    return $Value -replace "'", "''"
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
}

function Search-ADUser {
    <#
    .SYNOPSIS
        Searches on-premises Active Directory for users matching the supplied identity.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Identity,

        [Parameter()]
        [switch]$IncludeDisabled
    )

    # Sanitize input for AD filter safety
    $safeIdentity = $Identity -replace "['\*\\]", ""
    $wildcard = "*$safeIdentity*"

    $filter = "(Name -like '$wildcard') -or (UserPrincipalName -like '$wildcard') -or (SamAccountName -like '$wildcard') -or (EmailAddress -like '$wildcard')"

    Write-Log "Searching Active Directory with filter: $filter" -Level INFO

    try {
        $adUsers = Get-ADUser -Filter $filter -Properties `
            DisplayName, UserPrincipalName, SamAccountName, EmailAddress, `
            Enabled, Department, Title, whenCreated, MemberOf, `
            DistinguishedName -ResultSetSize $Config.MaxResults -ErrorAction Stop

        if (-not $IncludeDisabled) {
            $adUsers = $adUsers | Where-Object { $_.Enabled -eq $true }
        }

        $results = foreach ($u in $adUsers) {
            $ou = if ($u.DistinguishedName) {
                ($u.DistinguishedName -split ",", 2)[1]
            } else { "" }

            $groupCount = 0
            if ($u.MemberOf) {
                $groupCount = @($u.MemberOf).Count
            }

            [PSCustomObject]@{
                Source       = "On-Prem AD"
                DisplayName  = $u.DisplayName
                UPN          = $u.UserPrincipalName
                SamAccountName = $u.SamAccountName
                Email        = $u.EmailAddress
                Enabled      = $u.Enabled
                SyncStatus   = "N/A"
                LastSignIn   = ""
                WhenCreated  = $u.whenCreated
                OU           = $ou
                Department   = $u.Department
                JobTitle     = $u.Title
                GroupCount   = $groupCount
            }
        }

        $count = @($results).Count
        Write-Log "Active Directory returned $count result(s)." -Level INFO
        return $results
    }
    catch {
        Write-Log "Active Directory search failed: $_" -Level ERROR
        return @()
    }
}

function Search-EntraUser {
    <#
    .SYNOPSIS
        Searches Entra ID (Microsoft Graph) for users matching the supplied identity.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Identity,

        [Parameter()]
        [string]$Token,

        [Parameter()]
        [switch]$IncludeDisabled
    )

    $escapedIdentity = Protect-ODataValue -Value $Identity
    $headers = @{ Authorization = "Bearer $Token"; ConsistencyLevel = "eventual" }
    $selectFields = "id,displayName,userPrincipalName,mail,accountEnabled,department,jobTitle,createdDateTime,onPremisesSyncEnabled,signInActivity"

    # Build the filter — exact UPN match if input looks like an email, otherwise startsWith on displayName
    if ($Identity -match "@") {
        $filter = "userPrincipalName eq '$escapedIdentity'"
    }
    else {
        $filter = "startsWith(displayName,'$escapedIdentity')"
    }

    $graphUri = "https://graph.microsoft.com/v1.0/users?`$filter=$filter&`$select=$selectFields&`$top=$($Config.MaxResults)&`$count=true"

    Write-Log "Searching Entra ID with filter: $filter" -Level INFO

    try {
        $response = Invoke-WithRetry -OperationName "Graph user search" -ScriptBlock {
            Invoke-RestMethod -Method Get -Uri $graphUri -Headers $headers -ErrorAction Stop
        }

        $entraUsers = $response.value

        if (-not $IncludeDisabled) {
            $entraUsers = $entraUsers | Where-Object { $_.accountEnabled -eq $true }
        }

        $results = foreach ($u in $entraUsers) {
            $syncStatus = if ($u.onPremisesSyncEnabled -eq $true) { "Synced" } else { "Cloud-Only" }
            $lastSignIn = if ($u.signInActivity -and $u.signInActivity.lastSignInDateTime) {
                $u.signInActivity.lastSignInDateTime
            } else { "" }

            # Get group count for the user
            $groupCount = 0
            try {
                $groupUri = "https://graph.microsoft.com/v1.0/users/$($u.id)/memberOf/`$count"
                $countResponse = Invoke-WithRetry -OperationName "Graph group count for $($u.userPrincipalName)" -ScriptBlock {
                    Invoke-RestMethod -Method Get -Uri $groupUri -Headers $headers -ErrorAction Stop
                }
                $groupCount = [int]$countResponse
            }
            catch {
                Write-Log "Could not retrieve group count for $($u.userPrincipalName): $_" -Level WARN
                # Fall back to listing memberOf
                try {
                    $memberOfUri = "https://graph.microsoft.com/v1.0/users/$($u.id)/memberOf?`$select=id"
                    $memberOfResponse = Invoke-RestMethod -Method Get -Uri $memberOfUri -Headers $headers -ErrorAction Stop
                    $groupCount = @($memberOfResponse.value).Count
                }
                catch {
                    Write-Log "Could not retrieve group membership for $($u.userPrincipalName): $_" -Level WARN
                }
            }

            [PSCustomObject]@{
                Source         = "Entra ID"
                DisplayName    = $u.displayName
                UPN            = $u.userPrincipalName
                SamAccountName = ""
                Email          = $u.mail
                Enabled        = $u.accountEnabled
                SyncStatus     = $syncStatus
                LastSignIn     = $lastSignIn
                WhenCreated    = $u.createdDateTime
                OU             = ""
                Department     = $u.department
                JobTitle       = $u.jobTitle
                GroupCount     = $groupCount
            }
        }

        $count = @($results).Count
        Write-Log "Entra ID returned $count result(s)." -Level INFO
        return $results
    }
    catch {
        Write-Log "Entra ID search failed: $_" -Level ERROR
        return @()
    }
}

function Write-Summary {
    <#
    .SYNOPSIS
        Displays a color-coded summary table of search results to the console.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [object[]]$Results
    )

    if (-not $Results -or $Results.Count -eq 0) {
        Write-Host ""
        Write-Host "  No results found." -ForegroundColor Yellow
        Write-Host ""
        return
    }

    $divider = "-" * 120

    Write-Host ""
    Write-Host $divider -ForegroundColor DarkGray
    Write-Host ("{0,-14} {1,-25} {2,-30} {3,-10} {4,-12} {5,-8}" -f `
        "Source", "Display Name", "UPN", "Enabled", "Sync Status", "Groups") -ForegroundColor White
    Write-Host $divider -ForegroundColor DarkGray

    foreach ($r in $Results) {
        $enabledColor = if ($r.Enabled) { "Green" } else { "Red" }
        $sourceColor  = if ($r.Source -eq "On-Prem AD") { "Cyan" } else { "Magenta" }

        $line = "{0,-14} {1,-25} {2,-30} {3,-10} {4,-12} {5,-8}" -f `
            $r.Source,
            ($r.DisplayName -replace "^(.{22}).*", '$1...'),
            ($r.UPN -replace "^(.{27}).*", '$1...'),
            $r.Enabled,
            $r.SyncStatus,
            $r.GroupCount

        # Write segments with color
        Write-Host ("{0,-14}" -f $r.Source) -ForegroundColor $sourceColor -NoNewline
        Write-Host (" {0,-25}" -f ($r.DisplayName -replace "^(.{22}).*", '$1...')) -ForegroundColor White -NoNewline
        Write-Host (" {0,-30}" -f ($r.UPN -replace "^(.{27}).*", '$1...')) -ForegroundColor White -NoNewline
        Write-Host (" {0,-10}" -f $r.Enabled) -ForegroundColor $enabledColor -NoNewline
        Write-Host (" {0,-12}" -f $r.SyncStatus) -ForegroundColor Gray -NoNewline
        Write-Host (" {0,-8}" -f $r.GroupCount) -ForegroundColor Gray
    }

    Write-Host $divider -ForegroundColor DarkGray
    Write-Host "  Total: $($Results.Count) result(s)" -ForegroundColor White
    Write-Host ""
}

# ── Main Execution ──────────────────────────────────────────────────────────

try {
    Write-Log "=== $($Config.ScriptName) started ===" -Level INFO
    Write-Log "Searching for identity: '$Identity'" -Level INFO

    # ── Module / credential dependency check ────────────────────────────────
    $adAvailable = $null -ne (Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue)
    if (-not $adAvailable -and $Config.RequireAD) {
        Write-Log "ActiveDirectory module required but not found. Install with: Install-WindowsFeature RSAT-AD-PowerShell" -Level ERROR
        exit 1
    }
    if (-not $adAvailable) {
        Write-Log "ActiveDirectory module not found — AD searches will be skipped." -Level WARN
    }

    $entraAvailable = ($Config.TenantId -notlike "<*>")
    if (-not $entraAvailable) {
        Write-Log "Entra ID credentials not configured — Entra searches will be skipped." -Level WARN
    }

    if (-not $adAvailable -and -not $entraAvailable) {
        Write-Log "Neither AD module nor Entra credentials available. Configure at least one." -Level ERROR
        exit 1
    }

    # ── Collect results ─────────────────────────────────────────────────────
    $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Active Directory search
    if ($adAvailable) {
        $adResults = Search-ADUser -Identity $Identity -IncludeDisabled:$IncludeDisabled
        if ($adResults) {
            foreach ($r in @($adResults)) { $allResults.Add($r) }
        }
    }

    # Entra ID search
    if ($entraAvailable) {
        try {
            $graphToken = Get-GraphToken -TenantId $Config.TenantId -ClientId $Config.ClientId -ClientSecret $Config.ClientSecret
            $entraResults = Search-EntraUser -Identity $Identity -Token $graphToken -IncludeDisabled:$IncludeDisabled
            if ($entraResults) {
                foreach ($r in @($entraResults)) { $allResults.Add($r) }
            }
        }
        catch {
            Write-Log "Entra ID search could not be completed: $_" -Level ERROR
        }
    }

    # ── Display results ─────────────────────────────────────────────────────
    Write-Summary -Results $allResults

    # ── Export to CSV ────────────────────────────────────────────────────────
    if ($allResults.Count -gt 0) {
        if (-not (Test-Path $Config.OutputDir)) {
            New-Item -Path $Config.OutputDir -ItemType Directory -Force | Out-Null
        }

        $csvPath = Join-Path $Config.OutputDir "$($Config.ScriptName)_$timestamp.csv"
        $allResults | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log "Results exported to: $csvPath" -Level SUCCESS
    }

    Write-Log "=== $($Config.ScriptName) completed ===" -Level SUCCESS

    # Return results to the pipeline
    Write-Output $allResults

    exit 0
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    Write-Log $_.ScriptStackTrace -Level ERROR
    exit 1
}
