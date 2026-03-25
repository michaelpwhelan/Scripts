<#
.SYNOPSIS
    Reports Microsoft 365 license SKU consumption via Microsoft Graph API.

.DESCRIPTION
    Authenticates to Microsoft Graph using client credentials, retrieves all
    subscribed SKUs, and exports a summary showing purchased units, consumed
    units, available units, friendly SKU names, and warnings for SKUs near
    or over capacity. An optional per-user license detail export identifies
    licenses assigned to disabled accounts as waste.

.PARAMETER ExportUserDetail
    Also export per-user license assignments and detect waste (licenses on
    disabled accounts). Overrides $Config.ExportUserDetail.

.PARAMETER WarnBelowPct
    Warn when available seats fall below this percentage of purchased seats.
    Overrides $Config.WarnBelowPct.

.PARAMETER TenantId
    Entra ID tenant ID. Overrides $Config.TenantId.

.PARAMETER ClientId
    Entra ID app registration client ID. Overrides $Config.ClientId.

.PARAMETER ClientSecret
    Entra ID app registration client secret. Overrides $Config.ClientSecret.

.EXAMPLE
    .\Get-LicenseReport.ps1
    Exports SKU summary to $PSScriptRoot\output\LicenseReport_<timestamp>.csv

.EXAMPLE
    .\Get-LicenseReport.ps1 -ExportUserDetail -WarnBelowPct 15
    Exports SKU summary and per-user detail with waste detection, warning at 15%.
#>
#Requires -Version 5.1
param(
    [switch]$ExportUserDetail,
    [int]$WarnBelowPct,
    [string]$TenantId,
    [string]$ClientId,
    [string]$ClientSecret
)

# =============================================================================
# CONFIGURATION
# =============================================================================
$Config = @{
    ScriptName = "Get-LicenseReport"
    LogDir     = "$PSScriptRoot\logs"
    OutputDir  = "$PSScriptRoot\output"

    # --- Entra ID / Graph API credentials ---
    TenantId     = if ($env:ENTRA_TENANT_ID)     { $env:ENTRA_TENANT_ID }     else { "<YOUR_TENANT_ID>" }
    ClientId     = if ($env:ENTRA_CLIENT_ID)     { $env:ENTRA_CLIENT_ID }     else { "<YOUR_CLIENT_ID>" }
    ClientSecret = if ($env:ENTRA_CLIENT_SECRET) { $env:ENTRA_CLIENT_SECRET } else { "<YOUR_CLIENT_SECRET>" }

    # --- Report options ---
    # Warn when available seats fall below this percentage of purchased seats.
    WarnBelowPct       = 10
    ExportUserDetail   = $false   # Set to $true to also export per-user license assignments
}
# =============================================================================

# --- SKU friendly-name lookup ---
# Maps common skuPartNumber values to readable display names.
$SkuFriendlyNames = @{
    "ENTERPRISEPACK"               = "Office 365 E3"
    "ENTERPRISEPREMIUM"            = "Office 365 E5"
    "SPE_E3"                       = "Microsoft 365 E3"
    "SPE_E5"                       = "Microsoft 365 E5"
    "SPE_F1"                       = "Microsoft 365 F3"
    "FLOW_FREE"                    = "Power Automate Free"
    "POWER_BI_STANDARD"            = "Power BI Free"
    "POWER_BI_PRO"                 = "Power BI Pro"
    "POWERAPPS_VIRAL"              = "Power Apps Plan 2 Trial"
    "TEAMS_EXPLORATORY"            = "Teams Exploratory"
    "STREAM"                       = "Microsoft Stream Trial"
    "EXCHANGESTANDARD"             = "Exchange Online Plan 1"
    "EXCHANGEENTERPRISE"           = "Exchange Online Plan 2"
    "EMS"                          = "Enterprise Mobility + Security E3"
    "EMSPREMIUM"                   = "Enterprise Mobility + Security E5"
    "AAD_PREMIUM"                  = "Entra ID P1"
    "AAD_PREMIUM_P2"               = "Entra ID P2"
    "ATP_ENTERPRISE"               = "Defender for Office 365 P1"
    "THREAT_INTELLIGENCE"          = "Defender for Office 365 P2"
    "WIN_DEF_ATP"                  = "Defender for Endpoint P2"
    "IDENTITY_THREAT_PROTECTION"   = "Entra ID Threat Protection"
    "PROJECTPREMIUM"               = "Project Plan 5"
    "PROJECTPROFESSIONAL"          = "Project Plan 3"
    "VISIOCLIENT"                  = "Visio Plan 2"
    "RIGHTSMANAGEMENT"             = "Azure Information Protection P1"
    "MCOSTANDARD"                  = "Skype for Business Online Plan 2"
    "PHONESYSTEM_VIRTUALUSER"      = "Teams Phone Resource Account"
    "MCOMEETADV"                   = "Teams Audio Conferencing"
    "MCOPSTN1"                     = "Teams Domestic Calling Plan"
    "MCOPSTN2"                     = "Teams Domestic and International Calling Plan"
    "MICROSOFT_BUSINESS_CENTER"    = "Microsoft Business Center"
    "O365_BUSINESS_ESSENTIALS"     = "Microsoft 365 Business Basic"
    "O365_BUSINESS_PREMIUM"        = "Microsoft 365 Business Standard"
    "SMB_BUSINESS_PREMIUM"         = "Microsoft 365 Business Premium"
    "INTUNE_A"                     = "Microsoft Intune Plan 1"
    "WINDOWS_STORE"                = "Windows Store for Business"
    "DESKLESSPACK"                 = "Office 365 F3"
    "ENTERPRISEWITHSCAL"           = "Office 365 E4 (Retired)"
    "STANDARDPACK"                 = "Office 365 E1"
}

# --- Parameter overrides ---
if ($ExportUserDetail)                                    { $Config.ExportUserDetail = $true }
if ($PSBoundParameters.ContainsKey('WarnBelowPct'))       { $Config.WarnBelowPct    = $WarnBelowPct }
if ($PSBoundParameters.ContainsKey('TenantId'))           { $Config.TenantId        = $TenantId }
if ($PSBoundParameters.ContainsKey('ClientId'))           { $Config.ClientId         = $ClientId }
if ($PSBoundParameters.ContainsKey('ClientSecret'))       { $Config.ClientSecret     = $ClientSecret }

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


# --- Functions ---

function Get-GraphToken {
    <# Acquires an OAuth2 access token for Microsoft Graph using client credentials. #>
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
    <# Retrieves all pages from a Microsoft Graph API endpoint with retry logic. #>
    param([string]$Token, [string]$Url)
    $headers = @{ Authorization = "Bearer $Token" }
    $items   = [System.Collections.Generic.List[object]]::new()
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
        $items.AddRange($response.value)
        $Url = $response.'@odata.nextLink'
        if ($Url) { Write-Log "Fetching next page ($($items.Count) records so far)..." }
    }
    return $items
}


# --- Main ---

try {
    Write-Log "Starting $($Config.ScriptName)"

    foreach ($key in @("TenantId", "ClientId", "ClientSecret")) {
        if ($Config[$key] -like "<*>") { throw "Config '$key' is not set." }
    }

    Write-Log "Acquiring Graph API token..."
    $token = Get-GraphToken -TenantId $Config.TenantId -ClientId $Config.ClientId -ClientSecret $Config.ClientSecret

    # ── SKU summary ──────────────────────────────────────────────────────────
    Write-Log "Retrieving subscribed SKUs..."
    $skus = Get-PagedResults -Token $token -Url "https://graph.microsoft.com/v1.0/subscribedSkus"
    Write-Log "Found $($skus.Count) SKU(s)"

    $summary = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($sku in $skus) {
        $purchased = $sku.prepaidUnits.enabled
        $consumed  = $sku.consumedUnits
        $available = $purchased - $consumed
        $pctUsed   = if ($purchased -gt 0) { [math]::Round(($consumed / $purchased) * 100, 1) } else { 0 }
        $pctAvail  = if ($purchased -gt 0) { [math]::Round(($available / $purchased) * 100, 1) } else { 0 }

        $warning = ""
        if ($purchased -gt 0) {
            if ($available -lt 0)                          { $warning = "OVER" }
            elseif ($pctAvail -lt $Config.WarnBelowPct)    { $warning = "LOW" }
        }

        if ($warning) {
            Write-Log "$warning SEATS: $($sku.skuPartNumber) — $available remaining ($pctAvail%)" -Level WARNING
        }

        $friendlyName = if ($SkuFriendlyNames.ContainsKey($sku.skuPartNumber)) {
            $SkuFriendlyNames[$sku.skuPartNumber]
        } else {
            $sku.skuPartNumber
        }

        $summary.Add([PSCustomObject]@{
            SKU           = $sku.skuPartNumber
            FriendlyName  = $friendlyName
            SkuId         = $sku.skuId
            Status        = $sku.capabilityStatus
            Purchased     = $purchased
            Consumed      = $consumed
            Available     = $available
            PctUsed       = "$pctUsed%"
            Warning       = $warning
            ReportedAt    = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        })
    }

    if (-not (Test-Path $Config.OutputDir)) { New-Item -ItemType Directory -Path $Config.OutputDir | Out-Null }
    $ts          = Get-Date -Format "yyyyMMdd_HHmmss"
    $skuFile     = Join-Path $Config.OutputDir "LicenseReport_$ts.csv"
    $summary | Export-Csv -Path $skuFile -NoTypeInformation -Encoding UTF8
    Write-Log "SKU summary exported to $skuFile"

    # ── Per-user detail (optional) ────────────────────────────────────────────
    $wasteCount     = 0
    $wasteLicenses  = 0
    $userFile       = $null

    if ($Config.ExportUserDetail) {
        Write-Log "Retrieving per-user license assignments..."
        $users = Get-PagedResults -Token $token -Url `
            "https://graph.microsoft.com/v1.0/users?`$select=displayName,userPrincipalName,accountEnabled,assignedLicenses&`$top=999"

        # Build a SKU ID → name lookup
        $skuMap = @{}
        foreach ($sku in $skus) { $skuMap[$sku.skuId] = $sku.skuPartNumber }

        $userRows = [System.Collections.Generic.List[PSCustomObject]]::new()
        foreach ($user in $users) {
            $licNames = ($user.assignedLicenses | ForEach-Object {
                $name = $skuMap[$_.skuId]
                if (-not $name) { $name = $_.skuId }
                $name
            }) -join "; "

            $isWaste = (-not $user.accountEnabled) -and ($user.assignedLicenses.Count -gt 0)
            if ($isWaste) {
                $wasteCount++
                $wasteLicenses += $user.assignedLicenses.Count
            }

            $userRows.Add([PSCustomObject]@{
                DisplayName       = $user.displayName
                UserPrincipalName = $user.userPrincipalName
                AccountEnabled    = $user.accountEnabled
                LicenseCount      = $user.assignedLicenses.Count
                Licenses          = $licNames
                IsWaste           = $isWaste
            })
        }

        $userFile = Join-Path $Config.OutputDir "LicenseDetail_Users_$ts.csv"
        $userRows | Export-Csv -Path $userFile -NoTypeInformation -Encoding UTF8
        Write-Log "Per-user license detail exported to $userFile"

        if ($wasteCount -gt 0) {
            Write-Log "$wasteCount disabled user(s) hold $wasteLicenses license(s) (waste)" -Level WARNING
        }
    }

    # --- Console summary ---

    $separator   = [string]::new([char]0x2550, 72)
    $divider     = [string]::new([char]0x2500, 72)
    $displayTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $totalPurchased = ($summary | Measure-Object -Property Purchased -Sum).Sum
    $totalConsumed  = ($summary | Measure-Object -Property Consumed -Sum).Sum
    $totalAvailable = $totalPurchased - $totalConsumed
    $warningSkus    = @($summary | Where-Object { $_.Warning -ne "" })

    Write-Summary ""
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary "  M365 License Report  —  $displayTime"                          -Color Yellow
    Write-Summary "  SKUs: $($summary.Count)  |  Warn threshold: <$($Config.WarnBelowPct)% available" -Color Yellow
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary ""

    # SKU capacity table
    Write-Summary "  SKU CAPACITY"                                                  -Color Cyan
    Write-Summary $divider                                                          -Color Cyan
    Write-Summary ("  {0,-40} {1,10} {2,10} {3,10} {4,7}  {5}" -f "SKU", "Purchased", "Consumed", "Available", "Used%", "Status") -Color Cyan
    Write-Summary $divider                                                          -Color Cyan

    foreach ($s in ($summary | Sort-Object { $_.Warning -eq "OVER" }, { $_.Warning -eq "LOW" } -Descending)) {
        $color = "White"
        if ($s.Warning -eq "OVER")  { $color = "Red" }
        elseif ($s.Warning -eq "LOW") { $color = "Yellow" }

        $displayName = if ($s.FriendlyName.Length -gt 38) { $s.FriendlyName.Substring(0, 38) + ".." } else { $s.FriendlyName }
        $warnFlag = if ($s.Warning) { "  [$($s.Warning)]" } else { "" }
        Write-Summary ("  {0,-40} {1,10} {2,10} {3,10} {4,7}  {5}" -f $displayName, $s.Purchased, $s.Consumed, $s.Available, $s.PctUsed, $warnFlag) -Color $color
    }
    Write-Summary ""

    # Warnings
    if ($warningSkus.Count -gt 0) {
        $overCount = @($warningSkus | Where-Object { $_.Warning -eq "OVER" }).Count
        $lowCount  = @($warningSkus | Where-Object { $_.Warning -eq "LOW" }).Count
        $warnLine  = "  WARNINGS: $($warningSkus.Count) SKU(s) flagged"
        if ($overCount -gt 0) { $warnLine += " — $overCount OVER capacity" }
        if ($lowCount -gt 0)  { $warnLine += " — $lowCount LOW on seats" }
        Write-Summary $warnLine                                                     -Color Red
        Write-Summary ""
    }

    # Waste detection
    if ($Config.ExportUserDetail -and $wasteCount -gt 0) {
        Write-Summary "  LICENSE WASTE"                                             -Color Cyan
        Write-Summary $divider                                                      -Color Cyan
        Write-Summary "  $wasteCount disabled account(s) still hold $wasteLicenses license(s)" -Color Red
        Write-Summary "  Review: $userFile"                                         -Color Red
        Write-Summary ""
    }

    # Final totals
    Write-Summary $separator                                                        -Color Cyan
    Write-Summary ("  TOTAL: {0} SKUs  |  {1} purchased  |  {2} consumed  |  {3} available" -f $summary.Count, $totalPurchased, $totalConsumed, $totalAvailable) -Color Cyan
    Write-Summary "  CSV: $skuFile"                                                 -Color Cyan
    if ($userFile) { Write-Summary "  Users: $userFile"                             -Color Cyan }
    Write-Summary $separator                                                        -Color Cyan
    Write-Summary ""

    Write-Log "Completed $($Config.ScriptName) successfully"
    exit 0
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    exit 1
}
