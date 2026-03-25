<#
.SYNOPSIS
    Lists all devices associated with a user from Entra ID and optionally on-prem Active Directory.

.DESCRIPTION
    Queries Entra ID (Microsoft Graph) for owned and registered devices belonging to the
    specified user, then optionally queries on-premises Active Directory for computer
    objects whose ManagedBy attribute matches the user.  Results are merged, deduplicated,
    and displayed with compliance status, trust type, stale-device flagging, and
    relationship context.  A CSV export is always written; stale devices are excluded from
    console output by default unless -IncludeStale is specified.

.PARAMETER UserUPN
    User principal name to look up devices for (e.g. john.smith@contoso.com).

.PARAMETER IncludeStale
    Include devices that have been inactive beyond the configured stale threshold
    in the console output.  Stale devices are always included in the CSV export
    regardless of this switch.

.EXAMPLE
    .\Get-UserDevices.ps1 -UserUPN "john.smith@contoso.com"
    Lists all active devices for the specified user, excluding stale devices from display.

.EXAMPLE
    .\Get-UserDevices.ps1 -UserUPN "jane.doe@contoso.com" -IncludeStale
    Lists all devices including those inactive beyond the stale threshold.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0, HelpMessage = "User principal name to look up devices for.")]
    [ValidateNotNullOrEmpty()]
    [Alias("UPN")]
    [string]$UserUPN,

    [Parameter(HelpMessage = "Include devices inactive beyond the stale threshold.")]
    [switch]$IncludeStale
)

# =============================================================================
# CONFIGURATION
# =============================================================================
$Config = @{
    ScriptName         = "Get-UserDevices"
    LogDir             = "$PSScriptRoot\logs"
    OutputDir          = "$PSScriptRoot\output"

    TenantId           = if ($env:ENTRA_TENANT_ID)     { $env:ENTRA_TENANT_ID }     else { "<YOUR_TENANT_ID>" }
    ClientId           = if ($env:ENTRA_CLIENT_ID)     { $env:ENTRA_CLIENT_ID }     else { "<YOUR_CLIENT_ID>" }
    ClientSecret       = if ($env:ENTRA_CLIENT_SECRET) { $env:ENTRA_CLIENT_SECRET } else { "<YOUR_CLIENT_SECRET>" }

    RequireAD          = $false
    StaleDaysThreshold = 90    # Devices with no activity beyond this are "stale"
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

function Write-Summary {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $Message }
}


# --- Functions ---

if (-not $_toolkitLoaded) {
function Get-GraphToken {
    param([string]$TenantId, [string]$ClientId, [string]$ClientSecret)
    if ($TenantId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
        throw "TenantId '$TenantId' is not a valid GUID format."
    }
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

function Protect-ODataValue {
    param([string]$Value)
    return $Value -replace "'", "''"
}

function Get-PagedResults {
    param(
        [string]$Token,
        [string]$Uri,
        [string]$OperationName = "Graph API request"
    )
    $headers = @{ Authorization = "Bearer $Token" }
    $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()
    $currentUri = $Uri

    while ($currentUri) {
        $response = Invoke-WithRetry -OperationName $OperationName -ScriptBlock {
            try {
                $result = Invoke-RestMethod -Method GET -Uri $currentUri -Headers $headers -ErrorAction Stop
                return $result
            }
            catch {
                $statusCode = $null
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }
                if ($statusCode -eq 429 -or ($statusCode -ge 500 -and $statusCode -lt 600)) {
                    # Retriable error — let Invoke-WithRetry handle it
                    throw
                }
                # Non-retriable error — rethrow immediately
                throw
            }
        }

        if ($response.value) {
            foreach ($item in $response.value) {
                $allResults.Add($item)
            }
        }

        $currentUri = $response.'@odata.nextLink'
    }

    return $allResults
}
}

function Show-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor White
    Write-Host "  $Title" -ForegroundColor White
    Write-Host ("=" * 60) -ForegroundColor White
}

function Show-Property {
    param([string]$Label, $Value, [string]$Color = "Gray")
    $displayValue = if ($null -eq $Value -or $Value -eq "") { "(not set)" } else { $Value }
    Write-Host ("  {0,-28} " -f "${Label}:") -NoNewline -ForegroundColor DarkGray
    Write-Host $displayValue -ForegroundColor $Color
}

function Get-TrustType {
    param([PSCustomObject]$Device)
    $trustType = $Device.trustType
    switch ($trustType) {
        "ServerAd"      { return "Domain Joined" }
        "AzureAd"       { return "Entra ID Joined" }
        "Workplace"     { return "Entra ID Registered" }
        default {
            # Check for hybrid join: device has both on-prem sync and Entra registration
            if ($Device.onPremisesSyncEnabled -eq $true -and $Device.trustType -eq "AzureAd") {
                return "Hybrid Joined"
            }
            if ($trustType) { return $trustType }
            return "Unknown"
        }
    }
}

function Get-ComplianceState {
    param([PSCustomObject]$Device)
    if ($Device.isCompliant -eq $true) { return "Compliant" }
    if ($Device.isCompliant -eq $false) { return "Non-Compliant" }
    return "Unknown"
}


# --- Main ---

try {
    Write-Log "Starting $($Config.ScriptName) - looking up devices for '$UserUPN'"
    $allDevices = [System.Collections.Generic.List[PSCustomObject]]::new()

    # ── Dependency checks ────────────────────────────────────────────────────
    $adAvailable    = $null -ne (Get-Module -ListAvailable ActiveDirectory -ErrorAction SilentlyContinue)
    $entraAvailable = ($Config.TenantId -notlike "<*>")

    if (-not $entraAvailable) {
        Write-Log "Entra ID credentials not configured. Set ENTRA_TENANT_ID, ENTRA_CLIENT_ID, and ENTRA_CLIENT_SECRET environment variables." -Level ERROR
        throw "Entra ID credentials are required for device lookup."
    }

    if (-not $adAvailable -and $Config.RequireAD) {
        throw "ActiveDirectory module is required (RequireAD is set) but not available. Install RSAT or run on a domain controller."
    }

    if (-not $adAvailable) {
        Write-Log "ActiveDirectory module not available - skipping on-prem device lookup" -Level WARN
    }

    # ── Acquire Graph token ──────────────────────────────────────────────────
    Write-Log "Acquiring Graph API token..."
    $token = Invoke-WithRetry -OperationName "Graph token acquisition" -ScriptBlock {
        Get-GraphToken -TenantId $Config.TenantId -ClientId $Config.ClientId -ClientSecret $Config.ClientSecret
    }

    # ── Resolve user in Entra ID ─────────────────────────────────────────────
    Write-Log "Resolving user '$UserUPN' in Entra ID..."
    $escapedUPN = Protect-ODataValue -Value $UserUPN
    $userUri = "https://graph.microsoft.com/v1.0/users?`$filter=userPrincipalName eq '$escapedUPN'&`$select=id,displayName,userPrincipalName"

    $userResponse = Invoke-WithRetry -OperationName "User lookup" -ScriptBlock {
        $headers = @{ Authorization = "Bearer $token" }
        Invoke-RestMethod -Method GET -Uri $userUri -Headers $headers -ErrorAction Stop
    }

    if (-not $userResponse.value -or $userResponse.value.Count -eq 0) {
        throw "User '$UserUPN' not found in Entra ID."
    }

    $entraUser   = $userResponse.value[0]
    $entraUserId = $entraUser.id
    Write-Log "Found user: $($entraUser.displayName) (ID: $entraUserId)"

    # ── Entra ID Devices ─────────────────────────────────────────────────────
    Write-Log "Querying owned devices..."
    $ownedDevices = @()
    try {
        $selectFields = "id,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant,isManaged,approximateLastSignInDateTime,onPremisesSyncEnabled,registrationDateTime,deviceId"
        $ownedUri = "https://graph.microsoft.com/v1.0/users/$entraUserId/ownedDevices/microsoft.graph.device?`$select=$selectFields"
        $ownedDevices = @(Get-PagedResults -Token $token -Uri $ownedUri -OperationName "Owned devices query")
    }
    catch {
        Write-Log "Failed to query owned devices: $_" -Level WARN
    }

    Write-Log "Querying registered devices..."
    $registeredDevices = @()
    try {
        $registeredUri = "https://graph.microsoft.com/v1.0/users/$entraUserId/registeredDevices/microsoft.graph.device?`$select=$selectFields"
        $registeredDevices = @(Get-PagedResults -Token $token -Uri $registeredUri -OperationName "Registered devices query")
    }
    catch {
        Write-Log "Failed to query registered devices: $_" -Level WARN
    }

    # Build relationship map and deduplicate
    $deviceMap = @{}

    foreach ($device in $ownedDevices) {
        $deviceMap[$device.id] = @{
            Device       = $device
            Relationship = "Owner"
        }
    }

    foreach ($device in $registeredDevices) {
        if ($deviceMap.ContainsKey($device.id)) {
            $deviceMap[$device.id].Relationship = "Owner + Registered"
        } else {
            $deviceMap[$device.id] = @{
                Device       = $device
                Relationship = "Registered"
            }
        }
    }

    Write-Log "Found $($deviceMap.Count) unique Entra ID device(s) ($($ownedDevices.Count) owned, $($registeredDevices.Count) registered)"

    $staleThreshold = (Get-Date).AddDays(-$Config.StaleDaysThreshold)

    foreach ($entry in $deviceMap.Values) {
        $device       = $entry.Device
        $relationship = $entry.Relationship

        $lastActivity = $null
        if ($device.approximateLastSignInDateTime) {
            try {
                $lastActivity = [datetime]$device.approximateLastSignInDateTime
            } catch {
                $lastActivity = $null
            }
        }

        $isStale = $false
        if ($null -eq $lastActivity) {
            $isStale = $true
        } elseif ($lastActivity -lt $staleThreshold) {
            $isStale = $true
        }

        $trustType       = Get-TrustType -Device $device
        $complianceState = Get-ComplianceState -Device $device

        $deviceObj = [PSCustomObject]@{
            Source           = "Entra ID"
            DeviceName       = $device.displayName
            OS               = $device.operatingSystem
            OSVersion        = $device.operatingSystemVersion
            TrustType        = $trustType
            ComplianceState  = $complianceState
            IsManaged        = [bool]$device.isManaged
            LastActivity     = $lastActivity
            IsStale          = $isStale
            Relationship     = $relationship
            DeviceId         = $device.id
            RegistrationDate = $device.registrationDateTime
        }

        $allDevices.Add($deviceObj)
    }

    # ── On-Prem AD Devices ───────────────────────────────────────────────────
    if ($adAvailable) {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Log "Searching on-prem AD for devices managed by '$UserUPN'..."

        try {
            $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$($UserUPN -replace "'","''")'" `
                -Properties DistinguishedName -ErrorAction Stop

            if ($adUser) {
                $dn = $adUser.DistinguishedName
                $escapedDN = $dn -replace "'", "''"
                $adComputers = @(Get-ADComputer -Filter "ManagedBy -eq '$escapedDN'" `
                    -Properties Name, OperatingSystem, OperatingSystemVersion, LastLogonDate, Created, ManagedBy `
                    -ErrorAction Stop)

                Write-Log "Found $($adComputers.Count) on-prem AD computer(s) managed by user"

                foreach ($computer in $adComputers) {
                    $lastLogon = $computer.LastLogonDate

                    $isStale = $false
                    if ($null -eq $lastLogon) {
                        $isStale = $true
                    } elseif ($lastLogon -lt $staleThreshold) {
                        $isStale = $true
                    }

                    $deviceObj = [PSCustomObject]@{
                        Source           = "On-Prem AD"
                        DeviceName       = $computer.Name
                        OS               = $computer.OperatingSystem
                        OSVersion        = $computer.OperatingSystemVersion
                        TrustType        = "Domain Joined"
                        ComplianceState  = "Unknown"
                        IsManaged        = $true
                        LastActivity     = $lastLogon
                        IsStale          = $isStale
                        Relationship     = "ManagedBy"
                        DeviceId         = $computer.ObjectGUID.ToString()
                        RegistrationDate = $computer.Created
                    }

                    $allDevices.Add($deviceObj)
                }
            } else {
                Write-Log "User '$UserUPN' not found in on-prem AD" -Level WARN
            }
        }
        catch {
            Write-Log "Error querying on-prem AD: $_" -Level WARN
        }
    }

    # ── Console output ───────────────────────────────────────────────────────
    $entraDevices  = @($allDevices | Where-Object { $_.Source -eq "Entra ID" })
    $adDevicesList = @($allDevices | Where-Object { $_.Source -eq "On-Prem AD" })

    $displayDevices = if ($IncludeStale) {
        $allDevices
    } else {
        @($allDevices | Where-Object { -not $_.IsStale })
    }

    $staleCount     = @($allDevices | Where-Object { $_.IsStale }).Count
    $compliantCount = @($allDevices | Where-Object { $_.ComplianceState -eq "Compliant" }).Count

    # Entra ID section
    $entraDisplay = @($displayDevices | Where-Object { $_.Source -eq "Entra ID" })
    Show-Section "Entra ID Devices ($($entraDisplay.Count) shown, $($entraDevices.Count) total)"

    if ($entraDisplay.Count -eq 0) {
        Write-Summary "  No Entra ID devices to display." "DarkGray"
        if ($entraDevices.Count -gt 0 -and -not $IncludeStale) {
            Write-Summary "  ($($staleCount) stale device(s) hidden - use -IncludeStale to show)" "Yellow"
        }
    }

    foreach ($device in $entraDisplay) {
        Write-Host ""
        $nameColor = if ($device.IsStale) { "Yellow" } else { "White" }
        Show-Property "Device Name"       $device.DeviceName $nameColor
        Show-Property "OS"                "$($device.OS) $($device.OSVersion)"
        Show-Property "Trust Type"        $device.TrustType

        $compColor = switch ($device.ComplianceState) {
            "Compliant"     { "Green" }
            "Non-Compliant" { "Red" }
            default         { "DarkGray" }
        }
        Show-Property "Compliance"        $device.ComplianceState $compColor

        $managedColor = if ($device.IsManaged) { "Green" } else { "Yellow" }
        Show-Property "Managed"           $device.IsManaged $managedColor

        $activityColor = if ($device.IsStale) { "Yellow" } else { "Gray" }
        $activityDisplay = if ($device.LastActivity) { $device.LastActivity.ToString("yyyy-MM-dd HH:mm:ss") } else { "(never)" }
        Show-Property "Last Activity"     $activityDisplay $activityColor

        if ($device.IsStale) {
            Show-Property "Stale"         "Yes" "Yellow"
        }

        Show-Property "Relationship"      $device.Relationship
        Show-Property "Device ID"         $device.DeviceId "DarkGray"

        $regDisplay = if ($device.RegistrationDate) { ([datetime]$device.RegistrationDate).ToString("yyyy-MM-dd") } else { "(not set)" }
        Show-Property "Registered"        $regDisplay
    }

    # On-Prem AD section
    $adDisplay = @($displayDevices | Where-Object { $_.Source -eq "On-Prem AD" })
    Show-Section "On-Prem AD Devices ($($adDisplay.Count) shown, $($adDevicesList.Count) total)"

    if (-not $adAvailable) {
        Write-Summary "  ActiveDirectory module not available - skipped." "DarkGray"
    } elseif ($adDisplay.Count -eq 0) {
        Write-Summary "  No on-prem AD devices to display." "DarkGray"
    }

    foreach ($device in $adDisplay) {
        Write-Host ""
        $nameColor = if ($device.IsStale) { "Yellow" } else { "White" }
        Show-Property "Computer Name"     $device.DeviceName $nameColor
        Show-Property "OS"                "$($device.OS) $($device.OSVersion)"
        Show-Property "Trust Type"        $device.TrustType

        $managedColor = if ($device.IsManaged) { "Green" } else { "Yellow" }
        Show-Property "Managed"           $device.IsManaged $managedColor

        $activityColor = if ($device.IsStale) { "Yellow" } else { "Gray" }
        $activityDisplay = if ($device.LastActivity) { $device.LastActivity.ToString("yyyy-MM-dd HH:mm:ss") } else { "(never)" }
        Show-Property "Last Activity"     $activityDisplay $activityColor

        if ($device.IsStale) {
            Show-Property "Stale"         "Yes" "Yellow"
        }

        Show-Property "Device ID"         $device.DeviceId "DarkGray"

        $regDisplay = if ($device.RegistrationDate) { ([datetime]$device.RegistrationDate).ToString("yyyy-MM-dd") } else { "(not set)" }
        Show-Property "Created"           $regDisplay
    }

    # ── Summary ──────────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor White
    Write-Host "  Summary for $($entraUser.displayName) ($UserUPN)" -ForegroundColor White
    Write-Host ("=" * 60) -ForegroundColor White

    Write-Summary ("  {0,-28} {1}" -f "Total Devices:", $allDevices.Count) "White"

    $compliantColor = if ($compliantCount -eq $allDevices.Count -and $allDevices.Count -gt 0) { "Green" } else { "Yellow" }
    Write-Summary ("  {0,-28} {1}" -f "Compliant:", $compliantCount) $compliantColor

    $staleColor = if ($staleCount -gt 0) { "Yellow" } else { "Green" }
    Write-Summary ("  {0,-28} {1}" -f "Stale:", $staleCount) $staleColor

    if (-not $IncludeStale -and $staleCount -gt 0) {
        Write-Summary "  (Use -IncludeStale to show stale devices in console output)" "DarkGray"
    }

    # ── CSV export ───────────────────────────────────────────────────────────
    if ($allDevices.Count -gt 0) {
        if (-not (Test-Path $Config.OutputDir)) { New-Item -ItemType Directory -Path $Config.OutputDir | Out-Null }
        $safeUPN = $UserUPN -replace '[^a-zA-Z0-9.]', '_'
        $outputFile = Join-Path $Config.OutputDir (
            "{0}_{1}_{2}.csv" -f $Config.ScriptName, $safeUPN, (Get-Date -Format "yyyyMMdd_HHmmss")
        )

        $allDevices | Select-Object Source, DeviceName, OS, OSVersion, TrustType, ComplianceState, `
            IsManaged, LastActivity, IsStale, Relationship, DeviceId, RegistrationDate |
            Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8

        Write-Log "Exported $($allDevices.Count) device(s) to $outputFile"
    } else {
        Write-Log "No devices found for user '$UserUPN'" -Level WARN
    }

    # ── Output result objects ────────────────────────────────────────────────
    Write-Output $allDevices

    Write-Host ""
    Write-Log "Completed $($Config.ScriptName) successfully"
    exit 0
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    exit 1
}
