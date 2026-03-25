#Requires -Version 5.1

<#
.SYNOPSIS
    Resets a user's password in the appropriate directory (on-prem AD or Entra ID).

.DESCRIPTION
    Determines whether a user is synced from on-premises Active Directory or is
    cloud-only in Entra ID, then resets the password in the correct directory.
    A cryptographically secure temporary password is generated, displayed once on
    screen, and never written to any log or export file.

    For synced users the reset is performed against on-prem AD using
    Set-ADAccountPassword. For cloud-only users a PATCH request is sent to the
    Microsoft Graph /users endpoint. An audit CSV is written after each
    successful reset recording the timestamp, admin, UPN, directory, and whether
    a password change is required at next logon.

.PARAMETER UserPrincipalName
    User principal name of the user whose password will be reset.

.PARAMETER PasswordLength
    Length of the generated temporary password. Must be between 12 and 128.
    Defaults to 16.

.PARAMETER NoChangeRequired
    When specified the user will NOT be forced to change their password at next
    logon. By default the user is required to change.

.EXAMPLE
    .\Reset-UserPassword.ps1 -UserPrincipalName jsmith@contoso.com

    Resets the password for jsmith@contoso.com with a 16-character temporary
    password and requires a password change at next logon.

.EXAMPLE
    .\Reset-UserPassword.ps1 -UPN jsmith@contoso.com -PasswordLength 24 -NoChangeRequired

    Resets the password with a 24-character temporary password and does not
    require a change at next logon.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, Position = 0, HelpMessage = "User principal name of the user to reset.")]
    [ValidateNotNullOrEmpty()]
    [Alias("UPN")]
    [string]$UserPrincipalName,

    [Parameter(HelpMessage = "Length of the generated temporary password.")]
    [ValidateRange(12, 128)]
    [int]$PasswordLength = 16,

    [Parameter(HelpMessage = "Do not require password change at next logon.")]
    [switch]$NoChangeRequired
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
$Config = @{
    ScriptName   = "Reset-UserPassword"
    LogDir       = "$PSScriptRoot\logs"
    OutputDir    = "$PSScriptRoot\output"

    TenantId     = if ($env:ENTRA_TENANT_ID)     { $env:ENTRA_TENANT_ID }     else { "<YOUR_TENANT_ID>" }
    ClientId     = if ($env:ENTRA_CLIENT_ID)     { $env:ENTRA_CLIENT_ID }     else { "<YOUR_CLIENT_ID>" }
    ClientSecret = if ($env:ENTRA_CLIENT_SECRET) { $env:ENTRA_CLIENT_SECRET } else { "<YOUR_CLIENT_SECRET>" }

    RequireAD    = $false
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

# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry     = "[$timestamp] [$Level] $Message"

    if (-not (Test-Path -Path $Config.LogDir)) {
        New-Item -Path $Config.LogDir -ItemType Directory -Force | Out-Null
    }

    $logFile = Join-Path -Path $Config.LogDir -ChildPath "$($Config.ScriptName)_$(Get-Date -Format 'yyyyMMdd').log"
    $entry | Out-File -FilePath $logFile -Append -Encoding UTF8

    switch ($Level) {
        "WARN"    { Write-Warning $Message }
        "ERROR"   { Write-Error $Message }
        "SUCCESS" { Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor Green }
        "DEBUG"   { Write-Verbose "[$timestamp] [$Level] $Message" }
        default   { Write-Verbose $Message }
    }
}

function Write-Summary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Data
    )

    Write-Host ""
    Write-Host "========== $($Config.ScriptName) Summary ==========" -ForegroundColor Cyan
    foreach ($key in $Data.Keys | Sort-Object) {
        Write-Host "  ${key}: $($Data[$key])"
    }
    Write-Host "====================================================" -ForegroundColor Cyan
    Write-Host ""
}

if (-not $_toolkitLoaded) {
function Invoke-WithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [int]$MaxAttempts = 3,

        [int]$BaseDelaySeconds = 2,

        [string]$OperationName = "Operation"
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return (& $ScriptBlock)
        }
        catch {
            if ($attempt -eq $MaxAttempts) {
                Write-Log -Message "$OperationName failed after $MaxAttempts attempts: $_" -Level ERROR
                throw
            }
            $delay = $BaseDelaySeconds * [math]::Pow(2, $attempt - 1)
            Write-Log -Message "$OperationName attempt $attempt failed. Retrying in ${delay}s: $_" -Level WARN
            Start-Sleep -Seconds $delay
        }
    }
}

function Protect-ODataValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    return $Value.Replace("'", "''")
}
}

function Get-GraphToken {
    [CmdletBinding()]
    param()

    # Validate tenant and client IDs are GUIDs
    $guidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'

    if ($Config.TenantId -notmatch $guidPattern) {
        throw "TenantId is not a valid GUID. Set the ENTRA_TENANT_ID environment variable."
    }
    if ($Config.ClientId -notmatch $guidPattern) {
        throw "ClientId is not a valid GUID. Set the ENTRA_CLIENT_ID environment variable."
    }
    if ([string]::IsNullOrWhiteSpace($Config.ClientSecret) -or $Config.ClientSecret -eq '<YOUR_CLIENT_SECRET>') {
        throw "ClientSecret is not configured. Set the ENTRA_CLIENT_SECRET environment variable."
    }

    $tokenUrl = "https://login.microsoftonline.com/$($Config.TenantId)/oauth2/v2.0/token"
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $Config.ClientId
        client_secret = $Config.ClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }

    $response = Invoke-WithRetry -OperationName "Acquire Graph token" -ScriptBlock {
        Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
    }

    if (-not $response.access_token) {
        throw "Token response did not contain an access_token."
    }

    return $response.access_token
}

function Get-SecureRandomIndex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$MaxExclusive
    )

    if ($MaxExclusive -le 0) {
        throw "MaxExclusive must be greater than zero."
    }

    $rng   = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = [byte[]]::new(4)
    $rng.GetBytes($bytes)
    $value = [System.BitConverter]::ToUInt32($bytes, 0)
    $rng.Dispose()

    return [int]($value % $MaxExclusive)
}

function New-RandomPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(12, 128)]
        [int]$Length
    )

    $upperChars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $lowerChars  = "abcdefghijklmnopqrstuvwxyz"
    $digitChars  = "0123456789"
    $symbolChars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    $allChars    = $upperChars + $lowerChars + $digitChars + $symbolChars

    # Guarantee at least one of each category
    $passwordChars = [char[]]::new($Length)
    $passwordChars[0] = $upperChars[(Get-SecureRandomIndex -MaxExclusive $upperChars.Length)]
    $passwordChars[1] = $lowerChars[(Get-SecureRandomIndex -MaxExclusive $lowerChars.Length)]
    $passwordChars[2] = $digitChars[(Get-SecureRandomIndex -MaxExclusive $digitChars.Length)]
    $passwordChars[3] = $symbolChars[(Get-SecureRandomIndex -MaxExclusive $symbolChars.Length)]

    # Fill remaining positions from the full character set
    for ($i = 4; $i -lt $Length; $i++) {
        $passwordChars[$i] = $allChars[(Get-SecureRandomIndex -MaxExclusive $allChars.Length)]
    }

    # Fisher-Yates shuffle using cryptographic RNG
    for ($i = $Length - 1; $i -gt 0; $i--) {
        $j = Get-SecureRandomIndex -MaxExclusive ($i + 1)
        $temp              = $passwordChars[$i]
        $passwordChars[$i] = $passwordChars[$j]
        $passwordChars[$j] = $temp
    }

    return -join $passwordChars
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$exitCode = 0

try {
    Write-Log -Message "=== $($Config.ScriptName) started ==="
    Write-Log -Message "Target UPN: $UserPrincipalName"

    # -----------------------------------------------------------------------
    # Module dependency check
    # -----------------------------------------------------------------------
    $adModuleAvailable = $false
    if (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $adModuleAvailable = $true
            Write-Log -Message "ActiveDirectory module loaded."
        }
        catch {
            Write-Log -Message "ActiveDirectory module found but failed to import: $_" -Level WARN
        }
    }
    else {
        Write-Log -Message "ActiveDirectory module not available on this system." -Level WARN
    }

    if ($Config.RequireAD -and -not $adModuleAvailable) {
        throw "ActiveDirectory module is required (RequireAD = true) but is not available."
    }

    $entraAvailable = $true
    try {
        $null = Get-GraphToken
        Write-Log -Message "Entra ID credentials validated."
    }
    catch {
        $entraAvailable = $false
        Write-Log -Message "Entra ID credentials not configured or invalid: $_" -Level WARN
    }

    if (-not $adModuleAvailable -and -not $entraAvailable) {
        throw "Neither on-prem AD nor Entra ID is available. Cannot reset password."
    }

    # -----------------------------------------------------------------------
    # Determine user type
    # -----------------------------------------------------------------------
    $entraUser          = $null
    $isSyncedUser       = $false
    $isCloudOnly        = $false
    $adUser             = $null
    $targetDirectory    = $null

    if ($entraAvailable) {
        Write-Log -Message "Querying Entra ID for user..."
        try {
            $token          = Get-GraphToken
            $escapedUpn     = Protect-ODataValue -Value $UserPrincipalName
            $filterQuery    = "userPrincipalName eq '$escapedUpn'"
            $selectFields   = "id,displayName,onPremisesSyncEnabled,userPrincipalName"
            $graphUri       = "https://graph.microsoft.com/v1.0/users?`$filter=$filterQuery&`$select=$selectFields"

            $headers = @{
                Authorization = "Bearer $token"
            }

            $graphResponse = Invoke-WithRetry -OperationName "Query Entra user" -ScriptBlock {
                Invoke-RestMethod -Uri $graphUri -Headers $headers -Method GET -ContentType "application/json" -ErrorAction Stop
            }

            if ($graphResponse.value -and $graphResponse.value.Count -gt 0) {
                $entraUser = $graphResponse.value[0]
                Write-Log -Message "Found Entra user: $($entraUser.displayName) ($($entraUser.userPrincipalName))"

                if ($entraUser.onPremisesSyncEnabled -eq $true) {
                    $isSyncedUser = $true
                    Write-Log -Message "User is synced from on-premises AD."
                }
                else {
                    $isCloudOnly = $true
                    Write-Log -Message "User is cloud-only."
                }
            }
            else {
                Write-Log -Message "User not found in Entra ID." -Level WARN
            }
        }
        catch {
            Write-Log -Message "Failed to query Entra ID: $_" -Level WARN
        }
    }

    # Check on-prem AD if available
    if ($adModuleAvailable) {
        Write-Log -Message "Checking on-prem AD for user..."
        try {
            $sanitizedUpn = $UserPrincipalName -replace '[\\*]', ''
            $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$sanitizedUpn'" -Properties UserPrincipalName -ErrorAction Stop
            if ($adUser) {
                Write-Log -Message "Found on-prem AD user: $($adUser.Name)"
            }
            else {
                Write-Log -Message "User not found in on-prem AD."
            }
        }
        catch {
            Write-Log -Message "Failed to query on-prem AD: $_" -Level WARN
        }
    }

    # Decide target directory
    if ($isSyncedUser -and $adUser) {
        $targetDirectory = "On-Premises Active Directory"
    }
    elseif ($isSyncedUser -and -not $adUser -and -not $adModuleAvailable) {
        throw "User is synced from on-prem AD but the ActiveDirectory module is not available. Reset must be performed against on-prem AD."
    }
    elseif ($isSyncedUser -and -not $adUser) {
        throw "User is synced from on-prem AD but was not found in on-prem AD. Verify connectivity and the user's account."
    }
    elseif ($isCloudOnly) {
        $targetDirectory = "Entra ID (Cloud)"
    }
    elseif ($adUser -and -not $entraUser) {
        $targetDirectory = "On-Premises Active Directory"
    }
    else {
        throw "Unable to determine user directory for '$UserPrincipalName'. User not found in Entra ID or on-prem AD."
    }

    Write-Log -Message "Target directory: $targetDirectory"

    # -----------------------------------------------------------------------
    # Generate temporary password
    # -----------------------------------------------------------------------
    $tempPassword = New-RandomPassword -Length $PasswordLength
    Write-Log -Message "Generated temporary password ($PasswordLength characters)."

    # -----------------------------------------------------------------------
    # ShouldProcess confirmation
    # -----------------------------------------------------------------------
    if (-not $PSCmdlet.ShouldProcess($UserPrincipalName, "Reset password in $targetDirectory")) {
        Write-Log -Message "Operation cancelled by user."
        exit 0
    }

    # -----------------------------------------------------------------------
    # Reset password
    # -----------------------------------------------------------------------
    $requireChange = -not $NoChangeRequired

    if ($targetDirectory -eq "On-Premises Active Directory") {
        Write-Log -Message "Resetting password in on-prem AD..."
        try {
            $securePassword = ConvertTo-SecureString -String $tempPassword -AsPlainText -Force
            Set-ADAccountPassword -Identity $adUser.DistinguishedName -Reset -NewPassword $securePassword -ErrorAction Stop
            Write-Log -Message "Password reset successfully in on-prem AD."

            if ($requireChange) {
                Set-ADUser -Identity $adUser.DistinguishedName -ChangePasswordAtLogon $true -ErrorAction Stop
                Write-Log -Message "User must change password at next logon."
            }
            else {
                Set-ADUser -Identity $adUser.DistinguishedName -ChangePasswordAtLogon $false -ErrorAction Stop
                Write-Log -Message "User is NOT required to change password at next logon."
            }
        }
        catch {
            Write-Log -Message "Failed to reset password in on-prem AD: $_" -Level ERROR
            throw
        }
    }
    elseif ($targetDirectory -eq "Entra ID (Cloud)") {
        Write-Log -Message "Resetting password in Entra ID..."
        try {
            $token   = Get-GraphToken
            $headers = @{
                Authorization  = "Bearer $token"
                "Content-Type" = "application/json"
            }

            $body = @{
                passwordProfile = @{
                    forceChangePasswordNextSignIn = $requireChange
                    password                     = $tempPassword
                }
            } | ConvertTo-Json -Depth 4

            $patchUri = "https://graph.microsoft.com/v1.0/users/$($entraUser.id)"

            Invoke-WithRetry -OperationName "Reset Entra password" -ScriptBlock {
                Invoke-RestMethod -Uri $patchUri -Headers $headers -Method PATCH -Body $body -ErrorAction Stop
            }

            Write-Log -Message "Password reset successfully in Entra ID."
            if ($requireChange) {
                Write-Log -Message "User must change password at next sign-in."
            }
            else {
                Write-Log -Message "User is NOT required to change password at next sign-in."
            }
        }
        catch {
            Write-Log -Message "Failed to reset password in Entra ID: $_" -Level ERROR
            throw
        }
    }

    # -----------------------------------------------------------------------
    # Display password ONCE
    # -----------------------------------------------------------------------
    Write-Host ""
    Write-Host "  Password reset successful for: $UserPrincipalName" -ForegroundColor Green
    Write-Host "  Directory: $targetDirectory" -ForegroundColor Green
    Write-Host ""
    # Password displayed to console only -- intentionally NOT logged
    Write-Host "  Temporary Password: $tempPassword" -ForegroundColor Yellow
    Write-Host "  >> Copy this password now. It will not be shown again." -ForegroundColor Cyan
    Write-Host ""

    if ($requireChange) {
        Write-Host "  The user must change their password at next logon." -ForegroundColor White
    }
    else {
        Write-Host "  The user is NOT required to change their password." -ForegroundColor White
    }

    # Securely discard the password from memory
    $tempPassword = $null
    [System.GC]::Collect()

    # -----------------------------------------------------------------------
    # Audit CSV export
    # -----------------------------------------------------------------------
    if (-not (Test-Path -Path $Config.OutputDir)) {
        New-Item -Path $Config.OutputDir -ItemType Directory -Force | Out-Null
    }

    $csvPath = Join-Path -Path $Config.OutputDir -ChildPath "$($Config.ScriptName)_audit.csv"

    $auditRecord = [PSCustomObject]@{
        Timestamp       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Admin           = ([Environment]::UserName)
        UserPrincipalName = $UserPrincipalName
        Directory       = $targetDirectory
        RequireChange   = $requireChange
    }

    $auditRecord | Export-Csv -Path $csvPath -Append -NoTypeInformation -Encoding UTF8
    Write-Log -Message "Audit record written to $csvPath"

    # -----------------------------------------------------------------------
    # AD Connect sync note
    # -----------------------------------------------------------------------
    if ($targetDirectory -eq "On-Premises Active Directory") {
        Write-Host ""
        Write-Host "  NOTE: This user is synced via AD Connect. The password change" -ForegroundColor Magenta
        Write-Host "  will sync to Entra ID on the next sync cycle (typically ~30 min)." -ForegroundColor Magenta
        Write-Host "  The user may not be able to sign in to cloud services until sync completes." -ForegroundColor Magenta
        Write-Host ""
    }

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    Write-Summary -Data @{
        "1-User"            = $UserPrincipalName
        "2-Directory"       = $targetDirectory
        "3-RequireChange"   = $requireChange
        "4-AuditLog"        = $csvPath
        "5-Status"          = "Success"
    }

    Write-Log -Message "=== $($Config.ScriptName) completed successfully ==="
}
catch {
    Write-Log -Message "FATAL: $_" -Level ERROR
    Write-Log -Message $_.ScriptStackTrace -Level ERROR
    $exitCode = 1
}

exit $exitCode
