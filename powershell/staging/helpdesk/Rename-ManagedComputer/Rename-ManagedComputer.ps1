<#
.SYNOPSIS
    Renames a managed computer with pre-flight safety checks.

.DESCRIPTION
    A superpowered wrapper around Rename-Computer. Performs pre-flight checks
    (elevation, name collisions in AD and Entra ID, join type detection) before
    renaming. Supports serial-number-based naming (prefix + BIOS serial) or
    explicit naming via -NewName. Dry-run by default for safety -- pass -Execute
    to actually rename.

    Configuration is loaded from a JSON config file, with parameter overrides
    and environment variable support for secrets. Run -GenerateConfig to create
    a template config file.

.PARAMETER ComputerName
    The hostname of the target workstation. Defaults to localhost.
    Remote targets require WinRM to be enabled.

.PARAMETER NewName
    Explicit new computer name. When specified, bypasses serial-number-based
    naming. The name is still validated (length, characters) and checked for
    collisions.

.PARAMETER Prefix
    String prepended to the serial number when building the new name.
    Overrides the config file value. Ignored when -NewName is used.

.PARAMETER Execute
    Actually perform the rename. Without this switch, the script runs in
    dry-run mode: discovery and checks only, no changes made.

.PARAMETER Force
    Skip the interactive confirmation prompt before renaming.
    Useful for automation. Requires -Execute.

.PARAMETER SkipADCheck
    Skip the Active Directory name collision check.

.PARAMETER SkipEntraCheck
    Skip the Entra ID (Azure AD) name collision check.

.PARAMETER ConfigFile
    Path to a JSON configuration file. If not specified, looks for
    config.json in the script directory. See -GenerateConfig.

.PARAMETER GenerateConfig
    Create a template config.json file and exit. Use -ConfigFile to
    specify the output path. Use -Force to overwrite an existing file.

.PARAMETER DomainCredential
    PSCredential for hybrid/AD-joined computer rename. If not provided,
    the script prompts when -Execute is used on a domain-joined device.

.PARAMETER TenantId
    Entra ID tenant ID. Overrides config file and environment variable.

.PARAMETER ClientId
    Entra ID app registration client ID. Overrides config file and
    environment variable.

.PARAMETER ClientSecret
    Entra ID app registration client secret. Overrides config file and
    environment variable.

.PARAMETER LogDir
    Directory for log files. Overrides config file value.

.PARAMETER OutputDir
    Directory for CSV output files. Overrides config file value.

.EXAMPLE
    .\Rename-ManagedComputer.ps1 -ComputerName "CUAPA1B2C3D4"
    Runs discovery and pre-flight checks in dry-run mode. Shows what the
    rename would do without making any changes.

.EXAMPLE
    .\Rename-ManagedComputer.ps1 -ComputerName "CUAPA1B2C3D4" -Execute
    Runs all checks and renames the computer to prefix + serial number.

.EXAMPLE
    .\Rename-ManagedComputer.ps1 -ComputerName "OLDPC01" -NewName "NEWPC01" -Execute
    Renames OLDPC01 to NEWPC01 after running all pre-flight checks.

.EXAMPLE
    .\Rename-ManagedComputer.ps1 -GenerateConfig
    Creates a template config.json in the script directory.

.EXAMPLE
    .\Rename-ManagedComputer.ps1 -ComputerName "PC01" -Execute -Force -SkipEntraCheck
    Renames without confirmation prompt and skips the Entra ID check.
#>
#Requires -Version 5.1

[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[a-zA-Z0-9._-]+$')]
    [string]$ComputerName = "localhost",

    [ValidateLength(1, 15)]
    [string]$NewName,

    [ValidateLength(0, 14)]
    [string]$Prefix,

    [switch]$Execute,
    [switch]$Force,
    [switch]$SkipADCheck,
    [switch]$SkipEntraCheck,

    [string]$ConfigFile,
    [switch]$GenerateConfig,

    [pscredential]$DomainCredential,

    [ValidatePattern('^$|^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$TenantId,

    [ValidatePattern('^$|^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$ClientId,

    [string]$ClientSecret,

    [string]$LogDir,
    [string]$OutputDir
)

# =============================================================================
# BUILT-IN DEFAULTS
# =============================================================================

$Script:Defaults = @{
    Prefix          = ""
    MaxLength       = 15
    OldNamePattern  = ""
    InvalidSerials  = @(
        "To Be Filled By O.E.M.", "To be filled by O.E.M.",
        "Default string", "System Serial Number",
        "None", "N/A", "Chassis Serial Number"
    )
    GraphApiVersion = "v1.0"
    LogDir          = Join-Path $PSScriptRoot "logs"
    OutputDir       = Join-Path $PSScriptRoot "output"
}

# =============================================================================
# FUNCTIONS -- Logging
# =============================================================================

$Script:LogFile = $null

# ── Shared toolkit ──────────────────────────────────────────────────────────
$_toolkitPath = Join-Path (Split-Path $PSScriptRoot -Parent) "HelpdeskToolkit.ps1"
$_toolkitLoaded = $false
if (Test-Path $_toolkitPath) {
    try {
        . $_toolkitPath
        $_toolkitLoaded = $true
    } catch { }
}

function Write-Log {
    <#
    .SYNOPSIS
        Writes a timestamped, color-coded log entry to console, verbose stream, and log file.
    .PARAMETER Message
        The log message text.
    .PARAMETER Level
        Severity level: INFO, WARNING, or ERROR.
    .PARAMETER Computer
        Optional computer name prefix for remote operation context.
    #>
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG")][string]$Level = "INFO",
        [string]$Computer
    )
    $prefix = if ($Computer) { "[$Computer] " } else { "" }
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $prefix$Message"
    switch ($Level) {
        "INFO"    { Write-Host $line -ForegroundColor Cyan }
        "WARN"    { Write-Host $line -ForegroundColor Yellow }
        "ERROR"   { Write-Host $line -ForegroundColor Red }
        "SUCCESS" { Write-Host $line -ForegroundColor Green }
        "DEBUG"   { Write-Host $line -ForegroundColor Gray }
    }
    Write-Verbose $line
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $line }
}

function Write-Summary {
    <#
    .SYNOPSIS
        Writes a line to console with color and appends it to the log file.
    .PARAMETER Line
        The text to display.
    .PARAMETER Color
        Console foreground color. Defaults to White.
    #>
    param([string]$Line, [string]$Color = "White")
    Write-Host $Line -ForegroundColor $Color
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $Line }
}

# =============================================================================
# FUNCTIONS -- Helpers
# =============================================================================

if (-not $_toolkitLoaded) {
function Protect-ODataValue {
    <#
    .SYNOPSIS
        Escapes a string value for safe use in OData filter expressions.
    .PARAMETER Value
        The string to escape. Single quotes are doubled per OData convention.
    .OUTPUTS
        System.String. The escaped value (without surrounding quotes).
    #>
    param([string]$Value)
    return $Value -replace "'", "''"
}
}

if (-not $_toolkitLoaded) {
function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Executes a scriptblock with exponential backoff retry on failure.
    .PARAMETER ScriptBlock
        The operation to attempt.
    .PARAMETER MaxAttempts
        Maximum number of attempts. Defaults to 3.
    .PARAMETER DelaySeconds
        Initial delay between retries in seconds. Doubles each attempt. Defaults to 2.
    .PARAMETER OperationName
        Descriptive name for log messages.
    .OUTPUTS
        The output of the scriptblock on success.
    #>
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
            if ($attempt -ge $MaxAttempts) {
                throw
            }
            $wait = $DelaySeconds * [math]::Pow(2, $attempt - 1)
            Write-Log "$OperationName failed (attempt $attempt/$MaxAttempts): $_. Retrying in ${wait}s..." -Level WARN
            Start-Sleep -Seconds $wait
        }
    }
}
}

function New-CheckResult {
    <#
    .SYNOPSIS
        Creates a standardized check result object for the discovery phase.
    .PARAMETER Check
        Short name of the check (e.g. "Running elevated").
    .PARAMETER Status
        Result status: PASS, FAIL, WARN, or SKIP.
    .PARAMETER Detail
        Descriptive text explaining the result.
    .OUTPUTS
        PSCustomObject with Check, Status, and Detail properties.
    #>
    param(
        [string]$Check,
        [ValidateSet("PASS", "FAIL", "WARN", "SKIP")]
        [string]$Status,
        [string]$Detail
    )
    return [PSCustomObject]@{
        Check  = $Check
        Status = $Status
        Detail = $Detail
    }
}

function Write-CheckResult {
    <#
    .SYNOPSIS
        Displays a color-coded check result line in the console summary.
    .PARAMETER Result
        A PSCustomObject from New-CheckResult with Check, Status, and Detail properties.
    #>
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

function Test-IsRemote {
    <#
    .SYNOPSIS
        Determines whether a target computer name refers to a remote machine.
    .PARAMETER Computer
        The computer name to evaluate. Returns $false for "localhost", ".", or the local hostname.
    .OUTPUTS
        System.Boolean.
    #>
    param([string]$Computer)
    return ($Computer -ne "localhost" -and
            $Computer -ne $env:COMPUTERNAME -and
            $Computer -ne ".")
}

function Invoke-OnTarget {
    <#
    .SYNOPSIS
        Executes a scriptblock locally or remotely via WinRM depending on the target.
    .PARAMETER Computer
        Target computer name. If remote, uses Invoke-Command over WinRM.
    .PARAMETER ScriptBlock
        The scriptblock to execute on the target.
    .OUTPUTS
        The output of the scriptblock.
    #>
    param(
        [string]$Computer,
        [scriptblock]$ScriptBlock
    )
    if (Test-IsRemote -Computer $Computer) {
        Invoke-Command -ComputerName $Computer -ScriptBlock $ScriptBlock -ErrorAction Stop
    } else {
        & $ScriptBlock
    }
}

# =============================================================================
# FUNCTIONS -- Configuration
# =============================================================================

function Import-ScriptConfig {
    <#
    .SYNOPSIS
        Resolves configuration from three layers: defaults, config file, environment variables, and parameter overrides.
    .PARAMETER ConfigFilePath
        Path to a JSON configuration file. May be null if no file is available.
    .PARAMETER ParamOverrides
        Hashtable of parameter-level overrides (highest priority).
    .PARAMETER Defaults
        Hashtable of built-in default values (lowest priority).
    .OUTPUTS
        Hashtable containing the resolved configuration.
    #>
    param(
        [string]$ConfigFilePath,
        [hashtable]$ParamOverrides,
        [hashtable]$Defaults
    )

    $config = @{
        ScriptName      = ""
        Prefix          = $Defaults.Prefix
        MaxLength       = $Defaults.MaxLength
        OldNamePattern  = $Defaults.OldNamePattern
        InvalidSerials  = $Defaults.InvalidSerials
        GraphApiVersion = $Defaults.GraphApiVersion
        LogDir          = $Defaults.LogDir
        OutputDir       = $Defaults.OutputDir
        TenantId        = ""
        ClientId        = ""
        ClientSecret    = ""
    }

    # Layer 1: Config file
    if ($ConfigFilePath -and (Test-Path $ConfigFilePath)) {
        $fileConfig = $null
        try {
            $fileConfig = Get-Content -Path $ConfigFilePath -Raw | ConvertFrom-Json
        } catch {
            Write-Log "Config file '$ConfigFilePath' contains invalid JSON: $_. Using defaults." -Level WARN
        }

        if ($fileConfig) {
            if ($null -ne $fileConfig.Prefix)         { $config.Prefix         = $fileConfig.Prefix }
            if ($null -ne $fileConfig.MaxLength) {
                $mlValue = [int]$fileConfig.MaxLength
                if ($mlValue -ge 1 -and $mlValue -le 15) {
                    $config.MaxLength = $mlValue
                } else {
                    Write-Log "Config MaxLength '$mlValue' out of range (1-15). Using default $($Defaults.MaxLength)." -Level WARN
                }
            }
            if ($null -ne $fileConfig.OldNamePattern) { $config.OldNamePattern = $fileConfig.OldNamePattern }
            if ($null -ne $fileConfig.InvalidSerials) {
                if ($fileConfig.InvalidSerials -is [array] -or $fileConfig.InvalidSerials -is [System.Collections.IEnumerable]) {
                    $config.InvalidSerials = @($fileConfig.InvalidSerials)
                } else {
                    Write-Log "Config InvalidSerials is not an array. Using defaults." -Level WARN
                }
            }
            if ($null -ne $fileConfig.GraphApiVersion) { $config.GraphApiVersion = $fileConfig.GraphApiVersion }
            if ($null -ne $fileConfig.LogDir)         { $config.LogDir         = $fileConfig.LogDir }
            if ($null -ne $fileConfig.OutputDir)      { $config.OutputDir      = $fileConfig.OutputDir }

            if ($fileConfig.EntraId) {
                if ($fileConfig.EntraId.TenantId)     { $config.TenantId     = $fileConfig.EntraId.TenantId }
                if ($fileConfig.EntraId.ClientId)     { $config.ClientId     = $fileConfig.EntraId.ClientId }
                if ($fileConfig.EntraId.ClientSecret)  { $config.ClientSecret = $fileConfig.EntraId.ClientSecret }
            }
        }
    } elseif ($ConfigFilePath) {
        Write-Log "Specified config file not found: $ConfigFilePath. Using defaults." -Level WARN
    }

    # Layer 2: Environment variables (secrets only)
    if ($env:ENTRA_TENANT_ID)     { $config.TenantId     = $env:ENTRA_TENANT_ID }
    if ($env:ENTRA_CLIENT_ID)     { $config.ClientId     = $env:ENTRA_CLIENT_ID }
    if ($env:ENTRA_CLIENT_SECRET) { $config.ClientSecret = $env:ENTRA_CLIENT_SECRET }

    # Layer 3: Parameter overrides (highest priority)
    if ($ParamOverrides.ContainsKey('Prefix'))       { $config.Prefix       = $ParamOverrides.Prefix }
    if ($ParamOverrides.ContainsKey('TenantId'))     { $config.TenantId     = $ParamOverrides.TenantId }
    if ($ParamOverrides.ContainsKey('ClientId'))     { $config.ClientId     = $ParamOverrides.ClientId }
    if ($ParamOverrides.ContainsKey('ClientSecret')) { $config.ClientSecret = $ParamOverrides.ClientSecret }
    if ($ParamOverrides.ContainsKey('LogDir'))       { $config.LogDir       = $ParamOverrides.LogDir }
    if ($ParamOverrides.ContainsKey('OutputDir'))    { $config.OutputDir    = $ParamOverrides.OutputDir }

    return $config
}

function New-TemplateConfig {
    <#
    .SYNOPSIS
        Generates a template config.json file with all configurable fields.
    .PARAMETER OutputPath
        File path for the generated config.
    .PARAMETER ForceOverwrite
        Overwrite an existing file at OutputPath.
    .OUTPUTS
        System.String. The path to the created file.
    #>
    param([string]$OutputPath, [switch]$ForceOverwrite)

    if ((Test-Path $OutputPath) -and -not $ForceOverwrite) {
        throw "Config file already exists: $OutputPath. Use -Force to overwrite."
    }

    $template = [ordered]@{
        Prefix          = $Script:Defaults.Prefix
        MaxLength       = $Script:Defaults.MaxLength
        OldNamePattern  = $Script:Defaults.OldNamePattern
        InvalidSerials  = $Script:Defaults.InvalidSerials
        GraphApiVersion = $Script:Defaults.GraphApiVersion
        EntraId = [ordered]@{
            TenantId     = ""
            ClientId     = ""
            ClientSecret = ""
        }
        LogDir    = ".\logs"
        OutputDir = ".\output"
    }

    $template | ConvertTo-Json -Depth 3 | Set-Content -Path $OutputPath -Encoding UTF8
    return $OutputPath
}

# =============================================================================
# FUNCTIONS -- Discovery helpers
# =============================================================================

function Test-TargetOnline {
    <#
    .SYNOPSIS
        Verifies that a remote target is reachable via ICMP ping with retry.
    .PARAMETER Computer
        The computer name to test. Returns $true immediately for local targets.
    .OUTPUTS
        System.Boolean. $true if the target is reachable.
    #>
    param([string]$Computer)

    if (-not (Test-IsRemote -Computer $Computer)) {
        return $true
    }

    $result = Invoke-WithRetry -OperationName "Ping $Computer" -MaxAttempts 3 -DelaySeconds 2 -ScriptBlock {
        $ping = Test-Connection -ComputerName $Computer -Count 2 -Quiet -ErrorAction Stop
        if (-not $ping) {
            throw "Target '$Computer' is not reachable."
        }
        return $true
    }
    return $result
}

$Script:GraphTokenCache = @{ Token = $null; ExpiresAt = [datetime]::MinValue }

function Get-GraphToken {
    <#
    .SYNOPSIS
        Acquires an OAuth2 access token from Microsoft Graph using client credentials.
        Caches the token and reuses it if not expired.
    .PARAMETER TenantId
        Entra ID tenant GUID.
    .PARAMETER ClientId
        App registration client GUID.
    .PARAMETER ClientSecret
        App registration client secret.
    .OUTPUTS
        System.String. The access token.
    #>
    param([string]$TenantId, [string]$ClientId, [string]$ClientSecret)

    # Return cached token if still valid (with 5-minute safety margin)
    if ($Script:GraphTokenCache.Token -and [datetime]::UtcNow.AddMinutes(5) -lt $Script:GraphTokenCache.ExpiresAt) {
        return $Script:GraphTokenCache.Token
    }

    # Validate TenantId is a GUID to prevent URL path injection
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

    $response = Invoke-WithRetry -OperationName "Graph token acquisition" -MaxAttempts 3 -DelaySeconds 2 -ScriptBlock {
        Invoke-RestMethod -Method POST -Uri $tokenUrl -Body $body -ContentType "application/x-www-form-urlencoded"
    }

    # Cache the token with expiry
    $expiresIn = if ($response.expires_in) { [int]$response.expires_in } else { 3600 }
    $Script:GraphTokenCache.Token = $response.access_token
    $Script:GraphTokenCache.ExpiresAt = [datetime]::UtcNow.AddSeconds($expiresIn)

    return $response.access_token
}

function Get-SerialNumber {
    <#
    .SYNOPSIS
        Retrieves the BIOS serial number from a local or remote computer via CIM.
    .PARAMETER Computer
        Target computer name.
    .OUTPUTS
        System.String. The trimmed serial number.
    #>
    param([string]$Computer)

    $serial = Invoke-OnTarget -Computer $Computer -ScriptBlock {
        (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
    }
    return ($serial).Trim()
}

function Test-SerialValid {
    <#
    .SYNOPSIS
        Checks whether a serial number is valid (not a known placeholder or non-alphanumeric).
    .PARAMETER Serial
        The serial number string to validate.
    .PARAMETER InvalidSerials
        Array of known placeholder serial strings to reject.
    .OUTPUTS
        System.Boolean. $true if the serial is valid.
    #>
    param([string]$Serial, [string[]]$InvalidSerials)

    if ($InvalidSerials -contains $Serial) {
        return $false
    }
    if ($Serial -notmatch '[a-zA-Z0-9]') {
        return $false
    }
    return $true
}

function ConvertTo-SafeComputerName {
    <#
    .SYNOPSIS
        Converts a serial number into a valid NetBIOS computer name with optional prefix.
    .PARAMETER Serial
        The raw serial number to sanitize.
    .PARAMETER Prefix
        String prepended to the sanitized serial.
    .PARAMETER MaxLength
        Maximum allowed name length (NetBIOS limit is 15).
    .OUTPUTS
        PSCustomObject with Name, Truncated, and OrigLength properties.
    #>
    param([string]$Serial, [string]$Prefix, [int]$MaxLength)

    $cleaned = $Serial -replace '[^a-zA-Z0-9-]', ''
    $cleaned = $cleaned.Trim('-')
    $fullName = "$Prefix$cleaned".ToUpper()

    $origLength = $fullName.Length
    $truncated  = $false

    if ($fullName.Length -gt $MaxLength) {
        $fullName  = $fullName.Substring(0, $MaxLength)
        $truncated = $true
    }

    return [PSCustomObject]@{
        Name       = $fullName
        Truncated  = $truncated
        OrigLength = $origLength
    }
}

function Get-JoinType {
    <#
    .SYNOPSIS
        Detects the domain/cloud join state of a computer using dsregcmd.
    .PARAMETER Computer
        Target computer name.
    .OUTPUTS
        System.String. One of: "Hybrid", "EntraJoined", "ADJoined", "Workgroup".
    #>
    param([string]$Computer)

    $dsregOutput = Invoke-OnTarget -Computer $Computer -ScriptBlock {
        dsregcmd /status 2>&1
    }

    $dsregText = $dsregOutput | Out-String

    $azureAdJoined = $dsregText -match 'AzureAdJoined\s*:\s*YES'
    $domainJoined  = $dsregText -match 'DomainJoined\s*:\s*YES'

    if ($azureAdJoined -and $domainJoined) {
        return "Hybrid"
    } elseif ($azureAdJoined) {
        return "EntraJoined"
    } elseif ($domainJoined) {
        return "ADJoined"
    } else {
        return "Workgroup"
    }
}

function Test-ADNameCollision {
    <#
    .SYNOPSIS
        Checks Active Directory for an existing computer object with the target name.
    .PARAMETER TargetName
        The proposed computer name to check for collisions.
    .OUTPUTS
        PSCustomObject check result (PASS, FAIL, or WARN).
    #>
    param([string]$TargetName)

    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        return (New-CheckResult -Check "No AD name collision" -Status "WARN" -Detail "ActiveDirectory module not available -- cannot check")
    }

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $existing = Get-ADComputer -Identity $TargetName -ErrorAction Stop
        return (New-CheckResult -Check "No AD name collision" -Status "FAIL" -Detail "Computer object '$TargetName' already exists in AD (DN: $($existing.DistinguishedName))")
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        return (New-CheckResult -Check "No AD name collision" -Status "PASS" -Detail "No computer object '$TargetName' found in AD")
    } catch {
        return (New-CheckResult -Check "No AD name collision" -Status "WARN" -Detail "AD query failed: $_")
    }
}

function Test-EntraNameCollision {
    <#
    .SYNOPSIS
        Checks Entra ID (Azure AD) for an existing device with the target display name.
    .PARAMETER TargetName
        The proposed computer name to check for collisions.
    .PARAMETER Token
        A valid Microsoft Graph API access token.
    .PARAMETER ApiVersion
        Graph API version string (e.g. "v1.0" or "beta"). Defaults to "v1.0".
    .OUTPUTS
        PSCustomObject check result (PASS, FAIL, or WARN).
    #>
    param(
        [string]$TargetName,
        [string]$Token,
        [string]$ApiVersion = "v1.0"
    )

    $headers  = @{ Authorization = "Bearer $Token" }
    $safeName = Protect-ODataValue -Value $TargetName
    $filter   = "displayName eq '$safeName'"
    $url      = "https://graph.microsoft.com/$ApiVersion/devices?`$filter=$filter&`$select=displayName,id"

    try {
        $response = Invoke-WithRetry -OperationName "Entra ID device query" -MaxAttempts 3 -DelaySeconds 2 -ScriptBlock {
            Invoke-RestMethod -Method GET -Uri $url -Headers $headers
        }
        if ($response.value.Count -gt 0) {
            return (New-CheckResult -Check "No Entra ID name collision" -Status "FAIL" -Detail "Device '$TargetName' already exists in Entra ID")
        }
        return (New-CheckResult -Check "No Entra ID name collision" -Status "PASS" -Detail "No device '$TargetName' found in Entra ID")
    } catch {
        return (New-CheckResult -Check "No Entra ID name collision" -Status "WARN" -Detail "Entra ID query failed: $_")
    }
}

function Get-DeviceInfo {
    <#
    .SYNOPSIS
        Retrieves the manufacturer and model of a computer via CIM.
    .PARAMETER Computer
        Target computer name.
    .OUTPUTS
        System.String. "Manufacturer Model" string.
    #>
    param([string]$Computer)

    $cs = Invoke-OnTarget -Computer $Computer -ScriptBlock {
        Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Manufacturer, Model
    }
    $mfr   = ($cs.Manufacturer).Trim()
    $model = ($cs.Model).Trim()
    return "$mfr $model"
}

function Invoke-ComputerRename {
    <#
    .SYNOPSIS
        Wraps Rename-Computer with support for domain credentials and remote execution.
    .PARAMETER Computer
        Target computer name.
    .PARAMETER TargetName
        The new computer name.
    .PARAMETER JoinType
        Join state ("Hybrid", "ADJoined", "EntraJoined", "Workgroup") to determine if domain credentials are needed.
    .PARAMETER Credential
        Domain credentials for AD/Hybrid joined renames.
    #>
    param(
        [string]$Computer,
        [string]$TargetName,
        [string]$JoinType,
        [pscredential]$Credential
    )

    $renameParams = @{
        NewName = $TargetName
        Force   = $true
    }

    if ($JoinType -eq "Hybrid" -or $JoinType -eq "ADJoined") {
        if ($Credential) {
            $renameParams.DomainCredential = $Credential
        }
    }

    if (Test-IsRemote -Computer $Computer) {
        $renameParams.ComputerName = $Computer
    }

    Rename-Computer @renameParams
}

# =============================================================================
# FUNCTIONS -- Phases
# =============================================================================

function Invoke-Discovery {
    <#
    .SYNOPSIS
        Orchestrates all pre-flight discovery checks and returns a comprehensive result object.
    .PARAMETER Config
        Resolved configuration hashtable.
    .PARAMETER ComputerName
        Target computer name.
    .PARAMETER NewName
        Explicit new name override (bypasses serial-based naming).
    .PARAMETER SkipADCheck
        Skip the Active Directory name collision check.
    .PARAMETER SkipEntraCheck
        Skip the Entra ID name collision check.
    .OUTPUTS
        PSCustomObject with Results, CurrentName, TargetName, SerialNumber, JoinType, DeviceInfo, counts, and flags.
    #>
    param(
        [hashtable]$Config,
        [string]$ComputerName,
        [string]$NewName,
        [switch]$SkipADCheck,
        [switch]$SkipEntraCheck
    )

    $results    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $isRemote   = Test-IsRemote -Computer $ComputerName
    $manualName = [bool]$NewName
    $logComputer = if ($isRemote) { $ComputerName } else { $null }

    # --- Check 1: Running elevated ---

    Write-Log "Checking elevation..." -Computer $logComputer
    if ($isRemote) {
        $results.Add((New-CheckResult -Check "Running elevated" -Status "PASS" -Detail "Remote execution -- elevation checked on target via WinRM credentials"))
    } else {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        if ($isAdmin) {
            $results.Add((New-CheckResult -Check "Running elevated" -Status "PASS" -Detail "Process is running as administrator"))
        } else {
            $results.Add((New-CheckResult -Check "Running elevated" -Status "FAIL" -Detail "Not running as administrator -- rename requires elevation"))
        }
    }

    # --- Check 2: Serial number retrieved ---

    $serialNumber = $null
    if ($manualName) {
        $results.Add((New-CheckResult -Check "Serial number retrieved" -Status "SKIP" -Detail "Manual name specified -- serial lookup not needed"))
    } else {
        Write-Log "Retrieving serial number..." -Computer $logComputer
        try {
            $serialNumber = Get-SerialNumber -Computer $ComputerName
            if ($serialNumber) {
                $results.Add((New-CheckResult -Check "Serial number retrieved" -Status "PASS" -Detail "Serial: $serialNumber"))
            } else {
                $results.Add((New-CheckResult -Check "Serial number retrieved" -Status "FAIL" -Detail "CIM query returned empty serial number"))
            }
        } catch {
            $results.Add((New-CheckResult -Check "Serial number retrieved" -Status "FAIL" -Detail "CIM query failed: $_"))
        }
    }

    # --- Check 3: Serial number valid ---

    $serialValid = $false
    if ($manualName) {
        $results.Add((New-CheckResult -Check "Serial number valid" -Status "SKIP" -Detail "Manual name specified -- serial validation not needed"))
    } elseif ($serialNumber) {
        $serialValid = Test-SerialValid -Serial $serialNumber -InvalidSerials $Config.InvalidSerials
        if ($serialValid) {
            $results.Add((New-CheckResult -Check "Serial number valid" -Status "PASS" -Detail "Serial '$serialNumber' is not a placeholder"))
        } else {
            $results.Add((New-CheckResult -Check "Serial number valid" -Status "FAIL" -Detail "Serial '$serialNumber' is a known placeholder or invalid"))
        }
    } else {
        $results.Add((New-CheckResult -Check "Serial number valid" -Status "FAIL" -Detail "No serial number to validate"))
    }

    # --- Check 4: Target name built/validated ---

    $targetName = $null
    if ($manualName) {
        $cleaned = $NewName -replace '[^a-zA-Z0-9-]', ''
        $cleaned = $cleaned.Trim('-')

        if ([string]::IsNullOrWhiteSpace($cleaned) -or $cleaned.Length -lt 1) {
            $results.Add((New-CheckResult -Check "Target name valid" -Status "FAIL" -Detail "Specified name '$NewName' is empty after sanitization"))
        } elseif ($cleaned.Length -gt $Config.MaxLength) {
            $results.Add((New-CheckResult -Check "Target name valid" -Status "FAIL" -Detail "Specified name '$cleaned' exceeds $($Config.MaxLength) character limit ($($cleaned.Length) chars)"))
        } elseif ($cleaned -ne $NewName) {
            $targetName = $cleaned.ToUpper()
            $results.Add((New-CheckResult -Check "Target name valid" -Status "WARN" -Detail "Sanitized '$NewName' to '$targetName' (removed invalid characters)"))
        } else {
            $targetName = $cleaned.ToUpper()
            $results.Add((New-CheckResult -Check "Target name valid" -Status "PASS" -Detail "Target name: $targetName (manually specified)"))
        }
    } elseif ($serialNumber -and $serialValid) {
        $nameResult = ConvertTo-SafeComputerName -Serial $serialNumber -Prefix $Config.Prefix -MaxLength $Config.MaxLength

        if ([string]::IsNullOrWhiteSpace($nameResult.Name) -or $nameResult.Name.Length -lt 3) {
            $results.Add((New-CheckResult -Check "Target name built" -Status "FAIL" -Detail "Name is empty or too short after sanitization"))
        } elseif ($nameResult.Truncated) {
            $targetName = $nameResult.Name
            $results.Add((New-CheckResult -Check "Target name built" -Status "WARN" -Detail "Truncated from $($nameResult.OrigLength) to $($Config.MaxLength) chars: $targetName"))
        } else {
            $targetName = $nameResult.Name
            $results.Add((New-CheckResult -Check "Target name built" -Status "PASS" -Detail "Target name: $targetName"))
        }
    } else {
        $results.Add((New-CheckResult -Check "Target name built" -Status "FAIL" -Detail "Cannot build name -- serial number missing or invalid"))
    }

    # --- Get current hostname ---

    $currentName = Invoke-OnTarget -Computer $ComputerName -ScriptBlock { $env:COMPUTERNAME }

    # --- Get device info ---

    $deviceInfo = $null
    try {
        $deviceInfo = Get-DeviceInfo -Computer $ComputerName
    } catch {
        Write-Log "Could not retrieve device info: $_" -Level WARN -Computer $logComputer
    }

    # --- Check 5: Old name pattern detected ---

    if ($Config.OldNamePattern) {
        if ($currentName -notmatch $Config.OldNamePattern) {
            $results.Add((New-CheckResult -Check "Old name pattern detected" -Status "WARN" -Detail "Current name '$currentName' doesn't match pattern '$($Config.OldNamePattern)'"))
        } else {
            $results.Add((New-CheckResult -Check "Old name pattern detected" -Status "PASS" -Detail "Current name '$currentName' matches pattern '$($Config.OldNamePattern)'"))
        }
    } else {
        $results.Add((New-CheckResult -Check "Old name pattern detected" -Status "SKIP" -Detail "No old name pattern configured"))
    }

    # --- Check 6: Not already renamed ---

    $alreadyRenamed = $false
    if ($targetName) {
        if ($currentName -eq $targetName) {
            $alreadyRenamed = $true
            $results.Add((New-CheckResult -Check "Not already renamed" -Status "WARN" -Detail "Current name already matches target ($targetName) -- nothing to do"))
        } else {
            $results.Add((New-CheckResult -Check "Not already renamed" -Status "PASS" -Detail "Current name '$currentName' differs from target '$targetName'"))
        }
    } else {
        $results.Add((New-CheckResult -Check "Not already renamed" -Status "FAIL" -Detail "No target name to compare"))
    }

    # --- Check 7: Join type detected ---

    Write-Log "Detecting join type..." -Computer $logComputer
    $joinType = $null
    try {
        $joinType = Get-JoinType -Computer $ComputerName
        if ($joinType -eq "Workgroup") {
            $results.Add((New-CheckResult -Check "Join type detected" -Status "WARN" -Detail "Workgroup (not domain or cloud joined)"))
        } else {
            $joinTypeDetail = switch ($joinType) {
                "Hybrid"      { "Hybrid (AD + Entra ID)" }
                "EntraJoined" { "Entra ID joined" }
                "ADJoined"    { "Active Directory joined" }
            }
            $results.Add((New-CheckResult -Check "Join type detected" -Status "PASS" -Detail $joinTypeDetail))
        }
    } catch {
        $results.Add((New-CheckResult -Check "Join type detected" -Status "WARN" -Detail "Could not determine join type: $_"))
    }

    # --- Check 8: No AD name collision ---

    if ($SkipADCheck) {
        $results.Add((New-CheckResult -Check "No AD name collision" -Status "SKIP" -Detail "Skipped by -SkipADCheck"))
    } elseif ($targetName) {
        Write-Log "Checking AD for name collision..." -Computer $logComputer
        $results.Add((Test-ADNameCollision -TargetName $targetName))
    } else {
        $results.Add((New-CheckResult -Check "No AD name collision" -Status "FAIL" -Detail "No target name to check"))
    }

    # --- Check 9: No Entra ID name collision ---

    if ($SkipEntraCheck) {
        $results.Add((New-CheckResult -Check "No Entra ID name collision" -Status "SKIP" -Detail "Skipped by -SkipEntraCheck"))
    } elseif ($targetName -and $Config.TenantId -and $Config.ClientId -and $Config.ClientSecret) {
        Write-Log "Checking Entra ID for name collision..." -Computer $logComputer
        try {
            $graphToken = Get-GraphToken -TenantId $Config.TenantId -ClientId $Config.ClientId -ClientSecret $Config.ClientSecret
            $results.Add((Test-EntraNameCollision -TargetName $targetName -Token $graphToken -ApiVersion $Config.GraphApiVersion))
        } catch {
            $results.Add((New-CheckResult -Check "No Entra ID name collision" -Status "WARN" -Detail "Graph API token acquisition failed: $_"))
        }
    } elseif (-not $targetName) {
        $results.Add((New-CheckResult -Check "No Entra ID name collision" -Status "FAIL" -Detail "No target name to check"))
    } else {
        $results.Add((New-CheckResult -Check "No Entra ID name collision" -Status "WARN" -Detail "Graph API not configured -- skipping Entra ID check"))
    }

    # --- Compute counts ---

    $failCount = @($results | Where-Object { $_.Status -eq "FAIL" }).Count
    $warnCount = @($results | Where-Object { $_.Status -eq "WARN" }).Count
    $passCount = @($results | Where-Object { $_.Status -eq "PASS" }).Count
    $skipCount = @($results | Where-Object { $_.Status -eq "SKIP" }).Count

    return [PSCustomObject]@{
        Results        = $results
        CurrentName    = $currentName
        TargetName     = $targetName
        SerialNumber   = $serialNumber
        JoinType       = $joinType
        DeviceInfo     = $deviceInfo
        AlreadyRenamed = $alreadyRenamed
        ManualName     = $manualName
        FailCount      = $failCount
        WarnCount      = $warnCount
        PassCount      = $passCount
        SkipCount      = $skipCount
    }
}

function Export-DiscoveryResults {
    <#
    .SYNOPSIS
        Exports discovery check results to a timestamped CSV file.
    .PARAMETER Config
        Resolved configuration hashtable (provides OutputDir).
    .PARAMETER Discovery
        Discovery result object from Invoke-Discovery.
    .PARAMETER ComputerName
        Target computer name (used in the output filename).
    .OUTPUTS
        System.String. Path to the created CSV file.
    #>
    param(
        [hashtable]$Config,
        [PSCustomObject]$Discovery,
        [string]$ComputerName
    )

    if (-not (Test-Path $Config.OutputDir)) {
        New-Item -ItemType Directory -Path $Config.OutputDir | Out-Null
    }

    $timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeHost   = $ComputerName -replace '[^a-zA-Z0-9]', '_'
    $outputFile = Join-Path $Config.OutputDir ("RenameComputer_{0}_{1}.csv" -f $safeHost, $timestamp)

    $Discovery.Results | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
    Write-Log "Exported to $outputFile"
    return $outputFile
}

function Format-DiscoveryData {
    <#
    .SYNOPSIS
        Formats discovery data into label/value pairs for display and ticket generation.
    .PARAMETER Discovery
        Discovery result object from Invoke-Discovery.
    .OUTPUTS
        Array of hashtables with Label and Value keys.
    #>
    param([PSCustomObject]$Discovery)

    $serialDisplay = if ($Discovery.SerialNumber) {
        $Discovery.SerialNumber
    } elseif ($Discovery.ManualName) {
        "(not retrieved)"
    } else {
        "(unknown)"
    }

    return @(
        @{ Label = "Current name";  Value = $Discovery.CurrentName }
        @{ Label = "Device";        Value = if ($Discovery.DeviceInfo) { $Discovery.DeviceInfo } else { "(unknown)" } }
        @{ Label = "Serial number"; Value = $serialDisplay }
        @{ Label = "Target name";   Value = if ($Discovery.TargetName) { $Discovery.TargetName } else { "(could not determine)" } }
        @{ Label = "Join type";     Value = if ($Discovery.JoinType) { $Discovery.JoinType } else { "(unknown)" } }
    )
}

function Write-DiscoverySummary {
    <#
    .SYNOPSIS
        Displays the formatted discovery results and checklist in the console.
    .PARAMETER Discovery
        Discovery result object from Invoke-Discovery.
    .PARAMETER Config
        Resolved configuration hashtable.
    .PARAMETER ComputerName
        Target computer name.
    #>
    param(
        [PSCustomObject]$Discovery,
        [hashtable]$Config,
        [string]$ComputerName
    )

    $separator   = "=" * 60
    $divider     = "-" * 60
    $displayTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    Write-Summary ""
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary "  $($Config.ScriptName)  --  $displayTime"                       -Color Yellow
    Write-Summary "  Target: $ComputerName"                                         -Color Yellow
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary ""

    # DISCOVERY
    Write-Summary "  DISCOVERY"                                                     -Color Cyan
    Write-Summary $divider                                                          -Color Cyan
    $fields = Format-DiscoveryData -Discovery $Discovery
    foreach ($field in $fields) {
        Write-Summary ("  {0,-17}{1}" -f "$($field.Label):", $field.Value)
    }
    Write-Summary ""

    # CHECKLIST
    Write-Summary "  CHECKLIST"                                                     -Color Cyan
    Write-Summary $divider                                                          -Color Cyan
    foreach ($result in $Discovery.Results) {
        Write-CheckResult -Result $result
    }
    Write-Summary ""
}

function Invoke-RenamePhase {
    <#
    .SYNOPSIS
        Executes the rename operation after validating discovery results, with confirmation and credential handling.
    .PARAMETER Discovery
        Discovery result object from Invoke-Discovery.
    .PARAMETER Config
        Resolved configuration hashtable.
    .PARAMETER ComputerName
        Target computer name.
    .PARAMETER Execute
        Must be set to actually perform the rename (dry-run otherwise).
    .PARAMETER Force
        Skip interactive confirmation prompt.
    .PARAMETER DomainCredential
        Pre-supplied domain credentials for AD/Hybrid renames.
    .OUTPUTS
        System.String. Status: "DryRun", "Skipped", "Blocked", "Cancelled", "WhatIf", "Renamed", or "Failed".
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [PSCustomObject]$Discovery,
        [hashtable]$Config,
        [string]$ComputerName,
        [switch]$Execute,
        [switch]$Force,
        [pscredential]$DomainCredential
    )

    $divider = "-" * 60

    if (-not $Execute) {
        Write-Summary "  ** DRY RUN -- no changes made. Run again with -Execute to rename. **" -Color Yellow
        Write-Summary ""
        return "DryRun"
    }

    Write-Summary "  RENAME"                                                        -Color Cyan
    Write-Summary $divider                                                          -Color Cyan

    if ($Discovery.AlreadyRenamed) {
        Write-Summary "  Skipped -- computer is already named $($Discovery.TargetName)" -Color Green
        Write-Summary ""
        return "Skipped"
    }

    if ($Discovery.FailCount -gt 0) {
        Write-Summary "  Blocked -- $($Discovery.FailCount) check(s) failed. Resolve failures before renaming." -Color Red
        Write-Summary ""
        return "Blocked"
    }

    # Prompt for domain credentials if hybrid/AD-joined and not provided
    $credential = $DomainCredential
    if (($Discovery.JoinType -eq "Hybrid" -or $Discovery.JoinType -eq "ADJoined") -and -not $credential) {
        Write-Log "Prompting for domain credentials (required for $($Discovery.JoinType) rename)..."
        $credential = Get-Credential -Message "Enter domain credentials for computer rename ($($Discovery.JoinType) joined)"
        if (-not $credential) {
            throw "Domain credentials are required for $($Discovery.JoinType) rename -- cancelled."
        }
    }

    # Confirm before rename (unless -Force)
    if (-not $Force) {
        $confirm = Read-Host "  Rename $($Discovery.CurrentName) -> $($Discovery.TargetName)? Type YES to confirm"
        if ($confirm -ne "YES") {
            Write-Log "Rename cancelled by user" -Level WARN
            Write-Summary "  Rename cancelled by user."                              -Color Yellow
            Write-Summary ""
            return "Cancelled"
        }
    }

    # ShouldProcess check (-WhatIf / -Confirm support)
    if (-not $PSCmdlet.ShouldProcess($Discovery.CurrentName, "Rename to $($Discovery.TargetName)")) {
        Write-Summary "  Rename skipped by -WhatIf"                                  -Color Yellow
        Write-Summary ""
        return "WhatIf"
    }

    # Execute rename
    Write-Log "Renaming $($Discovery.CurrentName) to $($Discovery.TargetName)..."
    try {
        Invoke-ComputerRename -Computer $ComputerName -TargetName $Discovery.TargetName -JoinType $Discovery.JoinType -Credential $credential
        Write-Log "Rename completed successfully"

        # Verify rename registered (pending until reboot)
        try {
            $pendingName = Invoke-OnTarget -Computer $ComputerName -ScriptBlock {
                (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName").ComputerName
            }

            if ($pendingName -eq $Discovery.TargetName) {
                Write-Log "Post-rename verification passed -- pending name matches target"
                Write-Summary "  Renamed $($Discovery.CurrentName) -> $($Discovery.TargetName) (verified in registry)" -Color Green
            } else {
                Write-Log "Post-rename verification: pending name '$pendingName' does not match target '$($Discovery.TargetName)'" -Level WARN
                Write-Summary "  Renamed $($Discovery.CurrentName) -> $($Discovery.TargetName) (registry shows '$pendingName' -- verify manually)" -Color Yellow
            }
        } catch {
            Write-Log "Could not verify pending name in registry: $_" -Level WARN
            Write-Summary "  Renamed $($Discovery.CurrentName) -> $($Discovery.TargetName) (could not verify registry)" -Color Yellow
        }

        Write-Summary ""
        Write-Summary "  +=========================================================+" -Color Yellow
        Write-Summary "  |  REBOOT REQUIRED to complete the rename.                 |" -Color Yellow
        Write-Summary "  |  Coordinate with the user before rebooting.              |" -Color Yellow
        Write-Summary "  +=========================================================+" -Color Yellow
        Write-Summary ""
        return "Renamed"
    } catch {
        Write-Log "Rename failed: $_" -Level ERROR
        Write-Summary "  Rename FAILED: $_"                                          -Color Red
        Write-Summary ""
        return "Failed"
    }
}

function Get-TicketClipboard {
    <#
    .SYNOPSIS
        Formats all discovery and rename results into a ticket-ready text block for copy-paste.
    .PARAMETER Discovery
        Discovery result object from Invoke-Discovery.
    .PARAMETER Config
        Resolved configuration hashtable.
    .PARAMETER ComputerName
        Target computer name.
    .PARAMETER Execute
        Whether -Execute was specified.
    .PARAMETER RenameStatus
        The status string returned by Invoke-RenamePhase.
    .OUTPUTS
        System.String. The formatted ticket text.
    #>
    param(
        [PSCustomObject]$Discovery,
        [hashtable]$Config,
        [string]$ComputerName,
        [switch]$Execute,
        [string]$RenameStatus
    )

    $displayTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $fields = Format-DiscoveryData -Discovery $Discovery

    $clipLines = [System.Collections.Generic.List[string]]::new()
    $clipLines.Add("--- COPY FOR TICKET ---")
    $clipLines.Add("$($Config.ScriptName): $ComputerName")
    $clipLines.Add("Generated: $displayTime")
    $clipLines.Add("")

    foreach ($field in $fields) {
        $clipLines.Add("{0,-17} {1}" -f "$($field.Label):", $field.Value)
    }
    $clipLines.Add("")

    foreach ($result in $Discovery.Results) {
        $clipLines.Add("[$($result.Status)]  $($result.Check): $($result.Detail)")
    }
    $clipLines.Add("")

    $checkSummary = "Checks: $($Discovery.PassCount) passed, $($Discovery.FailCount) failed, $($Discovery.WarnCount) warnings"
    if ($Discovery.SkipCount -gt 0) { $checkSummary += ", $($Discovery.SkipCount) skipped" }
    $clipLines.Add($checkSummary)
    $clipLines.Add("")

    switch ($RenameStatus) {
        "DryRun"    { $clipLines.Add("Mode: DRY RUN (no changes made)") }
        "Skipped"   { $clipLines.Add("Mode: EXECUTE (skipped -- already renamed)") }
        "Blocked"   { $clipLines.Add("Mode: EXECUTE (blocked -- checks failed)") }
        "Cancelled" { $clipLines.Add("Mode: EXECUTE (cancelled by user)") }
        "WhatIf"    { $clipLines.Add("Mode: EXECUTE (skipped by -WhatIf)") }
        "Renamed"   {
            $clipLines.Add("Mode: EXECUTE (renamed $($Discovery.CurrentName) -> $($Discovery.TargetName))")
            $clipLines.Add("Next steps: Reboot to complete rename. Intune will sync new name within ~8 hours.")
        }
        "Failed"    { $clipLines.Add("Mode: EXECUTE (rename FAILED)") }
    }
    $clipLines.Add("--- END COPY ---")

    return ($clipLines -join "`n")
}

function Copy-ToClipboard {
    <#
    .SYNOPSIS
        Copies text to the Windows clipboard. Fails gracefully if clipboard is unavailable.
    .PARAMETER Text
        The text to copy.
    #>
    param([string]$Text)
    try {
        Set-Clipboard -Value $Text -ErrorAction Stop
        Write-Log "Ticket text copied to clipboard"
    } catch [System.Management.Automation.CommandNotFoundException] {
        Write-Log "Set-Clipboard not available in this environment" -Level WARN
    } catch {
        Write-Log "Failed to copy to clipboard: $_" -Level WARN
    }
}

# =============================================================================
# MAIN
# =============================================================================

# When dot-sourced (e.g. by Pester tests), load functions only -- do not execute
if ($MyInvocation.InvocationName -eq '.') { return }

# --- Handle -GenerateConfig ---

if ($GenerateConfig) {
    $configPath = if ($ConfigFile) { $ConfigFile } else { Join-Path $PSScriptRoot "config.json" }
    try {
        $outputPath = New-TemplateConfig -OutputPath $configPath -ForceOverwrite:$Force
        Write-Host "Template config created: $outputPath" -ForegroundColor Green
        Write-Host "Edit this file to configure the script for your organization." -ForegroundColor Cyan
    } catch {
        Write-Host "Error: $_" -ForegroundColor Red
        exit 1
    }
    exit 0
}

try {
    # --- Resolve config ---

    $resolvedConfigFile = if ($ConfigFile) {
        $ConfigFile
    } elseif (Test-Path (Join-Path $PSScriptRoot "config.json")) {
        Join-Path $PSScriptRoot "config.json"
    } else {
        $null
    }

    $paramOverrides = @{}
    if ($PSBoundParameters.ContainsKey('Prefix'))       { $paramOverrides.Prefix       = $Prefix }
    if ($PSBoundParameters.ContainsKey('TenantId'))     { $paramOverrides.TenantId     = $TenantId }
    if ($PSBoundParameters.ContainsKey('ClientId'))     { $paramOverrides.ClientId     = $ClientId }
    if ($PSBoundParameters.ContainsKey('ClientSecret')) { $paramOverrides.ClientSecret = $ClientSecret }
    if ($PSBoundParameters.ContainsKey('LogDir'))       { $paramOverrides.LogDir       = $LogDir }
    if ($PSBoundParameters.ContainsKey('OutputDir'))    { $paramOverrides.OutputDir    = $OutputDir }

    $Config = Import-ScriptConfig -ConfigFilePath $resolvedConfigFile -ParamOverrides $paramOverrides -Defaults $Script:Defaults
    $Config.ScriptName = ($MyInvocation.MyCommand.Name -replace '\.ps1$', '')

    # --- Initialize logging ---

    if ($Config.LogDir) {
        if (-not (Test-Path $Config.LogDir)) {
            New-Item -ItemType Directory -Path $Config.LogDir | Out-Null
        }
        $Script:LogFile = Join-Path $Config.LogDir (
            "{0}_{1}.log" -f $Config.ScriptName, (Get-Date -Format "yyyyMMdd_HHmmss")
        )
    }

    Write-Log "Starting $($Config.ScriptName)"
    Write-Log "Target: $ComputerName"
    if ($resolvedConfigFile) { Write-Log "Config: $resolvedConfigFile" }

    # --- Connectivity check (remote only) ---

    if (Test-IsRemote -Computer $ComputerName) {
        Write-Log "Testing connectivity to $ComputerName..."
        Test-TargetOnline -Computer $ComputerName
        Write-Log "Target is reachable"
    }

    # --- Phase 1: Discovery ---

    $discovery = Invoke-Discovery -Config $Config -ComputerName $ComputerName -NewName $NewName -SkipADCheck:$SkipADCheck -SkipEntraCheck:$SkipEntraCheck

    # --- Export CSV ---

    $outputFile = Export-DiscoveryResults -Config $Config -Discovery $discovery -ComputerName $ComputerName

    # --- Console summary ---

    Write-DiscoverySummary -Discovery $discovery -Config $Config -ComputerName $ComputerName

    # --- Phase 2: Rename ---

    $renameStatus = Invoke-RenamePhase -Discovery $discovery -Config $Config -ComputerName $ComputerName -Execute:$Execute -Force:$Force -DomainCredential $DomainCredential

    # --- Clipboard ---

    $clipText = Get-TicketClipboard -Discovery $discovery -Config $Config -ComputerName $ComputerName -Execute:$Execute -RenameStatus $renameStatus
    Write-Summary $clipText
    Write-Summary ""
    Copy-ToClipboard -Text $clipText

    # --- Final totals ---

    $separator  = "=" * 60
    $totalCount = $discovery.Results.Count
    $totalColor = if ($discovery.FailCount -gt 0) { "Red" } elseif ($discovery.WarnCount -gt 0) { "Yellow" } else { "Green" }

    Write-Summary $separator                                                        -Color $totalColor
    Write-Summary ("  RESULT: {0}/{1} passed  |  {2} failed  |  {3} warnings" -f
        $discovery.PassCount, $totalCount, $discovery.FailCount, $discovery.WarnCount) -Color $totalColor
    Write-Summary "  CSV: $outputFile"                                              -Color Cyan
    Write-Summary $separator                                                        -Color $totalColor
    Write-Summary ""

    Write-Log "Completed $($Config.ScriptName) successfully"
    $exitCode = if ($renameStatus -eq "Failed" -or $discovery.FailCount -gt 0) { 1 } else { 0 }
    exit $exitCode
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    exit 1
}
