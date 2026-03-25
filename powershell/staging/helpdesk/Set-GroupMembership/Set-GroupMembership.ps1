#Requires -Version 5.1

<#
.SYNOPSIS
    Adds or removes a user from security groups in on-prem Active Directory or Entra ID.

.DESCRIPTION
    Set-GroupMembership modifies group membership for a specified user in either on-prem
    Active Directory or Entra ID (Azure AD). The script automatically detects whether a
    group exists in on-prem AD, Entra ID, or both, and prefers on-prem AD for synced groups.

    Supports single operations via parameters or bulk operations via CSV input. All
    modifications honour ShouldProcess (-WhatIf / -Confirm) and protected groups require
    the -Force switch to modify.

    No interactive prompts are used. Everything is driven by parameters.

.PARAMETER UserPrincipalName
    The user principal name of the target user (e.g., jsmith@contoso.com).
    Required for single operations. Ignored when -InputCSV is specified.

.PARAMETER GroupName
    The exact display name of the target group (e.g., "VPN Users").
    Required for single operations. Ignored when -InputCSV is specified.

.PARAMETER Action
    The operation to perform: "Add" to grant membership or "Remove" to revoke it.
    Required for single operations. Ignored when -InputCSV is specified.

.PARAMETER Force
    Allows modification of protected groups such as Domain Admins, Enterprise Admins,
    Schema Admins, and Administrators. Without this switch, attempts to remove users
    from protected groups will throw a terminating error.

.PARAMETER InputCSV
    Path to a CSV file for bulk operations. The CSV must contain columns:
    UserPrincipalName, GroupName, Action. Each row is processed with the same logic
    as a single operation and results are exported to a summary CSV.

.EXAMPLE
    .\Set-GroupMembership.ps1 -UserPrincipalName "jsmith@contoso.com" -GroupName "VPN Users" -Action Add

    Adds jsmith@contoso.com to the "VPN Users" group.

.EXAMPLE
    .\Set-GroupMembership.ps1 -UPN "jsmith@contoso.com" -GroupName "Domain Admins" -Action Remove -Force

    Removes jsmith@contoso.com from the protected "Domain Admins" group. The -Force
    switch is required because Domain Admins is a protected group.

.EXAMPLE
    .\Set-GroupMembership.ps1 -InputCSV "C:\temp\group_changes.csv"

    Processes all rows in the CSV file. Each row must have UserPrincipalName, GroupName,
    and Action columns. Results are exported to a timestamped CSV in the output directory.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Position = 0, HelpMessage = "User principal name.")]
    [ValidateNotNullOrEmpty()]
    [Alias("UPN")]
    [string]$UserPrincipalName,

    [Parameter(Position = 1, HelpMessage = "Exact group display name.")]
    [ValidateNotNullOrEmpty()]
    [string]$GroupName,

    [Parameter(Position = 2, HelpMessage = "Action to perform.")]
    [ValidateSet("Add", "Remove")]
    [string]$Action,

    [Parameter(HelpMessage = "Allow modification of protected groups (Domain Admins, etc.).")]
    [switch]$Force,

    [Parameter(HelpMessage = "Path to CSV file for bulk operations. CSV must have columns: UserPrincipalName, GroupName, Action")]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$InputCSV
)

# ── Configuration ────────────────────────────────────────────────────────────

$Config = @{
    ScriptName       = "Set-GroupMembership"
    LogDir           = "$PSScriptRoot\logs"
    OutputDir        = "$PSScriptRoot\output"

    TenantId         = if ($env:ENTRA_TENANT_ID)     { $env:ENTRA_TENANT_ID }     else { "<YOUR_TENANT_ID>" }
    ClientId         = if ($env:ENTRA_CLIENT_ID)     { $env:ENTRA_CLIENT_ID }     else { "<YOUR_CLIENT_ID>" }
    ClientSecret     = if ($env:ENTRA_CLIENT_SECRET) { $env:ENTRA_CLIENT_SECRET } else { "<YOUR_CLIENT_SECRET>" }

    RequireAD        = $false

    ProtectedGroups  = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
}

# ── Parameter validation ─────────────────────────────────────────────────────

if (-not $InputCSV -and (-not $UserPrincipalName -or -not $GroupName -or -not $Action)) {
    throw "Provide either -InputCSV or all three of -UserPrincipalName, -GroupName, and -Action."
}

# ── Ensure directories exist ─────────────────────────────────────────────────

foreach ($dir in @($Config.LogDir, $Config.OutputDir)) {
    if (-not (Test-Path -Path $dir -PathType Container)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
}

# ── State variables ──────────────────────────────────────────────────────────

$timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile     = Join-Path $Config.LogDir "$($Config.ScriptName)_$timestamp.log"
$auditFile   = Join-Path $Config.OutputDir "$($Config.ScriptName)_audit_$timestamp.csv"
$adminUser   = "$env:USERDOMAIN\$env:USERNAME"
$adAvailable = $false
$graphToken  = $null
$exitCode    = 0

# ── Shared toolkit ──────────────────────────────────────────────────────────
$_toolkitPath = Join-Path (Split-Path $PSScriptRoot -Parent) "HelpdeskToolkit.ps1"
$_toolkitLoaded = $false
if (Test-Path $_toolkitPath) {
    try {
        . $_toolkitPath
        $_toolkitLoaded = $true
    } catch { }
}

# ── Functions ────────────────────────────────────────────────────────────────

function Write-Log {
    <#
    .SYNOPSIS
        Writes a timestamped message to the log file and the appropriate output stream.
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

    Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue

    switch ($Level) {
        "ERROR"   { Write-Error   $Message }
        "WARN"    { Write-Warning $Message }
        "SUCCESS" { Write-Host    $entry -ForegroundColor Green }
        "DEBUG"   { Write-Verbose $entry }
        default   { Write-Verbose $entry }
    }
}

function Write-Summary {
    <#
    .SYNOPSIS
        Writes a final summary block to the log and console.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$Total,

        [Parameter(Mandatory)]
        [int]$Succeeded,

        [Parameter(Mandatory)]
        [int]$Failed,

        [Parameter(Mandatory)]
        [int]$Skipped
    )

    $divider = "=" * 60
    $lines = @(
        ""
        $divider
        "  $($Config.ScriptName) — Execution Summary"
        $divider
        "  Total operations  : $Total"
        "  Succeeded         : $Succeeded"
        "  Failed            : $Failed"
        "  Skipped           : $Skipped"
        "  Log file          : $logFile"
        "  Audit file        : $auditFile"
        $divider
        ""
    )

    foreach ($line in $lines) {
        Add-Content -Path $logFile -Value $line -ErrorAction SilentlyContinue
        Write-Host $line
    }
}

if (-not $_toolkitLoaded) {
function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Executes a script block with retry logic and exponential backoff.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [Parameter()]
        [int]$MaxAttempts = 3,

        [Parameter()]
        [int]$BaseDelaySeconds = 2,

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
                Write-Log "[$OperationName] Failed after $MaxAttempts attempts: $_" -Level ERROR
                throw
            }
            $delay = [math]::Pow($BaseDelaySeconds, $attempt)
            Write-Log "[$OperationName] Attempt $attempt/$MaxAttempts failed. Retrying in ${delay}s — $_" -Level WARN
            Start-Sleep -Seconds $delay
        }
    }
}

function Protect-ODataValue {
    <#
    .SYNOPSIS
        Escapes single quotes for OData filter expressions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    return $Value -replace "'", "''"
}
}

function Get-GraphToken {
    <#
    .SYNOPSIS
        Obtains an OAuth2 access token for Microsoft Graph using client credentials.
    #>
    [CmdletBinding()]
    param()

    # Validate tenant and client IDs are GUIDs
    $guidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'

    if ($Config.TenantId -notmatch $guidPattern) {
        throw "TenantId '$($Config.TenantId)' is not a valid GUID. Set the ENTRA_TENANT_ID environment variable."
    }
    if ($Config.ClientId -notmatch $guidPattern) {
        throw "ClientId '$($Config.ClientId)' is not a valid GUID. Set the ENTRA_CLIENT_ID environment variable."
    }
    if ([string]::IsNullOrWhiteSpace($Config.ClientSecret) -or $Config.ClientSecret -eq "<YOUR_CLIENT_SECRET>") {
        throw "ClientSecret is not configured. Set the ENTRA_CLIENT_SECRET environment variable."
    }

    $tokenUrl = "https://login.microsoftonline.com/$($Config.TenantId)/oauth2/v2.0/token"

    $body = @{
        grant_type    = "client_credentials"
        client_id     = $Config.ClientId
        client_secret = $Config.ClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }

    $response = Invoke-WithRetry -OperationName "Get-GraphToken" -ScriptBlock {
        Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
    }

    if (-not $response.access_token) {
        throw "Token response did not contain an access_token."
    }

    return $response.access_token
}

function Invoke-GraphRequest {
    <#
    .SYNOPSIS
        Sends an authenticated request to the Microsoft Graph API with retry logic.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter()]
        [ValidateSet("GET", "POST", "DELETE", "PATCH")]
        [string]$Method = "GET",

        [Parameter()]
        [object]$Body,

        [Parameter()]
        [string]$OperationName = "GraphRequest"
    )

    $headers = @{
        Authorization  = "Bearer $graphToken"
        "Content-Type" = "application/json"
    }

    $params = @{
        Uri         = $Uri
        Method      = $Method
        Headers     = $headers
        ErrorAction = "Stop"
    }

    if ($Body) {
        $params.Body = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 10 }
    }

    return (Invoke-WithRetry -OperationName $OperationName -ScriptBlock {
        Invoke-RestMethod @params
    })
}

function Process-GroupMembershipChange {
    <#
    .SYNOPSIS
        Processes a single group membership add or remove operation.
    .OUTPUTS
        A PSCustomObject representing the audit result for this operation.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$TargetUPN,

        [Parameter(Mandatory)]
        [string]$TargetGroupName,

        [Parameter(Mandatory)]
        [ValidateSet("Add", "Remove")]
        [string]$TargetAction,

        [Parameter()]
        [switch]$TargetForce
    )

    # Sanitise inputs for AD filter safety
    $safeGroupName = $TargetGroupName -replace "['\*\\]", ""
    $safeUpn       = $TargetUPN -replace "['\*\\]", ""

    $result = [PSCustomObject]@{
        Timestamp         = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Admin             = $adminUser
        UserPrincipalName = $TargetUPN
        GroupName         = $TargetGroupName
        Source            = ""
        Action            = $TargetAction
        Status            = "Pending"
        Verified          = $false
        Detail            = ""
    }

    # ── Step 1: Find group ────────────────────────────────────────────────

    $adGroup    = $null
    $entraGroup = $null

    # Search on-prem AD first
    if ($adAvailable) {
        try {
            $adGroup = Get-ADGroup -Filter "Name -eq '$safeGroupName'" -Properties Members -ErrorAction Stop
            if ($adGroup) {
                Write-Log "Found group '$TargetGroupName' in on-prem AD (DN: $($adGroup.DistinguishedName))."
            }
        }
        catch {
            Write-Log "AD group lookup for '$TargetGroupName' failed: $_" -Level WARN
        }
    }

    # Search Entra ID
    if ($graphToken) {
        try {
            $escapedName = Protect-ODataValue -Value $TargetGroupName
            $uri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$escapedName'&`$select=id,displayName,securityEnabled"
            $entraResult = Invoke-GraphRequest -Uri $uri -OperationName "FindEntraGroup"
            if ($entraResult.value -and $entraResult.value.Count -gt 0) {
                $entraGroup = $entraResult.value[0]
                Write-Log "Found group '$TargetGroupName' in Entra ID (ID: $($entraGroup.id))."
            }
        }
        catch {
            Write-Log "Entra group lookup for '$TargetGroupName' failed: $_" -Level WARN
        }
    }

    # Determine source — prefer on-prem AD for synced groups
    $source = $null
    if ($adGroup) {
        $source = "AD"
        Write-Log "Using on-prem AD as source for group '$TargetGroupName'."
    }
    elseif ($entraGroup) {
        $source = "Entra"
        Write-Log "Using Entra ID as source for group '$TargetGroupName'."
    }
    else {
        $result.Status = "Failed"
        $result.Detail = "Group '$TargetGroupName' not found in AD or Entra ID."
        Write-Log $result.Detail -Level ERROR
        return $result
    }

    $result.Source = $source

    # ── Step 2: Protected group check ─────────────────────────────────────

    if ($TargetAction -eq "Remove" -and $Config.ProtectedGroups -contains $TargetGroupName) {
        if (-not $TargetForce) {
            $result.Status = "Failed"
            $result.Detail = "Group '$TargetGroupName' is protected. Use -Force to allow removal."
            Write-Log $result.Detail -Level ERROR
            return $result
        }
        Write-Log "WARNING: Proceeding with removal from protected group '$TargetGroupName' because -Force was specified." -Level WARN
    }

    # ── Step 3: Find user ─────────────────────────────────────────────────

    $adUser    = $null
    $entraUser = $null

    if ($source -eq "AD") {
        try {
            $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$safeUpn'" -ErrorAction Stop
            if (-not $adUser) {
                $result.Status = "Failed"
                $result.Detail = "User '$TargetUPN' not found in on-prem AD."
                Write-Log $result.Detail -Level ERROR
                return $result
            }
            Write-Log "Found user '$TargetUPN' in AD (DN: $($adUser.DistinguishedName))."
        }
        catch {
            $result.Status = "Failed"
            $result.Detail = "AD user lookup for '$TargetUPN' failed: $_"
            Write-Log $result.Detail -Level ERROR
            return $result
        }
    }
    else {
        try {
            $escapedUpn = Protect-ODataValue -Value $TargetUPN
            $uri = "https://graph.microsoft.com/v1.0/users?`$filter=userPrincipalName eq '$escapedUpn'&`$select=id,userPrincipalName,displayName"
            $userResult = Invoke-GraphRequest -Uri $uri -OperationName "FindEntraUser"
            if (-not $userResult.value -or $userResult.value.Count -eq 0) {
                $result.Status = "Failed"
                $result.Detail = "User '$TargetUPN' not found in Entra ID."
                Write-Log $result.Detail -Level ERROR
                return $result
            }
            $entraUser = $userResult.value[0]
            Write-Log "Found user '$TargetUPN' in Entra ID (ID: $($entraUser.id))."
        }
        catch {
            $result.Status = "Failed"
            $result.Detail = "Entra user lookup for '$TargetUPN' failed: $_"
            Write-Log $result.Detail -Level ERROR
            return $result
        }
    }

    # ── Step 4: Check current membership ──────────────────────────────────

    $isMember = $false

    if ($source -eq "AD") {
        try {
            $members = Get-ADGroupMember -Identity $adGroup.DistinguishedName -ErrorAction Stop
            $isMember = ($members | Where-Object { $_.SID -eq $adUser.SID }) -ne $null
        }
        catch {
            Write-Log "Failed to check AD group membership: $_" -Level WARN
        }
    }
    else {
        try {
            $uri = "https://graph.microsoft.com/v1.0/groups/$($entraGroup.id)/members?`$select=id,userPrincipalName"
            $membersResult = Invoke-GraphRequest -Uri $uri -OperationName "CheckEntraMembership"
            $memberIds = @()
            if ($membersResult.value) {
                $memberIds = $membersResult.value | ForEach-Object { $_.id }
            }
            $isMember = $memberIds -contains $entraUser.id
        }
        catch {
            Write-Log "Failed to check Entra group membership: $_" -Level WARN
        }
    }

    # Idempotency checks
    if ($TargetAction -eq "Add" -and $isMember) {
        $result.Status   = "Skipped"
        $result.Verified = $true
        $result.Detail   = "User '$TargetUPN' is already a member of '$TargetGroupName'."
        Write-Log $result.Detail -Level WARN
        return $result
    }
    if ($TargetAction -eq "Remove" -and -not $isMember) {
        $result.Status   = "Skipped"
        $result.Verified = $true
        $result.Detail   = "User '$TargetUPN' is not a member of '$TargetGroupName'. Nothing to remove."
        Write-Log $result.Detail -Level WARN
        return $result
    }

    # ── Step 5: ShouldProcess ─────────────────────────────────────────────

    if (-not $PSCmdlet.ShouldProcess("$TargetUPN", "$TargetAction membership in '$TargetGroupName'")) {
        $result.Status = "Skipped"
        $result.Detail = "Operation declined by ShouldProcess (WhatIf/Confirm)."
        Write-Log $result.Detail -Level WARN
        return $result
    }

    # ── Step 6: Execute ───────────────────────────────────────────────────

    try {
        if ($source -eq "AD") {
            if ($TargetAction -eq "Add") {
                Add-ADGroupMember -Identity $adGroup.DistinguishedName -Members $adUser.DistinguishedName -ErrorAction Stop
                Write-Log "Added '$TargetUPN' to AD group '$TargetGroupName'."
            }
            else {
                Remove-ADGroupMember -Identity $adGroup.DistinguishedName -Members $adUser.DistinguishedName -Confirm:$false -ErrorAction Stop
                Write-Log "Removed '$TargetUPN' from AD group '$TargetGroupName'."
            }
        }
        else {
            if ($TargetAction -eq "Add") {
                $uri  = "https://graph.microsoft.com/v1.0/groups/$($entraGroup.id)/members/`$ref"
                $body = @{
                    "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($entraUser.id)"
                }
                Invoke-GraphRequest -Uri $uri -Method POST -Body $body -OperationName "AddEntraMember"
                Write-Log "Added '$TargetUPN' to Entra group '$TargetGroupName'."
            }
            else {
                $uri = "https://graph.microsoft.com/v1.0/groups/$($entraGroup.id)/members/$($entraUser.id)/`$ref"
                Invoke-GraphRequest -Uri $uri -Method DELETE -OperationName "RemoveEntraMember"
                Write-Log "Removed '$TargetUPN' from Entra group '$TargetGroupName'."
            }
        }
    }
    catch {
        $result.Status = "Failed"
        $result.Detail = "$TargetAction operation failed: $_"
        Write-Log $result.Detail -Level ERROR
        return $result
    }

    # ── Step 7: Verify ────────────────────────────────────────────────────

    $verified = $false
    Start-Sleep -Seconds 1  # Brief pause to allow replication/propagation

    try {
        if ($source -eq "AD") {
            $members  = Get-ADGroupMember -Identity $adGroup.DistinguishedName -ErrorAction Stop
            $nowMember = ($members | Where-Object { $_.SID -eq $adUser.SID }) -ne $null
            $verified  = if ($TargetAction -eq "Add") { $nowMember } else { -not $nowMember }
        }
        else {
            $uri = "https://graph.microsoft.com/v1.0/groups/$($entraGroup.id)/members?`$select=id"
            $membersResult = Invoke-GraphRequest -Uri $uri -OperationName "VerifyEntraMembership"
            $memberIds = @()
            if ($membersResult.value) {
                $memberIds = $membersResult.value | ForEach-Object { $_.id }
            }
            $nowMember = $memberIds -contains $entraUser.id
            $verified  = if ($TargetAction -eq "Add") { $nowMember } else { -not $nowMember }
        }
    }
    catch {
        Write-Log "Post-operation verification failed: $_" -Level WARN
    }

    if ($verified) {
        $result.Status   = "Success"
        $result.Verified = $true
        $result.Detail   = "$TargetAction operation completed and verified."
        Write-Log $result.Detail -Level SUCCESS
    }
    else {
        $result.Status   = "Unverified"
        $result.Verified = $false
        $result.Detail   = "$TargetAction operation executed but verification could not confirm the change."
        Write-Log $result.Detail -Level WARN
    }

    return $result
}

# ── Main Execution ───────────────────────────────────────────────────────────

try {
    Write-Log "========== $($Config.ScriptName) started by $adminUser =========="

    # ── Module dependency check ───────────────────────────────────────────

    # Check for Active Directory module
    if (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $adAvailable = $true
            Write-Log "Active Directory module loaded."
        }
        catch {
            Write-Log "Active Directory module found but failed to load: $_" -Level WARN
        }
    }
    else {
        Write-Log "Active Directory module not available. AD operations will be skipped." -Level WARN
        if ($Config.RequireAD) {
            throw "Active Directory module is required (RequireAD = `$true) but not available."
        }
    }

    # Acquire Entra ID token
    $entraAvailable = $false
    try {
        $graphToken = Get-GraphToken
        $entraAvailable = $true
        Write-Log "Microsoft Graph token acquired."
    }
    catch {
        Write-Log "Failed to acquire Graph token. Entra ID operations will be unavailable: $_" -Level WARN
    }

    if (-not $adAvailable -and -not $entraAvailable) {
        throw "No directory backend available. Ensure the AD module is installed or Entra ID credentials are configured."
    }

    # ── Process operations ────────────────────────────────────────────────

    $results   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $succeeded = 0
    $failed    = 0
    $skipped   = 0

    if ($InputCSV) {
        # Bulk mode
        Write-Log "Bulk mode: processing CSV '$InputCSV'."

        try {
            $csvRows = Import-Csv -Path $InputCSV -ErrorAction Stop
        }
        catch {
            throw "Failed to import CSV '$InputCSV': $_"
        }

        # Validate required columns
        $requiredColumns = @("UserPrincipalName", "GroupName", "Action")
        $csvColumns = $csvRows[0].PSObject.Properties.Name
        foreach ($col in $requiredColumns) {
            if ($col -notin $csvColumns) {
                throw "CSV is missing required column '$col'. Expected columns: $($requiredColumns -join ', ')."
            }
        }

        Write-Log "CSV contains $($csvRows.Count) row(s) to process."

        $rowIndex = 0
        foreach ($row in $csvRows) {
            $rowIndex++
            Write-Log "Processing CSV row $rowIndex/$($csvRows.Count): UPN=$($row.UserPrincipalName), Group=$($row.GroupName), Action=$($row.Action)"

            # Validate row-level action
            if ($row.Action -notin @("Add", "Remove")) {
                $badResult = [PSCustomObject]@{
                    Timestamp         = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    Admin             = $adminUser
                    UserPrincipalName = $row.UserPrincipalName
                    GroupName         = $row.GroupName
                    Source            = ""
                    Action            = $row.Action
                    Status            = "Failed"
                    Verified          = $false
                    Detail            = "Invalid Action '$($row.Action)'. Must be 'Add' or 'Remove'."
                }
                Write-Log $badResult.Detail -Level ERROR
                $results.Add($badResult)
                $failed++
                continue
            }

            $opResult = Process-GroupMembershipChange -TargetUPN $row.UserPrincipalName `
                                                      -TargetGroupName $row.GroupName `
                                                      -TargetAction $row.Action `
                                                      -TargetForce:$Force
            $results.Add($opResult)

            switch ($opResult.Status) {
                "Success"    { $succeeded++ }
                "Unverified" { $succeeded++ }
                "Skipped"    { $skipped++ }
                default      { $failed++ }
            }
        }
    }
    else {
        # Single operation mode
        Write-Log "Single mode: UPN=$UserPrincipalName, Group=$GroupName, Action=$Action"

        $opResult = Process-GroupMembershipChange -TargetUPN $UserPrincipalName `
                                                  -TargetGroupName $GroupName `
                                                  -TargetAction $Action `
                                                  -TargetForce:$Force
        $results.Add($opResult)

        switch ($opResult.Status) {
            "Success"    { $succeeded++ }
            "Unverified" { $succeeded++ }
            "Skipped"    { $skipped++ }
            default      { $failed++ }
        }
    }

    # ── Export audit CSV ──────────────────────────────────────────────────

    try {
        $results | Export-Csv -Path $auditFile -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Write-Log "Audit results exported to '$auditFile'."
    }
    catch {
        Write-Log "Failed to export audit CSV: $_" -Level ERROR
    }

    # ── Summary ───────────────────────────────────────────────────────────

    $total = $results.Count
    Write-Summary -Total $total -Succeeded $succeeded -Failed $failed -Skipped $skipped

    if ($failed -gt 0) {
        $exitCode = 1
    }
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    Write-Log $_.ScriptStackTrace -Level ERROR
    $exitCode = 1
}
finally {
    Write-Log "========== $($Config.ScriptName) finished (exit code: $exitCode) =========="
}

exit $exitCode
