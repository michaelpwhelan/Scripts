# ═══════════════════════════════════════════════════════════════════════════════
# CONNECTOR BASE -- Shared infrastructure for live data connectors
# ═══════════════════════════════════════════════════════════════════════════════

$Script:Connectors = @{}  # Registry of active connectors

function Register-Connector {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [ValidateSet("WindowsEventLog", "RestApi", "Custom")]
        [string]$Type,
        [hashtable]$Config = @{}
    )
    $Script:Connectors[$Id] = @{
        Id           = $Id
        Name         = $Name
        Type         = $Type
        Config       = $Config
        Status       = "Disconnected"
        LastError    = $null
        LastPull     = $null
        CachedData   = $null
        CacheTTL     = 300  # seconds
        CacheExpiry  = $null
    }
    Write-Log "Connector registered: $Name ($Type)" -Level INFO
}

function Get-ConnectorStatus {
    <#
    .SYNOPSIS
        Returns an array of connector status objects for all registered connectors.
    #>
    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($key in $Script:Connectors.Keys) {
        $conn = $Script:Connectors[$key]
        $results.Add([PSCustomObject]@{
            Id        = $conn.Id
            Name      = $conn.Name
            Type      = $conn.Type
            Status    = $conn.Status
            LastError = $conn.LastError
            LastPull  = $conn.LastPull
        })
    }
    return $results
}

function Set-ConnectorStatus {
    <#
    .SYNOPSIS
        Updates the status of a registered connector.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [ValidateSet("Connected", "Disconnected", "Error", "Pulling")]
        [string]$Status,
        [string]$ErrorMessage = $null
    )
    if ($Script:Connectors.ContainsKey($Id)) {
        $Script:Connectors[$Id].Status = $Status
        if ($ErrorMessage) {
            $Script:Connectors[$Id].LastError = $ErrorMessage
        }
        if ($Status -eq "Pulling") {
            $Script:Connectors[$Id].LastPull = Get-Date
        }
    }
}

function Get-ConnectorCache {
    <#
    .SYNOPSIS
        Returns cached data for a connector if the cache is still valid.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id
    )
    if (-not $Script:Connectors.ContainsKey($Id)) { return $null }
    $conn = $Script:Connectors[$Id]
    if ($conn.CachedData -and $conn.CacheExpiry -and (Get-Date) -lt $conn.CacheExpiry) {
        Write-Log "Returning cached data for connector: $Id" -Level INFO
        return $conn.CachedData
    }
    return $null
}

function Set-ConnectorCache {
    <#
    .SYNOPSIS
        Stores data in a connector's cache with the configured TTL.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [Parameter(Mandatory = $true)]
        $Data
    )
    if ($Script:Connectors.ContainsKey($Id)) {
        $ttl = $Script:Connectors[$Id].CacheTTL
        $Script:Connectors[$Id].CachedData  = $Data
        $Script:Connectors[$Id].CacheExpiry = (Get-Date).AddSeconds($ttl)
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# HTTP helper with retry logic
# ═══════════════════════════════════════════════════════════════════════════════

function Invoke-RestWithRetry {
    <#
    .SYNOPSIS
        Invokes a REST API call with automatic retry on transient failures.
    .DESCRIPTION
        Retries on timeout, 5xx, and connection errors. Returns the response
        body on success or throws on final failure after exhausting retries.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [ValidateSet("GET", "POST", "PUT", "PATCH", "DELETE")]
        [string]$Method = "GET",
        [hashtable]$Headers = @{},
        $Body = $null,
        [string]$ContentType = "application/json",
        [int]$TimeoutSec = 30,
        [int]$MaxRetries = 3,
        [int]$RetryDelayMs = 1000,
        [switch]$SkipCertificateCheck
    )

    $attempt = 0
    $lastError = $null

    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            $splatParams = @{
                Uri         = $Uri
                Method      = $Method
                Headers     = $Headers
                TimeoutSec  = $TimeoutSec
                ErrorAction = 'Stop'
            }
            if ($ContentType) {
                $splatParams['ContentType'] = $ContentType
            }
            if ($null -ne $Body) {
                if ($Body -is [hashtable] -or $Body -is [PSCustomObject]) {
                    $splatParams['Body'] = ($Body | ConvertTo-Json -Depth 10 -Compress)
                } else {
                    $splatParams['Body'] = $Body
                }
            }

            # Handle self-signed certificates for on-prem appliances
            if ($SkipCertificateCheck) {
                # PowerShell 5.1: override certificate validation callback
                $previousCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            }

            try {
                $response = Invoke-RestMethod @splatParams
                return $response
            } finally {
                if ($SkipCertificateCheck) {
                    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $previousCallback
                }
            }
        } catch {
            $lastError = $_
            $statusCode = 0
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            # Determine if the failure is retryable
            $isRetryable = $false
            $errMsg = $_.Exception.Message

            # Transient: 5xx server errors
            if ($statusCode -ge 500 -and $statusCode -lt 600) {
                $isRetryable = $true
            }
            # Transient: timeout
            elseif ($errMsg -match 'timed?\s*out|timeout' -or $statusCode -eq 408) {
                $isRetryable = $true
            }
            # Transient: connection refused / network unreachable
            elseif ($errMsg -match 'Unable to connect|connection was closed|network|unreachable|refused') {
                $isRetryable = $true
            }
            # Rate limited
            elseif ($statusCode -eq 429) {
                $isRetryable = $true
                $RetryDelayMs = $RetryDelayMs * 2  # back off harder on rate limit
            }

            if ($isRetryable -and $attempt -lt $MaxRetries) {
                $delay = $RetryDelayMs * $attempt  # linear backoff
                Write-Log "REST call to $Uri failed (attempt $attempt/$MaxRetries, HTTP $statusCode): $errMsg -- retrying in ${delay}ms" -Level WARNING
                Start-Sleep -Milliseconds $delay
            } elseif (-not $isRetryable) {
                # Non-retryable: 4xx client error, auth failure, etc. -- fail immediately
                Write-Log "REST call to $Uri failed with non-retryable error (HTTP $statusCode): $errMsg" -Level ERROR
                throw $lastError
            }
        }
    }

    # All retries exhausted
    Write-Log "REST call to $Uri failed after $MaxRetries attempts" -Level ERROR
    throw $lastError
}

# ═══════════════════════════════════════════════════════════════════════════════
# Credential management (Windows Credential Manager)
# ═══════════════════════════════════════════════════════════════════════════════

function Get-StoredApiCredential {
    <#
    .SYNOPSIS
        Retrieves a credential from Windows Credential Manager, or prompts the user
        if not found.
    .OUTPUTS
        Hashtable with Username, Password (plain text for API use), Token keys,
        or $null if the user cancels.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetName
    )

    # Attempt retrieval via .NET CredentialManager interop
    try {
        $cred = $null
        # Use cmdkey /list and parse output (works without extra modules on PS 5.1)
        $cmdOutput = & cmdkey /list:$TargetName 2>&1
        if ($cmdOutput -match 'User:\s*(.+)') {
            $storedUser = ($Matches[1]).Trim()

            # Build a NetworkCredential to retrieve the password
            # cmdkey stores Generic credentials accessible via CredRead
            # Use P/Invoke through Add-Type for CredRead
            $credResult = Invoke-CredRead -TargetName $TargetName
            if ($credResult) {
                return @{
                    Username = $credResult.Username
                    Password = $credResult.Password
                    Token    = $credResult.Password  # For token-based auth
                }
            }

            # Fallback: we know the user exists but cannot read the password
            # Prompt for password only
            Write-Log "Found stored username '$storedUser' for $TargetName but cannot read password -- prompting" -Level WARNING
            $secPass = Read-Host "Enter password/token for $storedUser ($TargetName)" -AsSecureString
            $plainPass = ConvertTo-PlainText -SecureString $secPass
            return @{
                Username = $storedUser
                Password = $plainPass
                Token    = $plainPass
            }
        }
    } catch {
        Write-Log "Credential Manager lookup failed for ${TargetName}: $_" -Level WARNING
    }

    # Not found in Credential Manager -- prompt the user
    Write-Log "No stored credential found for $TargetName -- prompting user" -Level INFO
    try {
        $username = Read-Host "Enter username for $TargetName"
        if ([string]::IsNullOrWhiteSpace($username)) { return $null }

        $secPass = Read-Host "Enter password/token for $username ($TargetName)" -AsSecureString
        $plainPass = ConvertTo-PlainText -SecureString $secPass

        # Offer to save
        $saveChoice = Read-Host "Save credential to Windows Credential Manager? (Y/N)"
        if ($saveChoice -match '^[Yy]') {
            Save-ApiCredential -TargetName $TargetName -Username $username -Password $secPass
        }

        return @{
            Username = $username
            Password = $plainPass
            Token    = $plainPass
        }
    } catch {
        Write-Log "Credential prompt failed: $_" -Level ERROR
        return $null
    }
}

function Save-ApiCredential {
    <#
    .SYNOPSIS
        Saves a credential to Windows Credential Manager via cmdkey.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetName,
        [Parameter(Mandatory = $true)]
        [string]$Username,
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$Password
    )

    try {
        $plainPass = ConvertTo-PlainText -SecureString $Password
        # cmdkey /generic: stores a generic credential
        $null = & cmdkey /generic:$TargetName /user:$Username /pass:$plainPass 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "Credential saved to Credential Manager: $TargetName" -Level INFO
        } else {
            Write-Log "cmdkey returned exit code $LASTEXITCODE when saving $TargetName" -Level WARNING
        }
    } catch {
        Write-Log "Failed to save credential for ${TargetName}: $_" -Level ERROR
    }
}

function Remove-ApiCredential {
    <#
    .SYNOPSIS
        Removes a credential from Windows Credential Manager.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetName
    )
    try {
        $null = & cmdkey /delete:$TargetName 2>&1
        Write-Log "Credential removed from Credential Manager: $TargetName" -Level INFO
    } catch {
        Write-Log "Failed to remove credential for ${TargetName}: $_" -Level WARNING
    }
}

function ConvertTo-PlainText {
    <#
    .SYNOPSIS
        Converts a SecureString to plain text for API calls.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]$SecureString
    )
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# P/Invoke helper for Windows Credential Manager CredRead
# ═══════════════════════════════════════════════════════════════════════════════

function Invoke-CredRead {
    <#
    .SYNOPSIS
        Reads a generic credential from Windows Credential Manager using P/Invoke.
    .OUTPUTS
        Hashtable with Username and Password, or $null on failure.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$TargetName
    )

    # Define the native types if not already loaded
    if (-not ([System.Management.Automation.PSTypeName]'InvokeLogParser.NativeCredManager').Type) {
        try {
            Add-Type -Namespace 'InvokeLogParser' -Name 'NativeCredManager' -MemberDefinition @'
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct CREDENTIAL {
    public int Flags;
    public int Type;
    public string TargetName;
    public string Comment;
    public long LastWritten;
    public int CredentialBlobSize;
    public IntPtr CredentialBlob;
    public int Persist;
    public int AttributeCount;
    public IntPtr Attributes;
    public string TargetAlias;
    public string UserName;
}

[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool CredRead(string target, int type, int reservedFlag, out IntPtr credential);

[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool CredFree(IntPtr credential);
'@ -ErrorAction Stop
        } catch {
            # Type may already exist from a previous load
            if ($_.Exception.Message -notmatch 'already exists') {
                Write-Log "Failed to load CredManager P/Invoke types: $_" -Level WARNING
                return $null
            }
        }
    }

    try {
        $credPtr = [IntPtr]::Zero
        # Type 1 = CRED_TYPE_GENERIC
        $success = [InvokeLogParser.NativeCredManager]::CredRead($TargetName, 1, 0, [ref]$credPtr)
        if (-not $success -or $credPtr -eq [IntPtr]::Zero) {
            return $null
        }

        try {
            $cred = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
                $credPtr,
                [System.Type][InvokeLogParser.NativeCredManager+CREDENTIAL]
            )

            $password = ""
            if ($cred.CredentialBlobSize -gt 0 -and $cred.CredentialBlob -ne [IntPtr]::Zero) {
                $password = [System.Runtime.InteropServices.Marshal]::PtrToStringUni(
                    $cred.CredentialBlob,
                    $cred.CredentialBlobSize / 2
                )
            }

            return @{
                Username = $cred.UserName
                Password = $password
            }
        } finally {
            [InvokeLogParser.NativeCredManager]::CredFree($credPtr) | Out-Null
        }
    } catch {
        Write-Log "CredRead P/Invoke failed for ${TargetName}: $_" -Level WARNING
        return $null
    }
}
