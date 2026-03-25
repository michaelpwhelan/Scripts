# HelpdeskToolkit.ps1
# Shared helper functions for the helpdesk script suite.
# Dot-source this file from individual scripts to avoid duplicating these utilities.
# Each script embeds fallback copies so it remains independently runnable.

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
        [string]$Level = "INFO",

        [Parameter()]
        [string]$Computer
    )

    $prefix = if ($Computer) { "[$Computer] " } else { "" }
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] $prefix$Message"

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
        [Alias("BaseDelaySeconds")]
        [int]$DelaySeconds = 2,

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
            $delay = $DelaySeconds * [math]::Pow(2, $attempt - 1)
            Write-Log "Attempt $attempt/$MaxAttempts for $OperationName failed: $_ — retrying in ${delay}s" -Level WARN
            Start-Sleep -Seconds $delay
        }
    }
}

function Get-GraphToken {
    <#
    .SYNOPSIS
        Acquires an OAuth2 client-credentials token for Microsoft Graph.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$ClientSecret
    )

    $guidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
    if ($TenantId -notmatch $guidPattern) {
        throw "TenantId '$TenantId' is not a valid GUID format."
    }
    if ($ClientId -notmatch $guidPattern) {
        throw "ClientId '$ClientId' is not a valid GUID format."
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
        Retrieves paginated results from the Microsoft Graph API with retry on 429/5xx.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter(Mandatory)]
        [string]$Token,

        [Parameter()]
        [int]$MaxResults = 0
    )

    $headers = @{ Authorization = "Bearer $Token" }
    $results = [System.Collections.Generic.List[object]]::new()

    while ($Url) {
        $response = $null
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                $response = Invoke-RestMethod -Method Get -Uri $Url -Headers $headers -ErrorAction Stop
                break
            }
            catch {
                $statusCode = $null
                if ($_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }
                if ($statusCode -eq 429 -or ($statusCode -ge 500 -and $statusCode -le 599)) {
                    if ($attempt -eq 3) { throw }
                    $retryAfter = [math]::Pow(2, $attempt) * 2
                    if ($statusCode -eq 429) {
                        $retryHeader = $_.Exception.Response.Headers['Retry-After']
                        if ($retryHeader) { $retryAfter = [int]$retryHeader }
                    }
                    Write-Log "HTTP $statusCode on attempt $attempt/3 — retrying in ${retryAfter}s..." -Level WARN
                    Start-Sleep -Seconds $retryAfter
                }
                else {
                    throw
                }
            }
        }

        if ($response.value) {
            $results.AddRange($response.value)
        }
        if ($MaxResults -gt 0 -and $results.Count -ge $MaxResults) {
            break
        }
        $Url = $response.'@odata.nextLink'
    }

    return $results
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
