<#
.SYNOPSIS
    Generic REST API caller with authentication, retry logic, pagination, and timing.

.DESCRIPTION
    Makes authenticated HTTP requests to REST API endpoints with configurable retry
    logic, pagination support, response validation, and request timing. Supports
    Bearer token, API key header, and Basic auth. Responses are logged with timing
    and optionally saved to a JSON file.

.PARAMETER Method
    HTTP method (GET, POST, PUT, PATCH, DELETE). Overrides $Config.Method.

.PARAMETER Url
    Full URL to call. When specified, bypasses BaseUrl + Endpoint concatenation.

.PARAMETER Body
    JSON string for the request body (POST/PUT/PATCH). Overrides $Config.Body.

.PARAMETER BearerToken
    Bearer token for Authorization header. Overrides $Config.BearerToken.

.PARAMETER ApiKey
    API key value. Overrides $Config.ApiKey.

.PARAMETER BasicUser
    Username for Basic auth. Overrides $Config.BasicUser.

.PARAMETER BasicPass
    Password for Basic auth. Overrides $Config.BasicPass.

.EXAMPLE
    .\Invoke-ApiRequest.ps1
    Calls the configured endpoint with default settings.

.EXAMPLE
    .\Invoke-ApiRequest.ps1 -Url "https://api.example.com/v1/users" -BearerToken $token
    GET request to a specific URL with Bearer authentication.

.EXAMPLE
    .\Invoke-ApiRequest.ps1 -Method POST -Url "https://api.example.com/v1/items" -Body '{"name":"test"}'
    POST request with a JSON body.

.EXAMPLE
    .\Invoke-ApiRequest.ps1 -Url "https://api.example.com/data" -ApiKey "sk-abc123"
    GET request authenticated via API key header.
#>
#Requires -Version 5.1
param(
    [ValidateSet("GET", "POST", "PUT", "PATCH", "DELETE")]
    [string]$Method,
    [string]$Url,
    [string]$Body,
    [string]$BearerToken,
    [string]$ApiKey,
    [string]$BasicUser,
    [string]$BasicPass
)

# =============================================================================
# CONFIGURATION
# =============================================================================
$Config = @{
    ScriptName  = "Invoke-ApiRequest"
    LogDir      = "$PSScriptRoot\logs"
    OutputDir   = "$PSScriptRoot\output"    # Set to $null to skip saving the response to disk

    # --- Request ---
    BaseUrl     = "https://api.example.com"
    Endpoint    = "/v1/resource"             # Path appended to BaseUrl
    Method      = "GET"                      # GET, POST, PUT, PATCH, DELETE
    Body        = $null                      # Hashtable for POST/PUT body; $null for GET

    # --- Authentication (choose one; set others to $null) ---
    # Option 1: Bearer token
    BearerToken = if ($env:API_BEARER_TOKEN) { $env:API_BEARER_TOKEN } else { $null }

    # Option 2: API key in a header
    ApiKeyHeader = "X-API-Key"               # Header name for the API key
    ApiKey       = if ($env:API_KEY) { $env:API_KEY } else { $null }

    # Option 3: Basic auth
    BasicUser    = if ($env:API_USER) { $env:API_USER } else { $null }
    BasicPass    = if ($env:API_PASS) { $env:API_PASS } else { $null }

    # --- Additional headers (merged with auth headers) ---
    ExtraHeaders = @{
        # "Accept" = "application/json"
    }

    # --- Retry logic ---
    MaxRetries   = 3      # Total attempts (1 = no retry)
    RetryOnCodes = @(429, 500, 502, 503, 504)

    # --- Pagination ---
    # "NextLink" — follows @odata.nextLink or a custom property
    # "Offset"   — offset-based pagination with configurable page size
    # "None"     — single request, no pagination
    PaginationMode    = "None"
    NextLinkProperty  = '@odata.nextLink'    # Property name containing the next page URL
    OffsetPageSize    = 100                  # Page size for offset-based pagination

    # --- Response validation ---
    ExpectedStatusCodes = @(200, 201, 204)   # Warn if response status code is not in this list
}
# =============================================================================

# --- Parameter overrides ---
if ($PSBoundParameters.ContainsKey('Method'))      { $Config.Method      = $Method }
if ($PSBoundParameters.ContainsKey('Url'))          { $Config.BaseUrl     = $Url; $Config.Endpoint = "" }
if ($PSBoundParameters.ContainsKey('Body'))         { $Config.Body        = $Body }
if ($PSBoundParameters.ContainsKey('BearerToken'))  { $Config.BearerToken = $BearerToken }
if ($PSBoundParameters.ContainsKey('ApiKey'))        { $Config.ApiKey      = $ApiKey }
if ($PSBoundParameters.ContainsKey('BasicUser'))    { $Config.BasicUser   = $BasicUser }
if ($PSBoundParameters.ContainsKey('BasicPass'))    { $Config.BasicPass   = $BasicPass }

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

function New-RequestHeaders {
    <# Builds the HTTP headers hashtable based on the configured authentication method. #>
    param($Config)

    $headers = @{ "Content-Type" = "application/json" }

    if ($Config.BearerToken) {
        $headers["Authorization"] = "Bearer $($Config.BearerToken)"
    }
    elseif ($Config.ApiKey) {
        $headers[$Config.ApiKeyHeader] = $Config.ApiKey
    }
    elseif ($Config.BasicUser -and $Config.BasicPass) {
        $pair = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($Config.BasicUser):$($Config.BasicPass)"))
        $headers["Authorization"] = "Basic $pair"
    }

    foreach ($key in $Config.ExtraHeaders.Keys) {
        $headers[$key] = $Config.ExtraHeaders[$key]
    }

    return $headers
}

function Invoke-ApiWithRetry {
    <# Executes an HTTP request with configurable retry logic and timing. #>
    param(
        [hashtable]$InvokeParams,
        [int]$MaxRetries,
        [int[]]$RetryOnCodes
    )

    $sw = [System.Diagnostics.Stopwatch]::new()

    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            $sw.Restart()
            $response = Invoke-WebRequest @InvokeParams -UseBasicParsing
            $sw.Stop()

            return @{
                StatusCode  = $response.StatusCode
                Headers     = $response.Headers
                Content     = $response.Content
                ElapsedMs   = $sw.ElapsedMilliseconds
            }
        } catch {
            $sw.Stop()
            $statusCode = 0
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }

            if ($statusCode -in $RetryOnCodes -and $attempt -lt $MaxRetries) {
                $retryAfter = 5
                if ($statusCode -eq 429 -and $_.Exception.Response.Headers['Retry-After']) {
                    $retryAfter = [int]$_.Exception.Response.Headers['Retry-After']
                } else {
                    # Exponential backoff: 2, 4, 8, ...
                    $retryAfter = [math]::Pow(2, $attempt)
                }
                Write-Log "HTTP $statusCode on attempt $attempt/$MaxRetries — retrying in ${retryAfter}s..." -Level WARNING
                Start-Sleep -Seconds $retryAfter
            } else {
                return @{
                    StatusCode  = $statusCode
                    Headers     = $null
                    Content     = $_.Exception.Message
                    ElapsedMs   = $sw.ElapsedMilliseconds
                    Error       = $true
                }
            }
        }
    }
}

function Get-AuthType {
    <# Returns a human-readable string describing the active authentication method. #>
    param($Config)
    if ($Config.BearerToken) { return "Bearer Token" }
    if ($Config.ApiKey)       { return "API Key ($($Config.ApiKeyHeader))" }
    if ($Config.BasicUser)   { return "Basic Auth ($($Config.BasicUser))" }
    return "None"
}


# --- Main ---

try {
    Write-Log "Starting $($Config.ScriptName)"

    $url = "$($Config.BaseUrl.TrimEnd('/'))/$($Config.Endpoint.TrimStart('/'))".TrimEnd('/')
    $authType = Get-AuthType -Config $Config
    Write-Log "$($Config.Method) $url"
    Write-Log "Auth: $authType  |  Retries: $($Config.MaxRetries)  |  Pagination: $($Config.PaginationMode)"

    $headers = New-RequestHeaders -Config $Config

    $baseParams = @{
        Method  = $Config.Method
        Headers = $headers
    }

    # Add body for methods that support it
    if ($Config.Body -and $Config.Method -notin @("GET", "DELETE")) {
        $bodyJson = if ($Config.Body -is [string]) { $Config.Body } else { $Config.Body | ConvertTo-Json -Depth 10 }
        $baseParams["Body"] = $bodyJson
    }

    $allContent      = [System.Collections.Generic.List[object]]::new()
    $totalElapsedMs  = 0
    $totalRequests   = 0
    $lastStatusCode  = 0
    $currentUrl      = $url

    # Pagination loop
    $pageIndex = 0
    do {
        $requestParams = $baseParams.Clone()
        $requestParams["Uri"] = $currentUrl

        # Offset-based pagination
        if ($Config.PaginationMode -eq "Offset" -and $pageIndex -gt 0) {
            $joinChar = if ($currentUrl.Contains('?')) { '&' } else { '?' }
            $requestParams["Uri"] = "$currentUrl${joinChar}offset=$($pageIndex * $Config.OffsetPageSize)&limit=$($Config.OffsetPageSize)"
        }

        $result = Invoke-ApiWithRetry -InvokeParams $requestParams -MaxRetries $Config.MaxRetries -RetryOnCodes $Config.RetryOnCodes

        $totalRequests++
        $totalElapsedMs += $result.ElapsedMs
        $lastStatusCode = $result.StatusCode

        if ($result.Error) {
            Write-Log "Request failed with HTTP $($result.StatusCode): $($result.Content)" -Level ERROR
            break
        }

        # Validate status code
        if ($result.StatusCode -notin $Config.ExpectedStatusCodes) {
            Write-Log "Unexpected HTTP status: $($result.StatusCode) (expected: $($Config.ExpectedStatusCodes -join ', '))" -Level WARNING
        }

        Write-Log "HTTP $($result.StatusCode) — $($result.ElapsedMs)ms — $($result.Content.Length) bytes"

        # Parse response
        $parsed = $null
        if ($result.Content) {
            try { $parsed = $result.Content | ConvertFrom-Json } catch { $parsed = $result.Content }
        }

        # Accumulate paginated results
        if ($parsed.value -is [array]) {
            $allContent.AddRange($parsed.value)
        } elseif ($parsed) {
            $allContent.Add($parsed)
        }

        # Determine next page
        $currentUrl = $null
        if ($Config.PaginationMode -eq "NextLink" -and $parsed) {
            $nextLink = $parsed.PSObject.Properties[$Config.NextLinkProperty]
            if ($nextLink -and $nextLink.Value) {
                $currentUrl = $nextLink.Value
                $pageIndex++
                Write-Log "Following next link (page $($pageIndex + 1), $($allContent.Count) items so far)..."
            }
        } elseif ($Config.PaginationMode -eq "Offset" -and $parsed.value -is [array] -and $parsed.value.Count -eq $Config.OffsetPageSize) {
            $currentUrl = $url
            $pageIndex++
            Write-Log "Fetching next offset page (page $($pageIndex + 1), $($allContent.Count) items so far)..."
        }
    } while ($currentUrl)

    # Build final response JSON
    $responseJson = if ($allContent.Count -eq 1 -and $Config.PaginationMode -eq "None") {
        $allContent[0] | ConvertTo-Json -Depth 20
    } else {
        $allContent | ConvertTo-Json -Depth 20
    }

    # Save to file
    $outputFile = $null
    if ($Config.OutputDir) {
        if (-not (Test-Path $Config.OutputDir)) { New-Item -ItemType Directory -Path $Config.OutputDir | Out-Null }
        $outputFile = Join-Path $Config.OutputDir (
            "response_{0}.json" -f (Get-Date -Format "yyyyMMdd_HHmmss")
        )
        $responseJson | Out-File -FilePath $outputFile -Encoding UTF8
        Write-Log "Response saved to $outputFile"
    }

    # --- Console summary ---

    $separator   = [string]::new([char]0x2550, 72)
    $divider     = [string]::new([char]0x2500, 72)
    $displayTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $avgMs       = if ($totalRequests -gt 0) { [math]::Round($totalElapsedMs / $totalRequests, 0) } else { 0 }
    $responseSize = if ($responseJson) { $responseJson.Length } else { 0 }

    Write-Summary ""
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary "  API Request  —  $displayTime"                                  -Color Yellow
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary ""

    Write-Summary "  REQUEST"                                                       -Color Cyan
    Write-Summary $divider                                                          -Color Cyan
    Write-Summary "  Method:         $($Config.Method)"                             -Color White
    Write-Summary "  URL:            $url"                                          -Color White
    Write-Summary "  Auth:           $authType"                                     -Color White
    Write-Summary "  Pagination:     $($Config.PaginationMode)"                     -Color White
    Write-Summary ""

    Write-Summary "  RESPONSE"                                                      -Color Cyan
    Write-Summary $divider                                                          -Color Cyan
    $statusColor = if ($lastStatusCode -in $Config.ExpectedStatusCodes) { "Green" } elseif ($lastStatusCode -eq 0) { "Red" } else { "Yellow" }
    Write-Summary "  Status:         $lastStatusCode"                               -Color $statusColor
    Write-Summary "  Requests:       $totalRequests"                                -Color White
    Write-Summary "  Total time:     ${totalElapsedMs}ms (avg: ${avgMs}ms/request)" -Color White
    Write-Summary "  Response size:  $responseSize bytes"                           -Color White
    if ($allContent.Count -gt 1) {
        Write-Summary "  Items:          $($allContent.Count)"                      -Color White
    }
    Write-Summary ""

    # Show first 20 lines of response
    Write-Summary "  RESPONSE BODY (first 20 lines)"                                -Color Cyan
    Write-Summary $divider                                                          -Color Cyan
    $lines = $responseJson -split "`n" | Select-Object -First 20
    foreach ($line in $lines) {
        Write-Summary "  $line"                                                     -Color White
    }
    if (($responseJson -split "`n").Count -gt 20) {
        Write-Summary "  ... ($((($responseJson -split "`n").Count) - 20) more lines)" -Color DarkGray
    }
    Write-Summary ""

    # Final
    Write-Summary $separator                                                        -Color Cyan
    if ($outputFile) { Write-Summary "  JSON: $outputFile"                          -Color Cyan }
    Write-Summary $separator                                                        -Color Cyan
    Write-Summary ""

    Write-Log "Completed $($Config.ScriptName) successfully"
    if ($result.Error) { exit 1 } else { exit 0 }
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    exit 1
}
