<#
.SYNOPSIS
    Reports Entra ID users with mode-specific filtering, enrichment, and analysis.

.DESCRIPTION
    Authenticates to Microsoft Graph using client credentials and retrieves Entra ID
    users in one of three report modes:

      All      — Lists all users with department and account status.
      Guest    — Reports external (guest) accounts with domain analysis, sensitive
                 group detection, and inactivity flagging.
      Inactive — Reports users who have not signed in for InactiveDays or more,
                 optionally including accounts that have never signed in.

    Each mode produces a timestamped CSV export, a color-coded console summary,
    and an optional self-contained HTML report.

.PARAMETER ReportType
    Report mode: All, Guest, or Inactive. Default: All.

.PARAMETER InactiveDays
    Flag users inactive for this many days. Used by Guest mode (flagging) and
    Inactive mode (filtering). Set to 0 to disable. Overrides $Config.InactiveDays.

.PARAMETER DepartmentFilter
    Filter users by department (exact match). Only applies to All mode.
    Overrides $Config.DepartmentFilter.

.PARAMETER IncludeNeverSignedIn
    Include accounts that have never signed in. Applies to Inactive mode.
    Overrides $Config.IncludeNeverSignedIn.

.PARAMETER GenerateHtml
    Generate a self-contained HTML report alongside the CSV.

.PARAMETER TenantId
    Entra ID tenant ID. Overrides $Config.TenantId.

.PARAMETER ClientId
    Entra ID app registration client ID. Overrides $Config.ClientId.

.PARAMETER ClientSecret
    Entra ID app registration client secret. Overrides $Config.ClientSecret.

.EXAMPLE
    .\Get-EntraUserReport.ps1 -ReportType All
    Lists all Entra ID users with department and account status.

.EXAMPLE
    .\Get-EntraUserReport.ps1 -ReportType Guest -InactiveDays 60
    Reports all guest accounts, flagging those inactive for 60+ days, with
    external domain analysis and sensitive group detection.

.EXAMPLE
    .\Get-EntraUserReport.ps1 -ReportType Inactive -InactiveDays 90
    Reports users who have not signed in for 90+ days.

.EXAMPLE
    .\Get-EntraUserReport.ps1 -ReportType All -DepartmentFilter "IT" -GenerateHtml
    Lists all users in the IT department and generates an HTML report.
#>
#Requires -Version 5.1
param(
    [ValidateSet("All", "Guest", "Inactive")]
    [string]$ReportType = "All",
    [int]$InactiveDays,
    [string]$DepartmentFilter,
    [switch]$IncludeNeverSignedIn,
    [switch]$GenerateHtml,
    [string]$TenantId,
    [string]$ClientId,
    [string]$ClientSecret
)

# =============================================================================
# CONFIGURATION
# =============================================================================
$Config = @{
    ScriptName = "Get-EntraUserReport"
    LogDir     = "$PSScriptRoot\logs"
    OutputDir  = "$PSScriptRoot\output"

    # --- Entra ID / Graph API credentials ---
    TenantId     = if ($env:ENTRA_TENANT_ID)     { $env:ENTRA_TENANT_ID }     else { "<YOUR_TENANT_ID>" }
    ClientId     = if ($env:ENTRA_CLIENT_ID)     { $env:ENTRA_CLIENT_ID }     else { "<YOUR_CLIENT_ID>" }
    ClientSecret = if ($env:ENTRA_CLIENT_SECRET) { $env:ENTRA_CLIENT_SECRET } else { "<YOUR_CLIENT_SECRET>" }

    # --- Report settings ---
    InactiveDays         = 90
    IncludeNeverSignedIn = $true
    DepartmentFilter     = ""
    GenerateHtml         = $false

    # --- Guest mode: sensitive group detection ---
    SensitiveGroupPatterns = @("*Admin*", "*Owner*", "*Privileged*", "*Executive*", "*Finance*", "*Security*")
}
# =============================================================================

# --- Parameter overrides ---
if ($PSBoundParameters.ContainsKey('InactiveDays'))        { $Config.InactiveDays         = $InactiveDays }
if ($PSBoundParameters.ContainsKey('DepartmentFilter'))    { $Config.DepartmentFilter     = $DepartmentFilter }
if ($IncludeNeverSignedIn)                                 { $Config.IncludeNeverSignedIn = $true }
if ($GenerateHtml)                                         { $Config.GenerateHtml         = $true }
if ($PSBoundParameters.ContainsKey('TenantId'))            { $Config.TenantId             = $TenantId }
if ($PSBoundParameters.ContainsKey('ClientId'))            { $Config.ClientId              = $ClientId }
if ($PSBoundParameters.ContainsKey('ClientSecret'))        { $Config.ClientSecret          = $ClientSecret }

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


# =============================================================================
# FUNCTIONS
# =============================================================================

function Get-GraphToken {
    <# Acquires an OAuth2 access token for Microsoft Graph using client credentials. #>
    param([string]$TenantId, [string]$ClientId, [string]$ClientSecret)
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }
    $r = Invoke-RestMethod -Method POST `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Body $body -ContentType "application/x-www-form-urlencoded"
    return $r.access_token
}

function Invoke-GraphRequest {
    <# Makes a single Graph API request with retry logic for 429 and 5xx errors. #>
    param([string]$Token, [string]$Url)
    $headers = @{ Authorization = "Bearer $Token" }
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            return Invoke-RestMethod -Method GET -Uri $Url -Headers $headers
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
}

function Get-PagedGraphResults {
    <# Retrieves all pages from a Microsoft Graph endpoint using Invoke-GraphRequest. #>
    param([string]$Token, [string]$Url)
    $items = [System.Collections.Generic.List[object]]::new()
    while ($Url) {
        $r = Invoke-GraphRequest -Token $Token -Url $Url
        $items.AddRange($r.value)
        $Url = $r.'@odata.nextLink'
        if ($Url) { Write-Log "Fetching next page ($($items.Count) records so far)..." }
    }
    return $items
}

# --- Guest mode functions ---

function Get-GuestSensitiveGroups {
    <# Checks if a guest user is a member of any groups matching sensitive patterns. #>
    param([string]$Token, [string]$UserId, [string[]]$Patterns)
    $matched = [System.Collections.Generic.List[string]]::new()
    try {
        $url = "https://graph.microsoft.com/v1.0/users/$UserId/memberOf?`$select=displayName,id&`$top=999"
        $r = Invoke-GraphRequest -Token $Token -Url $url
        foreach ($group in $r.value) {
            foreach ($pattern in $Patterns) {
                if ($group.displayName -like $pattern) {
                    $matched.Add($group.displayName)
                    break
                }
            }
        }
    } catch {
        Write-Log "Could not retrieve groups for user $UserId : $_" -Level WARNING
    }
    return $matched
}

function Get-ExternalDomain {
    <# Extracts the external email domain from a guest's mail or UPN. #>
    param([string]$Mail, [string]$Upn)
    $email = if ($Mail) { $Mail } else { $Upn }
    if ($email -match '@(.+)$') { return $Matches[1] }
    if ($Upn -match '_([^#]+)#EXT#@') { return $Matches[1] }
    return "Unknown"
}

# --- HTML report ---

function Export-HtmlReport {
    <# Generates a self-contained HTML report for user report results. #>
    param(
        [System.Collections.Generic.List[PSCustomObject]]$Rows,
        [string]$OutputPath,
        [string]$Mode,
        [int]$TotalRetrieved
    )
    $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $columns = @($Rows[0].PSObject.Properties.Name)

    $headerCells = ($columns | ForEach-Object { "<th>$_</th>" }) -join ""
    $bodyRows = [System.Text.StringBuilder]::new()
    foreach ($row in $Rows) {
        [void]$bodyRows.Append("<tr>")
        foreach ($col in $columns) {
            $val = [System.Net.WebUtility]::HtmlEncode("$($row.$col)")
            [void]$bodyRows.Append("<td>$val</td>")
        }
        [void]$bodyRows.AppendLine("</tr>")
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Entra User Report — $Mode</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;color:#1a1a2e;line-height:1.5;padding:2rem}
.wrap{max-width:1400px;margin:0 auto}
.header{background:#1a1a2e;color:#fff;padding:1.5rem 2rem;border-radius:10px 10px 0 0}
.header h1{font-size:1.5rem;margin-bottom:.3rem}
.header .meta{opacity:.8;font-size:.85rem}
.cards{display:flex;gap:.75rem;padding:1.25rem 2rem;background:#fff;border-bottom:1px solid #e0e0e0}
.card{flex:1;padding:1rem;border-radius:8px;text-align:center}
.card .count{font-size:2rem;font-weight:700}
.card .label{font-size:.75rem;text-transform:uppercase;letter-spacing:.05em;margin-top:.25rem}
.card.neutral{background:#eff6ff;color:#2563eb}
.card.good{background:#f0fdf4;color:#16a34a}
.card.warn{background:#fefce8;color:#ca8a04}
.section{background:#fff;padding:1.5rem 2rem;border-radius:0 0 10px 10px}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{text-align:left;padding:.6rem .5rem;border-bottom:2px solid #d1d5db;color:#6b7280;font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}
td{padding:.6rem .5rem;border-bottom:1px solid #f3f4f6;vertical-align:top}
tr:hover{background:#f9fafb}
.footer{text-align:center;padding:1rem;color:#9ca3af;font-size:.8rem}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <h1>Entra User Report &mdash; $Mode</h1>
    <div class="meta">Generated: $now &mdash; Retrieved: $TotalRetrieved &mdash; Reported: $($Rows.Count)</div>
  </div>
  <div class="cards">
    <div class="card neutral"><div class="count">$TotalRetrieved</div><div class="label">Retrieved</div></div>
    <div class="card good"><div class="count">$($Rows.Count)</div><div class="label">Reported</div></div>
  </div>
  <div class="section">
    <table><thead><tr>$headerCells</tr></thead><tbody>$($bodyRows.ToString())</tbody></table>
  </div>
</div>
<div class="footer">Get-EntraUserReport &mdash; $now</div>
</body>
</html>
"@
    [System.IO.File]::WriteAllText($OutputPath, $html, [System.Text.Encoding]::UTF8)
}


# =============================================================================
# MAIN
# =============================================================================

try {
    Write-Log "Starting $($Config.ScriptName) — ReportType: $ReportType"

    foreach ($key in @("TenantId", "ClientId", "ClientSecret")) {
        if ($Config[$key] -like "<*>") { throw "Config '$key' is not set." }
    }

    $cutoff = if ($Config.InactiveDays -gt 0) { (Get-Date).AddDays(-$Config.InactiveDays) } else { $null }
    if ($cutoff -and $ReportType -in @("Guest", "Inactive")) {
        Write-Log "Inactivity threshold: $($Config.InactiveDays) day(s) — cutoff $($cutoff.ToString('yyyy-MM-dd'))"
    }

    Write-Log "Acquiring Graph API token..."
    $token = Get-GraphToken -TenantId $Config.TenantId -ClientId $Config.ClientId -ClientSecret $Config.ClientSecret

    # --- Build Graph URL based on report type ---

    $graphUrl = switch ($ReportType) {
        "All" {
            $select = "displayName,userPrincipalName,department,jobTitle,accountEnabled,createdDateTime"
            $url = "https://graph.microsoft.com/v1.0/users?`$select=$select&`$top=999"
            if ($Config.DepartmentFilter) {
                $safeDept = $Config.DepartmentFilter -replace "'", "''"
                $url += "&`$filter=department eq '$safeDept'"
            }
            $url
        }
        "Guest" {
            $select = "id,displayName,userPrincipalName,mail,department,companyName,accountEnabled,createdDateTime,signInActivity,externalUserState,externalUserStateChangeDateTime"
            "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$select=$select&`$top=999"
        }
        "Inactive" {
            $select = "id,displayName,userPrincipalName,department,jobTitle,accountEnabled,createdDateTime,signInActivity"
            "https://graph.microsoft.com/v1.0/users?`$select=$select&`$top=999"
        }
    }

    Write-Log "Retrieving users from Entra ID..."
    $users = Get-PagedGraphResults -Token $token -Url $graphUrl
    Write-Log "Retrieved $($users.Count) user(s)"

    # --- Process users based on report type ---

    $rows = [System.Collections.Generic.List[PSCustomObject]]::new()
    $sensitiveWarnings = [System.Collections.Generic.List[string]]::new()
    $i = 0

    foreach ($u in $users) {
        $i++
        if ($i % 100 -eq 0) { Write-Log "Processing user $i/$($users.Count)..." }

        switch ($ReportType) {
            "All" {
                $rows.Add([PSCustomObject]@{
                    DisplayName       = $u.displayName
                    UserPrincipalName = $u.userPrincipalName
                    Department        = $u.department
                    JobTitle          = $u.jobTitle
                    AccountEnabled    = $u.accountEnabled
                    CreatedDateTime   = $u.createdDateTime
                })
            }
            "Guest" {
                $lastSignIn = $u.signInActivity.lastSignInDateTime
                $lastSignInDisplay = "Never"
                $daysSince  = "N/A"
                $inactiveFlag = ""

                if ($lastSignIn) {
                    $dt = [datetime]$lastSignIn
                    $lastSignInDisplay = $dt.ToString("yyyy-MM-dd HH:mm:ss")
                    $daysSince = [int]((Get-Date) - $dt).TotalDays
                    if ($cutoff -and $dt -lt $cutoff) { $inactiveFlag = "INACTIVE" }
                } elseif ($cutoff) {
                    $inactiveFlag = "NEVER_SIGNED_IN"
                }

                $domain = Get-ExternalDomain -Mail $u.mail -Upn $u.userPrincipalName
                $sensitiveGroups = Get-GuestSensitiveGroups -Token $token -UserId $u.id -Patterns $Config.SensitiveGroupPatterns
                $sensitiveGroupsStr = $sensitiveGroups -join "; "

                if ($sensitiveGroups.Count -gt 0) {
                    $sensitiveWarnings.Add("$($u.userPrincipalName) in: $sensitiveGroupsStr")
                    Write-Log "SENSITIVE: $($u.userPrincipalName) — groups: $sensitiveGroupsStr" -Level WARNING
                }

                $rows.Add([PSCustomObject]@{
                    DisplayName                  = $u.displayName
                    UserPrincipalName            = $u.userPrincipalName
                    Mail                         = $u.mail
                    ExternalDomain               = $domain
                    Department                   = $u.department
                    CompanyName                  = $u.companyName
                    AccountEnabled               = $u.accountEnabled
                    ExternalUserState            = $u.externalUserState
                    ExternalUserStateChangedDate = $u.externalUserStateChangeDateTime
                    CreatedDateTime              = $u.createdDateTime
                    LastSignInDateTime           = $lastSignInDisplay
                    DaysSinceSignIn              = $daysSince
                    InactiveFlag                 = $inactiveFlag
                    SensitiveGroups              = $sensitiveGroupsStr
                })
            }
            "Inactive" {
                $lastSignIn = $u.signInActivity.lastSignInDateTime

                if ($null -eq $lastSignIn -or $lastSignIn -eq '') {
                    if ($Config.IncludeNeverSignedIn) {
                        $rows.Add([PSCustomObject]@{
                            DisplayName        = $u.displayName
                            UserPrincipalName  = $u.userPrincipalName
                            Department         = $u.department
                            JobTitle           = $u.jobTitle
                            AccountEnabled     = $u.accountEnabled
                            CreatedDateTime    = $u.createdDateTime
                            LastSignInDateTime = "Never"
                            DaysSinceSignIn    = "N/A"
                        })
                    }
                } else {
                    $signInDate = [datetime]$lastSignIn
                    if ($cutoff -and $signInDate -lt $cutoff) {
                        $rows.Add([PSCustomObject]@{
                            DisplayName        = $u.displayName
                            UserPrincipalName  = $u.userPrincipalName
                            Department         = $u.department
                            JobTitle           = $u.jobTitle
                            AccountEnabled     = $u.accountEnabled
                            CreatedDateTime    = $u.createdDateTime
                            LastSignInDateTime = $signInDate.ToString("yyyy-MM-dd HH:mm:ss")
                            DaysSinceSignIn    = [int]((Get-Date) - $signInDate).TotalDays
                        })
                    }
                }
            }
        }
    }

    Write-Log "Report rows: $($rows.Count)"

    if ($rows.Count -eq 0) {
        Write-Log "No users matched the report criteria. Exiting." -Level WARNING
        exit 0
    }

    # --- CSV export ---

    if (-not (Test-Path $Config.OutputDir)) { New-Item -ItemType Directory -Path $Config.OutputDir | Out-Null }
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputFile = Join-Path $Config.OutputDir ("{0}Users_{1}.csv" -f $ReportType, $ts)
    $rows | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
    Write-Log "Exported $($rows.Count) row(s) to $outputFile"

    # --- HTML export ---

    $htmlFile = $null
    if ($Config.GenerateHtml) {
        $htmlFile = Join-Path $Config.OutputDir ("{0}Users_{1}.html" -f $ReportType, $ts)
        Export-HtmlReport -Rows $rows -OutputPath $htmlFile -Mode $ReportType -TotalRetrieved $users.Count
        Write-Log "HTML report exported to $htmlFile"
    }

    # --- Console summary ---

    $separator   = [string]::new([char]0x2550, 72)
    $divider     = [string]::new([char]0x2500, 72)
    $displayTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    Write-Summary ""
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary "  Entra User Report [$ReportType]  —  $displayTime"              -Color Yellow

    switch ($ReportType) {
        "All" {
            $enabledCount  = @($rows | Where-Object { $_.AccountEnabled -eq $true }).Count
            $disabledCount = $rows.Count - $enabledCount

            if ($Config.DepartmentFilter) {
                Write-Summary "  Department filter: $($Config.DepartmentFilter)"    -Color Yellow
            }
            Write-Summary $separator                                                -Color Yellow
            Write-Summary ""

            $deptGroups = $rows | Group-Object -Property Department | Sort-Object Count -Descending
            if ($deptGroups.Count -gt 0) {
                Write-Summary "  BY DEPARTMENT"                                     -Color Cyan
                Write-Summary $divider                                              -Color Cyan
                foreach ($dg in ($deptGroups | Select-Object -First 15)) {
                    $deptName = if ($dg.Name) { $dg.Name } else { "(none)" }
                    Write-Summary ("  {0,4}  {1}" -f $dg.Count, $deptName)
                }
                if ($deptGroups.Count -gt 15) {
                    Write-Summary "  ... and $($deptGroups.Count - 15) more"        -Color DarkGray
                }
                Write-Summary ""
            }

            Write-Summary $separator                                                -Color Cyan
            Write-Summary ("  TOTAL: {0} users  |  {1} enabled  |  {2} disabled" -f
                $rows.Count, $enabledCount, $disabledCount)                         -Color Cyan
        }
        "Guest" {
            Write-Summary "  Total guests: $($rows.Count)  |  Inactivity threshold: $($Config.InactiveDays) days" -Color Yellow
            Write-Summary $separator                                                -Color Yellow
            Write-Summary ""

            $inactiveCount  = @($rows | Where-Object { $_.InactiveFlag -eq "INACTIVE" }).Count
            $neverSignedIn  = @($rows | Where-Object { $_.InactiveFlag -eq "NEVER_SIGNED_IN" }).Count
            $enabledCount   = @($rows | Where-Object { $_.AccountEnabled -eq $true }).Count
            $disabledCount  = $rows.Count - $enabledCount
            $sensitiveCount = @($rows | Where-Object { $_.SensitiveGroups -ne "" }).Count

            $stateGroups = $rows | Group-Object -Property ExternalUserState
            Write-Summary "  INVITATION STATE"                                      -Color Cyan
            Write-Summary $divider                                                  -Color Cyan
            foreach ($sg in $stateGroups) {
                $stateName = if ($sg.Name) { $sg.Name } else { "(blank)" }
                Write-Summary ("  {0,-30}  {1}" -f $stateName, $sg.Count)
            }
            Write-Summary ""

            if ($inactiveCount -gt 0 -or $neverSignedIn -gt 0) {
                Write-Summary "  INACTIVITY FLAGS"                                  -Color Cyan
                Write-Summary $divider                                              -Color Cyan
                if ($inactiveCount -gt 0)  { Write-Summary "  Inactive (>$($Config.InactiveDays) days):  $inactiveCount" -Color Yellow }
                if ($neverSignedIn -gt 0)  { Write-Summary "  Never signed in:             $neverSignedIn" -Color Red }
                Write-Summary ""
            }

            $domainGroups = $rows | Group-Object -Property ExternalDomain | Sort-Object Count -Descending | Select-Object -First 10
            Write-Summary "  TOP EXTERNAL DOMAINS"                                  -Color Cyan
            Write-Summary $divider                                                  -Color Cyan
            foreach ($dg in $domainGroups) {
                Write-Summary ("  {0,-40}  {1} guest(s)" -f $dg.Name, $dg.Count)
            }
            Write-Summary ""

            if ($sensitiveCount -gt 0) {
                Write-Summary "  GUESTS IN SENSITIVE GROUPS ($sensitiveCount)"       -Color Cyan
                Write-Summary $divider                                              -Color Cyan
                foreach ($warn in $sensitiveWarnings) {
                    Write-Summary "  $warn"                                         -Color Red
                }
                Write-Summary ""
            }

            Write-Summary $separator                                                -Color Cyan
            Write-Summary ("  TOTAL: {0} guests  |  {1} enabled  |  {2} disabled  |  {3} inactive  |  {4} in sensitive groups" -f
                $rows.Count, $enabledCount, $disabledCount, ($inactiveCount + $neverSignedIn), $sensitiveCount) -Color Cyan
        }
        "Inactive" {
            Write-Summary "  Threshold: $($Config.InactiveDays) days  |  Cutoff: $($cutoff.ToString('yyyy-MM-dd'))" -Color Yellow
            Write-Summary $separator                                                -Color Yellow
            Write-Summary ""

            $neverCount   = @($rows | Where-Object { $_.LastSignInDateTime -eq "Never" }).Count
            $expiredCount = $rows.Count - $neverCount

            $ranked = $rows | Where-Object { $_.DaysSinceSignIn -ne "N/A" } |
                Sort-Object { [int]$_.DaysSinceSignIn } -Descending |
                Select-Object -First 10
            if ($ranked.Count -gt 0) {
                Write-Summary "  MOST STALE ACCOUNTS"                               -Color Cyan
                Write-Summary $divider                                              -Color Cyan
                foreach ($entry in $ranked) {
                    $line = "  {0,-6}  {1,-40}  {2}" -f "$($entry.DaysSinceSignIn)d", $entry.UserPrincipalName, $entry.Department
                    Write-Summary $line                                             -Color Red
                }
                Write-Summary ""
            }

            if ($neverCount -gt 0) {
                $neverAccounts = $rows | Where-Object { $_.LastSignInDateTime -eq "Never" } | Select-Object -First 10
                Write-Summary "  NEVER SIGNED IN ($neverCount total)"               -Color Cyan
                Write-Summary $divider                                              -Color Cyan
                foreach ($entry in $neverAccounts) {
                    Write-Summary ("          {0,-40}  {1}" -f $entry.UserPrincipalName, $entry.Department) -Color Red
                }
                if ($neverCount -gt 10) {
                    Write-Summary "          ... and $($neverCount - 10) more"      -Color DarkGray
                }
                Write-Summary ""
            }

            $deptGroups = $rows | Group-Object -Property Department | Sort-Object Count -Descending
            if ($deptGroups.Count -gt 1) {
                Write-Summary "  BY DEPARTMENT"                                     -Color Cyan
                Write-Summary $divider                                              -Color Cyan
                foreach ($group in $deptGroups) {
                    $deptName = if ($group.Name) { $group.Name } else { "(none)" }
                    Write-Summary ("  {0,4}  {1}" -f $group.Count, $deptName)
                }
                Write-Summary ""
            }

            Write-Summary $separator                                                -Color Cyan
            Write-Summary ("  TOTAL: {0} inactive  |  {1} expired  |  {2} never signed in  |  {3} retrieved" -f
                $rows.Count, $expiredCount, $neverCount, $users.Count)              -Color Cyan
        }
    }

    Write-Summary "  CSV: $outputFile"                                              -Color Cyan
    if ($htmlFile) { Write-Summary "  HTML: $htmlFile"                               -Color Cyan }
    Write-Summary $separator                                                        -Color Cyan
    Write-Summary ""

    Write-Log "Completed $($Config.ScriptName) successfully"
    exit 0
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    exit 1
}
