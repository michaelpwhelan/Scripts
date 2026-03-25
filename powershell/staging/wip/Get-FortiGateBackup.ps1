<#
.SYNOPSIS
    Downloads a full configuration backup from a FortiGate via the REST API.

.DESCRIPTION
    Authenticates to the FortiOS REST API using an API token and calls the
    system config backup monitor endpoint. Saves the raw config text to a
    timestamped .conf file in the configured output directory.
    Run nightly as a cron/Task Scheduler job to maintain a rolling backup history.
    Commit the output directory to Git for automatic version history.

.NOTES
    Author:       Michael Whelan
    Created:      2026-03-11
    Dependencies: None. Uses Invoke-RestMethod (built-in).
                  Requires a FortiOS REST API admin token with read access.
                  Create via: System > Administrators > Create New > REST API Admin

.EXAMPLE
    .\Get-FortiGateBackup.ps1
    Downloads a global config backup and saves to .\output\FortiGateBackup_<host>_<timestamp>.conf
#>
#Requires -Version 5.1

# =============================================================================
# CONFIGURATION
# =============================================================================
$Config = @{
    ScriptName = "Get-FortiGateBackup"
    LogDir     = "$PSScriptRoot\logs"    # Set to $null to disable file logging
    OutputDir  = "$PSScriptRoot\output"

    # --- FortiGate connection ---
    # Set FGT_HOST and FGT_TOKEN as environment variables, or replace placeholders.
    Host  = if ($env:FGT_HOST)  { $env:FGT_HOST }  else { "<YOUR_FORTIGATE_HOST_OR_IP>" }
    Token = if ($env:FGT_TOKEN) { $env:FGT_TOKEN } else { "<YOUR_API_TOKEN>" }
    Port  = 443

    # --- Backup scope ---
    # "global" — entire device config (recommended)
    # "vdom"   — single VDOM; also set Vdom below
    Scope = "global"
    Vdom  = "root"   # Only used when Scope = "vdom"
}
# =============================================================================


# --- Logging setup ---

$Script:LogFile = $null

if ($Config.LogDir) {
    if (-not (Test-Path $Config.LogDir)) {
        New-Item -ItemType Directory -Path $Config.LogDir | Out-Null
    }
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

# Write-Summary: colored console output + plain text to log file
function Write-Summary {
    param([string]$Line, [string]$Color = "White")
    Write-Host $Line -ForegroundColor $Color
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $Line }
}


# --- Main ---

try {
    Write-Log "Starting $($Config.ScriptName)"

    foreach ($key in @("Host", "Token")) {
        if ($Config[$key] -like "<*>") { throw "Config '$key' is not set." }
    }

    $baseUrl = "https://$($Config.Host):$($Config.Port)"
    $params  = "scope=$($Config.Scope)&access_token=$($Config.Token)"
    if ($Config.Scope -eq "vdom") { $params += "&vdom=$($Config.Vdom)" }
    $url = "$baseUrl/api/v2/monitor/system/config/backup?$params"

    Write-Log "Connecting to $($Config.Host):$($Config.Port) — scope: $($Config.Scope)"

    # Disable cert validation for self-signed certs (common on FortiGate)
    add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAll : ICertificatePolicy {
            public bool CheckValidationResult(ServicePoint sp, X509Certificate cert,
                WebRequest req, int problem) { return true; }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAll
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $response = Invoke-WebRequest -Method GET -Uri $url -UseBasicParsing -ErrorAction Stop
    $configText = $response.Content

    if ([string]::IsNullOrWhiteSpace($configText)) {
        throw "Received empty response — check token permissions and host connectivity."
    }

    Write-Log "Received $([math]::Round($configText.Length / 1KB, 1)) KB of config data"

    if (-not (Test-Path $Config.OutputDir)) { New-Item -ItemType Directory -Path $Config.OutputDir | Out-Null }

    $safeHost   = $Config.Host -replace '[^\w\-.]', '_'
    $outputFile = Join-Path $Config.OutputDir (
        "FortiGateBackup_{0}_{1}.conf" -f $safeHost, (Get-Date -Format "yyyyMMdd_HHmmss")
    )

    [System.IO.File]::WriteAllText($outputFile, $configText, [System.Text.Encoding]::UTF8)
    Write-Log "Backup saved to $outputFile"

    # --- Count top-level config sections ---
    $sectionCount = @($configText -split "`n" | Where-Object { $_ -match '^config ' }).Count

    # --- File size (human-readable) ---
    $fileSizeBytes = (Get-Item $outputFile).Length
    if ($fileSizeBytes -ge 1MB) {
        $fileSizeDisplay = "{0:N1} MB" -f ($fileSizeBytes / 1MB)
    } else {
        $fileSizeDisplay = "{0:N1} KB" -f ($fileSizeBytes / 1KB)
    }

    # --- Console summary ---

    $separator = "═" * 52
    $divider   = "─" * 52
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $scopeDisplay = if ($Config.Scope -eq "vdom") { "vdom ($($Config.Vdom))" } else { $Config.Scope }

    Write-Summary ""
    Write-Summary $separator                                                   -Color Yellow
    Write-Summary "  FortiGate Backup  —  $timestamp"                         -Color Yellow
    Write-Summary "  Host: $($Config.Host):$($Config.Port)  |  Scope: $scopeDisplay" -Color Yellow
    Write-Summary $separator                                                   -Color Yellow
    Write-Summary ""
    Write-Summary "  BACKUP DETAILS"                                           -Color Cyan
    Write-Summary $divider                                                     -Color Cyan
    Write-Summary "  File size:  $fileSizeDisplay"
    Write-Summary "  Sections:   $sectionCount top-level config blocks"
    Write-Summary "  Output:     $outputFile"
    Write-Summary ""
    Write-Summary $separator                                                   -Color Cyan
    Write-Summary "  STATUS: OK  —  Backup saved successfully"                -Color Cyan
    Write-Summary $separator                                                   -Color Cyan
    Write-Summary ""

    Write-Log "Completed $($Config.ScriptName) successfully"
    exit 0
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    exit 1
}
