<#
.SYNOPSIS
    Runs Invoke-IntuneHealthCheck.ps1 across multiple endpoints via PSRemoting and
    aggregates results into JSON and CSV outputs.

.DESCRIPTION
    Fleet orchestrator that dispatches the single-device diagnostic script to all
    target machines in parallel using Invoke-Command. Produces two output files:

      1. Full JSON  — complete diagnostic data for every machine (including unreachable)
      2. Summary CSV — one row per machine with key health indicators for quick triage

    Input sources (mutually exclusive):
      -ComputerName  Direct array of hostnames
      -CsvPath       CSV file with a ComputerName column
      -SearchBase    AD OU distinguished name (queries all enabled Windows computers)

.PARAMETER ComputerName
    One or more computer names to scan.

.PARAMETER CsvPath
    Path to a CSV file with a ComputerName column.

.PARAMETER SearchBase
    Active Directory OU distinguished name. Queries all enabled computers with a
    Windows operating system in the specified OU and sub-OUs.
    Requires the ActiveDirectory module (RSAT).

.PARAMETER ThrottleLimit
    Maximum concurrent PSRemoting sessions. Default: 50.

.PARAMETER OutputPath
    Directory for output files. Default: current directory.

.EXAMPLE
    .\Invoke-FleetScan.ps1 -SearchBase "OU=Workstations,DC=contoso,DC=com"
    Scan all enabled Windows workstations in the Workstations OU.

.EXAMPLE
    .\Invoke-FleetScan.ps1 -ComputerName WS01,WS02,WS03 -OutputPath C:\Reports
    Scan three specific machines and save output to C:\Reports.

.EXAMPLE
    .\Invoke-FleetScan.ps1 -CsvPath .\targets.csv -ThrottleLimit 25
    Scan machines from a CSV file with reduced parallelism.
#>
#Requires -Version 5.1
[CmdletBinding(DefaultParameterSetName = 'ComputerName')]
param(
    [Parameter(ParameterSetName = 'ComputerName', Mandatory,
               HelpMessage = 'One or more computer names to scan.')]
    [string[]]$ComputerName,

    [Parameter(ParameterSetName = 'CsvPath', Mandatory,
               HelpMessage = 'Path to CSV file with ComputerName column.')]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$CsvPath,

    [Parameter(ParameterSetName = 'SearchBase', Mandatory,
               HelpMessage = 'AD OU distinguished name to query for computers.')]
    [string]$SearchBase,

    [Parameter(HelpMessage = 'Maximum concurrent PSRemoting sessions.')]
    [ValidateRange(1, 200)]
    [int]$ThrottleLimit = 50,

    [Parameter(HelpMessage = 'Directory for output files.')]
    [string]$OutputPath = (Get-Location).Path
)

# =============================================================================
# Configuration
# =============================================================================
$Config = @{
    ScriptName    = 'Invoke-FleetScan'
    LogDir        = Join-Path $PSScriptRoot 'logs'
    DiagScript    = Join-Path $PSScriptRoot 'Invoke-IntuneHealthCheck.ps1'
    TimestampFile = Get-Date -Format 'yyyyMMdd_HHmmss'
}

# =============================================================================
# Logging
# =============================================================================
$Script:LogFile = $null
if ($Config.LogDir) {
    if (-not (Test-Path $Config.LogDir)) { New-Item -ItemType Directory -Path $Config.LogDir | Out-Null }
    $Script:LogFile = Join-Path $Config.LogDir ('{0}_{1}.log' -f $Config.ScriptName, $Config.TimestampFile)
}

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARNING','ERROR')][string]$Level = 'INFO')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts] [$Level] $Message"
    switch ($Level) {
        'INFO'    { Write-Host $line -ForegroundColor Cyan }
        'WARNING' { Write-Host $line -ForegroundColor Yellow }
        'ERROR'   { Write-Host $line -ForegroundColor Red }
    }
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $line }
}

function Write-Summary {
    param([string]$Line, [string]$Color = 'White')
    Write-Host $Line -ForegroundColor $Color
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $Line }
}

# =============================================================================
# Validate prerequisites
# =============================================================================
if (-not (Test-Path $Config.DiagScript)) {
    throw "Cannot find Invoke-IntuneHealthCheck.ps1 at $($Config.DiagScript)"
}

if (-not (Test-Path $OutputPath -PathType Container)) {
    throw "Output directory does not exist: $OutputPath"
}

# =============================================================================
# Resolve computer list from parameter set
# =============================================================================
Write-Log 'Resolving target computer list...'

$computers = switch ($PSCmdlet.ParameterSetName) {
    'ComputerName' {
        $ComputerName
    }
    'CsvPath' {
        $csv = Import-Csv $CsvPath
        if (-not ($csv | Get-Member -Name ComputerName -EA SilentlyContinue)) {
            throw "CSV file does not contain a 'ComputerName' column: $CsvPath"
        }
        @($csv.ComputerName | Where-Object { $_ -and $_.Trim() -ne '' })
    }
    'SearchBase' {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            throw 'ActiveDirectory module required for -SearchBase. Install RSAT or use -ComputerName/-CsvPath.'
        }
        Import-Module ActiveDirectory
        @((Get-ADComputer -Filter "Enabled -eq 'True' -and OperatingSystem -like 'Windows*'" `
            -SearchBase $SearchBase -Properties OperatingSystem).Name)
    }
}

if ($computers.Count -eq 0) {
    throw 'No target computers resolved. Check your input parameters.'
}

Write-Log "Resolved $($computers.Count) target computer(s)"

# =============================================================================
# Run diagnostic across fleet
# =============================================================================
Write-Log "Starting fleet scan with ThrottleLimit $ThrottleLimit..."
$scanStart = Get-Date

$rawResults = Invoke-Command -ComputerName $computers `
    -FilePath $Config.DiagScript `
    -ThrottleLimit $ThrottleLimit `
    -ErrorAction SilentlyContinue `
    -ErrorVariable remoteErrors

$scanDuration = (Get-Date) - $scanStart
Write-Log "Invoke-Command completed in $([Math]::Round($scanDuration.TotalSeconds, 1))s"

# =============================================================================
# Parse results
# =============================================================================
$allResults = [System.Collections.Generic.List[PSObject]]::new()

# Parse successful results (each is a JSON string from Write-Output on the remote machine)
foreach ($result in $rawResults) {
    try {
        $parsed = $result | ConvertFrom-Json

        # Ensure ComputerName is populated (fallback to PSRemoting metadata)
        if (-not $parsed.ComputerName -and $result.PSComputerName) {
            $parsed | Add-Member -NotePropertyName ComputerName -NotePropertyValue $result.PSComputerName -Force
        }

        $allResults.Add($parsed)
    } catch {
        # Result was not valid JSON — treat as parse error
        $allResults.Add([PSCustomObject][ordered]@{
            ComputerName = if ($result.PSComputerName) { $result.PSComputerName } else { 'UNKNOWN' }
            Timestamp    = (Get-Date).ToUniversalTime().ToString('o')
            Status       = 'PARSE_ERROR'
            Error        = "Failed to parse diagnostic output: $($_.Exception.Message)"
            RawOutput    = "$result".Substring(0, [Math]::Min(500, "$result".Length))
            HealthScore  = [PSCustomObject]@{ Healthy = $false; Findings = @('CRITICAL: Failed to parse diagnostic output') }
        })
        Write-Log "Parse error for $($result.PSComputerName): $($_.Exception.Message)" -Level WARNING
    }
}

# Build stubs for unreachable machines
$reachedComputers = @($allResults | ForEach-Object { $_.ComputerName })
foreach ($err in $remoteErrors) {
    # Extract the target computer name from the error
    $failedHost = $null
    if ($err.TargetObject) {
        $failedHost = $err.TargetObject.ToString()
    } elseif ($err.Exception.Message -match '(\S+)\s') {
        $failedHost = $Matches[1]
    }

    # Skip if we already have a result for this host (error may be supplementary)
    if ($failedHost -and $failedHost -notin $reachedComputers) {
        $errMsg = $err.Exception.Message
        $allResults.Add([PSCustomObject][ordered]@{
            ComputerName = $failedHost
            Timestamp    = (Get-Date).ToUniversalTime().ToString('o')
            Status       = 'UNREACHABLE'
            Error        = $errMsg
            HealthScore  = [PSCustomObject]@{ Healthy = $false; Findings = @("CRITICAL: Device unreachable - $errMsg") }
        })
        $reachedComputers += $failedHost
        Write-Log "Unreachable: $failedHost - $errMsg" -Level WARNING
    }
}

# Catch any computers that returned no result and no error
foreach ($comp in $computers) {
    if ($comp -notin $reachedComputers) {
        $allResults.Add([PSCustomObject][ordered]@{
            ComputerName = $comp
            Timestamp    = (Get-Date).ToUniversalTime().ToString('o')
            Status       = 'UNREACHABLE'
            Error        = 'No response received'
            HealthScore  = [PSCustomObject]@{ Healthy = $false; Findings = @('CRITICAL: Device unreachable - no response received') }
        })
        Write-Log "No response: $comp" -Level WARNING
    }
}

Write-Log "Parsed $($allResults.Count) total results"

# =============================================================================
# Output: Full JSON
# =============================================================================
$jsonFile = Join-Path $OutputPath ("FleetHealth_{0}.json" -f $Config.TimestampFile)
$allResults | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonFile -Encoding UTF8
Write-Log "Full JSON written to $jsonFile"

# =============================================================================
# Output: Summary CSV
# =============================================================================
$csvFile = Join-Path $OutputPath ("FleetHealthSummary_{0}.csv" -f $Config.TimestampFile)

$csvRows = foreach ($r in $allResults) {
    # Handle unreachable/parse error stubs
    if ($r.Status -in @('UNREACHABLE', 'PARSE_ERROR')) {
        [PSCustomObject][ordered]@{
            ComputerName     = $r.ComputerName
            AzureAdPrt       = $r.Status
            HasIntuneMDM     = $r.Status
            IMEInstalled     = $r.Status
            EditionID        = $r.Status
            MmpcFlag         = $r.Status
            ExternallyManaged = $r.Status
            SCCMRemnants     = $r.Status
            PushHealthy      = $r.Status
            MDMCertValid     = $r.Status
            SSLIntercepted   = $r.Status
            ClockHealthy     = $r.Status
            Healthy          = $false
            FindingsCount    = if ($r.HealthScore.Findings) { $r.HealthScore.Findings.Count } else { 1 }
            TopFinding       = if ($r.HealthScore.Findings) { $r.HealthScore.Findings[0] } else { $r.Status }
        }
        continue
    }

    # Check if any SCCM remnant boolean is true
    $hasSccm = $false
    if ($r.SCCMRemnants) {
        $hasSccm = $r.SCCMRemnants.CcmExecService -or $r.SCCMRemnants.CCMRegistryKey -or
                   $r.SCCMRemnants.CCMWmiNamespace -or $r.SCCMRemnants.CCMDirectory -or
                   $r.SCCMRemnants.SmsCfgIni -or $r.SCCMRemnants.HasSCCMEnrollment
    }

    # Push healthy = both services running AND no cloud notification not set to 1
    $pushOk = $false
    if ($r.PushNotifications) {
        $pushOk = $r.PushNotifications.DmwappushStatus -eq 'Running' -and
                  $r.PushNotifications.WpnServiceStatus -eq 'Running' -and
                  $r.PushNotifications.NoCloudNotification -ne 1
    }

    # SSL intercepted = any host confirmed intercepted
    $sslBad = $false
    if ($r.SSLInspection) {
        $sslBad = @($r.SSLInspection | Where-Object { $_.Intercepted -eq $true }).Count -gt 0
    }

    # Clock healthy = hierarchy not broken AND skew <= 120s
    $clockOk = $true
    if ($r.ClockHealth) {
        if ($r.ClockHealth.DomainHierarchyBroken) { $clockOk = $false }
        if ($null -ne $r.ClockHealth.SkewSeconds -and [Math]::Abs($r.ClockHealth.SkewSeconds) -gt 120) { $clockOk = $false }
    }

    [PSCustomObject][ordered]@{
        ComputerName     = $r.ComputerName
        AzureAdPrt       = if ($r.Identity) { $r.Identity.AzureAdPrt } else { 'N/A' }
        HasIntuneMDM     = if ($r.Enrollment) { $r.Enrollment.HasValidIntuneMDM } else { 'N/A' }
        IMEInstalled     = if ($r.IME) { $r.IME.ServiceExists } else { 'N/A' }
        EditionID        = if ($r.WindowsEdition) { $r.WindowsEdition.EditionID } else { 'N/A' }
        MmpcFlag         = if ($r.Enrollment) { $r.Enrollment.MmpcEnrollmentFlag } else { 'N/A' }
        ExternallyManaged = if ($r.Enrollment) { $r.Enrollment.ExternallyManaged } else { 'N/A' }
        SCCMRemnants     = $hasSccm
        PushHealthy      = $pushOk
        MDMCertValid     = if ($r.MDMCertificate) { $r.MDMCertificate.Valid } else { 'N/A' }
        SSLIntercepted   = $sslBad
        ClockHealthy     = $clockOk
        Healthy          = if ($r.HealthScore) { $r.HealthScore.Healthy } else { $false }
        FindingsCount    = if ($r.HealthScore -and $r.HealthScore.Findings) { $r.HealthScore.Findings.Count } else { 0 }
        TopFinding       = if ($r.HealthScore -and $r.HealthScore.Findings -and $r.HealthScore.Findings.Count -gt 0) { $r.HealthScore.Findings[0] } else { '' }
    }
}

$csvRows | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
Write-Log "Summary CSV written to $csvFile"

# =============================================================================
# Console Summary
# =============================================================================
$healthyCount     = @($allResults | Where-Object { $_.HealthScore -and $_.HealthScore.Healthy -eq $true }).Count
$unhealthyCount   = @($allResults | Where-Object { $_.HealthScore -and $_.HealthScore.Healthy -eq $false -and $_.Status -notin @('UNREACHABLE','PARSE_ERROR') }).Count
$unreachableCount = @($allResults | Where-Object { $_.Status -in @('UNREACHABLE','PARSE_ERROR') }).Count

Write-Summary ''
Write-Summary '================================================================' -Color White
Write-Summary '  INTUNE FLEET SCAN COMPLETE' -Color White
Write-Summary '================================================================' -Color White
Write-Summary "  Scan Duration:  $([Math]::Round($scanDuration.TotalSeconds, 1))s"
Write-Summary "  Total Targets:  $($computers.Count)"
Write-Summary "  Healthy:        $healthyCount" -Color Green
Write-Summary "  Unhealthy:      $unhealthyCount" -Color Yellow
Write-Summary "  Unreachable:    $unreachableCount" -Color Red
Write-Summary '----------------------------------------------------------------' -Color White

# Top findings across fleet
$allFindings = @($allResults |
    Where-Object { $_.HealthScore -and $_.HealthScore.Findings } |
    ForEach-Object { $_.HealthScore.Findings } |
    Where-Object { $_ -notmatch '^LOW:' })

if ($allFindings.Count -gt 0) {
    $topFindings = $allFindings | Group-Object | Sort-Object Count -Descending | Select-Object -First 5
    Write-Summary '  TOP FINDINGS:' -Color White
    $rank = 1
    foreach ($f in $topFindings) {
        Write-Summary "  $rank. $($f.Name) ($($f.Count) device(s))"
        $rank++
    }
    Write-Summary '----------------------------------------------------------------' -Color White
}

# List unreachable machines
if ($unreachableCount -gt 0) {
    $unreachableNames = @($allResults | Where-Object { $_.Status -in @('UNREACHABLE','PARSE_ERROR') } | ForEach-Object { $_.ComputerName })
    Write-Summary '  UNREACHABLE:' -Color Red
    $shown = [Math]::Min($unreachableNames.Count, 20)
    for ($i = 0; $i -lt $shown; $i++) {
        Write-Summary "    - $($unreachableNames[$i])" -Color Red
    }
    if ($unreachableNames.Count -gt 20) {
        Write-Summary "    ...and $($unreachableNames.Count - 20) more" -Color Red
    }
    Write-Summary '----------------------------------------------------------------' -Color White
}

Write-Summary ''
Write-Summary "  Full JSON:   $jsonFile" -Color Cyan
Write-Summary "  Summary CSV: $csvFile" -Color Cyan
Write-Summary "  Log:         $($Script:LogFile)" -Color Cyan
Write-Summary ''
