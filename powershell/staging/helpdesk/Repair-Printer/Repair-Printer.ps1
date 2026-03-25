<#
.SYNOPSIS
    Diagnoses and repairs common print spooler issues on a Windows workstation.

.DESCRIPTION
    Captures before/after printer status and pending print jobs, then performs a
    spooler repair cycle: stops the Print Spooler service, clears spool files,
    and restarts the service. Optionally tests TCP port connectivity for a named
    printer and can remove and reinstall a printer driver. Produces a color-coded
    console summary, CSV export, and a plain-text clipboard block for pasting
    into a ticket system.

.PARAMETER ComputerName
    The hostname of the target workstation. Defaults to localhost. Accepts
    standard hostname characters (alphanumeric, dot, hyphen, underscore).

.PARAMETER PrinterName
    Target a specific printer for port connectivity testing. When combined with
    -Reinstall, the named printer driver is removed and re-added after the
    spooler repair.

.PARAMETER Reinstall
    Remove and re-add the printer driver specified by -PrinterName after the
    spooler repair completes. Requires -PrinterName to be set.

.EXAMPLE
    .\Repair-Printer.ps1
    Diagnoses all printers on the local computer, clears the print spooler,
    and reports before/after status.

.EXAMPLE
    .\Repair-Printer.ps1 -ComputerName "WS-JSMITH01" -PrinterName "HP LaserJet 4050"
    Repairs the spooler on WS-JSMITH01 and tests TCP connectivity to the
    specified printer's IP address on port 9100.

.EXAMPLE
    .\Repair-Printer.ps1 -ComputerName "WS-JDOE03" -PrinterName "Canon iR-ADV C5560" -Reinstall
    Repairs the spooler on WS-JDOE03, removes and reinstalls the Canon printer
    driver, and tests port connectivity.
#>
#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Position = 0, HelpMessage = "Target workstation hostname. Defaults to localhost.")]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[a-zA-Z0-9._-]+$')]
    [Alias("CN", "Computer")]
    [string]$ComputerName = "localhost",

    [Parameter(HelpMessage = "Target a specific printer for port connectivity testing.")]
    [string]$PrinterName,

    [Parameter(HelpMessage = "Remove and re-add the specified printer driver after spooler repair.")]
    [switch]$Reinstall
)

# =============================================================================
# CONFIGURATION
# =============================================================================
$Config = @{
    ScriptName      = "Repair-Printer"
    LogDir          = "$PSScriptRoot\logs"
    OutputDir       = "$PSScriptRoot\output"
    DefaultPort     = 9100        # Default TCP port for printer connectivity testing
}
# =============================================================================

# --- Logging setup ---

$Script:LogFile = $null

if ($Config.LogDir) {
    if (-not (Test-Path $Config.LogDir)) {
        New-Item -ItemType Directory -Path $Config.LogDir -Force | Out-Null
    }
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

# =============================================================================
# FUNCTIONS
# =============================================================================

if (-not $_toolkitLoaded) {
function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
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
        [Parameter(Mandatory)][string]$Line,
        [string]$Color = "White"
    )
    Write-Host $Line -ForegroundColor $Color
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $Line }
}

function Test-IsRemote {
    param([Parameter(Mandatory)][string]$Computer)
    $localNames = @("localhost", ".", $env:COMPUTERNAME)
    return ($Computer -notin $localNames)
}

function Test-TargetOnline {
    param([Parameter(Mandatory)][string]$Computer)
    try {
        $ping = Test-Connection -ComputerName $Computer -Count 2 -Quiet -ErrorAction Stop
        if (-not $ping) {
            throw "Target '$Computer' is not reachable."
        }
    }
    catch {
        throw "Target '$Computer' is not reachable. Verify the hostname and network connectivity. $_"
    }
    return $true
}

function Invoke-OnTarget {
    param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @()
    )
    if (Test-IsRemote -Computer $Computer) {
        if ($ArgumentList.Count -gt 0) {
            return Invoke-Command -ComputerName $Computer -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
        }
        else {
            return Invoke-Command -ComputerName $Computer -ScriptBlock $ScriptBlock -ErrorAction Stop
        }
    }
    else {
        if ($ArgumentList.Count -gt 0) {
            return & $ScriptBlock @ArgumentList
        }
        else {
            return & $ScriptBlock
        }
    }
}

function Get-PrinterStatus {
    param([Parameter(Mandatory)][string]$Computer)

    try {
        $printers = Invoke-OnTarget -Computer $Computer -ScriptBlock {
            Get-Printer | Select-Object Name, DriverName, PortName, PrinterStatus, Shared
        }
    }
    catch {
        Write-Log "Failed to retrieve printers: $_" -Level ERROR
        $printers = @()
    }

    try {
        $jobs = Invoke-OnTarget -Computer $Computer -ScriptBlock {
            $allJobs = @()
            foreach ($p in (Get-Printer)) {
                $pJobs = Get-PrintJob -PrinterName $p.Name -ErrorAction SilentlyContinue
                foreach ($j in $pJobs) {
                    $allJobs += [PSCustomObject]@{
                        PrinterName  = $p.Name
                        DocumentName = $j.DocumentName
                        JobStatus    = $j.JobStatus
                        Size         = $j.Size
                        UserName     = $j.UserName
                    }
                }
            }
            return $allJobs
        }
    }
    catch {
        Write-Log "Failed to retrieve print jobs: $_" -Level ERROR
        $jobs = @()
    }

    return @{
        Printers = @($printers)
        Jobs     = @($jobs)
    }
}

function Clear-PrintQueue {
    param([Parameter(Mandatory)][string]$Computer)

    $actions = [System.Collections.Generic.List[string]]::new()

    if (-not $PSCmdlet.ShouldProcess($Computer, "Clear print queue and restart spooler")) {
        Write-Log "Spooler repair skipped by -WhatIf"
        return $actions
    }

    # Stop spooler
    try {
        Invoke-OnTarget -Computer $Computer -ScriptBlock {
            Stop-Service -Name Spooler -Force -ErrorAction Stop
        }
        $actions.Add("Stopped Print Spooler service")
        Write-Log "Stopped Print Spooler service"
    }
    catch {
        Write-Log "Failed to stop Print Spooler: $_" -Level ERROR
        throw
    }

    # Clear spool files
    try {
        $filesCleared = Invoke-OnTarget -Computer $Computer -ScriptBlock {
            $spoolPath = "$env:SystemRoot\System32\spool\PRINTERS\*"
            $files = Get-ChildItem -Path $spoolPath -ErrorAction SilentlyContinue
            $count = if ($files) { @($files).Count } else { 0 }
            if ($files) {
                Remove-Item -Path $spoolPath -Force -ErrorAction SilentlyContinue
            }
            return $count
        }
        $actions.Add("Cleared $filesCleared spool file(s)")
        Write-Log "Cleared $filesCleared spool file(s)"
    }
    catch {
        Write-Log "Failed to clear spool files: $_" -Level WARN
        $actions.Add("Failed to clear spool files")
    }

    # Restart spooler
    try {
        Invoke-OnTarget -Computer $Computer -ScriptBlock {
            Start-Service -Name Spooler -ErrorAction Stop
        }
        $actions.Add("Restarted Print Spooler service")
        Write-Log "Restarted Print Spooler service"
    }
    catch {
        Write-Log "Failed to restart Print Spooler: $_" -Level ERROR
        throw
    }

    return $actions
}

function Test-PrinterPort {
    param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][string]$Printer
    )

    try {
        $portInfo = Invoke-OnTarget -Computer $Computer -ScriptBlock {
            param($PrinterName)
            $p = Get-Printer -Name $PrinterName -ErrorAction SilentlyContinue
            if (-not $p) { return $null }
            $port = Get-PrinterPort -Name $p.PortName -ErrorAction SilentlyContinue
            if ($port -and $port.PrinterHostAddress) {
                return [PSCustomObject]@{
                    PortName    = $port.Name
                    HostAddress = $port.PrinterHostAddress
                    PortNumber  = $port.PortNumber
                }
            }
            return $null
        } -ArgumentList $Printer
    }
    catch {
        return [PSCustomObject]@{
            Tested      = $false
            Detail      = "Failed to query port info for '$Printer': $_"
            HostAddress = ""
            Reachable   = $false
        }
    }

    if (-not $portInfo) {
        return [PSCustomObject]@{
            Tested      = $false
            Detail      = "Printer '$Printer' not found or not a TCP/IP port"
            HostAddress = ""
            Reachable   = $false
        }
    }

    $portNum = if ($portInfo.PortNumber -and $portInfo.PortNumber -gt 0) {
        $portInfo.PortNumber
    }
    else {
        $Config.DefaultPort
    }

    try {
        $test = Test-NetConnection -ComputerName $portInfo.HostAddress -Port $portNum -WarningAction SilentlyContinue
        return [PSCustomObject]@{
            Tested      = $true
            Detail      = "Port $portNum on $($portInfo.HostAddress)"
            HostAddress = $portInfo.HostAddress
            Reachable   = $test.TcpTestSucceeded
        }
    }
    catch {
        return [PSCustomObject]@{
            Tested      = $true
            Detail      = "Port $portNum on $($portInfo.HostAddress) - test failed: $_"
            HostAddress = $portInfo.HostAddress
            Reachable   = $false
        }
    }
}

function Invoke-PrinterReinstall {
    param(
        [Parameter(Mandatory)][string]$Computer,
        [Parameter(Mandatory)][string]$Printer
    )

    if (-not $PSCmdlet.ShouldProcess($Printer, "Remove and reinstall printer driver")) {
        Write-Log "Printer reinstall skipped by -WhatIf"
        return @("Printer reinstall skipped by -WhatIf")
    }

    $actions = [System.Collections.Generic.List[string]]::new()

    # Capture current printer config before removal
    try {
        $printerConfig = Invoke-OnTarget -Computer $Computer -ScriptBlock {
            param($PrinterName)
            $p = Get-Printer -Name $PrinterName -ErrorAction Stop
            return [PSCustomObject]@{
                Name       = $p.Name
                DriverName = $p.DriverName
                PortName   = $p.PortName
            }
        } -ArgumentList $Printer
    }
    catch {
        Write-Log "Failed to retrieve printer config for '$Printer': $_" -Level ERROR
        throw "Cannot reinstall: printer '$Printer' not found or inaccessible. $_"
    }

    # Remove the printer
    try {
        Invoke-OnTarget -Computer $Computer -ScriptBlock {
            param($PrinterName)
            Remove-Printer -Name $PrinterName -ErrorAction Stop
        } -ArgumentList $Printer
        $actions.Add("Removed printer '$Printer'")
        Write-Log "Removed printer '$Printer'"
    }
    catch {
        Write-Log "Failed to remove printer '$Printer': $_" -Level ERROR
        throw
    }

    # Remove the printer driver
    try {
        Invoke-OnTarget -Computer $Computer -ScriptBlock {
            param($DriverName)
            Remove-PrinterDriver -Name $DriverName -ErrorAction Stop
        } -ArgumentList $printerConfig.DriverName
        $actions.Add("Removed driver '$($printerConfig.DriverName)'")
        Write-Log "Removed driver '$($printerConfig.DriverName)'"
    }
    catch {
        Write-Log "Failed to remove driver '$($printerConfig.DriverName)': $_" -Level ERROR
        throw
    }

    # Re-add the printer driver
    try {
        Invoke-OnTarget -Computer $Computer -ScriptBlock {
            param($DriverName)
            Add-PrinterDriver -Name $DriverName -ErrorAction Stop
        } -ArgumentList $printerConfig.DriverName
        $actions.Add("Re-added driver '$($printerConfig.DriverName)'")
        Write-Log "Re-added driver '$($printerConfig.DriverName)'"
    }
    catch {
        Write-Log "Failed to re-add driver '$($printerConfig.DriverName)': $_" -Level ERROR
        throw
    }

    # Re-add the printer with original port
    try {
        Invoke-OnTarget -Computer $Computer -ScriptBlock {
            param($PrinterName, $DriverName, $PortName)
            Add-Printer -Name $PrinterName -DriverName $DriverName -PortName $PortName -ErrorAction Stop
        } -ArgumentList $printerConfig.Name, $printerConfig.DriverName, $printerConfig.PortName
        $actions.Add("Re-added printer '$Printer' on port '$($printerConfig.PortName)'")
        Write-Log "Re-added printer '$Printer' on port '$($printerConfig.PortName)'"
    }
    catch {
        Write-Log "Failed to re-add printer '$Printer': $_" -Level ERROR
        throw
    }

    return $actions
}

# =============================================================================
# MAIN
# =============================================================================

try {
    Write-Log "Starting $($Config.ScriptName)"
    Write-Log "Target: $ComputerName"
    if ($PrinterName) { Write-Log "Printer: $PrinterName" }
    if ($Reinstall)   { Write-Log "Reinstall mode enabled" }

    # --- Step 1: Connectivity check (remote only) ---

    if (Test-IsRemote -Computer $ComputerName) {
        Write-Log "Testing connectivity to $ComputerName..."
        Test-TargetOnline -Computer $ComputerName
        Write-Log "Target is reachable"
    }

    # --- Step 2-3: BEFORE state ---

    Write-Log "Capturing printer status (before repair)..."
    $beforeStatus  = Get-PrinterStatus -Computer $ComputerName
    $beforePrinters = $beforeStatus.Printers
    $beforeJobs     = $beforeStatus.Jobs
    Write-Log "Found $($beforePrinters.Count) printer(s) and $($beforeJobs.Count) pending job(s)"

    $separator   = "=" * 60
    $divider     = "-" * 60
    $displayTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    Write-Summary ""
    Write-Summary $separator -Color Yellow
    Write-Summary "  BEFORE REPAIR  --  $displayTime" -Color Yellow
    Write-Summary $separator -Color Yellow
    Write-Summary ""

    if ($beforePrinters.Count -gt 0) {
        foreach ($printer in $beforePrinters) {
            $jobCount = @($beforeJobs | Where-Object { $_.PrinterName -eq $printer.Name }).Count
            $statusColor = if ($printer.PrinterStatus -eq "Normal") { "Green" } else { "Yellow" }
            $line = "  {0,-35} Status: {1,-12} Driver: {2,-20} Port: {3}" -f $printer.Name, $printer.PrinterStatus, $printer.DriverName, $printer.PortName
            Write-Summary $line -Color $statusColor
        }
    }
    else {
        Write-Summary "  (no printers found)" -Color DarkGray
    }

    Write-Summary ""
    Write-Summary "  Pending jobs: $($beforeJobs.Count)" -Color Cyan
    if ($beforeJobs.Count -gt 0) {
        foreach ($job in $beforeJobs) {
            $line = "    [{0}] {1} - {2} ({3} bytes)" -f $job.JobStatus, $job.DocumentName, $job.UserName, $job.Size
            Write-Summary $line -Color DarkGray
        }
    }
    Write-Summary ""

    # --- Step 4: Spooler repair ---

    Write-Log "Performing spooler repair..."
    $repairActions = Clear-PrintQueue -Computer $ComputerName

    # --- Step 5: Printer reinstall (optional) ---

    $reinstallActions = @()
    if ($Reinstall -and $PrinterName) {
        Write-Log "Performing printer driver reinstall for '$PrinterName'..."
        $reinstallActions = Invoke-PrinterReinstall -Computer $ComputerName -Printer $PrinterName
    }
    elseif ($Reinstall -and -not $PrinterName) {
        Write-Log "-Reinstall specified without -PrinterName; skipping driver reinstall" -Level WARN
    }

    # --- Step 6: Brief pause ---

    Start-Sleep -Seconds 2

    # --- Step 7-8: AFTER state ---

    Write-Log "Capturing printer status (after repair)..."
    $afterStatus   = Get-PrinterStatus -Computer $ComputerName
    $afterPrinters = $afterStatus.Printers
    $afterJobs     = $afterStatus.Jobs
    Write-Log "After repair: $($afterPrinters.Count) printer(s) and $($afterJobs.Count) pending job(s)"

    Write-Summary $separator -Color Green
    Write-Summary "  AFTER REPAIR" -Color Green
    Write-Summary $separator -Color Green
    Write-Summary ""

    if ($afterPrinters.Count -gt 0) {
        foreach ($printer in $afterPrinters) {
            $beforeMatch = $beforePrinters | Where-Object { $_.Name -eq $printer.Name }
            $jobsBefore = @($beforeJobs | Where-Object { $_.PrinterName -eq $printer.Name }).Count
            $jobsAfter  = @($afterJobs  | Where-Object { $_.PrinterName -eq $printer.Name }).Count
            $statusColor = if ($printer.PrinterStatus -eq "Normal") { "Green" } else { "Yellow" }
            $statusBefore = if ($beforeMatch) { $beforeMatch.PrinterStatus } else { "(new)" }
            $line = "  {0,-35} {1,-12} -> {2,-12} Jobs: {3} -> {4}" -f $printer.Name, $statusBefore, $printer.PrinterStatus, $jobsBefore, $jobsAfter
            Write-Summary $line -Color $statusColor
        }
    }
    else {
        Write-Summary "  (no printers found)" -Color DarkGray
    }
    Write-Summary ""

    # Repair actions summary
    Write-Summary "  REPAIR ACTIONS" -Color Cyan
    Write-Summary $divider -Color Cyan
    foreach ($action in $repairActions) {
        Write-Summary "    - $action" -Color Green
    }
    foreach ($action in $reinstallActions) {
        Write-Summary "    - $action" -Color Green
    }
    if ($repairActions.Count -eq 0 -and $reinstallActions.Count -eq 0) {
        Write-Summary "    (no actions taken)" -Color DarkGray
    }
    Write-Summary ""

    # --- Step 9: Port connectivity test ---

    $portResult = $null
    if ($PrinterName) {
        Write-Log "Testing port connectivity for '$PrinterName'..."
        $portResult = Test-PrinterPort -Computer $ComputerName -Printer $PrinterName

        Write-Summary "  PORT CONNECTIVITY" -Color Cyan
        Write-Summary $divider -Color Cyan
        if ($portResult.Tested) {
            $connColor  = if ($portResult.Reachable) { "Green" } else { "Red" }
            $connStatus = if ($portResult.Reachable) { "Reachable" } else { "Unreachable" }
            Write-Summary "    $PrinterName : $connStatus ($($portResult.Detail))" -Color $connColor
            if ($portResult.Reachable) {
                Write-Log "Port test PASSED: $($portResult.Detail)"
            }
            else {
                Write-Log "Port test FAILED: $($portResult.Detail)" -Level WARN
            }
        }
        else {
            Write-Summary "    $($portResult.Detail)" -Color DarkGray
            Write-Log "Port test skipped: $($portResult.Detail)" -Level WARN
        }
        Write-Summary ""
    }

    # --- Step 10: CSV export ---

    if (-not (Test-Path $Config.OutputDir)) {
        New-Item -ItemType Directory -Path $Config.OutputDir -Force | Out-Null
    }

    $timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeHost   = $ComputerName -replace '[^a-zA-Z0-9]', '_'
    $outputFile = Join-Path $Config.OutputDir ("PrinterRepair_{0}_{1}.csv" -f $safeHost, $timestamp)

    $csvData = foreach ($printer in $afterPrinters) {
        $beforeMatch = $beforePrinters | Where-Object { $_.Name -eq $printer.Name }
        $jobsBefore  = @($beforeJobs | Where-Object { $_.PrinterName -eq $printer.Name }).Count
        $jobsAfter   = @($afterJobs  | Where-Object { $_.PrinterName -eq $printer.Name }).Count

        [PSCustomObject]@{
            Computer     = $ComputerName
            PrinterName  = $printer.Name
            DriverName   = $printer.DriverName
            PortName     = $printer.PortName
            StatusBefore = if ($beforeMatch) { $beforeMatch.PrinterStatus } else { "(new)" }
            StatusAfter  = $printer.PrinterStatus
            JobsBefore   = $jobsBefore
            JobsAfter    = $jobsAfter
            Shared       = $printer.Shared
            ReportedAt   = $displayTime
        }
    }

    if ($csvData) {
        $csvData | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
        Write-Log "Exported CSV to $outputFile"
    }
    else {
        Write-Log "No printer data to export" -Level WARN
    }

    # --- Step 11: Clipboard block ---

    $clipLines = [System.Collections.Generic.List[string]]::new()
    $clipLines.Add("--- COPY FOR TICKET ---")
    $clipLines.Add("Printer Repair: $ComputerName")
    $clipLines.Add("Generated: $displayTime")
    $clipLines.Add("")
    $clipLines.Add("BEFORE REPAIR")
    foreach ($printer in $beforePrinters) {
        $jobCount = @($beforeJobs | Where-Object { $_.PrinterName -eq $printer.Name }).Count
        $clipLines.Add("  $($printer.Name): Status=$($printer.PrinterStatus), Jobs=$jobCount, Driver=$($printer.DriverName)")
    }
    $clipLines.Add("")
    $clipLines.Add("REPAIR ACTIONS")
    foreach ($action in $repairActions)    { $clipLines.Add("  - $action") }
    foreach ($action in $reinstallActions) { $clipLines.Add("  - $action") }
    $clipLines.Add("")
    $clipLines.Add("AFTER REPAIR")
    foreach ($printer in $afterPrinters) {
        $jobCount = @($afterJobs | Where-Object { $_.PrinterName -eq $printer.Name }).Count
        $clipLines.Add("  $($printer.Name): Status=$($printer.PrinterStatus), Jobs=$jobCount, Driver=$($printer.DriverName)")
    }
    if ($portResult -and $portResult.Tested) {
        $clipLines.Add("")
        $clipLines.Add("PORT CONNECTIVITY")
        $connStatus = if ($portResult.Reachable) { "Reachable" } else { "Unreachable" }
        $clipLines.Add("  $PrinterName : $connStatus ($($portResult.Detail))")
    }
    $clipLines.Add("--- END COPY ---")

    $clipText = $clipLines -join "`n"

    try {
        $clipText | Set-Clipboard -ErrorAction Stop
        Write-Log "Summary copied to clipboard"
    }
    catch {
        Write-Log "Could not copy to clipboard (Set-Clipboard unavailable)" -Level WARN
    }

    Write-Summary $clipText
    Write-Summary ""

    # --- Final totals ---

    $totalJobsBefore = $beforeJobs.Count
    $totalJobsAfter  = $afterJobs.Count
    $jobsCleared     = [Math]::Max(0, $totalJobsBefore - $totalJobsAfter)

    Write-Summary $separator -Color Cyan
    Write-Summary ("  Printers: {0}  |  Jobs before: {1}  |  Jobs after: {2}  |  Cleared: {3}" -f
        $afterPrinters.Count, $totalJobsBefore, $totalJobsAfter, $jobsCleared) -Color Cyan
    if ($csvData) {
        Write-Summary "  CSV: $outputFile" -Color Cyan
    }
    Write-Summary $separator -Color Cyan
    Write-Summary ""

    # --- Step 12: Exit ---

    Write-Log "Completed $($Config.ScriptName) successfully"
    exit 0
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level ERROR
    exit 1
}
