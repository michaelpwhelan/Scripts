<#
.SYNOPSIS
    Retrieves a quick diagnostic summary for a Windows workstation.

.DESCRIPTION
    Gathers system, hardware, disk, network, security, and reboot-pending information
    from a local or remote Windows workstation using CIM/WMI queries. Produces a
    color-coded console summary, a PSCustomObject result, a timestamped CSV export,
    and a clipboard-ready text block suitable for pasting into a ticket system.

    No Graph API dependency. All queries use CIM/WMI and built-in PowerShell cmdlets.

.PARAMETER ComputerName
    The hostname of the target workstation. Defaults to localhost.
    Accepts pipeline input so multiple hostnames can be processed in bulk.

.EXAMPLE
    .\Get-WorkstationInfo.ps1
    Gathers diagnostic info from the local computer and displays a color-coded
    summary with a clipboard-ready block.

.EXAMPLE
    .\Get-WorkstationInfo.ps1 -ComputerName "WS-JSMITH01"
    Gathers diagnostic info from the remote workstation WS-JSMITH01 over WinRM.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, HelpMessage = "Target workstation hostname. Defaults to localhost.")]
    [ValidateNotNullOrEmpty()]
    [ValidatePattern('^[a-zA-Z0-9._-]+$')]
    [Alias("CN", "Computer")]
    [string]$ComputerName = "localhost"
)

# =============================================================================
# CONFIGURATION
# =============================================================================
$Config = @{
    ScriptName        = "Get-WorkstationInfo"
    LogDir            = "$PSScriptRoot\logs"
    OutputDir         = "$PSScriptRoot\output"
    DiskWarningPct    = 15      # Warn below this % free
    DiskCriticalPct   = 5       # Critical below this % free
    UptimeWarningDays = 14      # Warn if uptime exceeds this
    DefenderSigAgeDays = 3      # Warn if Defender signatures older than this
}
# =============================================================================

# -----------------------------------------------------------------------------
# Logging setup
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# Helper: determine if a target is remote
# -----------------------------------------------------------------------------
function Test-IsRemote {
    param([string]$Target)
    return ($Target -ne "localhost" -and $Target -ne "." -and $Target -ne $env:COMPUTERNAME)
}

# -----------------------------------------------------------------------------
# Write-Log  --  timestamped, color-coded, console + log file
# -----------------------------------------------------------------------------
if (-not $_toolkitLoaded) {
function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO"
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

# -----------------------------------------------------------------------------
# Write-Summary  --  colored console display + plain text to log file
# -----------------------------------------------------------------------------
function Write-Summary {
    param(
        [string]$Line = "",
        [string]$Color = "White"
    )
    Write-Host $Line -ForegroundColor $Color
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $Line }
}

# -----------------------------------------------------------------------------
# Test-TargetOnline  --  ping check for remote targets
# -----------------------------------------------------------------------------
function Test-TargetOnline {
    param([Parameter(Mandatory)][string]$Target)

    if (-not (Test-IsRemote -Target $Target)) {
        return $true
    }

    try {
        $ping = Test-Connection -ComputerName $Target -Count 2 -Quiet -ErrorAction Stop
    } catch {
        throw "Unable to test connectivity to '$Target': $_"
    }

    if (-not $ping) {
        throw "Target '$Target' is not reachable. Verify the hostname and network connectivity."
    }
    return $true
}

# -----------------------------------------------------------------------------
# Get-SystemInfo  --  OS, hardware, serial, logged-on user, uptime
# -----------------------------------------------------------------------------
function Get-SystemInfo {
    param([Parameter(Mandatory)][string]$Target)

    $cimParams = @{}
    if (Test-IsRemote -Target $Target) { $cimParams.ComputerName = $Target }

    try {
        $os  = Get-CimInstance -ClassName Win32_OperatingSystem @cimParams -ErrorAction Stop
        $cs  = Get-CimInstance -ClassName Win32_ComputerSystem @cimParams -ErrorAction Stop
        $bios = Get-CimInstance -ClassName Win32_BIOS @cimParams -ErrorAction Stop
    } catch {
        throw "Failed to retrieve system information from '$Target': $_"
    }

    $lastBoot = $os.LastBootUpTime
    $uptime   = (Get-Date) - $lastBoot

    return [PSCustomObject]@{
        Hostname      = $cs.Name
        Domain        = $cs.Domain
        OSName        = $os.Caption
        OSBuild       = $os.BuildNumber
        OSVersion     = $os.Version
        Architecture  = $os.OSArchitecture
        SerialNumber  = $bios.SerialNumber
        Manufacturer  = $cs.Manufacturer
        Model         = $cs.Model
        LastBootTime  = $lastBoot
        UptimeDays    = $uptime.Days
        UptimeHours   = $uptime.Hours
        UptimeString  = "{0}d {1}h {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes
        LoggedOnUser  = $cs.UserName
    }
}

# -----------------------------------------------------------------------------
# Get-CpuInfo  --  processor details
# -----------------------------------------------------------------------------
function Get-CpuInfo {
    param([Parameter(Mandatory)][string]$Target)

    $cimParams = @{}
    if (Test-IsRemote -Target $Target) { $cimParams.ComputerName = $Target }

    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor @cimParams -ErrorAction Stop |
               Select-Object -First 1
    } catch {
        throw "Failed to retrieve CPU information from '$Target': $_"
    }

    return [PSCustomObject]@{
        ModelName         = $cpu.Name.Trim()
        Cores             = $cpu.NumberOfCores
        LogicalProcessors = $cpu.NumberOfLogicalProcessors
    }
}

# -----------------------------------------------------------------------------
# Get-MemoryInfo  --  RAM usage
# -----------------------------------------------------------------------------
function Get-MemoryInfo {
    param([Parameter(Mandatory)][string]$Target)

    $cimParams = @{}
    if (Test-IsRemote -Target $Target) { $cimParams.ComputerName = $Target }

    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem @cimParams -ErrorAction Stop
    } catch {
        throw "Failed to retrieve memory information from '$Target': $_"
    }

    $totalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
    $freeGB  = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
    $usedGB  = [math]::Round($totalGB - $freeGB, 1)
    $pctUsed = if ($totalGB -gt 0) { [math]::Round(($usedGB / $totalGB) * 100, 0) } else { 0 }

    return [PSCustomObject]@{
        TotalGB = $totalGB
        FreeGB  = $freeGB
        UsedGB  = $usedGB
        PctUsed = $pctUsed
    }
}

# -----------------------------------------------------------------------------
# Get-DiskInfo  --  per-drive space with thresholds
# -----------------------------------------------------------------------------
function Get-DiskInfo {
    param(
        [Parameter(Mandatory)][string]$Target,
        [int]$WarningPct  = 15,
        [int]$CriticalPct = 5
    )

    $cimParams = @{}
    if (Test-IsRemote -Target $Target) { $cimParams.ComputerName = $Target }

    try {
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" @cimParams -ErrorAction Stop
    } catch {
        throw "Failed to retrieve disk information from '$Target': $_"
    }

    $results = foreach ($disk in $disks) {
        $totalGB = [math]::Round($disk.Size / 1GB, 1)
        $freeGB  = [math]::Round($disk.FreeSpace / 1GB, 1)
        $pctFree = if ($totalGB -gt 0) { [math]::Round(($freeGB / $totalGB) * 100, 0) } else { 0 }

        $status = "OK"
        if ($pctFree -lt $CriticalPct) {
            $status = "CRITICAL"
        } elseif ($pctFree -lt $WarningPct) {
            $status = "WARNING"
        }

        [PSCustomObject]@{
            Drive   = $disk.DeviceID
            Label   = $disk.VolumeName
            TotalGB = $totalGB
            FreeGB  = $freeGB
            PctFree = $pctFree
            Status  = $status
        }
    }
    return $results
}

# -----------------------------------------------------------------------------
# Get-NetworkInfo  --  adapter configurations
# -----------------------------------------------------------------------------
function Get-NetworkInfo {
    param([Parameter(Mandatory)][string]$Target)

    $cimParams = @{}
    if (Test-IsRemote -Target $Target) { $cimParams.ComputerName = $Target }

    try {
        $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" @cimParams -ErrorAction Stop
    } catch {
        throw "Failed to retrieve network information from '$Target': $_"
    }

    $results = foreach ($adapter in $adapters) {
        [PSCustomObject]@{
            AdapterName    = $adapter.Description
            IPAddress      = ($adapter.IPAddress -join ", ")
            SubnetMask     = ($adapter.IPSubnet -join ", ")
            DefaultGateway = ($adapter.DefaultIPGateway -join ", ")
            DNSServers     = ($adapter.DNSServerSearchOrder -join ", ")
            DHCPEnabled    = $adapter.DHCPEnabled
        }
    }
    return $results
}

# -----------------------------------------------------------------------------
# Get-SecurityInfo  --  BitLocker + Defender
# -----------------------------------------------------------------------------
function Get-SecurityInfo {
    param([Parameter(Mandatory)][string]$Target)

    $isRemote = Test-IsRemote -Target $Target

    $result = [PSCustomObject]@{
        BitLockerProtection   = "(unable to query)"
        BitLockerEncryption   = "(unable to query)"
        DefenderRealTime      = "(unable to query)"
        DefenderLastScanTime  = "(unable to query)"
        DefenderSignatureDate = "(unable to query)"
        DefenderSignatureAge  = "(unable to query)"
    }

    # --- BitLocker ---
    try {
        if ($isRemote) {
            $blData = Invoke-Command -ComputerName $Target -ScriptBlock {
                $vol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
                [PSCustomObject]@{
                    Protection = $vol.ProtectionStatus.ToString()
                    Method     = ($vol.EncryptionMethod).ToString()
                }
            } -ErrorAction Stop
        } else {
            $vol = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
            $blData = [PSCustomObject]@{
                Protection = $vol.ProtectionStatus.ToString()
                Method     = ($vol.EncryptionMethod).ToString()
            }
        }
        $result.BitLockerProtection = $blData.Protection
        $result.BitLockerEncryption = $blData.Method
    } catch {
        Write-Log "BitLocker query failed: $_" -Level WARN
    }

    # --- Windows Defender ---
    try {
        if ($isRemote) {
            $defender = Invoke-Command -ComputerName $Target -ScriptBlock {
                Get-MpComputerStatus -ErrorAction Stop
            } -ErrorAction Stop
        } else {
            $defender = Get-MpComputerStatus -ErrorAction Stop
        }

        $result.DefenderRealTime = if ($defender.RealTimeProtectionEnabled) { "On" } else { "Off" }

        if ($defender.QuickScanEndTime) {
            $result.DefenderLastScanTime = $defender.QuickScanEndTime.ToString("yyyy-MM-dd HH:mm:ss")
        } else {
            $result.DefenderLastScanTime = "(no scan recorded)"
        }

        if ($defender.AntivirusSignatureLastUpdated) {
            $result.DefenderSignatureDate = $defender.AntivirusSignatureLastUpdated.ToString("yyyy-MM-dd HH:mm:ss")
            $sigAge = ((Get-Date) - $defender.AntivirusSignatureLastUpdated).Days
            $result.DefenderSignatureAge = $sigAge
        }
    } catch {
        Write-Log "Defender query failed: $_" -Level WARN
    }

    return $result
}

# -----------------------------------------------------------------------------
# Get-PendingReboot  --  registry checks
# -----------------------------------------------------------------------------
function Get-PendingReboot {
    param([Parameter(Mandatory)][string]$Target)

    $isRemote = Test-IsRemote -Target $Target
    $reasons  = [System.Collections.Generic.List[string]]::new()

    $scriptBlock = {
        $flags = @()

        # Component Based Servicing
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
            $flags += "Component Based Servicing"
        }

        # Windows Update
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
            $flags += "Windows Update"
        }

        # Pending file rename operations
        $pfr = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "PendingFileRenameOperations" -ErrorAction SilentlyContinue
        if ($null -ne $pfr) {
            $flags += "Pending File Rename"
        }

        # Pending computer rename
        $activeComputerName = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" -Name "ComputerName" -ErrorAction SilentlyContinue).ComputerName
        $pendingComputerName = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName" -Name "ComputerName" -ErrorAction SilentlyContinue).ComputerName
        if ($activeComputerName -and $pendingComputerName -and ($activeComputerName -ne $pendingComputerName)) {
            $flags += "Pending Computer Rename"
        }

        return $flags
    }

    try {
        if ($isRemote) {
            $flags = Invoke-Command -ComputerName $Target -ScriptBlock $scriptBlock -ErrorAction Stop
        } else {
            $flags = & $scriptBlock
        }
        if ($flags) {
            foreach ($f in $flags) { $reasons.Add($f) }
        }
    } catch {
        Write-Log "Pending reboot check failed: $_" -Level WARN
        $reasons.Add("(unable to query)")
    }

    $isPending = $reasons.Count -gt 0 -and $reasons[0] -ne "(unable to query)"

    return [PSCustomObject]@{
        PendingReboot = $isPending
        Reasons       = if ($reasons.Count -gt 0) { $reasons -join "; " } else { "(none)" }
    }
}

# -----------------------------------------------------------------------------
# Format-ClipboardBlock  --  ticket-ready plain text
# -----------------------------------------------------------------------------
function Format-ClipboardBlock {
    param(
        [Parameter(Mandatory)]$SystemInfo,
        [Parameter(Mandatory)]$CpuInfo,
        [Parameter(Mandatory)]$MemoryInfo,
        [Parameter(Mandatory)]$DiskInfo,
        [Parameter(Mandatory)]$NetworkInfo,
        [Parameter(Mandatory)]$SecurityInfo,
        [Parameter(Mandatory)]$RebootInfo
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    $now   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $lines.Add("=== Workstation Diagnostic Summary ===")
    $lines.Add("Generated: $now")
    $lines.Add("Target:    $($SystemInfo.Hostname)")
    $lines.Add("")

    $lines.Add("SYSTEM")
    $lines.Add("  Hostname:       $($SystemInfo.Hostname)")
    $lines.Add("  Domain:         $($SystemInfo.Domain)")
    $lines.Add("  OS:             $($SystemInfo.OSName)")
    $lines.Add("  Build:          $($SystemInfo.OSBuild) ($($SystemInfo.OSVersion))")
    $lines.Add("  Architecture:   $($SystemInfo.Architecture)")
    $lines.Add("  Manufacturer:   $($SystemInfo.Manufacturer)")
    $lines.Add("  Model:          $($SystemInfo.Model)")
    $lines.Add("  Serial:         $($SystemInfo.SerialNumber)")
    $lines.Add("  Logged-on user: $($SystemInfo.LoggedOnUser)")
    $lines.Add("  Uptime:         $($SystemInfo.UptimeString) (boot: $($SystemInfo.LastBootTime.ToString('yyyy-MM-dd HH:mm:ss')))")
    $lines.Add("")

    $lines.Add("CPU")
    $lines.Add("  Model:          $($CpuInfo.ModelName)")
    $lines.Add("  Cores:          $($CpuInfo.Cores)")
    $lines.Add("  Logical:        $($CpuInfo.LogicalProcessors)")
    $lines.Add("")

    $lines.Add("MEMORY")
    $lines.Add("  Total:          $($MemoryInfo.TotalGB) GB")
    $lines.Add("  Used:           $($MemoryInfo.UsedGB) GB ($($MemoryInfo.PctUsed)%)")
    $lines.Add("  Free:           $($MemoryInfo.FreeGB) GB")
    $lines.Add("")

    $lines.Add("DISK")
    foreach ($disk in $DiskInfo) {
        $tag = if ($disk.Status -ne "OK") { " [$($disk.Status)]" } else { "" }
        $lbl = if ($disk.Label) { " ($($disk.Label))" } else { "" }
        $lines.Add("  $($disk.Drive)$lbl  $($disk.TotalGB) GB total, $($disk.FreeGB) GB free ($($disk.PctFree)%)$tag")
    }
    $lines.Add("")

    $lines.Add("NETWORK")
    foreach ($net in $NetworkInfo) {
        $lines.Add("  $($net.AdapterName)")
        $lines.Add("    IP:      $($net.IPAddress)")
        $lines.Add("    Subnet:  $($net.SubnetMask)")
        $lines.Add("    Gateway: $($net.DefaultGateway)")
        $lines.Add("    DNS:     $($net.DNSServers)")
        $lines.Add("    DHCP:    $(if ($net.DHCPEnabled) { 'Yes' } else { 'No' })")
    }
    $lines.Add("")

    $lines.Add("SECURITY")
    $lines.Add("  BitLocker:       $($SecurityInfo.BitLockerProtection) ($($SecurityInfo.BitLockerEncryption))")
    $lines.Add("  Defender RT:     $($SecurityInfo.DefenderRealTime)")
    $lines.Add("  Last scan:       $($SecurityInfo.DefenderLastScanTime)")
    $lines.Add("  Signatures:      $($SecurityInfo.DefenderSignatureDate) (age: $($SecurityInfo.DefenderSignatureAge) days)")
    $lines.Add("")

    $lines.Add("PENDING REBOOT")
    $lines.Add("  Pending: $(if ($RebootInfo.PendingReboot) { 'Yes' } else { 'No' })")
    $lines.Add("  Reasons: $($RebootInfo.Reasons)")
    $lines.Add("")
    $lines.Add("=== End Summary ===")

    return ($lines -join "`n")
}

# =============================================================================
# PIPELINE EXECUTION
# =============================================================================

begin {
    Write-Log "Starting $($Config.ScriptName)"
}

process {
    try {
        $target = $ComputerName
        Write-Log "Target: $target"

        # --- Test connectivity ---
        Write-Log "Testing connectivity..."
        Test-TargetOnline -Target $target
        Write-Log "Target is reachable"

        # --- Gather data ---
        Write-Log "Gathering system information..."
        $sysInfo = Get-SystemInfo -Target $target

        Write-Log "Gathering CPU information..."
        $cpuInfo = Get-CpuInfo -Target $target

        Write-Log "Gathering memory information..."
        $memInfo = Get-MemoryInfo -Target $target

        Write-Log "Gathering disk information..."
        $diskInfo = Get-DiskInfo -Target $target -WarningPct $Config.DiskWarningPct -CriticalPct $Config.DiskCriticalPct

        Write-Log "Gathering network information..."
        $netInfo = Get-NetworkInfo -Target $target

        Write-Log "Gathering security information..."
        $secInfo = Get-SecurityInfo -Target $target

        Write-Log "Checking for pending reboot..."
        $rebootInfo = Get-PendingReboot -Target $target

        # --- Console summary ---
        $separator   = "=" * 64
        $divider     = "-" * 64
        $displayTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        Write-Summary ""
        Write-Summary $separator                                                        -Color Yellow
        Write-Summary "  Workstation Diagnostic Summary  --  $displayTime"              -Color Yellow
        Write-Summary "  Target: $($sysInfo.Hostname)"                                  -Color Yellow
        Write-Summary $separator                                                        -Color Yellow
        Write-Summary ""

        # SYSTEM
        Write-Summary "  SYSTEM"                                                        -Color Cyan
        Write-Summary $divider                                                          -Color DarkGray
        Write-Summary "  Hostname:       $($sysInfo.Hostname)"
        Write-Summary "  Domain:         $($sysInfo.Domain)"
        Write-Summary "  OS:             $($sysInfo.OSName)"
        Write-Summary "  Build:          $($sysInfo.OSBuild) ($($sysInfo.OSVersion))"
        Write-Summary "  Architecture:   $($sysInfo.Architecture)"
        Write-Summary "  Serial:         $($sysInfo.SerialNumber)"
        Write-Summary "  Manufacturer:   $($sysInfo.Manufacturer)"
        Write-Summary "  Model:          $($sysInfo.Model)"
        Write-Summary "  Logged-on user: $($sysInfo.LoggedOnUser)"
        Write-Summary ""

        # UPTIME
        Write-Summary "  UPTIME"                                                        -Color Cyan
        Write-Summary $divider                                                          -Color DarkGray
        Write-Summary "  Last boot:      $($sysInfo.LastBootTime.ToString('yyyy-MM-dd HH:mm:ss'))"
        $uptimeColor = if ($sysInfo.UptimeDays -gt 30) { "Red" } elseif ($sysInfo.UptimeDays -ge $Config.UptimeWarningDays) { "Yellow" } else { "Green" }
        $uptimeTag   = if ($sysInfo.UptimeDays -gt 30) { " [REBOOT RECOMMENDED]" } elseif ($sysInfo.UptimeDays -ge $Config.UptimeWarningDays) { " [EXTENDED UPTIME]" } else { "" }
        Write-Summary "  Uptime:         $($sysInfo.UptimeString)$uptimeTag"            -Color $uptimeColor
        Write-Summary ""

        # CPU
        Write-Summary "  CPU"                                                           -Color Cyan
        Write-Summary $divider                                                          -Color DarkGray
        Write-Summary "  Model:          $($cpuInfo.ModelName)"
        Write-Summary "  Cores:          $($cpuInfo.Cores)"
        Write-Summary "  Logical procs:  $($cpuInfo.LogicalProcessors)"
        Write-Summary ""

        # MEMORY
        Write-Summary "  MEMORY"                                                        -Color Cyan
        Write-Summary $divider                                                          -Color DarkGray
        $ramColor = if ($memInfo.PctUsed -gt 90) { "Red" } elseif ($memInfo.PctUsed -gt 75) { "Yellow" } else { "Green" }
        Write-Summary "  Total:          $($memInfo.TotalGB) GB"
        Write-Summary "  Used:           $($memInfo.UsedGB) GB ($($memInfo.PctUsed)%)"  -Color $ramColor
        Write-Summary "  Free:           $($memInfo.FreeGB) GB"
        Write-Summary ""

        # DISK
        Write-Summary "  DISK"                                                          -Color Cyan
        Write-Summary $divider                                                          -Color DarkGray
        foreach ($disk in $diskInfo) {
            $diskColor = switch ($disk.Status) {
                "CRITICAL" { "Red" }
                "WARNING"  { "Yellow" }
                default    { "Green" }
            }
            $statusTag = if ($disk.Status -ne "OK") { " [$($disk.Status)]" } else { "" }
            $lbl = if ($disk.Label) { " ($($disk.Label))" } else { "" }
            Write-Summary ("  {0}{1}  {2} GB total  |  {3} GB free  |  {4}% free{5}" -f
                $disk.Drive, $lbl, $disk.TotalGB, $disk.FreeGB, $disk.PctFree, $statusTag) -Color $diskColor
        }
        Write-Summary ""

        # NETWORK
        Write-Summary "  NETWORK"                                                       -Color Cyan
        Write-Summary $divider                                                          -Color DarkGray
        foreach ($net in $netInfo) {
            Write-Summary "  Adapter:        $($net.AdapterName)"
            Write-Summary "  IP:             $($net.IPAddress)"
            Write-Summary "  Subnet:         $($net.SubnetMask)"
            Write-Summary "  Gateway:        $($net.DefaultGateway)"
            Write-Summary "  DNS:            $($net.DNSServers)"
            Write-Summary "  DHCP:           $(if ($net.DHCPEnabled) { 'Yes' } else { 'No' })"
            Write-Summary ""
        }

        # SECURITY
        Write-Summary "  SECURITY"                                                      -Color Cyan
        Write-Summary $divider                                                          -Color DarkGray

        $blColor = switch ($secInfo.BitLockerProtection) {
            "On"  { "Green" }
            "Off" { "Red" }
            default { "White" }
        }
        Write-Summary "  BitLocker:      $($secInfo.BitLockerProtection) ($($secInfo.BitLockerEncryption))" -Color $blColor

        $dfColor = switch ($secInfo.DefenderRealTime) {
            "On"  { "Green" }
            "Off" { "Red" }
            default { "White" }
        }
        Write-Summary "  Defender RT:    $($secInfo.DefenderRealTime)"                  -Color $dfColor
        Write-Summary "  Last scan:      $($secInfo.DefenderLastScanTime)"

        $sigColor = "White"
        if ($secInfo.DefenderSignatureAge -is [int] -and $secInfo.DefenderSignatureAge -gt $Config.DefenderSigAgeDays) {
            $sigColor = "Yellow"
        }
        Write-Summary "  Sig date:       $($secInfo.DefenderSignatureDate) (age: $($secInfo.DefenderSignatureAge) days)" -Color $sigColor
        Write-Summary ""

        # PENDING REBOOT
        Write-Summary "  PENDING REBOOT"                                                -Color Cyan
        Write-Summary $divider                                                          -Color DarkGray
        $rebootColor = if ($rebootInfo.PendingReboot) { "Yellow" } else { "Green" }
        Write-Summary "  Pending:        $(if ($rebootInfo.PendingReboot) { 'Yes' } else { 'No' })" -Color $rebootColor
        Write-Summary "  Reasons:        $($rebootInfo.Reasons)"
        Write-Summary ""

        # --- Clipboard block ---
        $clipBlock = Format-ClipboardBlock -SystemInfo $sysInfo -CpuInfo $cpuInfo -MemoryInfo $memInfo `
            -DiskInfo $diskInfo -NetworkInfo $netInfo -SecurityInfo $secInfo -RebootInfo $rebootInfo

        try {
            $clipBlock | Set-Clipboard -ErrorAction Stop
            Write-Log "Clipboard block copied to clipboard"
        } catch {
            Write-Log "Unable to copy to clipboard (Set-Clipboard not available): $_" -Level WARN
        }

        Write-Summary $divider                                                          -Color DarkGray
        Write-Summary "  CLIPBOARD BLOCK (also copied to clipboard):"                  -Color Cyan
        Write-Summary $divider                                                          -Color DarkGray
        Write-Summary $clipBlock
        Write-Summary ""

        # --- Issue count ---
        $issueCount = 0
        $issueCount += @($diskInfo | Where-Object { $_.Status -ne "OK" }).Count
        if ($rebootInfo.PendingReboot) { $issueCount++ }
        if ($secInfo.DefenderRealTime -eq "Off") { $issueCount++ }
        if ($secInfo.BitLockerProtection -eq "Off") { $issueCount++ }
        if ($sysInfo.UptimeDays -ge $Config.UptimeWarningDays) { $issueCount++ }
        if ($secInfo.DefenderSignatureAge -is [int] -and $secInfo.DefenderSignatureAge -gt $Config.DefenderSigAgeDays) { $issueCount++ }

        $totalColor = if ($issueCount -gt 0) { "Yellow" } else { "Green" }
        Write-Summary $separator                                                        -Color $totalColor
        Write-Summary "  Issues found: $issueCount"                                     -Color $totalColor
        Write-Summary $separator                                                        -Color $totalColor
        Write-Summary ""

        # --- CSV export ---
        if (-not (Test-Path $Config.OutputDir)) {
            New-Item -ItemType Directory -Path $Config.OutputDir -Force | Out-Null
        }
        $timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
        $safeHost   = $sysInfo.Hostname -replace '[^a-zA-Z0-9]', '_'
        $outputFile = Join-Path $Config.OutputDir ("WorkstationInfo_{0}_{1}.csv" -f $safeHost, $timestamp)

        $csvData = [PSCustomObject]@{
            Hostname              = $sysInfo.Hostname
            Domain                = $sysInfo.Domain
            OSName                = $sysInfo.OSName
            OSBuild               = $sysInfo.OSBuild
            OSVersion             = $sysInfo.OSVersion
            Architecture          = $sysInfo.Architecture
            SerialNumber          = $sysInfo.SerialNumber
            Manufacturer          = $sysInfo.Manufacturer
            Model                 = $sysInfo.Model
            LoggedOnUser          = $sysInfo.LoggedOnUser
            LastBootTime          = $sysInfo.LastBootTime.ToString("yyyy-MM-dd HH:mm:ss")
            Uptime                = $sysInfo.UptimeString
            CPU                   = $cpuInfo.ModelName
            CPUCores              = $cpuInfo.Cores
            CPULogicalProcessors  = $cpuInfo.LogicalProcessors
            TotalRamGB           = $memInfo.TotalGB
            UsedRamGB            = $memInfo.UsedGB
            FreeRamGB            = $memInfo.FreeGB
            RamUsedPercent            = "$($memInfo.PctUsed)%"
            DiskSummary           = ($diskInfo | ForEach-Object { "$($_.Drive) $($_.FreeGB)GB free ($($_.PctFree)%) [$($_.Status)]" }) -join "; "
            NetworkSummary        = ($netInfo | ForEach-Object { "$($_.AdapterName): $($_.IPAddress)" }) -join "; "
            BitLockerProtection   = $secInfo.BitLockerProtection
            BitLockerEncryption   = $secInfo.BitLockerEncryption
            DefenderRealTime      = $secInfo.DefenderRealTime
            DefenderLastScan      = $secInfo.DefenderLastScanTime
            DefenderSignatureDate = $secInfo.DefenderSignatureDate
            DefenderSignatureAge  = $secInfo.DefenderSignatureAge
            PendingReboot         = $rebootInfo.PendingReboot
            PendingRebootReasons  = $rebootInfo.Reasons
            ReportedAt            = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        }
        $csvData | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
        Write-Log "CSV exported to $outputFile"

        # --- Result object via Write-Output ---
        $resultObject = [PSCustomObject]@{
            ComputerName = $sysInfo.Hostname
            System       = $sysInfo
            CPU          = $cpuInfo
            Memory       = $memInfo
            Disks        = $diskInfo
            Network      = $netInfo
            Security     = $secInfo
            PendingReboot = $rebootInfo
            IssueCount   = $issueCount
            CSVPath      = $outputFile
            ClipboardBlock = $clipBlock
        }

        Write-Output $resultObject

        Write-Log "Completed diagnostics for $target"

    } catch {
        Write-Log "Fatal error processing '$target': $_" -Level ERROR
        Write-Log $_.ScriptStackTrace -Level ERROR
        exit 1
    }
}

end {
    Write-Log "$($Config.ScriptName) finished"
    exit 0
}
