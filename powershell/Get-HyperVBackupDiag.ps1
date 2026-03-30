<#
.SYNOPSIS
    Collects read-only backup-readiness diagnostics from a standalone Hyper-V host.

.DESCRIPTION
    Diagnoses recurring Veeam "Cannot use CBT" and "file in use by another process"
    errors by inspecting Hyper-V state without making any changes to the host.

    Collects data across nine areas:
      1. Host overview       — OS version, Hyper-V version, disk space
      2. Checkpoint state    — active checkpoints, orphaned AVHDX detection
      3. RCT/CBT status      — RCT file presence per VM, config version check
      4. Hyper-V Replica     — replication mode, state, health per VM
      5. VSS writers         — state of all VSS writers, Hyper-V writer highlighted
      6. File locks          — AVHDX lock detection, Handle.exe integration if present
      7. Veeam state         — skips gracefully when Veeam console is not local
      8. Permissions         — SeServiceLogonRight for NT VIRTUAL MACHINE, NTFS ACLs
      9. Event logs          — Hyper-V VMMS, Worker, VSS, and disk I/O events

    All output is written to the console and a timestamped log file. A findings
    CSV is exported at the end. The script makes zero configuration changes.

.PARAMETER EventLogHours
    Number of hours back to query event logs. Default: 72.

.PARAMETER OutputPath
    Directory where log and CSV files are written. Default: script directory.

.EXAMPLE
    .\Get-HyperVBackupDiag.ps1
    Runs all diagnostic sections with default settings.

.EXAMPLE
    .\Get-HyperVBackupDiag.ps1 -EventLogHours 168 -OutputPath "C:\Diag"
    Queries the last 7 days of events and writes output to C:\Diag.
#>
#Requires -Version 5.1
#Requires -RunAsAdministrator
param(
    [int]$EventLogHours  = 72,
    [string]$OutputPath  = $PSScriptRoot
)

# =============================================================================
# CONFIGURATION
# =============================================================================
$Config = @{
    ScriptName           = "Get-HyperVBackupDiag"
    LogDir               = "$PSScriptRoot\logs"
    OutputDir            = "$PSScriptRoot\output"

    # --- Event log lookback window ---
    EventLogHours        = 72

    # --- File lock: flag AVHDX files written within this many minutes ---
    RecentWriteMinutes   = 5

    # --- Disk space warning threshold (percent free) ---
    DiskFreeWarnPct      = 10

    # --- Checkpoint age warning threshold (days) ---
    CheckpointAgeWarnDays = 7

    # --- Handle.exe search paths (checked in order before $env:PATH) ---
    HandleSearchPaths    = @(
        "C:\Sysinternals"
        "C:\Tools"
        "C:\Program Files\SysinternalsSuite"
        "C:\Windows\System32"
    )

    # --- Hyper-V VMMS Admin event IDs relevant to backup/checkpoint operations ---
    # 12240: attachment not found, 14260: permission denied, 15268: disk info failure
    # 19070: merge started, 19080: merge succeeded, 19090: merge interrupted, 19100: merge failed
    VmmsEventIds         = @(12240, 14260, 15268, 19070, 19080, 19090, 19100)

    # --- System log event IDs for disk/storage errors ---
    StorageEventIds      = @(9, 39, 51, 55, 129, 513)
}
# =============================================================================

# --- Parameter overrides ---
if ($PSBoundParameters.ContainsKey('EventLogHours')) { $Config.EventLogHours = $EventLogHours }
if ($PSBoundParameters.ContainsKey('OutputPath'))    { $Config.OutputDir     = $OutputPath; $Config.LogDir = Join-Path $OutputPath "logs" }

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
    <# Writes colored console output and appends plain text to the log file. #>
    param([string]$Line, [string]$Color = "White")
    Write-Host $Line -ForegroundColor $Color
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $Line }
}


# --- Findings accumulator ---

$Script:Findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Finding {
    <# Appends a diagnostic finding to the script-scoped findings list. #>
    param(
        [string]$Section,
        [ValidateSet("INFO", "WARNING", "ERROR")][string]$Severity,
        [string]$Message
    )
    $Script:Findings.Add([PSCustomObject]@{
        Section  = $Section
        Severity = $Severity
        Message  = $Message
    })
}


# --- Functions ---

function Get-HostOverview {
    <# Collects host identity, OS version, Hyper-V role status, uptime, and disk space on VM storage volumes. #>

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $uptime = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)

    # Hyper-V version comes from the VM management service config
    $hvVersion = "Unknown"
    $hvDefaultVhdPath = ""
    $hvDefaultVmPath  = ""
    try {
        $vmHost = Get-VMHost -ErrorAction Stop
        $hvVersion      = $vmHost.Version
        $hvDefaultVhdPath = $vmHost.VirtualHardDiskPath
        $hvDefaultVmPath  = $vmHost.VirtualMachinePath
    } catch {
        Write-Log "Could not query Get-VMHost: $_" -Level WARNING
        Add-Finding -Section "Host Overview" -Severity "WARNING" -Message "Get-VMHost failed — Hyper-V role may not be installed or VMMS is stopped: $_"
    }

    # Discover all drive letters hosting VM storage so we can report free space accurately
    $drivePaths = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($p in @($hvDefaultVhdPath, $hvDefaultVmPath)) {
        if ($p) {
            $root = [System.IO.Path]::GetPathRoot($p)
            if ($root) { $null = $drivePaths.Add($root.TrimEnd('\')) }
        }
    }

    # Also pull actual VM disk paths — default paths may not reflect where VMs actually live
    try {
        Get-VM -ErrorAction Stop | ForEach-Object {
            Get-VMHardDiskDrive -VMName $_.Name -ErrorAction SilentlyContinue | ForEach-Object {
                $root = [System.IO.Path]::GetPathRoot($_.Path)
                if ($root) { $null = $drivePaths.Add($root.TrimEnd('\')) }
            }
        }
    } catch {
        Write-Log "Could not enumerate VM disk paths for drive discovery: $_" -Level WARNING
    }

    $diskRows = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($drive in $drivePaths) {
        try {
            $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='${drive}:'" -ErrorAction Stop
            if (-not $disk) { $disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$drive'" -ErrorAction Stop }
            if ($disk) {
                $totalGB = [math]::Round($disk.Size / 1GB, 1)
                $freeGB  = [math]::Round($disk.FreeSpace / 1GB, 1)
                $freePct = if ($disk.Size -gt 0) { [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 1) } else { 0 }
                $isLow   = $freePct -lt $Config.DiskFreeWarnPct

                if ($isLow) {
                    Add-Finding -Section "Host Overview" -Severity "WARNING" -Message "Drive $drive is low on space: ${freePct}% free (${freeGB} GB / ${totalGB} GB)"
                }

                $diskRows.Add([PSCustomObject]@{
                    Drive   = $drive
                    TotalGB = $totalGB
                    FreeGB  = $freeGB
                    FreePct = $freePct
                    IsLow   = $isLow
                })
            }
        } catch {
            Write-Log "Could not query disk space for ${drive}: $_" -Level WARNING
        }
    }

    [PSCustomObject]@{
        ComputerName    = $env:COMPUTERNAME
        OSCaption       = $os.Caption
        OSVersion       = $os.Version
        OSBuild         = $os.BuildNumber
        LastBoot        = $os.LastBootUpTime
        UptimeDays      = $uptime
        HyperVVersion   = $hvVersion
        DefaultVhdPath  = $hvDefaultVhdPath
        DefaultVmPath   = $hvDefaultVmPath
        DiskSpace       = $diskRows
    }
}

function Get-VmCheckpointState {
    <# Enumerates VM checkpoints, walks VHD chains to build the referenced AVHDX set, and flags orphaned files on disk. #>

    $checkpointRows = [System.Collections.Generic.List[PSCustomObject]]::new()
    $orphanRows     = [System.Collections.Generic.List[PSCustomObject]]::new()
    $allAvhdxPaths  = [System.Collections.Generic.List[string]]::new()

    # Tracks every AVHDX that is legitimately part of a VM's disk chain or a checkpoint
    $referencedAvhdx = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    # Tracks unique directories to scan for orphaned files
    $storageDirs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    $vms = Get-VM -ErrorAction Stop
    Write-Log "Found $($vms.Count) VM(s) on this host"

    foreach ($vm in $vms) {

        # --- Registered checkpoints ---
        $checkpoints = @(Get-VMSnapshot -VMName $vm.Name -ErrorAction SilentlyContinue)
        if ($checkpoints.Count -gt 0) {
            Write-Log "VM '$($vm.Name)' has $($checkpoints.Count) checkpoint(s)"
        }

        foreach ($cp in $checkpoints) {
            $cpDisks = @(Get-VMHardDiskDrive -VMSnapshot $cp -ErrorAction SilentlyContinue)
            $cpSizeBytes = 0

            foreach ($disk in $cpDisks) {
                if ($disk.Path -match '\.avhdx$') {
                    $null = $referencedAvhdx.Add($disk.Path)
                    $allAvhdxPaths.Add($disk.Path)
                    try {
                        $f = Get-Item -LiteralPath $disk.Path -ErrorAction Stop
                        $cpSizeBytes += $f.Length
                        $null = $storageDirs.Add($f.DirectoryName)
                    } catch { }
                }
            }

            $ageDays = [math]::Round(((Get-Date) - $cp.CreationTime).TotalDays, 1)
            if ($ageDays -gt $Config.CheckpointAgeWarnDays) {
                Add-Finding -Section "Checkpoint State" -Severity "WARNING" -Message "VM '$($vm.Name)': checkpoint '$($cp.Name)' is $ageDays days old"
            }

            $checkpointRows.Add([PSCustomObject]@{
                VMName         = $vm.Name
                CheckpointName = $cp.Name
                Type           = $cp.SnapshotType
                CreationTime   = $cp.CreationTime
                AgeDays        = $ageDays
                SizeMB         = [math]::Round($cpSizeBytes / 1MB, 1)
            })
        }

        # --- Walk the active VHD chain to build the full referenced set ---
        # Differencing disks (AVHDX) will appear here when checkpoints exist but also
        # for in-flight merges; walking the chain catches files that have no checkpoint entry
        $activeDisks = @(Get-VMHardDiskDrive -VMName $vm.Name -ErrorAction SilentlyContinue)
        foreach ($disk in $activeDisks) {
            $currentPath = $disk.Path
            $depth = 0
            while ($currentPath -and $depth -lt 50) {
                $null = $storageDirs.Add([System.IO.Path]::GetDirectoryName($currentPath))
                try {
                    $vhd = Get-VHD -Path $currentPath -ErrorAction Stop
                    if ($currentPath -match '\.avhdx$') {
                        $null = $referencedAvhdx.Add($currentPath)
                        $allAvhdxPaths.Add($currentPath)
                    }
                    $currentPath = $vhd.ParentPath
                } catch {
                    Write-Log "Get-VHD failed for '$currentPath' (VM: $($vm.Name)): $_" -Level WARNING
                    break
                }
                $depth++
            }
        }
    }

    # --- Scan storage directories for AVHDX files not in the referenced set ---
    foreach ($dir in $storageDirs) {
        if (-not (Test-Path $dir)) { continue }
        $onDisk = @(Get-ChildItem -LiteralPath $dir -Filter '*.avhdx' -Recurse -ErrorAction SilentlyContinue)
        foreach ($f in $onDisk) {
            if (-not $referencedAvhdx.Contains($f.FullName)) {
                $orphanRows.Add([PSCustomObject]@{
                    FilePath      = $f.FullName
                    SizeMB        = [math]::Round($f.Length / 1MB, 1)
                    LastWriteTime = $f.LastWriteTime
                })
                Add-Finding -Section "Checkpoint State" -Severity "WARNING" -Message "Orphaned AVHDX on disk: $($f.FullName) ($([math]::Round($f.Length / 1MB, 1)) MB)"
            }
        }
    }

    [PSCustomObject]@{
        Checkpoints    = $checkpointRows
        OrphanedAvhdx  = $orphanRows
        AllAvhdxPaths  = $allAvhdxPaths
        StorageDirs    = $storageDirs
    }
}

function Get-RctStatus {
    <# Checks VM config version and RCT/MRT file presence per VHDX. Veeam CBT requires version >= 8.0 and valid RCT files. #>

    $rows = [System.Collections.Generic.List[PSCustomObject]]::new()

    $vms = Get-VM -ErrorAction Stop
    foreach ($vm in $vms) {
        # Version is a string like "9.0" — compare as [version] for reliability
        $vmVer = $null
        try { $vmVer = [version]$vm.Version } catch { }
        $rctSupported = ($vmVer -and $vmVer -ge [version]"8.0")

        $disks = @(Get-VMHardDiskDrive -VMName $vm.Name -ErrorAction SilentlyContinue)
        foreach ($disk in $disks) {
            # RCT and MRT files sit alongside the VHDX with the same base name
            $dir      = [System.IO.Path]::GetDirectoryName($disk.Path)
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($disk.Path)
            $rctPath  = Join-Path $dir "$baseName.rct"
            $mrtPath  = Join-Path $dir "$baseName.mrt"
            $rctExists = Test-Path $rctPath
            $mrtExists = Test-Path $mrtPath

            if ($rctSupported -and -not $rctExists) {
                Add-Finding -Section "RCT Status" -Severity "WARNING" -Message "VM '$($vm.Name)': RCT file missing for $($disk.Path) — Veeam cannot use CBT for this disk"
            }
            if (-not $rctSupported) {
                Add-Finding -Section "RCT Status" -Severity "WARNING" -Message "VM '$($vm.Name)': config version $($vm.Version) is below 8.0 — RCT/CBT not supported"
            }

            $rows.Add([PSCustomObject]@{
                VMName       = $vm.Name
                VMVersion    = $vm.Version
                RctSupported = $rctSupported
                DiskPath     = $disk.Path
                RctExists    = $rctExists
                MrtExists    = $mrtExists
            })
        }
    }

    $rows
}

function Get-ReplicaStatus {
    <# Hyper-V Replica is a prime suspect for file lock contention with Veeam — both create checkpoints and invoke VSS. #>

    $rows = [System.Collections.Generic.List[PSCustomObject]]::new()

    $replications = @(Get-VMReplication -ErrorAction SilentlyContinue)
    if ($replications.Count -eq 0) {
        Write-Log "No Hyper-V Replica relationships found on this host"
        return $rows
    }

    foreach ($r in $replications) {
        if ($r.ReplicationMode -ne "None") {
            Add-Finding -Section "Hyper-V Replica" -Severity "WARNING" -Message "VM '$($r.VMName)': Hyper-V Replica is active (mode: $($r.ReplicationMode)) — potential VSS/checkpoint contention with Veeam"
        }
        if ($r.ReplicationHealth -notin @("Normal", "NotApplicable")) {
            Add-Finding -Section "Hyper-V Replica" -Severity "ERROR" -Message "VM '$($r.VMName)': replication health is $($r.ReplicationHealth) — state: $($r.ReplicationState)"
        }

        $rows.Add([PSCustomObject]@{
            VMName              = $r.VMName
            ReplicationMode     = $r.ReplicationMode
            ReplicationState    = $r.ReplicationState
            ReplicationHealth   = $r.ReplicationHealth
            FrequencySec        = $r.ReplicationFrequencySec
            LastReplicationTime = $r.LastReplicationTime
            PrimaryServer       = $r.PrimaryServerName
            ReplicaServer       = $r.ReplicaServerName
        })
    }

    $rows
}

function Get-VssWriterStatus {
    <# VSS writer failures block Veeam's application-consistent snapshot creation. vssadmin output is English-locale dependent. #>

    $rows = [System.Collections.Generic.List[PSCustomObject]]::new()

    $output = & vssadmin list writers 2>&1
    $text   = $output -join "`n"

    # Split on writer blocks — each block starts with "Writer name:"
    $blocks = ($text -split '(?m)^Writer name:') | Where-Object { $_.Trim() }

    foreach ($block in $blocks) {
        $writerName = if ($block -match "^\s*'([^']+)'") { $matches[1] } else { "Unknown" }
        $writerId   = if ($block -match "Writer Id:\s+(\{[^}]+\})") { $matches[1] } else { "" }
        $stateId    = if ($block -match "State:\s+\[(\d+)\]") { [int]$matches[1] } else { -1 }
        $stateDesc  = if ($block -match "State:\s+\[\d+\]\s+(.+)") { $matches[1].Trim() } else { "Unknown" }
        $lastError  = if ($block -match "Last error:\s+(.+)") { $matches[1].Trim() } else { "No error" }

        # State 1 = Stable (healthy). All other states warrant investigation.
        $isHealthy  = ($stateId -eq 1)

        if (-not $isHealthy) {
            $sev = if ($stateId -in @(2, 8)) { "ERROR" } else { "WARNING" }
            Add-Finding -Section "VSS Writers" -Severity $sev -Message "VSS writer '$writerName' is in state [$stateId] $stateDesc (Last error: $lastError)"
        }

        $rows.Add([PSCustomObject]@{
            WriterName  = $writerName
            WriterId    = $writerId
            StateId     = $stateId
            State       = $stateDesc
            LastError   = $lastError
            IsHealthy   = $isHealthy
        })
    }

    $rows
}

function Get-FileLockStatus {
    <# Tests each AVHDX for file locks and recent write activity. Handle.exe used if present, but never downloaded. #>
    param(
        [System.Collections.Generic.List[string]]$AvhdxPaths,
        [int]$RecentWriteMinutes
    )

    $rows = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($AvhdxPaths.Count -eq 0) {
        Write-Log "No AVHDX files found — skipping file lock detection"
        return $rows
    }

    # Locate handle.exe — search configured paths then PATH
    $handleExe = $null
    foreach ($searchDir in $Config.HandleSearchPaths) {
        foreach ($name in @("handle64.exe", "handle.exe")) {
            $candidate = Join-Path $searchDir $name
            if (Test-Path $candidate) { $handleExe = $candidate; break }
        }
        if ($handleExe) { break }
    }
    if (-not $handleExe) {
        $cmd = Get-Command handle64.exe -ErrorAction SilentlyContinue
        if (-not $cmd) { $cmd = Get-Command handle.exe -ErrorAction SilentlyContinue }
        if ($cmd) { $handleExe = $cmd.Source }
    }

    if ($handleExe) {
        Write-Log "Found Handle.exe at: $handleExe"
    } else {
        Write-Log "Handle.exe not found — lock detection will report locked/not-locked but cannot identify the holding process" -Level WARNING
        Add-Finding -Section "File Locks" -Severity "INFO" -Message "Sysinternals Handle.exe not found on this host. Download from https://learn.microsoft.com/en-us/sysinternals/downloads/handle and place in C:\Sysinternals\ for process-level lock identification."
    }

    $now = Get-Date
    foreach ($path in $AvhdxPaths) {
        if (-not (Test-Path $path)) { continue }

        $fi           = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
        $recentWrite  = $fi -and (($now - $fi.LastWriteTime).TotalMinutes -lt $RecentWriteMinutes)
        $isLocked     = $false
        $lockDetail   = $null
        $fileStream   = $null

        try {
            # Requesting Read access with no FileShare (None) will fail if any process holds an exclusive lock.
            # Using FileShare.Read to detect exclusive locks held by writers (vmwp, Veeam agent, etc.)
            $fileStream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        } catch [System.IO.IOException] {
            $isLocked = $true
        } catch {
            $isLocked = $true
        } finally {
            if ($fileStream) { $fileStream.Close(); $fileStream.Dispose() }
        }

        # If locked and Handle.exe is available, identify the holding process
        if ($isLocked -and $handleExe) {
            try {
                $handleOutput = & $handleExe -accepteula -nobanner $path 2>&1
                $lockDetail = ($handleOutput | Where-Object { $_ -match [regex]::Escape($path) }) -join "; "
            } catch {
                $lockDetail = "Handle.exe query failed: $_"
            }
        }

        if ($isLocked) {
            $detail = if ($lockDetail) { " — Process: $lockDetail" } else { " — Run Handle.exe for process details" }
            Add-Finding -Section "File Locks" -Severity "ERROR" -Message "AVHDX is locked: $path$detail"
        }
        if ($recentWrite) {
            Add-Finding -Section "File Locks" -Severity "WARNING" -Message "AVHDX was written within the last $RecentWriteMinutes minutes: $path (LastWrite: $($fi.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')))"
        }

        $rows.Add([PSCustomObject]@{
            FilePath         = $path
            IsLocked         = $isLocked
            LockDetail       = $lockDetail
            RecentlyWritten  = $recentWrite
            LastWriteTime    = if ($fi) { $fi.LastWriteTime } else { $null }
            SizeMB           = if ($fi) { [math]::Round($fi.Length / 1MB, 1) } else { 0 }
        })
    }

    $rows
}

function Get-VeeamStatus {
    <# Veeam console is on a separate VBR server — this section will almost always report not available. #>

    $veeamAvailable = $false
    $message        = ""

    # Try the modern module name first (Veeam 11+), fall back to the legacy PSSnapin
    try {
        Import-Module Veeam.Backup.PowerShell -ErrorAction Stop
        $veeamAvailable = $true
        Write-Log "Veeam PowerShell module loaded successfully"
    } catch {
        try {
            Add-PSSnapin VeeamPSSnapIn -ErrorAction Stop
            $veeamAvailable = $true
            Write-Log "Veeam PSSnapin loaded successfully"
        } catch {
            $message = "Veeam Backup & Replication console is not installed on this host (expected — VBR runs on a separate server)."
            Write-Log $message
            Add-Finding -Section "Veeam" -Severity "INFO" -Message "$message For Veeam-side diagnostics, run from the VBR server: Get-VBRBackupSession, Get-VBRHvProxy, and review job logs for this host."
        }
    }

    $sessionRows = [System.Collections.Generic.List[PSCustomObject]]::new()
    $proxyRows   = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($veeamAvailable) {
        try {
            $cutoff  = (Get-Date).AddHours(-$Config.EventLogHours)
            $sessions = @(Get-VBRBackupSession -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -ge $cutoff })
            foreach ($s in $sessions) {
                if ($s.Result -in @("Failed", "Warning")) {
                    Add-Finding -Section "Veeam" -Severity "WARNING" -Message "Veeam job '$($s.JobName)' ended with $($s.Result) at $($s.EndTime)"
                }
                $sessionRows.Add([PSCustomObject]@{
                    JobName      = $s.JobName
                    Result       = $s.Result
                    CreationTime = $s.CreationTime
                    EndTime      = $s.EndTime
                })
            }
        } catch {
            Write-Log "Could not query Veeam backup sessions: $_" -Level WARNING
        }

        try {
            $proxies = @(Get-VBRHvProxy -ErrorAction SilentlyContinue)
            foreach ($p in $proxies) {
                $proxyRows.Add([PSCustomObject]@{
                    Name      = $p.Name
                    Host      = if ($p.Host) { $p.Host.Name } else { "N/A" }
                    Mode      = $p.Mode
                    MaxTasks  = $p.MaxTasksCount
                    Disabled  = $p.IsDisabled
                })
            }
        } catch {
            Write-Log "Could not query Veeam Hyper-V proxies: $_" -Level WARNING
        }
    }

    [PSCustomObject]@{
        Available = $veeamAvailable
        Message   = $message
        Sessions  = $sessionRows
        Proxies   = $proxyRows
    }
}

function Get-PermissionStatus {
    <# Missing SeServiceLogonRight for NT VIRTUAL MACHINE is a known cause of stuck checkpoint merges on Server 2019. #>
    param(
        [System.Collections.Generic.HashSet[string]]$StorageDirs
    )

    $logonRightOk = $null
    $aclRows      = [System.Collections.Generic.List[PSCustomObject]]::new()

    # --- Check SeServiceLogonRight via secedit export ---
    # S-1-5-83-0 = NT VIRTUAL MACHINE\Virtual Machines (local SID, Hyper-V host only)
    $tempFile = Join-Path $env:TEMP "hvdiag_secedit_$([guid]::NewGuid().ToString('N')).inf"
    try {
        $null = & secedit /export /cfg $tempFile /areas USER_RIGHTS 2>&1
        if (Test-Path $tempFile) {
            $secContent = Get-Content $tempFile -Raw -Encoding Unicode -ErrorAction Stop
            $line = ($secContent -split "`n") | Where-Object { $_ -match 'SeServiceLogonRight' } | Select-Object -First 1
            if ($line) {
                $logonRightOk = $line -match '\*S-1-5-83-0'
                if (-not $logonRightOk) {
                    Add-Finding -Section "Permissions" -Severity "WARNING" -Message "NT VIRTUAL MACHINE\Virtual Machines (S-1-5-83-0) does not have SeServiceLogonRight — this causes checkpoint merge failures on Server 2019 (often caused by GPO overwriting local policy)"
                }
            } else {
                Write-Log "SeServiceLogonRight line not found in secedit output" -Level WARNING
                Add-Finding -Section "Permissions" -Severity "WARNING" -Message "Could not locate SeServiceLogonRight in secedit output — verify manually via secpol.msc > Local Policies > User Rights Assignment"
            }
        }
    } catch {
        Write-Log "secedit export failed: $_" -Level WARNING
        Add-Finding -Section "Permissions" -Severity "WARNING" -Message "secedit export failed — could not check SeServiceLogonRight: $_"
    } finally {
        if (Test-Path $tempFile) { Remove-Item $tempFile -Force -ErrorAction SilentlyContinue }
    }

    # --- Check NTFS permissions on VM storage directories ---
    foreach ($dir in $StorageDirs) {
        if (-not (Test-Path $dir)) { continue }
        try {
            $acl = Get-Acl -LiteralPath $dir -ErrorAction Stop
            $hvSidFound = $false
            foreach ($ace in $acl.Access) {
                # The SID may appear as "NT VIRTUAL MACHINE\Virtual Machines" or as the raw SID string
                $id = $ace.IdentityReference.ToString()
                if ($id -match 'S-1-5-83-0' -or $id -match 'Virtual Machines') {
                    $hvSidFound = $true; break
                }
                # Translate SID if it wasn't resolved to a name
                try {
                    $sid = New-Object System.Security.Principal.NTAccount($id)
                    $resolved = $sid.Translate([System.Security.Principal.SecurityIdentifier])
                    if ($resolved.Value -eq 'S-1-5-83-0') { $hvSidFound = $true; break }
                } catch { }
            }
            if (-not $hvSidFound) {
                Add-Finding -Section "Permissions" -Severity "WARNING" -Message "Storage path '$dir' does not grant explicit access to NT VIRTUAL MACHINE\Virtual Machines — may cause VHDX access failures"
            }
            $aclRows.Add([PSCustomObject]@{
                Path          = $dir
                HvSidPresent  = $hvSidFound
            })
        } catch {
            Write-Log "Get-Acl failed for '$dir': $_" -Level WARNING
        }
    }

    [PSCustomObject]@{
        SeServiceLogonRightOk = $logonRightOk
        AclResults            = $aclRows
    }
}

function Get-RelevantEvents {
    <# Pulls Hyper-V, VSS, and storage events from the last N hours to surface errors concurrent with backup failures. #>
    param([int]$Hours)

    $rows      = [System.Collections.Generic.List[PSCustomObject]]::new()
    $startTime = (Get-Date).AddHours(-$Hours)

    $queries = @(
        @{
            Label    = "Hyper-V VMMS Admin"
            Filter   = @{ LogName = 'Microsoft-Windows-Hyper-V-VMMS-Admin'; StartTime = $startTime; Id = $Config.VmmsEventIds }
        },
        @{
            Label    = "Hyper-V Worker Admin"
            Filter   = @{ LogName = 'Microsoft-Windows-Hyper-V-Worker-Admin'; StartTime = $startTime; Level = @(1, 2, 3) }
        },
        @{
            Label    = "VSS (Application log)"
            Filter   = @{ LogName = 'Application'; StartTime = $startTime; ProviderName = 'VSS' }
        },
        @{
            Label    = "Storage I/O (System log)"
            Filter   = @{ LogName = 'System'; StartTime = $startTime; Id = $Config.StorageEventIds }
        }
    )

    foreach ($q in $queries) {
        try {
            $events = @(Get-WinEvent -FilterHashtable $q.Filter -MaxEvents 50 -ErrorAction Stop)
            Write-Log "$($q.Label): $($events.Count) matching event(s)"
            foreach ($e in $events) {
                $levelName = switch ($e.Level) { 1 { "Critical" } 2 { "Error" } 3 { "Warning" } default { "Information" } }
                $shortMsg = ($e.Message -replace '\s+', ' ').Trim()
                if ($shortMsg.Length -gt 200) { $shortMsg = $shortMsg.Substring(0, 200) + '...' }
                if ($e.Level -le 2) {
                    Add-Finding -Section "Event Logs" -Severity "ERROR" -Message "[$($q.Label)] $levelName at $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')): ID $($e.Id) — $shortMsg"
                } elseif ($e.Level -eq 3) {
                    Add-Finding -Section "Event Logs" -Severity "WARNING" -Message "[$($q.Label)] Warning at $($e.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')): ID $($e.Id) — $shortMsg"
                }
                $rows.Add([PSCustomObject]@{
                    Source      = $q.Label
                    LogName     = $e.LogName
                    EventId     = $e.Id
                    Level       = $levelName
                    TimeCreated = $e.TimeCreated
                    Provider    = $e.ProviderName
                    Message     = ($e.Message -replace '\s+', ' ')
                })
            }
        } catch [System.Exception] {
            # No events matching the filter is reported as an exception by Get-WinEvent — treat as zero results
            if ($_.Exception.Message -notmatch 'No events were found') {
                Write-Log "$($q.Label): query failed — $_" -Level WARNING
            } else {
                Write-Log "$($q.Label): no matching events in the last $Hours hours"
            }
        }
    }

    $rows | Sort-Object TimeCreated -Descending
}


# --- Main ---

try {
    Write-Log "Starting $($Config.ScriptName) on $env:COMPUTERNAME"
    Write-Log "Event log lookback: $($Config.EventLogHours) hours | Output: $($Config.OutputDir)"

    # === SECTION 1: HOST OVERVIEW ===
    Write-Log "--- Section 1: Host Overview ---"
    $hostOverview = $null
    try {
        $hostOverview = Get-HostOverview
        Write-Log "Host: $($hostOverview.ComputerName) | OS: $($hostOverview.OSCaption) (Build $($hostOverview.OSBuild)) | Uptime: $($hostOverview.UptimeDays) days | Hyper-V: $($hostOverview.HyperVVersion)"
    } catch {
        Write-Log "Host overview failed: $_" -Level ERROR
        Add-Finding -Section "Host Overview" -Severity "ERROR" -Message "Section failed: $_"
    }

    # === SECTION 2: VM CHECKPOINT STATE ===
    Write-Log "--- Section 2: VM Checkpoint State ---"
    $checkpointData = $null
    try {
        $checkpointData = Get-VmCheckpointState
        Write-Log "Checkpoints: $($checkpointData.Checkpoints.Count) | Orphaned AVHDX: $($checkpointData.OrphanedAvhdx.Count) | AVHDX files tracked: $($checkpointData.AllAvhdxPaths.Count)"
    } catch {
        Write-Log "Checkpoint state collection failed: $_" -Level ERROR
        Add-Finding -Section "Checkpoint State" -Severity "ERROR" -Message "Section failed: $_"
        # Initialize empty collections so downstream sections don't crash
        $checkpointData = [PSCustomObject]@{
            Checkpoints   = [System.Collections.Generic.List[PSCustomObject]]::new()
            OrphanedAvhdx = [System.Collections.Generic.List[PSCustomObject]]::new()
            AllAvhdxPaths = [System.Collections.Generic.List[string]]::new()
            StorageDirs   = [System.Collections.Generic.HashSet[string]]::new()
        }
    }

    # === SECTION 3: RCT/CBT STATUS ===
    Write-Log "--- Section 3: RCT/CBT Status ---"
    $rctData = $null
    try {
        $rctData = Get-RctStatus
        $rctOk = @($rctData | Where-Object { $_.RctSupported -and $_.RctExists }).Count
        Write-Log "RCT check complete: $($rctData.Count) disks checked, $rctOk with valid RCT files"
    } catch {
        Write-Log "RCT status collection failed: $_" -Level ERROR
        Add-Finding -Section "RCT Status" -Severity "ERROR" -Message "Section failed: $_"
    }

    # === SECTION 4: HYPER-V REPLICA STATUS ===
    Write-Log "--- Section 4: Hyper-V Replica Status ---"
    $replicaData = $null
    try {
        $replicaData = Get-ReplicaStatus
        Write-Log "Replica relationships found: $($replicaData.Count)"
    } catch {
        Write-Log "Replica status collection failed: $_" -Level ERROR
        Add-Finding -Section "Hyper-V Replica" -Severity "ERROR" -Message "Section failed: $_"
    }

    # === SECTION 5: VSS WRITER STATE ===
    Write-Log "--- Section 5: VSS Writer State ---"
    $vssData = $null
    try {
        $vssData = Get-VssWriterStatus
        $vssUnhealthy = @($vssData | Where-Object { -not $_.IsHealthy }).Count
        Write-Log "VSS writers: $($vssData.Count) total, $vssUnhealthy unhealthy"
    } catch {
        Write-Log "VSS writer status collection failed: $_" -Level ERROR
        Add-Finding -Section "VSS Writers" -Severity "ERROR" -Message "Section failed: $_"
    }

    # === SECTION 6: FILE LOCK DETECTION ===
    Write-Log "--- Section 6: File Lock Detection ---"
    $lockData = $null
    try {
        $lockData = Get-FileLockStatus -AvhdxPaths $checkpointData.AllAvhdxPaths -RecentWriteMinutes $Config.RecentWriteMinutes
        $lockedCount = @($lockData | Where-Object { $_.IsLocked }).Count
        Write-Log "File lock check: $($lockData.Count) AVHDX files tested, $lockedCount locked"
    } catch {
        Write-Log "File lock detection failed: $_" -Level ERROR
        Add-Finding -Section "File Locks" -Severity "ERROR" -Message "Section failed: $_"
    }

    # === SECTION 7: VEEAM STATE ===
    Write-Log "--- Section 7: Veeam State ---"
    $veeamData = $null
    try {
        $veeamData = Get-VeeamStatus
    } catch {
        Write-Log "Veeam status collection failed: $_" -Level ERROR
        Add-Finding -Section "Veeam" -Severity "ERROR" -Message "Section failed: $_"
    }

    # === SECTION 8: PERMISSIONS CHECK ===
    Write-Log "--- Section 8: Permissions Check ---"
    $permData = $null
    try {
        # Merge storage dirs from host overview and checkpoint data
        $allStorageDirs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        if ($checkpointData.StorageDirs) {
            foreach ($d in $checkpointData.StorageDirs) { $null = $allStorageDirs.Add($d) }
        }
        if ($hostOverview -and $hostOverview.DefaultVhdPath) { $null = $allStorageDirs.Add($hostOverview.DefaultVhdPath) }
        if ($hostOverview -and $hostOverview.DefaultVmPath)  { $null = $allStorageDirs.Add($hostOverview.DefaultVmPath) }
        $permData = Get-PermissionStatus -StorageDirs $allStorageDirs
        Write-Log "Permissions check complete | SeServiceLogonRight OK: $($permData.SeServiceLogonRightOk) | Paths checked: $($permData.AclResults.Count)"
    } catch {
        Write-Log "Permissions check failed: $_" -Level ERROR
        Add-Finding -Section "Permissions" -Severity "ERROR" -Message "Section failed: $_"
    }

    # === SECTION 9: EVENT LOG EXTRACTION ===
    Write-Log "--- Section 9: Event Log Extraction ---"
    $eventData = $null
    try {
        $eventData = Get-RelevantEvents -Hours $Config.EventLogHours
        Write-Log "Event log extraction complete: $($eventData.Count) relevant events found"
    } catch {
        Write-Log "Event log extraction failed: $_" -Level ERROR
        Add-Finding -Section "Event Logs" -Severity "ERROR" -Message "Section failed: $_"
    }

    # --- Export findings CSV ---
    if (-not (Test-Path $Config.OutputDir)) { New-Item -ItemType Directory -Path $Config.OutputDir | Out-Null }
    $ts           = Get-Date -Format "yyyyMMdd_HHmmss"
    $findingsFile = Join-Path $Config.OutputDir ("HyperVDiag_{0}_{1}.csv" -f $env:COMPUTERNAME, $ts)
    $Script:Findings | Export-Csv -Path $findingsFile -NoTypeInformation -Encoding UTF8
    Write-Log "Exported $($Script:Findings.Count) finding(s) to $findingsFile"

    # --- Console summary ---

    $separator   = [string]::new([char]0x2550, 72)
    $divider     = [string]::new([char]0x2500, 72)
    $displayTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $errorCount  = @($Script:Findings | Where-Object { $_.Severity -eq "ERROR"   }).Count
    $warnCount   = @($Script:Findings | Where-Object { $_.Severity -eq "WARNING" }).Count
    $infoCount   = @($Script:Findings | Where-Object { $_.Severity -eq "INFO"    }).Count

    $osStr  = if ($hostOverview) { $hostOverview.OSCaption } else { "Unknown" }
    $hvStr  = if ($hostOverview) { $hostOverview.HyperVVersion } else { "Unknown" }
    $upStr  = if ($hostOverview) { "$($hostOverview.UptimeDays)d" } else { "?" }

    Write-Summary ""
    Write-Summary $separator                                                                           -Color Yellow
    Write-Summary "  Hyper-V Backup Diagnostic  —  $displayTime"                                      -Color Yellow
    Write-Summary "  Host: $env:COMPUTERNAME  |  OS: $osStr  |  Hyper-V: $hvStr  |  Uptime: $upStr"  -Color Yellow
    Write-Summary $separator                                                                           -Color Yellow
    Write-Summary ""

    # DISK SPACE
    if ($hostOverview -and $hostOverview.DiskSpace.Count -gt 0) {
        Write-Summary "  DISK SPACE"  -Color Cyan
        Write-Summary $divider        -Color Cyan
        foreach ($d in $hostOverview.DiskSpace) {
            $color = if ($d.IsLow) { "Red" } else { "Green" }
            $line  = "  {0,-8}  {1,6} GB free / {2,6} GB total  ({3,5}% free)" -f $d.Drive, $d.FreeGB, $d.TotalGB, $d.FreePct
            Write-Summary $line -Color $color
        }
        Write-Summary ""
    }

    # CHECKPOINTS
    if ($checkpointData -and $checkpointData.Checkpoints.Count -gt 0) {
        Write-Summary "  CHECKPOINTS ($($checkpointData.Checkpoints.Count))"  -Color Cyan
        Write-Summary $divider                                                  -Color Cyan
        foreach ($cp in $checkpointData.Checkpoints) {
            $color = if ($cp.AgeDays -gt $Config.CheckpointAgeWarnDays) { "Yellow" } else { "White" }
            $line  = "  {0,-30}  {1,-28}  {2,5} days  {3,-12}  {4,7} MB" -f $cp.VMName, $cp.CheckpointName, $cp.AgeDays, $cp.Type, $cp.SizeMB
            Write-Summary $line -Color $color
        }
        Write-Summary ""
    }

    # ORPHANED AVHDX
    if ($checkpointData -and $checkpointData.OrphanedAvhdx.Count -gt 0) {
        Write-Summary "  ORPHANED AVHDX FILES ($($checkpointData.OrphanedAvhdx.Count))"  -Color Cyan
        Write-Summary $divider                                                              -Color Cyan
        foreach ($o in $checkpointData.OrphanedAvhdx) {
            $line = "  {0}  ({1} MB, last write: {2})" -f $o.FilePath, $o.SizeMB, $o.LastWriteTime.ToString('yyyy-MM-dd HH:mm')
            Write-Summary $line -Color Red
        }
        Write-Summary ""
    }

    # RCT/CBT STATUS
    if ($rctData -and $rctData.Count -gt 0) {
        Write-Summary "  RCT/CBT STATUS"  -Color Cyan
        Write-Summary $divider             -Color Cyan
        $rctByVm = $rctData | Group-Object VMName
        foreach ($g in $rctByVm) {
            $disksOk      = @($g.Group | Where-Object { $_.RctSupported -and $_.RctExists }).Count
            $disksMissing = @($g.Group | Where-Object { $_.RctSupported -and -not $_.RctExists }).Count
            $disksUnsup   = @($g.Group | Where-Object { -not $_.RctSupported }).Count
            $ver          = ($g.Group | Select-Object -First 1).VMVersion
            if ($disksMissing -gt 0) {
                $color = "Red"; $status = "RCT MISSING ($disksMissing disk(s))"
            } elseif ($disksUnsup -gt 0) {
                $color = "Yellow"; $status = "Version $ver < 8.0 — RCT unsupported"
            } else {
                $color = "Green"; $status = "OK ($disksOk disk(s) with RCT)"
            }
            $line = "  {0,-35}  ver {1,-6}  {2}" -f $g.Name, $ver, $status
            Write-Summary $line -Color $color
        }
        Write-Summary ""
    }

    # HYPER-V REPLICA
    if ($replicaData -and $replicaData.Count -gt 0) {
        Write-Summary "  HYPER-V REPLICA ($($replicaData.Count) relationship(s))"  -Color Cyan
        Write-Summary $divider                                                        -Color Cyan
        foreach ($r in $replicaData) {
            $color = if ($r.ReplicationHealth -notin @("Normal", "NotApplicable")) { "Red" } else { "Yellow" }
            $line  = "  {0,-30}  mode: {1,-10}  health: {2,-10}  state: {3}" -f $r.VMName, $r.ReplicationMode, $r.ReplicationHealth, $r.ReplicationState
            Write-Summary $line -Color $color
        }
        Write-Summary ""
    }

    # VSS WRITERS
    if ($vssData -and $vssData.Count -gt 0) {
        # Only show the full table when there are issues; always show a summary line
        $unhealthyWriters = @($vssData | Where-Object { -not $_.IsHealthy })
        if ($unhealthyWriters.Count -gt 0) {
            Write-Summary "  VSS WRITERS — UNHEALTHY ($($unhealthyWriters.Count))"  -Color Cyan
            Write-Summary $divider                                                     -Color Cyan
            foreach ($w in $unhealthyWriters) {
                $color = if ($w.StateId -in @(2, 8)) { "Red" } else { "Yellow" }
                $line  = "  {0,-40}  [{1}] {2}  (Last error: {3})" -f $w.WriterName, $w.StateId, $w.State, $w.LastError
                Write-Summary $line -Color $color
            }
        } else {
            Write-Summary "  VSS WRITERS"                                   -Color Cyan
            Write-Summary $divider                                           -Color Cyan
            Write-Summary "  All $($vssData.Count) VSS writers are stable"  -Color Green
        }
        # Always call out Hyper-V VSS Writer specifically
        $hvWriter = $vssData | Where-Object { $_.WriterName -match 'Hyper-V' } | Select-Object -First 1
        if ($hvWriter) {
            $color = if ($hvWriter.IsHealthy) { "Green" } else { "Red" }
            Write-Summary ("  Microsoft Hyper-V VSS Writer: [{0}] {1}" -f $hvWriter.StateId, $hvWriter.State)  -Color $color
        }
        Write-Summary ""
    }

    # LOCKED FILES
    if ($lockData -and $lockData.Count -gt 0) {
        $lockedFiles = @($lockData | Where-Object { $_.IsLocked })
        $recentFiles = @($lockData | Where-Object { $_.RecentlyWritten })
        if ($lockedFiles.Count -gt 0) {
            Write-Summary "  LOCKED AVHDX FILES ($($lockedFiles.Count))"  -Color Cyan
            Write-Summary $divider                                          -Color Cyan
            foreach ($lf in $lockedFiles) {
                $proc = if ($lf.LockDetail) { " — $($lf.LockDetail)" } else { "" }
                Write-Summary "  $($lf.FilePath)$proc"  -Color Red
            }
            Write-Summary ""
        }
        if ($recentFiles.Count -gt 0) {
            Write-Summary "  RECENTLY WRITTEN AVHDX ($($recentFiles.Count))"  -Color Cyan
            Write-Summary $divider                                               -Color Cyan
            foreach ($rf in $recentFiles) {
                Write-Summary "  $($rf.FilePath)  (last write: $($rf.LastWriteTime.ToString('HH:mm:ss')))"  -Color Yellow
            }
            Write-Summary ""
        }
    }

    # PERMISSIONS
    if ($permData) {
        Write-Summary "  PERMISSIONS"  -Color Cyan
        Write-Summary $divider          -Color Cyan
        $logonColor  = if ($permData.SeServiceLogonRightOk -eq $true) { "Green" } elseif ($permData.SeServiceLogonRightOk -eq $false) { "Red" } else { "Yellow" }
        $logonStatus = if ($permData.SeServiceLogonRightOk -eq $true) { "OK" } elseif ($permData.SeServiceLogonRightOk -eq $false) { "MISSING — fix via secpol.msc or GPO" } else { "Unknown (secedit failed)" }
        Write-Summary "  SeServiceLogonRight (NT VIRTUAL MACHINE): $logonStatus"  -Color $logonColor
        $aclIssues = @($permData.AclResults | Where-Object { -not $_.HvSidPresent })
        if ($aclIssues.Count -gt 0) {
            foreach ($ai in $aclIssues) {
                Write-Summary "  NTFS: NT VIRTUAL MACHINE SID missing on: $($ai.Path)"  -Color Yellow
            }
        }
        Write-Summary ""
    }

    # RECENT EVENTS
    if ($eventData -and $eventData.Count -gt 0) {
        Write-Summary "  RECENT EVENTS ($($eventData.Count) in last $($Config.EventLogHours)h)"  -Color Cyan
        Write-Summary $divider                                                                      -Color Cyan
        $eventsBySource = $eventData | Group-Object Source
        foreach ($eg in $eventsBySource) {
            $errs  = @($eg.Group | Where-Object { $_.Level -in @("Critical","Error")   }).Count
            $warns = @($eg.Group | Where-Object { $_.Level -eq "Warning" }).Count
            $color = if ($errs -gt 0) { "Red" } elseif ($warns -gt 0) { "Yellow" } else { "White" }
            $line  = "  {0,-35}  errors: {1,3}  warnings: {2,3}" -f $eg.Name, $errs, $warns
            Write-Summary $line -Color $color
        }
        # Show the 5 most recent error-level events inline
        $topErrors = @($eventData | Where-Object { $_.Level -in @("Critical","Error") } | Select-Object -First 5)
        if ($topErrors.Count -gt 0) {
            Write-Summary ""
            Write-Summary "  TOP ERRORS"  -Color Cyan
            Write-Summary $divider         -Color Cyan
            foreach ($e in $topErrors) {
                $msg = if ($e.Message.Length -gt 120) { $e.Message.Substring(0,120) + "..." } else { $e.Message }
                Write-Summary "  [$($e.TimeCreated.ToString('MM-dd HH:mm'))] $($e.Source) ID $($e.EventId): $msg"  -Color Red
            }
        }
        Write-Summary ""
    }

    # FINDINGS TOTALS
    Write-Summary $separator  -Color Cyan
    $totalColor = if ($errorCount -gt 0) { "Red" } elseif ($warnCount -gt 0) { "Yellow" } else { "Green" }
    Write-Summary ("  FINDINGS: {0} error(s)  |  {1} warning(s)  |  {2} info" -f $errorCount, $warnCount, $infoCount)  -Color $totalColor
    Write-Summary "  Log:      $Script:LogFile"  -Color Cyan
    Write-Summary "  Findings: $findingsFile"    -Color Cyan
    Write-Summary $separator  -Color Cyan
    Write-Summary ""

    Write-Log "Completed $($Config.ScriptName) — $errorCount error(s), $warnCount warning(s)"
    $hasIssues = ($errorCount -gt 0 -or $warnCount -gt 0)
    if ($hasIssues) { exit 1 } else { exit 0 }
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    exit 1
}
