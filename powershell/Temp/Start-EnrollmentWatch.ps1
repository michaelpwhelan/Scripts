# ============================================================================
# EnrollmentWatch.ps1
# 
# Unattended overnight Intune enrollment monitor and auto-retry script.
# Designed for a device with broken/incomplete MDM enrollment that needs
# to re-register with Intune and receive the Intune Management Extension.
#
# What it does:
#   - Checks every 30 minutes (configurable) for up to 6 cycles (3 hours)
#   - Looks for EnterpriseMgmt scheduled tasks (the heartbeat of MDM enrollment)
#   - If tasks exist, kicks an OMA-DM sync and checks for IME
#   - If tasks don't exist, retries enrollment via deviceenroller.exe
#   - Logs everything to C:\EnrollmentWatch.log with timestamps
#   - Stops early if IME is detected (success condition)
#
# How to run:
#   1. Open an elevated PowerShell window on the target device
#   2. powershell -ExecutionPolicy Bypass -File C:\EnrollmentWatch.ps1
#   3. Leave the machine on and go home
#   4. Check C:\EnrollmentWatch.log in the morning
#
# Requirements:
#   - Must run as administrator (enrollment and service checks need elevation)
#   - Device must stay powered on and network-connected
#   - MmpcEnrollmentFlag should already be set to 0 before running
#   - Any stale MDE-only device records should be deleted from Intune first
#
# Notes:
#   - This script does NOT reboot the machine
#   - This script does NOT modify registry keys (it only reads them for logging)
#   - The only active change it makes is calling deviceenroller.exe if tasks
#     are missing, and starting scheduled tasks if they exist
#   - Safe to run multiple times; it won't create duplicate enrollments
# ============================================================================

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# where to write the log file
$logFile = "C:\EnrollmentWatch.log"

# how many check cycles to run before giving up
$maxAttempts = 6

# how long to wait between check cycles (in seconds)
# 1800 seconds = 30 minutes
# 6 cycles x 30 minutes = 3 hours total runtime
$sleepBetweenChecks = 1800

# how long to wait after kicking a sync before checking for IME (in seconds)
# IME deployment can take a few minutes after a successful sync
$sleepAfterSync = 60

# how long to wait after attempting enrollment before checking for tasks (in seconds)
$sleepAfterEnroll = 30

# ---------------------------------------------------------------------------
# Logging function
# ---------------------------------------------------------------------------

function Write-Log {
    <#
    .SYNOPSIS
        Writes a timestamped message to both the console and the log file.
    .PARAMETER Message
        The message to log.
    #>
    param(
        [string]$Message
    )

    # build the timestamped log line
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "$timestamp - $Message"

    # write to console and append to log file simultaneously
    $logLine | Tee-Object -FilePath $logFile -Append
}

# ---------------------------------------------------------------------------
# Helper: Log the current enrollment registry state
# ---------------------------------------------------------------------------

function Write-EnrollmentState {
    <#
    .SYNOPSIS
        Reads all enrollment subkeys under HKLM:\SOFTWARE\Microsoft\Enrollments
        and logs the ones that have an EnrollmentType (filters out noise).
        This helps track whether enrollment GUIDs are being created/removed
        between check cycles.
    #>

    $enrollments = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments" -ErrorAction SilentlyContinue

    if (-not $enrollments) {
        Write-Log "  [REGISTRY] No enrollment subkeys found (Enrollments folder may be empty)"
        return
    }

    foreach ($enrollment in $enrollments) {
        $props = Get-ItemProperty $enrollment.PSPath -ErrorAction SilentlyContinue

        # only log entries that have an EnrollmentType - these are actual enrollments
        # (as opposed to the Status, Ownership, ValidNodePaths, and Context subkeys)
        if ($props.EnrollmentType) {
            # EnrollmentType reference:
            #   2  = MDM auto-enrollment (GPO/deviceenroller) -- this is what we want
            #   18 = Azure AD join enrollment
            #   32 = device credential enrollment
            #
            # EnrollmentState reference:
            #   1  = Enrolled (good)
            #   0  = Not enrolled / pending

            $guid = $enrollment.PSChildName
            $type = $props.EnrollmentType
            $state = $props.EnrollmentState
            $upn = $props.UPN
            $provider = $props.ProviderID

            Write-Log "  [REGISTRY] GUID=$guid | Type=$type | State=$state | UPN=$upn | Provider=$provider"
        }
    }
}

# ---------------------------------------------------------------------------
# Helper: Log recent MDM diagnostic events
# ---------------------------------------------------------------------------

function Write-RecentMdmEvents {
    <#
    .SYNOPSIS
        Pulls the most recent events from the MDM enterprise diagnostics log.
        These events show whether the OMA-DM client is actually communicating
        with Intune, and if not, what errors it's throwing.
    .PARAMETER Count
        Number of recent events to retrieve. Default 5.
    #>
    param(
        [int]$Count = 5
    )

    $logName = "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin"

    $events = Get-WinEvent -LogName $logName -MaxEvents $Count -ErrorAction SilentlyContinue

    if (-not $events) {
        Write-Log "  [EVENTS] No events found in MDM diagnostics log"
        return
    }

    foreach ($event in $events) {
        # truncate the message to keep the log readable
        # full messages can be hundreds of characters
        $maxLen = 150
        $msg = $event.Message
        if ($msg.Length -gt $maxLen) {
            $msg = $msg.Substring(0, $maxLen) + "..."
        }

        Write-Log "  [EVENTS] $($event.TimeCreated) | ID=$($event.Id) | Level=$($event.LevelDisplayName) | $msg"
    }
}

# ---------------------------------------------------------------------------
# Helper: Check for the Intune Management Extension service
# ---------------------------------------------------------------------------

function Test-IMEInstalled {
    <#
    .SYNOPSIS
        Checks whether the IntuneManagementExtension service exists.
        This is the success condition - if IME is installed, the enrollment
        pipeline is fully working and apps can be deployed.
    .OUTPUTS
        Returns $true if the service exists, $false otherwise.
    #>

    $service = Get-Service "IntuneManagementExtension" -ErrorAction SilentlyContinue

    if ($service) {
        Write-Log "  [IME] SERVICE FOUND - Status: $($service.Status) | StartType: $($service.StartType)"
        return $true
    }
    else {
        Write-Log "  [IME] Service not present"
        return $false
    }
}

# ---------------------------------------------------------------------------
# Helper: Check for EnterpriseMgmt scheduled tasks
# ---------------------------------------------------------------------------

function Get-MdmScheduledTasks {
    <#
    .SYNOPSIS
        Retrieves scheduled tasks under the EnterpriseMgmt path.
        These tasks are created by the MDM enrollment process and are
        responsible for periodic OMA-DM check-ins with Intune.
        Their existence confirms that enrollment is alive and functional.
    .OUTPUTS
        Returns the collection of matching scheduled tasks (may be empty).
    #>

    $tasks = Get-ScheduledTask | Where-Object { $_.TaskPath -like "*EnterpriseMgmt*" }
    return $tasks
}

# ---------------------------------------------------------------------------
# Helper: Attempt to kick an OMA-DM sync
# ---------------------------------------------------------------------------

function Start-MdmSync {
    <#
    .SYNOPSIS
        Finds and starts the OMA-DM client scheduled tasks, which triggers
        an immediate check-in with Intune. This is the equivalent of hitting
        "Sync" in the Company Portal or Intune admin center.
    #>

    $syncTasks = Get-ScheduledTask |
        Where-Object { $_.TaskPath -like "*EnterpriseMgmt*" } |
        Where-Object { $_.TaskName -like "*OmaDMClient*" }

    if ($syncTasks) {
        Write-Log "  [SYNC] Found $($syncTasks.Count) OmaDMClient task(s). Starting sync..."

        foreach ($task in $syncTasks) {
            try {
                Start-ScheduledTask -InputObject $task
                Write-Log "  [SYNC] Started task: $($task.TaskName)"
            }
            catch {
                Write-Log "  [SYNC] ERROR starting task $($task.TaskName): $($_.Exception.Message)"
            }
        }
    }
    else {
        Write-Log "  [SYNC] No OmaDMClient tasks found to start"
    }
}

# ---------------------------------------------------------------------------
# Helper: Attempt MDM enrollment via deviceenroller.exe
# ---------------------------------------------------------------------------

function Start-MdmEnrollment {
    <#
    .SYNOPSIS
        Calls deviceenroller.exe /c /AutoEnrollMDM to trigger a fresh
        MDM auto-enrollment. This is the same mechanism that the GPO
        auto-enrollment scheduled task uses.

        Safe to call multiple times - if enrollment already exists,
        it will either no-op or refresh the existing enrollment.
    #>

    Write-Log "  [ENROLL] Running deviceenroller.exe /c /AutoEnrollMDM..."

    try {
        $process = Start-Process "deviceenroller.exe" -ArgumentList "/c /AutoEnrollMDM" -Wait -PassThru -NoNewWindow
        Write-Log "  [ENROLL] deviceenroller.exe exited with code: $($process.ExitCode)"
    }
    catch {
        Write-Log "  [ENROLL] ERROR running deviceenroller.exe: $($_.Exception.Message)"
    }
}

# ============================================================================
# Main loop
# ============================================================================

Write-Log "========================================================"
Write-Log "=== Enrollment monitor started ==="
Write-Log "=== Max attempts: $maxAttempts ==="
Write-Log "=== Sleep between checks: $($sleepBetweenChecks / 60) minutes ==="
Write-Log "========================================================"

# --- Pre-flight checks ---

# log the current MmpcEnrollmentFlag value
# this should be 0; if it's 2, MDE-only enrollment is blocking real MDM enrollment
$flag = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Enrollments" -Name MmpcEnrollmentFlag -ErrorAction SilentlyContinue).MmpcEnrollmentFlag
Write-Log "[PREFLIGHT] MmpcEnrollmentFlag: $flag"

if ($flag -eq 2) {
    Write-Log "[PREFLIGHT] WARNING: MmpcEnrollmentFlag is 2 (MDE blocking enrollment). This should have been set to 0 before running this script."
}

# log the current Azure AD join state
# AzureAdPrt should be YES for enrollment to work
$dsregOutput = dsregcmd /status 2>&1
$prtLine = $dsregOutput | Select-String "AzureAdPrt "
$joinedLine = $dsregOutput | Select-String "AzureAdJoined "
$domainLine = $dsregOutput | Select-String "DomainJoined "
$mdmUrlLine = $dsregOutput | Select-String "MDMUrl "

Write-Log "[PREFLIGHT] $($joinedLine -replace '^\s+','')"
Write-Log "[PREFLIGHT] $($domainLine -replace '^\s+','')"
Write-Log "[PREFLIGHT] $($prtLine -replace '^\s+','')"
Write-Log "[PREFLIGHT] $($mdmUrlLine -replace '^\s+','')"

# log initial enrollment state
Write-Log "[PREFLIGHT] Current enrollment registry state:"
Write-EnrollmentState

Write-Log "========================================================"

# --- Main monitoring loop ---

$attempt = 0
$success = $false

while ($attempt -lt $maxAttempts) {
    $attempt++
    Write-Log ""
    Write-Log "========== CHECK $attempt of $maxAttempts =========="

    # ----- Step 1: Check if IME is already installed (maybe it came in between cycles) -----
    if (Test-IMEInstalled) {
        Write-Log "SUCCESS: IME is installed. Enrollment pipeline is fully functional."
        $success = $true
        break
    }

    # ----- Step 2: Check for EnterpriseMgmt scheduled tasks -----
    $tasks = Get-MdmScheduledTasks
    Write-Log "[TASKS] EnterpriseMgmt scheduled tasks found: $($tasks.Count)"

    if ($tasks -and $tasks.Count -gt 0) {
        # tasks exist = enrollment is alive, we just need to sync and wait for IME
        foreach ($t in $tasks) {
            Write-Log "  [TASKS] $($t.TaskPath)$($t.TaskName) | State=$($t.State)"
        }

        Write-Log "[ACTION] Tasks exist. Kicking OMA-DM sync and waiting $($sleepAfterSync / 60) minute(s) for IME..."
        Start-MdmSync
        Start-Sleep -Seconds $sleepAfterSync

        # check for IME after sync
        if (Test-IMEInstalled) {
            Write-Log "SUCCESS: IME appeared after sync. We're good."
            $success = $true
            break
        }
        else {
            Write-Log "[STATUS] IME still not present after sync. Will retry next cycle."
        }
    }
    else {
        # no tasks = enrollment isn't functional, try to enroll
        Write-Log "[ACTION] No tasks found. Attempting MDM enrollment..."
        Start-MdmEnrollment

        Write-Log "[ACTION] Waiting $sleepAfterEnroll seconds for enrollment to process..."
        Start-Sleep -Seconds $sleepAfterEnroll

        # check if tasks appeared after enrollment attempt
        $newTasks = Get-MdmScheduledTasks
        Write-Log "[RESULT] Post-enrollment EnterpriseMgmt tasks: $($newTasks.Count)"

        if ($newTasks -and $newTasks.Count -gt 0) {
            Write-Log "[RESULT] Tasks appeared! Enrollment is alive. Will kick sync next cycle."
        }
        else {
            Write-Log "[RESULT] Still no tasks after enrollment attempt."
        }
    }

    # ----- Step 3: Log current state for diagnostics -----
    Write-Log "[STATE] Enrollment registry:"
    Write-EnrollmentState

    Write-Log "[STATE] Recent MDM diagnostic events:"
    Write-RecentMdmEvents

    # ----- Step 4: Sleep until next check -----
    if ($attempt -lt $maxAttempts) {
        Write-Log "[WAIT] Sleeping $($sleepBetweenChecks / 60) minutes before next check..."
        Start-Sleep -Seconds $sleepBetweenChecks
    }
}

# --- Final summary ---

Write-Log ""
Write-Log "========================================================"
if ($success) {
    Write-Log "=== RESULT: SUCCESS - IME is installed ==="
    Write-Log "=== The enrollment pipeline is working. ==="
    Write-Log "=== Check Intune admin center for the device ==="
    Write-Log "=== with a primary user and proper enrollment. ==="
}
else {
    Write-Log "=== RESULT: IME did not appear after $maxAttempts attempts ==="
    Write-Log "=== Next steps to investigate: ==="
    Write-Log "===   1. Check C:\EnrollmentWatch.log for error patterns ==="
    Write-Log "===   2. Run dsregcmd /status and check AzureAdPrt ==="
    Write-Log "===   3. Check Intune admin center for device record ==="
    Write-Log "===   4. Verify Win32 app/script is assigned to device ==="
    Write-Log "===   5. Check AAD operational log: ==="
    Write-Log "===      Get-WinEvent 'Microsoft-Windows-AAD/Operational' ==="
    Write-Log "===   6. Consider full hybrid rejoin if all else fails ==="
}
Write-Log "=== Monitor finished at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ==="
Write-Log "========================================================"
