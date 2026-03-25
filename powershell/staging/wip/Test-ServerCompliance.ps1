<#
.SYNOPSIS
    Tests Windows servers against a security compliance baseline using PowerShell remoting.

.DESCRIPTION
    Connects to each target server via Invoke-Command and runs 10 security checks:
    SMB signing, Credential Guard, TLS 1.0/1.1 disabled, NTLMv1 disabled, audit
    policy, local admin group, BitLocker, Windows Firewall, PowerShell script block
    logging, and WDigest disabled. Results are exported to a timestamped CSV and a
    color-coded compliance scorecard is printed to the console.

.NOTES
    Author:       Michael Whelan
    Created:      2026-03-11
    Dependencies: None (stdlib only). Requires admin access to target servers.

.EXAMPLE
    .\Test-ServerCompliance.ps1
    Checks localhost against the security baseline and prints a compliance scorecard.
#>
#Requires -Version 5.1

# =============================================================================
# CONFIGURATION
# =============================================================================
$Config = @{
    ScriptName     = "Test-ServerCompliance"
    LogDir         = "$PSScriptRoot\logs"
    OutputDir      = "$PSScriptRoot\output"

    # --- Target servers ---
    Servers        = @("localhost")

    # --- Compliance settings ---
    # Expected local admin group members (UPN or SAMAccountName).
    # Any member not in this list is flagged.
    ExpectedAdmins = @(
        # "DOMAIN\AdminUser"
        # "Administrator"
    )
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


# --- Check names (used for scorecard column ordering) ---

$CheckNames = @(
    "SMB Signing"
    "Credential Guard"
    "Legacy TLS Disabled"
    "NTLMv1 Disabled"
    "Audit Policy"
    "Local Admin Group"
    "BitLocker"
    "Windows Firewall"
    "Script Block Logging"
    "WDigest Disabled"
)


# --- Main ---

try {
    Write-Log "Starting $($Config.ScriptName)"
    Write-Log "Target servers: $($Config.Servers -join ', ')"

    $allResults = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($server in $Config.Servers) {
        Write-Log "Running compliance checks on: $server"

        try {
            $expectedAdmins = $Config.ExpectedAdmins

            $results = Invoke-Command -ComputerName $server -ScriptBlock {
                param($expectedAdmins)

                $checks = [System.Collections.Generic.List[PSCustomObject]]::new()

                # ---------------------------------------------------------
                # 1. SMB Signing
                # ---------------------------------------------------------
                try {
                    $reg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" `
                           -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
                    if ($null -ne $reg -and $reg.RequireSecuritySignature -eq 1) {
                        $checks.Add([PSCustomObject]@{ Check = "SMB Signing"; Status = "Pass"; Detail = "RequireSecuritySignature is enabled" })
                    } else {
                        $v = if ($null -ne $reg) { $reg.RequireSecuritySignature } else { "(missing)" }
                        $checks.Add([PSCustomObject]@{ Check = "SMB Signing"; Status = "Fail"; Detail = "RequireSecuritySignature = $v" })
                    }
                } catch {
                    $checks.Add([PSCustomObject]@{ Check = "SMB Signing"; Status = "Error"; Detail = $_.Exception.Message })
                }

                # ---------------------------------------------------------
                # 2. Credential Guard
                # ---------------------------------------------------------
                try {
                    $reg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" `
                           -Name "LsaCfgFlags" -ErrorAction SilentlyContinue
                    if ($null -ne $reg -and $reg.LsaCfgFlags -in @(1, 2)) {
                        $checks.Add([PSCustomObject]@{ Check = "Credential Guard"; Status = "Pass"; Detail = "LsaCfgFlags = $($reg.LsaCfgFlags)" })
                    } else {
                        $v = if ($null -ne $reg) { $reg.LsaCfgFlags } else { "(missing)" }
                        $checks.Add([PSCustomObject]@{ Check = "Credential Guard"; Status = "Fail"; Detail = "Not configured (LsaCfgFlags = $v)" })
                    }
                } catch {
                    $checks.Add([PSCustomObject]@{ Check = "Credential Guard"; Status = "Error"; Detail = $_.Exception.Message })
                }

                # ---------------------------------------------------------
                # 3. Legacy TLS Disabled (TLS 1.0 + TLS 1.1)
                # ---------------------------------------------------------
                try {
                    $tlsStatus  = "Pass"
                    $tlsDetails = @()

                    foreach ($ver in @("TLS 1.0", "TLS 1.1")) {
                        $p = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$ver\Server"
                        if (-not (Test-Path $p)) {
                            # Key doesn't exist — relies on OS default behaviour
                            if ($tlsStatus -ne "Fail") { $tlsStatus = "Warning" }
                            $tlsDetails += "$ver key missing (OS default)"
                        } else {
                            $reg = Get-ItemProperty -Path $p -Name "Enabled" -ErrorAction SilentlyContinue
                            if ($null -ne $reg -and $reg.Enabled -eq 0) {
                                $tlsDetails += "$ver explicitly disabled"
                            } else {
                                $tlsStatus = "Fail"
                                $e = if ($null -ne $reg) { $reg.Enabled } else { "(Enabled not set)" }
                                $tlsDetails += "$ver still enabled ($e)"
                            }
                        }
                    }

                    $checks.Add([PSCustomObject]@{
                        Check  = "Legacy TLS Disabled"
                        Status = $tlsStatus
                        Detail = $tlsDetails -join "; "
                    })
                } catch {
                    $checks.Add([PSCustomObject]@{ Check = "Legacy TLS Disabled"; Status = "Error"; Detail = $_.Exception.Message })
                }

                # ---------------------------------------------------------
                # 4. NTLMv1 Disabled
                # ---------------------------------------------------------
                try {
                    $reg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
                           -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
                    if ($null -ne $reg -and $reg.LmCompatibilityLevel -ge 3) {
                        $checks.Add([PSCustomObject]@{ Check = "NTLMv1 Disabled"; Status = "Pass"; Detail = "LmCompatibilityLevel = $($reg.LmCompatibilityLevel)" })
                    } elseif ($null -ne $reg -and $reg.LmCompatibilityLevel -in @(1, 2)) {
                        $checks.Add([PSCustomObject]@{ Check = "NTLMv1 Disabled"; Status = "Warning"; Detail = "LmCompatibilityLevel = $($reg.LmCompatibilityLevel) (should be >= 3)" })
                    } else {
                        $v = if ($null -ne $reg) { $reg.LmCompatibilityLevel } else { "(missing)" }
                        $checks.Add([PSCustomObject]@{ Check = "NTLMv1 Disabled"; Status = "Fail"; Detail = "LmCompatibilityLevel = $v" })
                    }
                } catch {
                    $checks.Add([PSCustomObject]@{ Check = "NTLMv1 Disabled"; Status = "Error"; Detail = $_.Exception.Message })
                }

                # ---------------------------------------------------------
                # 5. Audit Policy (Logon/Logoff)
                # ---------------------------------------------------------
                try {
                    $auditRaw = auditpol /get /category:"Logon/Logoff" /r 2>&1
                    $auditCsv = $auditRaw | ConvertFrom-Csv -ErrorAction Stop
                    $logonRow = $auditCsv | Where-Object { $_.Subcategory -eq "Logon" }

                    if ($null -eq $logonRow) {
                        $checks.Add([PSCustomObject]@{ Check = "Audit Policy"; Status = "Warning"; Detail = "Logon subcategory not found in auditpol output" })
                    } else {
                        $setting = $logonRow.'Inclusion Setting'
                        if ($setting -match "Success and Failure") {
                            $checks.Add([PSCustomObject]@{ Check = "Audit Policy"; Status = "Pass"; Detail = "Logon audit: $setting" })
                        } elseif ($setting -match "Success|Failure") {
                            $checks.Add([PSCustomObject]@{ Check = "Audit Policy"; Status = "Warning"; Detail = "Logon audit: $setting (should be Success and Failure)" })
                        } else {
                            $checks.Add([PSCustomObject]@{ Check = "Audit Policy"; Status = "Fail"; Detail = "Logon audit: $setting" })
                        }
                    }
                } catch {
                    $checks.Add([PSCustomObject]@{ Check = "Audit Policy"; Status = "Error"; Detail = $_.Exception.Message })
                }

                # ---------------------------------------------------------
                # 6. Local Admin Group
                # ---------------------------------------------------------
                try {
                    $members     = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
                    $memberNames = $members | ForEach-Object { $_.Name }

                    if ($expectedAdmins.Count -eq 0) {
                        $checks.Add([PSCustomObject]@{ Check = "Local Admin Group"; Status = "Pass"
                            Detail = "No expected-admin list configured; $($memberNames.Count) member(s): $($memberNames -join ', ')" })
                    } else {
                        $unexpected = @($memberNames | Where-Object { $_ -notin $expectedAdmins })
                        if ($unexpected.Count -eq 0) {
                            $checks.Add([PSCustomObject]@{ Check = "Local Admin Group"; Status = "Pass"; Detail = "All $($memberNames.Count) member(s) are expected" })
                        } else {
                            $checks.Add([PSCustomObject]@{ Check = "Local Admin Group"; Status = "Warning"; Detail = "Unexpected members: $($unexpected -join ', ')" })
                        }
                    }
                } catch {
                    $checks.Add([PSCustomObject]@{ Check = "Local Admin Group"; Status = "Error"; Detail = $_.Exception.Message })
                }

                # ---------------------------------------------------------
                # 7. BitLocker
                # ---------------------------------------------------------
                try {
                    $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
                    if ($bl.ProtectionStatus -eq "On") {
                        $checks.Add([PSCustomObject]@{ Check = "BitLocker"; Status = "Pass"; Detail = "C: drive protection is On" })
                    } else {
                        $checks.Add([PSCustomObject]@{ Check = "BitLocker"; Status = "Fail"; Detail = "C: drive protection is $($bl.ProtectionStatus)" })
                    }
                } catch {
                    $checks.Add([PSCustomObject]@{ Check = "BitLocker"; Status = "Warning"
                        Detail = "BitLocker check failed (feature may not be installed): $($_.Exception.Message)" })
                }

                # ---------------------------------------------------------
                # 8. Windows Firewall
                # ---------------------------------------------------------
                try {
                    $profiles = Get-NetFirewallProfile -ErrorAction Stop
                    $enabled  = @($profiles | Where-Object { $_.Enabled -eq $true })
                    $disabled = @($profiles | Where-Object { $_.Enabled -eq $false })

                    if ($disabled.Count -eq 0) {
                        $checks.Add([PSCustomObject]@{ Check = "Windows Firewall"; Status = "Pass"; Detail = "All $($profiles.Count) profile(s) enabled" })
                    } elseif ($enabled.Count -eq 0) {
                        $n = ($disabled | ForEach-Object { $_.Name }) -join ", "
                        $checks.Add([PSCustomObject]@{ Check = "Windows Firewall"; Status = "Fail"; Detail = "All profiles disabled: $n" })
                    } else {
                        $n = ($disabled | ForEach-Object { $_.Name }) -join ", "
                        $checks.Add([PSCustomObject]@{ Check = "Windows Firewall"; Status = "Warning"; Detail = "Disabled profile(s): $n" })
                    }
                } catch {
                    $checks.Add([PSCustomObject]@{ Check = "Windows Firewall"; Status = "Error"; Detail = $_.Exception.Message })
                }

                # ---------------------------------------------------------
                # 9. Script Block Logging
                # ---------------------------------------------------------
                try {
                    $reg = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
                           -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
                    if ($null -ne $reg -and $reg.EnableScriptBlockLogging -eq 1) {
                        $checks.Add([PSCustomObject]@{ Check = "Script Block Logging"; Status = "Pass"; Detail = "EnableScriptBlockLogging = 1" })
                    } else {
                        $v = if ($null -ne $reg) { $reg.EnableScriptBlockLogging } else { "(missing)" }
                        $checks.Add([PSCustomObject]@{ Check = "Script Block Logging"; Status = "Fail"; Detail = "EnableScriptBlockLogging = $v" })
                    }
                } catch {
                    $checks.Add([PSCustomObject]@{ Check = "Script Block Logging"; Status = "Error"; Detail = $_.Exception.Message })
                }

                # ---------------------------------------------------------
                # 10. WDigest Disabled
                # ---------------------------------------------------------
                try {
                    $reg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
                           -Name "UseLogonCredential" -ErrorAction SilentlyContinue
                    if ($null -eq $reg -or $reg.UseLogonCredential -eq 0) {
                        $d = if ($null -eq $reg) { "UseLogonCredential not set (secure default)" } else { "UseLogonCredential = 0" }
                        $checks.Add([PSCustomObject]@{ Check = "WDigest Disabled"; Status = "Pass"; Detail = $d })
                    } else {
                        $checks.Add([PSCustomObject]@{ Check = "WDigest Disabled"; Status = "Fail"; Detail = "UseLogonCredential = $($reg.UseLogonCredential)" })
                    }
                } catch {
                    $checks.Add([PSCustomObject]@{ Check = "WDigest Disabled"; Status = "Error"; Detail = $_.Exception.Message })
                }

                return $checks

            } -ArgumentList (,$expectedAdmins) -ErrorAction Stop

            Write-Log "Completed $($results.Count) check(s) on $server"

            foreach ($result in $results) {
                $allResults.Add([PSCustomObject]@{
                    Server = $server
                    Check  = $result.Check
                    Status = $result.Status
                    Detail = $result.Detail
                })
            }
        } catch {
            Write-Log "Failed to connect to $server : $_" -Level ERROR
        }
    }

    if ($allResults.Count -eq 0) {
        Write-Log "No results collected. Exiting." -Level WARNING
        exit 0
    }

    # --- Export CSV ---

    if (-not (Test-Path $Config.OutputDir)) {
        New-Item -ItemType Directory -Path $Config.OutputDir | Out-Null
    }

    $timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputFile = Join-Path $Config.OutputDir (
        "ServerCompliance_{0}.csv" -f $timestamp
    )
    $allResults | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
    Write-Log "Exported $($allResults.Count) result(s) to $outputFile"


    # --- Console summary — compliance scorecard ---

    $separator  = [string]::new([char]0x2550, 65)   # ═
    $divider    = [string]::new([char]0x2500, 65)    # ─
    $now        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $serverList = $Config.Servers -join ", "

    # Build a lookup: $statusMap[$server][$check] = status
    $statusMap = @{}
    foreach ($row in $allResults) {
        if (-not $statusMap.ContainsKey($row.Server)) {
            $statusMap[$row.Server] = @{}
        }
        $statusMap[$row.Server][$row.Check] = $row.Status
    }

    # Compute per-server pass counts
    $serverScores = @{}
    foreach ($server in $Config.Servers) {
        if (-not $statusMap.ContainsKey($server)) { continue }
        $passCount = @($CheckNames | Where-Object { $statusMap[$server][$_] -eq "Pass" }).Count
        $serverScores[$server] = $passCount
    }

    # Determine column widths for the scorecard table
    $checkColWidth = ($CheckNames | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
    if ($checkColWidth -lt 22) { $checkColWidth = 22 }
    $checkColWidth += 2  # padding

    $serverColWidth = 12
    foreach ($server in $Config.Servers) {
        if ($server.Length + 2 -gt $serverColWidth) {
            $serverColWidth = $server.Length + 2
        }
    }

    $tableWidth = $checkColWidth + ($serverColWidth * $Config.Servers.Count) + 4
    if ($tableWidth -lt 65) { $tableWidth = 65 }
    $tableSep = [string]::new([char]0x2550, $tableWidth)
    $tableDiv = [string]::new([char]0x2500, $tableWidth)

    # Header
    Write-Summary ""
    Write-Summary $tableSep                                                        -Color Yellow
    Write-Summary "  Server Compliance Audit  $([char]0x2014)  $now"               -Color Yellow
    Write-Summary "  Servers: $serverList"                                         -Color Yellow
    Write-Summary $tableSep                                                        -Color Yellow
    Write-Summary ""

    # Scorecard table header
    Write-Summary "  COMPLIANCE SCORECARD"                                         -Color Cyan
    Write-Summary $tableDiv                                                        -Color Cyan

    $headerLine = "  {0,-$checkColWidth}" -f "Check"
    foreach ($server in $Config.Servers) {
        $headerLine += "{0,-$serverColWidth}" -f $server
    }
    Write-Summary $headerLine                                                      -Color Cyan
    Write-Summary $tableDiv                                                        -Color Cyan

    # Scorecard rows — each cell is colored individually
    foreach ($checkName in $CheckNames) {
        Write-Host ("  {0,-$checkColWidth}" -f $checkName) -NoNewline -ForegroundColor White
        $logLine = "  {0,-$checkColWidth}" -f $checkName

        foreach ($server in $Config.Servers) {
            $status = if ($statusMap.ContainsKey($server) -and $statusMap[$server].ContainsKey($checkName)) {
                $statusMap[$server][$checkName]
            } else { "N/A" }

            $display = $status.ToUpper()
            $color = switch ($status) {
                "Pass"    { "Green"    }
                "Fail"    { "Red"      }
                "Warning" { "Yellow"   }
                "Error"   { "DarkGray" }
                default   { "White"    }
            }

            Write-Host ("{0,-$serverColWidth}" -f $display) -NoNewline -ForegroundColor $color
            $logLine += "{0,-$serverColWidth}" -f $display
        }

        Write-Host ""
        if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $logLine }
    }

    Write-Summary $tableDiv                                                        -Color Cyan

    # Score row
    $scoreLine = "  {0,-$checkColWidth}" -f "Score"
    foreach ($server in $Config.Servers) {
        $score = if ($serverScores.ContainsKey($server)) { $serverScores[$server] } else { 0 }
        $scoreLine += "{0,-$serverColWidth}" -f "$score/$($CheckNames.Count)"
    }
    Write-Summary $scoreLine                                                       -Color Cyan
    Write-Summary $tableDiv                                                        -Color Cyan
    Write-Summary ""

    # Failures & Warnings detail section
    $issues = @($allResults | Where-Object { $_.Status -in @("Fail", "Warning", "Error") })

    if ($issues.Count -gt 0) {
        Write-Summary "  FAILURES & WARNINGS"                                      -Color Cyan
        Write-Summary $tableDiv                                                    -Color Cyan

        foreach ($issue in $issues) {
            $tag = switch ($issue.Status) {
                "Fail"    { "FAIL" }
                "Warning" { "WARN" }
                "Error"   { "ERR " }
            }
            $color = switch ($issue.Status) {
                "Fail"    { "Red"      }
                "Warning" { "Yellow"   }
                "Error"   { "DarkGray" }
            }
            $issueLine = "  [$tag] $($issue.Server): $($issue.Check) $([char]0x2014) $($issue.Detail)"
            Write-Summary $issueLine -Color $color
        }

        Write-Summary $tableDiv                                                    -Color Cyan
        Write-Summary ""
    }

    # Final totals
    $totalPass    = @($allResults | Where-Object { $_.Status -eq "Pass"    }).Count
    $totalFail    = @($allResults | Where-Object { $_.Status -eq "Fail"    }).Count
    $totalWarn    = @($allResults | Where-Object { $_.Status -eq "Warning" }).Count
    $totalError   = @($allResults | Where-Object { $_.Status -eq "Error"   }).Count
    $serverCount  = @($statusMap.Keys).Count

    Write-Summary $tableSep                                                        -Color Cyan
    $totalLine = "  TOTAL: $serverCount server(s)  |  $totalPass pass  |  $totalFail fail  |  $totalWarn warning"
    if ($totalError -gt 0) { $totalLine += "  |  $totalError error" }
    Write-Summary $totalLine                                                       -Color Cyan
    Write-Summary "  CSV: $outputFile"                                             -Color Cyan
    Write-Summary $tableSep                                                        -Color Cyan
    Write-Summary ""

    Write-Log "Completed $($Config.ScriptName) successfully"
    exit 0
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    exit 1
}
