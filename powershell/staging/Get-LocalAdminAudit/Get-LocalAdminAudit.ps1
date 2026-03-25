<#
.SYNOPSIS
    Audits privileged local group members on target servers and flags unexpected entries.

.DESCRIPTION
    Connects to each target server via Invoke-Command and retrieves the members of
    one or more configurable local groups (default: Administrators, Remote Desktop
    Users). Each member is checked against an allow-list. Unexpected entries and
    orphaned SIDs are flagged. Optionally compares against a baseline CSV to detect
    added/removed members and checks the built-in Administrator password age.
    Results are exported to a timestamped CSV and optional HTML report.

.PARAMETER Servers
    One or more server names to audit. Overrides $Config.Servers.

.PARAMETER ServerFile
    Path to a plain-text file with one server name per line. Overrides $Config.ServerFile.

.PARAMETER BaselineCsvPath
    Path to a previous audit CSV for baseline comparison. Overrides $Config.BaselineCsvPath.

.PARAMETER GenerateHtml
    Generate an HTML report alongside the CSV. Overrides $Config.GenerateHtml.

.EXAMPLE
    .\Get-LocalAdminAudit.ps1
    Audits local Administrators and Remote Desktop Users on servers listed in
    $Config.Servers and exports results to $PSScriptRoot\output\.

.EXAMPLE
    .\Get-LocalAdminAudit.ps1 -Servers "SRV01","SRV02" -BaselineCsvPath ".\output\previous.csv"
    Audits two servers and compares against a previous baseline.
#>
#Requires -Version 5.1
param(
    [string[]]$Servers,
    [string]$ServerFile,
    [string]$BaselineCsvPath,
    [switch]$GenerateHtml
)

# =============================================================================
# CONFIGURATION
# =============================================================================
$Config = @{
    ScriptName     = "Get-LocalAdminAudit"
    LogDir         = "$PSScriptRoot\logs"
    OutputDir      = "$PSScriptRoot\output"

    # --- Target servers ---
    # Leave empty or use @("localhost") for the local machine.
    Servers        = @("localhost")

    # Path to a plain-text file with one server per line (used when Servers is empty).
    ServerFile     = "$PSScriptRoot\servers.txt"

    # --- Audit scope ---
    # Local groups to audit. Each group is checked on every target server.
    AuditGroups    = @("Administrators", "Remote Desktop Users")

    # --- Expected admins allow-list ---
    # Members matching these names (short name, no domain prefix) are considered expected.
    ExpectedAdmins = @("Administrator", "Domain Admins")

    # --- Built-in Administrator password age ---
    # Warn if the built-in Administrator (SID *-500) password is older than this many days.
    # Set to 0 to skip this check.
    MaxAdminPwdAgeDays = 180

    # --- Baseline comparison ---
    # Path to a previous audit CSV. Set to $null to skip baseline comparison.
    BaselineCsvPath = $null

    # --- HTML report ---
    GenerateHtml = $false
}
# =============================================================================

# --- Parameter overrides ---
if ($PSBoundParameters.ContainsKey('Servers'))         { $Config.Servers         = $Servers }
if ($PSBoundParameters.ContainsKey('ServerFile'))      { $Config.ServerFile      = $ServerFile }
if ($PSBoundParameters.ContainsKey('BaselineCsvPath')) { $Config.BaselineCsvPath = $BaselineCsvPath }
if ($GenerateHtml)                                     { $Config.GenerateHtml    = $true }

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

function Get-ServerAdminMembers {
    <# Queries a remote server for members of the specified local groups with orphan detection. #>
    param(
        [string]$Server,
        [string[]]$Groups,
        [string[]]$ExpectedAdmins,
        [int]$MaxAdminPwdAgeDays
    )

    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $data = Invoke-Command -ComputerName $Server -ScriptBlock {
            param($Groups, $MaxPwdAge)
            $output = @{ Members = @(); AdminPwdAge = $null }

            foreach ($group in $Groups) {
                try {
                    $members = Get-LocalGroupMember -Group $group -ErrorAction Stop
                    foreach ($m in $members) {
                        $isOrphaned = $false
                        $name = $m.Name
                        # Orphaned SIDs appear as raw SID strings (S-1-5-...)
                        if ($name -match '^S-1-\d+-') { $isOrphaned = $true }
                        $output.Members += @{
                            Group           = $group
                            Name            = $name
                            ObjectClass     = $m.ObjectClass
                            PrincipalSource = "$($m.PrincipalSource)"
                            SID             = "$($m.SID)"
                            IsOrphanedSID   = $isOrphaned
                        }
                    }
                } catch {
                    $output.Members += @{
                        Group   = $group
                        Name    = "ERROR: $_"
                        ObjectClass = "Error"
                        PrincipalSource = ""
                        SID     = ""
                        IsOrphanedSID = $false
                    }
                }
            }

            # Built-in Administrator password age
            if ($MaxPwdAge -gt 0) {
                try {
                    $admin = Get-LocalUser | Where-Object { $_.SID -like '*-500' }
                    if ($admin -and $admin.PasswordLastSet) {
                        $output.AdminPwdAge = [int]((Get-Date) - $admin.PasswordLastSet).TotalDays
                    }
                } catch { }
            }

            return $output
        } -ArgumentList @($Groups, $MaxAdminPwdAgeDays) -ErrorAction Stop

        Write-Log "Retrieved $($data.Members.Count) member(s) from $Server across $($Groups.Count) group(s)"

        foreach ($member in $data.Members) {
            $shortName = $member.Name
            if ($shortName -match '\\') { $shortName = $shortName.Split('\')[-1] }
            $isUnexpected = $shortName -notin $ExpectedAdmins

            if ($member.IsOrphanedSID) {
                Write-Log "Orphaned SID on $Server in $($member.Group): $($member.Name)" -Level WARNING
            } elseif ($isUnexpected -and $member.ObjectClass -ne "Error") {
                Write-Log "Unexpected member on $Server in $($member.Group): $($member.Name)" -Level WARNING
            }

            $results.Add([PSCustomObject]@{
                Server          = $Server
                Group           = $member.Group
                Name            = $member.Name
                ObjectClass     = $member.ObjectClass
                PrincipalSource = $member.PrincipalSource
                SID             = $member.SID
                IsUnexpected    = $isUnexpected
                IsOrphanedSID   = $member.IsOrphanedSID
                AdminPwdAgeDays = $data.AdminPwdAge
            })
        }

        if ($MaxAdminPwdAgeDays -gt 0 -and $data.AdminPwdAge -and $data.AdminPwdAge -gt $MaxAdminPwdAgeDays) {
            Write-Log "Built-in Administrator password age on $Server : $($data.AdminPwdAge) days (threshold: $MaxAdminPwdAgeDays)" -Level WARNING
        }
    } catch {
        Write-Log "Failed to query $Server : $_" -Level ERROR
    }

    return ,$results
}

function Export-HtmlReport {
    <# Generates a self-contained HTML report for the local admin audit results. #>
    param(
        [System.Collections.Generic.List[PSCustomObject]]$AllRows,
        [string]$OutputPath,
        [string[]]$TargetServers
    )
    $now             = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $totalMembers    = $AllRows.Count
    $unexpectedCount = @($AllRows | Where-Object { $_.IsUnexpected -eq $true -and $_.ObjectClass -ne "Error" }).Count
    $orphanedCount   = @($AllRows | Where-Object { $_.IsOrphanedSID -eq $true }).Count

    $rows = [System.Text.StringBuilder]::new()
    foreach ($r in $AllRows) {
        $cls = "normal"
        if ($r.IsOrphanedSID)   { $cls = "orphan" }
        elseif ($r.IsUnexpected -and $r.ObjectClass -ne "Error") { $cls = "unexpected" }
        elseif ($r.ObjectClass -eq "Error") { $cls = "error" }

        $change = if ($r.PSObject.Properties['ChangeStatus']) { $r.ChangeStatus } else { "" }
        [void]$rows.AppendLine("<tr class=`"$cls`">")
        [void]$rows.AppendLine("  <td>$([System.Net.WebUtility]::HtmlEncode($r.Server))</td>")
        [void]$rows.AppendLine("  <td>$([System.Net.WebUtility]::HtmlEncode($r.Group))</td>")
        [void]$rows.AppendLine("  <td>$([System.Net.WebUtility]::HtmlEncode($r.Name))</td>")
        [void]$rows.AppendLine("  <td>$($r.ObjectClass)</td>")
        [void]$rows.AppendLine("  <td>$(if ($r.IsUnexpected) { 'Yes' } else { 'No' })</td>")
        [void]$rows.AppendLine("  <td>$(if ($r.IsOrphanedSID) { 'Yes' } else { 'No' })</td>")
        [void]$rows.AppendLine("  <td>$change</td>")
        [void]$rows.AppendLine("</tr>")
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Local Admin Audit Report</title>
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
.card.good{background:#f0fdf4;color:#16a34a}
.card.bad{background:#fef2f2;color:#dc2626}
.card.warn{background:#fefce8;color:#ca8a04}
.card.neutral{background:#eff6ff;color:#2563eb}
.section{background:#fff;padding:1.5rem 2rem;border-radius:0 0 10px 10px}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{text-align:left;padding:.6rem .5rem;border-bottom:2px solid #d1d5db;color:#6b7280;font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}
td{padding:.6rem .5rem;border-bottom:1px solid #f3f4f6;vertical-align:top}
tr:hover{background:#f9fafb}
tr.unexpected td{background:#fef2f2;color:#dc2626}
tr.orphan td{background:#fefce8;color:#ca8a04}
tr.error td{background:#f3f4f6;color:#6b7280;font-style:italic}
.footer{text-align:center;padding:1rem;color:#9ca3af;font-size:.8rem}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <h1>Local Admin Audit Report</h1>
    <div class="meta">Generated: $now &mdash; Servers: $($TargetServers.Count)</div>
  </div>
  <div class="cards">
    <div class="card neutral"><div class="count">$($TargetServers.Count)</div><div class="label">Servers</div></div>
    <div class="card neutral"><div class="count">$totalMembers</div><div class="label">Total Members</div></div>
    <div class="card bad"><div class="count">$unexpectedCount</div><div class="label">Unexpected</div></div>
    <div class="card warn"><div class="count">$orphanedCount</div><div class="label">Orphaned SIDs</div></div>
  </div>
  <div class="section">
    <table>
      <thead><tr><th>Server</th><th>Group</th><th>Name</th><th>Type</th><th>Unexpected</th><th>Orphaned</th><th>Baseline</th></tr></thead>
      <tbody>$($rows.ToString())</tbody>
    </table>
  </div>
</div>
<div class="footer">Get-LocalAdminAudit &mdash; $now</div>
</body>
</html>
"@
    [System.IO.File]::WriteAllText($OutputPath, $html, [System.Text.Encoding]::UTF8)
}


# --- Main ---

try {
    Write-Log "Starting $($Config.ScriptName)"

    # Resolve target list
    $targetServers = @()
    if ($Config.Servers.Count -gt 0) {
        $targetServers = $Config.Servers
        Write-Log "Using configured server list ($($targetServers.Count) server(s))"
    } elseif (Test-Path $Config.ServerFile) {
        $targetServers = Get-Content $Config.ServerFile | Where-Object { $_.Trim() -ne '' -and -not $_.StartsWith('#') }
        Write-Log "Loaded $($targetServers.Count) server(s) from $($Config.ServerFile)"
    } else {
        throw "No servers defined. Set Config.Servers, provide -Servers, or create '$($Config.ServerFile)'."
    }

    if ($targetServers.Count -eq 0) {
        Write-Log "Server list is empty. Exiting." -Level WARNING
        exit 0
    }

    Write-Log "Audit groups: $($Config.AuditGroups -join ', ')"
    Write-Log "Expected admins: $($Config.ExpectedAdmins -join ', ')"

    # Load baseline if configured
    $baseline = @{}
    if ($Config.BaselineCsvPath -and (Test-Path $Config.BaselineCsvPath)) {
        Write-Log "Loading baseline from $($Config.BaselineCsvPath)"
        $baselineRows = Import-Csv $Config.BaselineCsvPath
        foreach ($row in $baselineRows) {
            $key = "$($row.Server)|$($row.Group)|$($row.Name)"
            $baseline[$key] = $row
        }
        Write-Log "Loaded $($baseline.Count) baseline entries"
    } elseif ($Config.BaselineCsvPath) {
        Write-Log "Baseline file not found: $($Config.BaselineCsvPath)" -Level WARNING
    }

    $allRows = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($server in $targetServers) {
        Write-Log "Querying $server..."
        $members = Get-ServerAdminMembers -Server $server -Groups $Config.AuditGroups `
            -ExpectedAdmins $Config.ExpectedAdmins -MaxAdminPwdAgeDays $Config.MaxAdminPwdAgeDays
        $allRows.AddRange($members)
    }

    # Baseline comparison — mark current rows
    if ($baseline.Count -gt 0) {
        $currentKeys = @{}
        foreach ($row in $allRows) {
            $key = "$($row.Server)|$($row.Group)|$($row.Name)"
            $currentKeys[$key] = $true
            $row | Add-Member -NotePropertyName ChangeStatus -NotePropertyValue $(
                if ($baseline.ContainsKey($key)) { "UNCHANGED" } else { "NEW" }
            )
        }
        # Add REMOVED entries from baseline
        foreach ($key in $baseline.Keys) {
            if (-not $currentKeys.ContainsKey($key)) {
                $old = $baseline[$key]
                $allRows.Add([PSCustomObject]@{
                    Server          = $old.Server
                    Group           = $old.Group
                    Name            = $old.Name
                    ObjectClass     = $old.ObjectClass
                    PrincipalSource = $old.PrincipalSource
                    SID             = $old.SID
                    IsUnexpected    = $old.IsUnexpected
                    IsOrphanedSID   = $old.IsOrphanedSID
                    AdminPwdAgeDays = ""
                    ChangeStatus    = "REMOVED"
                })
                Write-Log "Baseline: REMOVED $($old.Name) from $($old.Server) / $($old.Group)" -Level WARNING
            }
        }
    }

    if ($allRows.Count -eq 0) {
        Write-Log "No members found. Exiting." -Level WARNING
        exit 0
    }

    if (-not (Test-Path $Config.OutputDir)) { New-Item -ItemType Directory -Path $Config.OutputDir | Out-Null }
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputFile = Join-Path $Config.OutputDir "LocalAdminAudit_$ts.csv"
    $allRows | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
    Write-Log "Exported $($allRows.Count) row(s) to $outputFile"

    # HTML report
    if ($Config.GenerateHtml) {
        $htmlFile = Join-Path $Config.OutputDir "LocalAdminAudit_$ts.html"
        Export-HtmlReport -AllRows $allRows -OutputPath $htmlFile -TargetServers $targetServers
        Write-Log "HTML report exported to $htmlFile"
    }

    # --- Console summary ---

    $separator    = [string]::new([char]0x2550, 72)
    $divider      = [string]::new([char]0x2500, 72)
    $displayTime  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $currentRows     = @($allRows | Where-Object { -not ($_.PSObject.Properties['ChangeStatus']) -or $_.ChangeStatus -ne "REMOVED" })
    $expectedCount   = @($currentRows | Where-Object { $_.IsUnexpected -eq $false -and $_.ObjectClass -ne "Error" }).Count
    $unexpectedCount = @($currentRows | Where-Object { $_.IsUnexpected -eq $true -and $_.ObjectClass -ne "Error" }).Count
    $orphanedCount   = @($currentRows | Where-Object { $_.IsOrphanedSID -eq $true }).Count
    $unexpectedRows  = @($currentRows | Where-Object { $_.IsUnexpected -eq $true -and $_.ObjectClass -ne "Error" })

    Write-Summary ""
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary "  Local Admin Audit  —  $displayTime"                            -Color Yellow
    Write-Summary "  Servers: $($targetServers.Count)  |  Groups: $($Config.AuditGroups -join ', ')" -Color Yellow
    Write-Summary $separator                                                        -Color Yellow
    Write-Summary ""

    # UNEXPECTED MEMBERS — per-server per-group
    if ($unexpectedCount -gt 0) {
        Write-Summary "  UNEXPECTED MEMBERS ($unexpectedCount found)"               -Color Cyan
        Write-Summary $divider                                                      -Color Cyan
        $byServerGroup = $unexpectedRows | Group-Object -Property { "$($_.Server) / $($_.Group)" }
        foreach ($group in $byServerGroup) {
            Write-Summary "  [$($group.Name)]"                                      -Color Red
            foreach ($entry in $group.Group) {
                $line = "    {0,-40}  {1}" -f $entry.Name, $entry.ObjectClass
                Write-Summary $line                                                 -Color Red
            }
        }
        Write-Summary ""
    }

    # ORPHANED SIDs
    if ($orphanedCount -gt 0) {
        Write-Summary "  ORPHANED SIDs ($orphanedCount found)"                      -Color Cyan
        Write-Summary $divider                                                      -Color Cyan
        foreach ($entry in @($currentRows | Where-Object { $_.IsOrphanedSID -eq $true })) {
            Write-Summary ("  {0,-20} {1,-25} {2}" -f $entry.Server, $entry.Group, $entry.Name) -Color Yellow
        }
        Write-Summary ""
    }

    # ADMIN PASSWORD AGE WARNINGS
    if ($Config.MaxAdminPwdAgeDays -gt 0) {
        $pwdWarnings = @($currentRows | Where-Object {
            $_.AdminPwdAgeDays -ne "" -and $_.AdminPwdAgeDays -ne $null -and
            [int]$_.AdminPwdAgeDays -gt $Config.MaxAdminPwdAgeDays
        } | Select-Object Server, AdminPwdAgeDays -Unique)
        if ($pwdWarnings.Count -gt 0) {
            Write-Summary "  ADMIN PASSWORD AGE WARNINGS (>$($Config.MaxAdminPwdAgeDays) days)" -Color Cyan
            Write-Summary $divider                                                  -Color Cyan
            foreach ($pw in $pwdWarnings) {
                Write-Summary ("  {0,-30}  {1} days" -f $pw.Server, $pw.AdminPwdAgeDays) -Color Red
            }
            Write-Summary ""
        }
    }

    # BASELINE CHANGES
    if ($baseline.Count -gt 0) {
        $newEntries     = @($allRows | Where-Object { $_.PSObject.Properties['ChangeStatus'] -and $_.ChangeStatus -eq "NEW" })
        $removedEntries = @($allRows | Where-Object { $_.PSObject.Properties['ChangeStatus'] -and $_.ChangeStatus -eq "REMOVED" })
        if ($newEntries.Count -gt 0 -or $removedEntries.Count -gt 0) {
            Write-Summary "  BASELINE CHANGES"                                      -Color Cyan
            Write-Summary $divider                                                  -Color Cyan
            foreach ($entry in $newEntries) {
                Write-Summary ("  + NEW     {0,-20} {1,-25} {2}" -f $entry.Server, $entry.Group, $entry.Name) -Color Green
            }
            foreach ($entry in $removedEntries) {
                Write-Summary ("  - REMOVED {0,-20} {1,-25} {2}" -f $entry.Server, $entry.Group, $entry.Name) -Color Red
            }
            Write-Summary ""
        }
    }

    # PER-SERVER COUNTS
    Write-Summary "  PER-SERVER COUNTS"                                             -Color Cyan
    Write-Summary $divider                                                          -Color Cyan
    $serverGroups = $currentRows | Group-Object -Property Server
    foreach ($sg in $serverGroups) {
        $sExpected   = @($sg.Group | Where-Object { $_.IsUnexpected -eq $false -and $_.ObjectClass -ne "Error" }).Count
        $sUnexpected = @($sg.Group | Where-Object { $_.IsUnexpected -eq $true -and $_.ObjectClass -ne "Error" }).Count
        $sOrphaned   = @($sg.Group | Where-Object { $_.IsOrphanedSID -eq $true }).Count
        $color = if ($sUnexpected -gt 0 -or $sOrphaned -gt 0) { "Red" } else { "Green" }
        $line = "  {0,-30}  total:{1,3}  expected:{2,3}  unexpected:{3,3}  orphaned:{4,3}" -f
            $sg.Name, $sg.Count, $sExpected, $sUnexpected, $sOrphaned
        Write-Summary $line                                                         -Color $color
    }
    Write-Summary ""

    # Final totals
    Write-Summary $separator                                                        -Color Cyan
    Write-Summary ("  TOTAL: {0} members  |  {1} expected  |  {2} unexpected  |  {3} orphaned  |  {4} servers" -f
        $currentRows.Count, $expectedCount, $unexpectedCount, $orphanedCount, $targetServers.Count) -Color Cyan
    Write-Summary "  CSV: $outputFile"                                              -Color Cyan
    if ($Config.GenerateHtml) { Write-Summary "  HTML: $htmlFile"                   -Color Cyan }
    Write-Summary $separator                                                        -Color Cyan
    Write-Summary ""

    Write-Log "Completed $($Config.ScriptName) successfully"
    if ($unexpectedCount -gt 0 -or $orphanedCount -gt 0) { exit 1 } else { exit 0 }
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    exit 1
}
