<#
.SYNOPSIS
    Diffs two FortiGate config backups section-by-section and prints a change audit trail to the console.

.DESCRIPTION
    Parses two FortiGate .conf backup files into named sections, compares them, and prints
    a structured, color-coded audit trail showing added, removed, and modified sections.
    Unchanged sections are skipped. An optional section filter limits output to specific
    sections by name. Console output is also written to a timestamped log file.

.EXAMPLE
    .\Compare-FortiGateConfigs.ps1
    Compares the two files defined in $Config and prints the diff to the console.
#>
#Requires -Version 5.1

# =============================================================================
# CONFIGURATION
# =============================================================================
$Config = @{
    ScriptName       = "Compare-FortiGateConfigs"
    ReferenceConfig  = "baseline.conf"   # Older/baseline file
    DifferenceConfig = "current.conf"    # Newer file to compare against baseline

    # Filter to specific sections — leave empty to compare all sections.
    # This is the part after "config"
    # e.g. @("firewall policy", "router bgp")
    SectionFilter    = @()

    LogDir           = "$PSScriptRoot\logs"  # Set to $null to disable file logging
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

# Write-Diff: colored console output + plain text to log file (bypasses Write-Log levels)
function Write-Diff {
    param([string]$Line, [string]$Color = "White")
    Write-Host $Line -ForegroundColor $Color
    if ($Script:LogFile) { Add-Content -Path $Script:LogFile -Value $Line }
}


# --- Functions ---

function ConvertTo-FortiSections {
    <#
    .SYNOPSIS
        Parses a FortiGate config file into a hashtable of top-level sections.
    .DESCRIPTION
        Tracks nesting depth so that inner config/end pairs (e.g. inside firewall policies)
        are captured as content rather than treated as new top-level sections.
    #>
    param([string]$FilePath)

    $sections = @{}
    $key      = $null
    $lines    = [System.Collections.Generic.List[string]]::new()
    $depth    = 0

    foreach ($raw in [System.IO.File]::ReadLines($FilePath)) {
        $trimmed = $raw.TrimEnd()

        if ($trimmed -match '^config ' -and $depth -eq 0) {
            # Start of a new top-level section
            $key = $trimmed
            $depth = 1
            $lines.Clear()
        }
        elseif ($trimmed -match '^config ' -and $depth -gt 0) {
            # Nested config block — accumulate, increment depth
            $depth++
            $lines.Add($trimmed)
        }
        elseif ($trimmed -eq 'end' -and $depth -eq 1) {
            # Close top-level section
            $sections[$key] = $lines.ToArray()
            $depth = 0
            $key   = $null
        }
        elseif ($trimmed -eq 'end' -and $depth -gt 1) {
            # Close nested block — accumulate, decrement depth
            $depth--
            $lines.Add($trimmed)
        }
        elseif ($depth -gt 0) {
            $lines.Add($trimmed)
        }
    }

    return $sections
}

function Get-LineDiff {
    <#
    .SYNOPSIS
        LCS-based line diff. Returns lines removed from Reference and added in Difference.
    .DESCRIPTION
        Uses the Longest Common Subsequence algorithm so that lines shared across
        multiple sub-blocks are matched positionally — newly added blocks show all
        their lines as additions rather than losing lines common to other blocks.
    #>
    param([string[]]$Reference, [string[]]$Difference)

    $ref  = @($Reference  | Where-Object { $_.Trim() -ne '' } | ForEach-Object { $_.Trim() })
    $diff = @($Difference | Where-Object { $_.Trim() -ne '' } | ForEach-Object { $_.Trim() })

    $m = $ref.Count
    $n = $diff.Count

    # Build LCS DP table. Use a flat 1-D int array with manual 2-D indexing
    # to avoid PowerShell 5.1 quirks with System.Int32[,] subscript operators.
    $cols = $n + 1
    $dp   = New-Object int[] (($m + 1) * $cols)

    for ($i = 1; $i -le $m; $i++) {
        for ($j = 1; $j -le $n; $j++) {
            if ($ref[$i - 1] -eq $diff[$j - 1]) {
                $dp[$i * $cols + $j] = $dp[($i - 1) * $cols + ($j - 1)] + 1
            } else {
                $a = $dp[($i - 1) * $cols + $j]
                $b = $dp[$i * $cols + ($j - 1)]
                $dp[$i * $cols + $j] = if ($a -ge $b) { $a } else { $b }
            }
        }
    }

    # Backtrack to extract removed / added lines
    $removed = [System.Collections.Generic.List[string]]::new()
    $added   = [System.Collections.Generic.List[string]]::new()

    $i = $m; $j = $n
    while ($i -gt 0 -or $j -gt 0) {
        if ($i -gt 0 -and $j -gt 0 -and $ref[$i - 1] -eq $diff[$j - 1]) {
            $i--; $j--   # lines match — part of LCS, skip
        } elseif ($j -gt 0 -and ($i -eq 0 -or $dp[$i * $cols + ($j - 1)] -ge $dp[($i - 1) * $cols + $j])) {
            $added.Add($diff[$j - 1]); $j--
        } else {
            $removed.Add($ref[$i - 1]); $i--
        }
    }

    $removed.Reverse()
    $added.Reverse()

    return @{
        Removed = $removed.ToArray()
        Added   = $added.ToArray()
    }
}


# --- Main ---

try {
    Write-Log "Starting $($Config.ScriptName)"

    # Validate input files
    foreach ($key in @("ReferenceConfig", "DifferenceConfig")) {
        if (-not (Test-Path $Config[$key])) {
            Write-Log "Config file not found: $($Config[$key]) (set via '$key')" -Level ERROR
            exit 1
        }
    }

    Write-Log "Reference : $($Config.ReferenceConfig)"
    Write-Log "Difference: $($Config.DifferenceConfig)"

    # Parse both files
    Write-Log "Parsing reference config..."
    $refSections  = ConvertTo-FortiSections -FilePath $Config.ReferenceConfig

    Write-Log "Parsing difference config..."
    $diffSections = ConvertTo-FortiSections -FilePath $Config.DifferenceConfig

    # Union of all section names
    $allSections = @($refSections.Keys) + @($diffSections.Keys) | Sort-Object -Unique

    # Apply section filter
    if ($Config.SectionFilter.Count -gt 0) {
        $allSections = $allSections | Where-Object {
            $sectionName = $_
            $Config.SectionFilter | Where-Object { $sectionName -like "*$_*" }
        }
        Write-Log "Section filter applied — $($allSections.Count) section(s) in scope"
    }

    # Categorize sections
    $results = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($section in $allSections) {
        $inRef  = $refSections.ContainsKey($section)
        $inDiff = $diffSections.ContainsKey($section)

        if ($inRef -and -not $inDiff) {
            $results.Add(@{ Section = $section; Status = "REMOVED"; Diff = $null })
        }
        elseif ($inDiff -and -not $inRef) {
            $results.Add(@{ Section = $section; Status = "ADDED"; Diff = $null
                Lines = $diffSections[$section] })
        }
        else {
            $diff = Get-LineDiff -Reference $refSections[$section] -Difference $diffSections[$section]
            if ($diff.Removed.Count -gt 0 -or $diff.Added.Count -gt 0) {
                $results.Add(@{ Section = $section; Status = "MODIFIED"; Diff = $diff })
            }
            # UNCHANGED — skip
        }
    }

    $countModified  = @($results | Where-Object { $_.Status -eq "MODIFIED"  }).Count
    $countAdded     = @($results | Where-Object { $_.Status -eq "ADDED"     }).Count
    $countRemoved   = @($results | Where-Object { $_.Status -eq "REMOVED"   }).Count
    $countUnchanged = $allSections.Count - $countModified - $countAdded - $countRemoved

    # --- Console output ---

    $separator = "═" * 46
    $divider   = "─" * 33
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    Write-Diff ""
    Write-Diff $separator                                   -Color Yellow
    Write-Diff "  FortiGate Config Diff  —  $timestamp"    -Color Yellow
    Write-Diff "  REF : $($Config.ReferenceConfig)"        -Color Yellow
    Write-Diff "  DIFF: $($Config.DifferenceConfig)"       -Color Yellow
    Write-Diff $separator                                   -Color Yellow
    Write-Diff ""

    if ($results.Count -eq 0) {
        Write-Diff "  No differences found." -Color Cyan
    }

    foreach ($entry in $results) {
        Write-Diff $separator                               -Color Yellow
        Write-Diff "[$($entry.Status)] $($entry.Section)"  -Color Yellow
        Write-Diff $separator                               -Color Yellow

        switch ($entry.Status) {
            "MODIFIED" {
                foreach ($line in $entry.Diff.Removed) {
                    Write-Diff "  - $line" -Color Red
                }
                foreach ($line in $entry.Diff.Added) {
                    Write-Diff "  + $line" -Color Green
                }
            }
            "ADDED" {
                foreach ($line in $entry.Lines) {
                    if ($line.Trim() -ne '') {
                        Write-Diff "  + $($line.Trim())" -Color Green
                    }
                }
            }
            "REMOVED" {
                $sectionLines = $refSections[$entry.Section]
                foreach ($line in $sectionLines) {
                    if ($line.Trim() -ne '') {
                        Write-Diff "  - $($line.Trim())" -Color Red
                    }
                }
            }
        }

        Write-Diff ""
    }

    # Summary
    Write-Diff $divider                                                                        -Color Cyan
    Write-Diff "SUMMARY  |  Modified: $countModified  Added: $countAdded  Removed: $countRemoved  Unchanged: $countUnchanged" -Color Cyan
    Write-Diff $divider                                                                        -Color Cyan
    Write-Diff ""

    Write-Log "Completed $($Config.ScriptName) successfully"
    exit 0
}
catch {
    Write-Log "Fatal error: $_" -Level ERROR
    exit 1
}