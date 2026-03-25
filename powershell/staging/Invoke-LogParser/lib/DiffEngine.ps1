# ═══════════════════════════════════════════════════════════════════════════════
# DIFF ENGINE — Compare datasets, time periods, and configurations
# ═══════════════════════════════════════════════════════════════════════════════

function Compare-LogPeriods {
    param(
        [System.Collections.Generic.List[object]]$Period1,
        [System.Collections.Generic.List[object]]$Period2,
        [string]$Period1Label = "Period 1",
        [string]$Period2Label = "Period 2"
    )

    if (-not $Period1) { $Period1 = [System.Collections.Generic.List[object]]::new() }
    if (-not $Period2) { $Period2 = [System.Collections.Generic.List[object]]::new() }

    $p1Count = $Period1.Count
    $p2Count = $Period2.Count

    # ── 1. Volume comparison by severity ──────────────────────────────────────
    $sevLevels = @('CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG', 'TRACE', 'UNKNOWN')
    $p1Sev = @{}; $p2Sev = @{}
    foreach ($lv in $sevLevels) { $p1Sev[$lv] = 0; $p2Sev[$lv] = 0 }

    foreach ($e in $Period1) {
        $lv = if ($e.Level -and $p1Sev.ContainsKey($e.Level)) { $e.Level } else { 'UNKNOWN' }
        $p1Sev[$lv]++
    }
    foreach ($e in $Period2) {
        $lv = if ($e.Level -and $p2Sev.ContainsKey($e.Level)) { $e.Level } else { 'UNKNOWN' }
        $p2Sev[$lv]++
    }

    $bySeverity = @{}
    foreach ($lv in $sevLevels) {
        $delta = $p2Sev[$lv] - $p1Sev[$lv]
        $pctChange = if ($p1Sev[$lv] -gt 0) { [Math]::Round(($delta / $p1Sev[$lv]) * 100, 1) } else { if ($p2Sev[$lv] -gt 0) { 100.0 } else { 0.0 } }
        $bySeverity[$lv] = @{ P1 = $p1Sev[$lv]; P2 = $p2Sev[$lv]; Delta = $delta; PctChange = $pctChange }
    }

    $totalDelta = $p2Count - $p1Count
    $totalPctChange = if ($p1Count -gt 0) { [Math]::Round(($totalDelta / $p1Count) * 100, 1) } else { if ($p2Count -gt 0) { 100.0 } else { 0.0 } }

    $volumeDiff = @{
        Period1Count = $p1Count
        Period2Count = $p2Count
        Delta        = $totalDelta
        PercentChange = $totalPctChange
        BySeverity   = $bySeverity
    }

    # ── 2. Source distribution ────────────────────────────────────────────────
    $p1Sources = @{}; $p2Sources = @{}
    foreach ($e in $Period1) {
        if ($e.Source) {
            $src = $e.Source
            if (-not $p1Sources.ContainsKey($src)) { $p1Sources[$src] = 0 }
            $p1Sources[$src]++
        }
    }
    foreach ($e in $Period2) {
        if ($e.Source) {
            $src = $e.Source
            if (-not $p2Sources.ContainsKey($src)) { $p2Sources[$src] = 0 }
            $p2Sources[$src]++
        }
    }

    $allSourceKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($k in $p1Sources.Keys) { $allSourceKeys.Add($k) | Out-Null }
    foreach ($k in $p2Sources.Keys) { $allSourceKeys.Add($k) | Out-Null }

    $newSources = [System.Collections.Generic.List[string]]::new()
    $disappearedSources = [System.Collections.Generic.List[string]]::new()
    $sharedSources = [System.Collections.Generic.List[string]]::new()
    $topSourceChanges = [System.Collections.Generic.List[object]]::new()

    foreach ($src in $allSourceKeys) {
        $c1 = if ($p1Sources.ContainsKey($src)) { $p1Sources[$src] } else { 0 }
        $c2 = if ($p2Sources.ContainsKey($src)) { $p2Sources[$src] } else { 0 }

        if ($c1 -eq 0 -and $c2 -gt 0) {
            $newSources.Add($src)
        } elseif ($c1 -gt 0 -and $c2 -eq 0) {
            $disappearedSources.Add($src)
        } else {
            $sharedSources.Add($src)
        }

        $topSourceChanges.Add(@{ Source = $src; P1Count = $c1; P2Count = $c2; Delta = $c2 - $c1 })
    }

    # Sort by absolute delta descending, take top 20
    $sortedSourceChanges = @($topSourceChanges | Sort-Object { [Math]::Abs($_.Delta) } -Descending | Select-Object -First 20)

    $sourceDiff = @{
        NewSources         = @($newSources)
        DisappearedSources = @($disappearedSources)
        SharedSources      = @($sharedSources)
        TopChanges         = $sortedSourceChanges
    }

    # ── 3. Top field changes ─────────────────────────────────────────────────
    $fieldNames = @('EventID', 'action', 'srcip', 'dstip', 'user', 'srcintf', 'dstintf')
    $fieldDiff = @{}

    foreach ($fieldName in $fieldNames) {
        $p1Vals = @{}; $p2Vals = @{}

        foreach ($e in $Period1) {
            if ($e.Extra -and $e.Extra[$fieldName]) {
                $v = [string]$e.Extra[$fieldName]
                if (-not $p1Vals.ContainsKey($v)) { $p1Vals[$v] = 0 }
                $p1Vals[$v]++
            }
        }
        foreach ($e in $Period2) {
            if ($e.Extra -and $e.Extra[$fieldName]) {
                $v = [string]$e.Extra[$fieldName]
                if (-not $p2Vals.ContainsKey($v)) { $p2Vals[$v] = 0 }
                $p2Vals[$v]++
            }
        }

        # Skip field if no data in either period
        if ($p1Vals.Count -eq 0 -and $p2Vals.Count -eq 0) { continue }

        $allKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($k in $p1Vals.Keys) { $allKeys.Add($k) | Out-Null }
        foreach ($k in $p2Vals.Keys) { $allKeys.Add($k) | Out-Null }

        $newValues = [System.Collections.Generic.List[string]]::new()
        $disappearedValues = [System.Collections.Generic.List[string]]::new()
        $topFieldChanges = [System.Collections.Generic.List[object]]::new()

        foreach ($v in $allKeys) {
            $c1 = if ($p1Vals.ContainsKey($v)) { $p1Vals[$v] } else { 0 }
            $c2 = if ($p2Vals.ContainsKey($v)) { $p2Vals[$v] } else { 0 }

            if ($c1 -eq 0 -and $c2 -gt 0) { $newValues.Add($v) }
            elseif ($c1 -gt 0 -and $c2 -eq 0) { $disappearedValues.Add($v) }

            $topFieldChanges.Add(@{ Value = $v; P1Count = $c1; P2Count = $c2; Delta = $c2 - $c1 })
        }

        $sortedFieldChanges = @($topFieldChanges | Sort-Object { [Math]::Abs($_.Delta) } -Descending | Select-Object -First 15)

        $fieldDiff[$fieldName] = @{
            NewValues         = @($newValues)
            DisappearedValues = @($disappearedValues)
            TopChanges        = $sortedFieldChanges
        }
    }

    # ── 4. Hourly distribution comparison ────────────────────────────────────
    $p1Hours = @(0) * 24
    $p2Hours = @(0) * 24
    $hourDeltas = @(0) * 24

    foreach ($e in $Period1) {
        if ($e.Timestamp -ne [datetime]::MinValue) {
            $p1Hours[$e.Timestamp.Hour]++
        }
    }
    foreach ($e in $Period2) {
        if ($e.Timestamp -ne [datetime]::MinValue) {
            $p2Hours[$e.Timestamp.Hour]++
        }
    }
    for ($h = 0; $h -lt 24; $h++) {
        $hourDeltas[$h] = $p2Hours[$h] - $p1Hours[$h]
    }

    $hourlyDiff = @{
        P1Counts = $p1Hours
        P2Counts = $p2Hours
        Deltas   = $hourDeltas
    }

    return @{
        Period1Label = $Period1Label
        Period2Label = $Period2Label
        VolumeDiff   = $volumeDiff
        SourceDiff   = $sourceDiff
        FieldDiff    = $fieldDiff
        HourlyDiff   = $hourlyDiff
    }
}

function Compare-Configurations {
    param(
        [System.Collections.Generic.List[object]]$Config1,
        [System.Collections.Generic.List[object]]$Config2,
        [string]$Label1 = "Config 1",
        [string]$Label2 = "Config 2"
    )

    if (-not $Config1) { $Config1 = [System.Collections.Generic.List[object]]::new() }
    if (-not $Config2) { $Config2 = [System.Collections.Generic.List[object]]::new() }

    # Build lookup maps: Section + edit-block-id -> entry and settings
    $map1 = @{}
    $map2 = @{}

    foreach ($entry in $Config1) {
        $section = if ($entry.Extra -and $entry.Extra['Section']) { [string]$entry.Extra['Section'] } else { "" }
        # Extract edit block id from the Source field (the last section component)
        # and the entry's Extra keys for settings
        $blockId = ""
        if ($entry.Extra -and $entry.Extra['name']) {
            $blockId = [string]$entry.Extra['name']
        } elseif ($entry.Message -match '^\[.+?\s+(\S+)\]') {
            $blockId = $Matches[1]
        }
        $key = "$section|$blockId"
        $map1[$key] = $entry
    }

    foreach ($entry in $Config2) {
        $section = if ($entry.Extra -and $entry.Extra['Section']) { [string]$entry.Extra['Section'] } else { "" }
        $blockId = ""
        if ($entry.Extra -and $entry.Extra['name']) {
            $blockId = [string]$entry.Extra['name']
        } elseif ($entry.Message -match '^\[.+?\s+(\S+)\]') {
            $blockId = $Matches[1]
        }
        $key = "$section|$blockId"
        $map2[$key] = $entry
    }

    $added = [System.Collections.Generic.List[object]]::new()
    $removed = [System.Collections.Generic.List[object]]::new()
    $modified = [System.Collections.Generic.List[object]]::new()
    $policyChanges = [System.Collections.Generic.List[object]]::new()

    # Collect all unique keys
    $allKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($k in $map1.Keys) { $allKeys.Add($k) | Out-Null }
    foreach ($k in $map2.Keys) { $allKeys.Add($k) | Out-Null }

    foreach ($key in $allKeys) {
        $inC1 = $map1.ContainsKey($key)
        $inC2 = $map2.ContainsKey($key)

        $parts = $key.Split('|', 2)
        $section = $parts[0]
        $blockId = if ($parts.Count -gt 1) { $parts[1] } else { "" }

        if (-not $inC1 -and $inC2) {
            # Added in Config2
            $e2 = $map2[$key]
            $added.Add(@{
                Section = $section
                BlockId = $blockId
                Message = $e2.Message
                Entry   = $e2
            })
        } elseif ($inC1 -and -not $inC2) {
            # Removed from Config2
            $e1 = $map1[$key]
            $removed.Add(@{
                Section = $section
                BlockId = $blockId
                Message = $e1.Message
                Entry   = $e1
            })
        } else {
            # Present in both — compare settings
            $e1 = $map1[$key]
            $e2 = $map2[$key]

            $extra1 = if ($e1.Extra) { $e1.Extra } else { @{} }
            $extra2 = if ($e2.Extra) { $e2.Extra } else { @{} }

            # Collect all setting keys (skip metadata keys)
            $metaKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($mk in @('Section', 'SourceFile', 'SourceFormat', 'Config_Model', 'Config_Firmware', 'Config_BuildNo')) {
                $metaKeys.Add($mk) | Out-Null
            }

            $settingKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($k in $extra1.Keys) {
                if (-not $metaKeys.Contains($k)) { $settingKeys.Add($k) | Out-Null }
            }
            foreach ($k in $extra2.Keys) {
                if (-not $metaKeys.Contains($k)) { $settingKeys.Add($k) | Out-Null }
            }

            $isPolicy = $section -match 'firewall policy'
            $blockModified = $false

            foreach ($sk in $settingKeys) {
                $v1 = if ($extra1.ContainsKey($sk)) { [string]$extra1[$sk] } else { $null }
                $v2 = if ($extra2.ContainsKey($sk)) { [string]$extra2[$sk] } else { $null }

                # Determine if setting has changed
                $changed = $false
                if ($null -eq $v1 -and $null -ne $v2) { $changed = $true }
                elseif ($null -ne $v1 -and $null -eq $v2) { $changed = $true }
                elseif ($null -ne $v1 -and $null -ne $v2 -and $v1 -ne $v2) { $changed = $true }

                if ($changed) {
                    $blockModified = $true
                    $changeEntry = @{
                        Section  = $section
                        BlockId  = $blockId
                        Setting  = $sk
                        OldValue = if ($null -ne $v1) { $v1 } else { "(not set)" }
                        NewValue = if ($null -ne $v2) { $v2 } else { "(removed)" }
                    }
                    $modified.Add($changeEntry)

                    # Track firewall policy changes specifically
                    if ($isPolicy -and $sk -in @('srcaddr', 'dstaddr', 'action', 'service', 'srcintf', 'dstintf',
                            'status', 'logtraffic', 'utm-status', 'av-profile', 'webfilter-profile',
                            'ips-sensor', 'application-list', 'ssl-ssh-profile', 'schedule')) {
                        $policyChanges.Add(@{
                            PolicyId = $blockId
                            Setting  = $sk
                            OldValue = if ($null -ne $v1) { $v1 } else { "(not set)" }
                            NewValue = if ($null -ne $v2) { $v2 } else { "(removed)" }
                            Section  = $section
                        })
                    }
                }
            }
        }
    }

    return @{
        Label1        = $Label1
        Label2        = $Label2
        Added         = @($added)
        Removed       = @($removed)
        Modified      = @($modified)
        PolicyChanges = @($policyChanges)
        Summary       = @{
            AddedCount    = $added.Count
            RemovedCount  = $removed.Count
            ModifiedCount = $modified.Count
        }
    }
}

function Show-DiffDialog {
    param($Results, [string]$DiffType = "Periods")

    if (-not $Results) { return }

    if ($Script:UseConsole) {
        Write-DiffTable -Results $Results -DiffType $DiffType
        return
    }

    try {
        $dlg = [System.Windows.Forms.Form]::new()
        $dlg.Text = if ($DiffType -eq 'Configurations') { "Configuration Diff Results" } else { "Period Comparison Results" }
        $dlg.Size = [System.Drawing.Size]::new(950, 650)
        $dlg.StartPosition = "CenterParent"
        $t = $Script:Themes[$Script:State.ActiveTheme]
        $dlg.BackColor = $t.FormBack
        $dlg.ForeColor = $t.FormFore

        $tabs = [System.Windows.Forms.TabControl]::new()
        $tabs.Dock = "Fill"

        if ($DiffType -eq 'Periods') {
            # ── Volume tab ──
            $volTab = [System.Windows.Forms.TabPage]::new("Volume")
            $volRtb = New-DiffRichTextBox -Theme $t
            $volText = [System.Text.StringBuilder]::new()
            $vd = $Results.VolumeDiff
            $volText.AppendLine("VOLUME COMPARISON") | Out-Null
            $volText.AppendLine("$([string][char]0x2500 * 60)") | Out-Null
            $volText.AppendLine("") | Out-Null
            $arrow = if ($vd.Delta -gt 0) { [string][char]0x2191 } elseif ($vd.Delta -lt 0) { [string][char]0x2193 } else { "=" }
            $volText.AppendLine("  $($Results.Period1Label): $($vd.Period1Count) events") | Out-Null
            $volText.AppendLine("  $($Results.Period2Label): $($vd.Period2Count) events") | Out-Null
            $volText.AppendLine("  Change: $arrow $($vd.Delta) ($($vd.PercentChange)%)") | Out-Null
            $volText.AppendLine("") | Out-Null
            $volText.AppendLine("  By Severity:") | Out-Null
            $volText.AppendLine("  {0,-12} {1,8} {2,8} {3,8} {4,8}" -f "Level", $Results.Period1Label, $Results.Period2Label, "Delta", "%Change") | Out-Null
            $volText.AppendLine("  $([string][char]0x2500 * 54)") | Out-Null
            foreach ($lv in @('CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG', 'TRACE', 'UNKNOWN')) {
                $s = $vd.BySeverity[$lv]
                if ($s.P1 -gt 0 -or $s.P2 -gt 0) {
                    $volText.AppendLine("  {0,-12} {1,8} {2,8} {3,+8} {4,7}%" -f $lv, $s.P1, $s.P2, $s.Delta, $s.PctChange) | Out-Null
                }
            }
            $volRtb.Text = $volText.ToString()
            $volTab.Controls.Add($volRtb)
            $tabs.TabPages.Add($volTab)

            # ── Sources tab ──
            $srcTab = [System.Windows.Forms.TabPage]::new("Sources")
            $srcRtb = New-DiffRichTextBox -Theme $t
            $srcText = [System.Text.StringBuilder]::new()
            $sd = $Results.SourceDiff
            $srcText.AppendLine("SOURCE DISTRIBUTION") | Out-Null
            $srcText.AppendLine("$([string][char]0x2500 * 60)") | Out-Null
            if ($sd.NewSources.Count -gt 0) {
                $srcText.AppendLine("") | Out-Null
                $srcText.AppendLine("  NEW SOURCES ($($sd.NewSources.Count)):") | Out-Null
                foreach ($ns in $sd.NewSources) { $srcText.AppendLine("    + $ns") | Out-Null }
            }
            if ($sd.DisappearedSources.Count -gt 0) {
                $srcText.AppendLine("") | Out-Null
                $srcText.AppendLine("  DISAPPEARED SOURCES ($($sd.DisappearedSources.Count)):") | Out-Null
                foreach ($ds in $sd.DisappearedSources) { $srcText.AppendLine("    - $ds") | Out-Null }
            }
            if ($sd.TopChanges.Count -gt 0) {
                $srcText.AppendLine("") | Out-Null
                $srcText.AppendLine("  TOP CHANGES:") | Out-Null
                $srcText.AppendLine("  {0,-35} {1,8} {2,8} {3,8}" -f "Source", "P1", "P2", "Delta") | Out-Null
                $srcText.AppendLine("  $([string][char]0x2500 * 62)") | Out-Null
                foreach ($sc in $sd.TopChanges) {
                    $name = if ($sc.Source.Length -gt 35) { $sc.Source.Substring(0, 32) + "..." } else { $sc.Source }
                    $srcText.AppendLine("  {0,-35} {1,8} {2,8} {3,+8}" -f $name, $sc.P1Count, $sc.P2Count, $sc.Delta) | Out-Null
                }
            }
            $srcRtb.Text = $srcText.ToString()
            $srcTab.Controls.Add($srcRtb)
            $tabs.TabPages.Add($srcTab)

            # ── Fields tab ──
            $fldTab = [System.Windows.Forms.TabPage]::new("Fields")
            $fldRtb = New-DiffRichTextBox -Theme $t
            $fldText = [System.Text.StringBuilder]::new()
            $fldText.AppendLine("FIELD VALUE CHANGES") | Out-Null
            $fldText.AppendLine("$([string][char]0x2500 * 60)") | Out-Null
            foreach ($fieldName in $Results.FieldDiff.Keys) {
                $fd = $Results.FieldDiff[$fieldName]
                $fldText.AppendLine("") | Out-Null
                $fldText.AppendLine("  [$fieldName]") | Out-Null
                if ($fd.NewValues.Count -gt 0) {
                    $fldText.AppendLine("    New: $($fd.NewValues.Count) values") | Out-Null
                    foreach ($nv in ($fd.NewValues | Select-Object -First 10)) { $fldText.AppendLine("      + $nv") | Out-Null }
                    if ($fd.NewValues.Count -gt 10) { $fldText.AppendLine("      ... and $($fd.NewValues.Count - 10) more") | Out-Null }
                }
                if ($fd.DisappearedValues.Count -gt 0) {
                    $fldText.AppendLine("    Disappeared: $($fd.DisappearedValues.Count) values") | Out-Null
                    foreach ($dv in ($fd.DisappearedValues | Select-Object -First 10)) { $fldText.AppendLine("      - $dv") | Out-Null }
                    if ($fd.DisappearedValues.Count -gt 10) { $fldText.AppendLine("      ... and $($fd.DisappearedValues.Count - 10) more") | Out-Null }
                }
                if ($fd.TopChanges.Count -gt 0) {
                    $fldText.AppendLine("    {0,-30} {1,8} {2,8} {3,8}" -f "Value", "P1", "P2", "Delta") | Out-Null
                    foreach ($fc in $fd.TopChanges) {
                        $val = if ($fc.Value.Length -gt 30) { $fc.Value.Substring(0, 27) + "..." } else { $fc.Value }
                        $fldText.AppendLine("    {0,-30} {1,8} {2,8} {3,+8}" -f $val, $fc.P1Count, $fc.P2Count, $fc.Delta) | Out-Null
                    }
                }
            }
            $fldRtb.Text = $fldText.ToString()
            $fldTab.Controls.Add($fldRtb)
            $tabs.TabPages.Add($fldTab)

            # ── Hourly tab ──
            $hrTab = [System.Windows.Forms.TabPage]::new("Hourly")
            $hrRtb = New-DiffRichTextBox -Theme $t
            $hrText = [System.Text.StringBuilder]::new()
            $hd = $Results.HourlyDiff
            $hrText.AppendLine("HOURLY DISTRIBUTION COMPARISON") | Out-Null
            $hrText.AppendLine("$([string][char]0x2500 * 60)") | Out-Null
            $hrText.AppendLine("") | Out-Null
            $hrText.AppendLine("  {0,-6} {1,8} {2,8} {3,8}" -f "Hour", $Results.Period1Label, $Results.Period2Label, "Delta") | Out-Null
            $hrText.AppendLine("  $([string][char]0x2500 * 38)") | Out-Null
            $maxHour = 1
            for ($h = 0; $h -lt 24; $h++) {
                if ($hd.P1Counts[$h] -gt $maxHour) { $maxHour = $hd.P1Counts[$h] }
                if ($hd.P2Counts[$h] -gt $maxHour) { $maxHour = $hd.P2Counts[$h] }
            }
            for ($h = 0; $h -lt 24; $h++) {
                $marker = if ($h -lt 7 -or $h -ge 18) { "*" } else { " " }
                $bar1Len = [Math]::Min(15, [Math]::Round(($hd.P1Counts[$h] / $maxHour) * 15))
                $bar2Len = [Math]::Min(15, [Math]::Round(($hd.P2Counts[$h] / $maxHour) * 15))
                $bar1 = [string][char]0x2588 * $bar1Len
                $bar2 = [string][char]0x2591 * $bar2Len
                $hrText.AppendLine("  {0:D2}:00{1} {2,8} {3,8} {4,+8}  {5}{6}" -f $h, $marker, $hd.P1Counts[$h], $hd.P2Counts[$h], $hd.Deltas[$h], $bar1, $bar2) | Out-Null
            }
            $hrText.AppendLine("") | Out-Null
            $hrText.AppendLine("  $([string][char]0x2588) = $($Results.Period1Label)   $([string][char]0x2591) = $($Results.Period2Label)   * = after hours") | Out-Null
            $hrRtb.Text = $hrText.ToString()
            $hrTab.Controls.Add($hrRtb)
            $tabs.TabPages.Add($hrTab)

        } elseif ($DiffType -eq 'Configurations') {
            # ── Summary tab ──
            $sumTab = [System.Windows.Forms.TabPage]::new("Summary")
            $sumRtb = New-DiffRichTextBox -Theme $t
            $sumText = [System.Text.StringBuilder]::new()
            $sumText.AppendLine("CONFIGURATION DIFF SUMMARY") | Out-Null
            $sumText.AppendLine("$([string][char]0x2500 * 60)") | Out-Null
            $sumText.AppendLine("") | Out-Null
            $sumText.AppendLine("  $($Results.Label1) vs $($Results.Label2)") | Out-Null
            $sumText.AppendLine("") | Out-Null
            $sumText.AppendLine("  Added sections/blocks:    $($Results.Summary.AddedCount)") | Out-Null
            $sumText.AppendLine("  Removed sections/blocks:  $($Results.Summary.RemovedCount)") | Out-Null
            $sumText.AppendLine("  Modified settings:        $($Results.Summary.ModifiedCount)") | Out-Null
            $sumText.AppendLine("  Firewall policy changes:  $($Results.PolicyChanges.Count)") | Out-Null
            $sumRtb.Text = $sumText.ToString()
            $sumTab.Controls.Add($sumRtb)
            $tabs.TabPages.Add($sumTab)

            # ── Added tab ──
            if ($Results.Added.Count -gt 0) {
                $addTab = [System.Windows.Forms.TabPage]::new("Added ($($Results.Added.Count))")
                $addRtb = New-DiffRichTextBox -Theme $t
                $addText = [System.Text.StringBuilder]::new()
                $addText.AppendLine("ADDED SECTIONS/BLOCKS") | Out-Null
                $addText.AppendLine("$([string][char]0x2500 * 60)") | Out-Null
                foreach ($a in $Results.Added) {
                    $addText.AppendLine("") | Out-Null
                    $addText.AppendLine("  + [$($a.Section)] $($a.BlockId)") | Out-Null
                    if ($a.Message) { $addText.AppendLine("    $($a.Message)") | Out-Null }
                }
                $addRtb.Text = $addText.ToString()
                $addTab.Controls.Add($addRtb)
                $tabs.TabPages.Add($addTab)
            }

            # ── Removed tab ──
            if ($Results.Removed.Count -gt 0) {
                $remTab = [System.Windows.Forms.TabPage]::new("Removed ($($Results.Removed.Count))")
                $remRtb = New-DiffRichTextBox -Theme $t
                $remText = [System.Text.StringBuilder]::new()
                $remText.AppendLine("REMOVED SECTIONS/BLOCKS") | Out-Null
                $remText.AppendLine("$([string][char]0x2500 * 60)") | Out-Null
                foreach ($r in $Results.Removed) {
                    $remText.AppendLine("") | Out-Null
                    $remText.AppendLine("  - [$($r.Section)] $($r.BlockId)") | Out-Null
                    if ($r.Message) { $remText.AppendLine("    $($r.Message)") | Out-Null }
                }
                $remRtb.Text = $remText.ToString()
                $remTab.Controls.Add($remRtb)
                $tabs.TabPages.Add($remTab)
            }

            # ── Modified tab ──
            if ($Results.Modified.Count -gt 0) {
                $modTab = [System.Windows.Forms.TabPage]::new("Modified ($($Results.Modified.Count))")
                $modRtb = New-DiffRichTextBox -Theme $t
                $modText = [System.Text.StringBuilder]::new()
                $modText.AppendLine("MODIFIED SETTINGS") | Out-Null
                $modText.AppendLine("$([string][char]0x2500 * 60)") | Out-Null
                # Group modifications by section+block for readability
                $modGroups = @{}
                foreach ($m in $Results.Modified) {
                    $gKey = "$($m.Section)|$($m.BlockId)"
                    if (-not $modGroups.ContainsKey($gKey)) {
                        $modGroups[$gKey] = [System.Collections.Generic.List[object]]::new()
                    }
                    $modGroups[$gKey].Add($m)
                }
                foreach ($gKey in $modGroups.Keys) {
                    $parts = $gKey.Split('|', 2)
                    $modText.AppendLine("") | Out-Null
                    $modText.AppendLine("  [$($parts[0])] $($parts[1])") | Out-Null
                    foreach ($m in $modGroups[$gKey]) {
                        $modText.AppendLine("    $($m.Setting):") | Out-Null
                        $modText.AppendLine("      - $($m.OldValue)") | Out-Null
                        $modText.AppendLine("      + $($m.NewValue)") | Out-Null
                    }
                }
                $modRtb.Text = $modText.ToString()
                $modTab.Controls.Add($modRtb)
                $tabs.TabPages.Add($modTab)
            }

            # ── Policy Changes tab ──
            if ($Results.PolicyChanges.Count -gt 0) {
                $polTab = [System.Windows.Forms.TabPage]::new("Policies ($($Results.PolicyChanges.Count))")
                $polGrid = [System.Windows.Forms.DataGridView]::new()
                $polGrid.Dock = "Fill"; $polGrid.ReadOnly = $true; $polGrid.AllowUserToAddRows = $false
                $polGrid.BackgroundColor = $t.GridBack
                $polGrid.DefaultCellStyle.BackColor = $t.GridBack; $polGrid.DefaultCellStyle.ForeColor = $t.FormFore
                $polGrid.ColumnHeadersDefaultCellStyle.BackColor = $t.GridBack
                $polGrid.ColumnHeadersDefaultCellStyle.ForeColor = $t.FormFore
                $polGrid.EnableHeadersVisualStyles = $false
                $polGrid.Columns.Add("PolicyId", "Policy ID") | Out-Null
                $polGrid.Columns.Add("Setting", "Setting") | Out-Null
                $polGrid.Columns.Add("OldValue", "Old Value") | Out-Null
                $polGrid.Columns.Add("NewValue", "New Value") | Out-Null

                foreach ($pc in $Results.PolicyChanges) {
                    $rowIdx = $polGrid.Rows.Add($pc.PolicyId, $pc.Setting, $pc.OldValue, $pc.NewValue)
                    # Color code: action changes are highlighted
                    if ($pc.Setting -eq 'action') {
                        $polGrid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::OrangeRed
                    } elseif ($pc.Setting -match 'status|logtraffic') {
                        $polGrid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Goldenrod
                    }
                }
                $polGrid.AutoResizeColumns()
                $polTab.Controls.Add($polGrid)
                $tabs.TabPages.Add($polTab)
            }
        }

        $dlg.Controls.Add($tabs)
        $dlg.ShowDialog($Script:UI.Form) | Out-Null
        $dlg.Dispose()
    } catch {
        Write-Log "Failed to show diff dialog: $_" -Level ERROR
    }
}

function New-DiffRichTextBox {
    param($Theme)
    $rtb = [System.Windows.Forms.RichTextBox]::new()
    $rtb.Dock = "Fill"
    $rtb.ReadOnly = $true
    $rtb.Font = [System.Drawing.Font]::new("Consolas", 9.5)
    $rtb.BackColor = $Theme.DetailBack
    $rtb.ForeColor = $Theme.DetailFore
    $rtb.WordWrap = $false
    return $rtb
}

function Write-DiffTable {
    param($Results, [string]$DiffType = "Periods")

    $r = $Script:ANSIReset
    $ct = $Script:ConsoleThemes[$Script:State.ActiveTheme]

    if ($DiffType -eq 'Periods') {
        # ── Volume ──
        Write-Host "`n$($ct.Title)Period Comparison: $($Results.Period1Label) vs $($Results.Period2Label)$r"
        Write-Host "$($ct.Border)$([string][char]0x2500 * 70)$r"

        $vd = $Results.VolumeDiff
        $arrow = if ($vd.Delta -gt 0) { [string][char]0x2191 } elseif ($vd.Delta -lt 0) { [string][char]0x2193 } else { "=" }
        $deltaColor = if ($vd.Delta -gt 0) { $ct.ERROR } elseif ($vd.Delta -lt 0) { $ct.INFO } else { $ct.Dim }
        Write-Host "$($ct.Header)Volume:$r  $($Results.Period1Label): $($ct.Count)$($vd.Period1Count)$r  $($Results.Period2Label): $($ct.Count)$($vd.Period2Count)$r  Change: $deltaColor$arrow $($vd.Delta) ($($vd.PercentChange)%)$r"
        Write-Host ""

        Write-Host "$($ct.Header)Severity Breakdown:$r"
        Write-Host "$($ct.Dim)  {0,-12} {1,10} {2,10} {3,8} {4,8}$r" -f "Level", $Results.Period1Label, $Results.Period2Label, "Delta", "%Change"
        Write-Host "$($ct.Border)  $([string][char]0x2500 * 54)$r"
        foreach ($lv in @('CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG', 'TRACE', 'UNKNOWN')) {
            $s = $vd.BySeverity[$lv]
            if ($s.P1 -gt 0 -or $s.P2 -gt 0) {
                $lvColor = if ($ct.ContainsKey($lv)) { $ct[$lv] } else { $ct.INFO }
                $dColor = if ($s.Delta -gt 0) { $ct.ERROR } elseif ($s.Delta -lt 0) { $ct.INFO } else { $ct.Dim }
                Write-Host "  $lvColor{0,-12}$r {1,10} {2,10} $dColor{3,+8}$r {4,7}%" -f $lv, $s.P1, $s.P2, $s.Delta, $s.PctChange
            }
        }

        # ── Sources ──
        $sd = $Results.SourceDiff
        if ($sd.NewSources.Count -gt 0) {
            Write-Host "`n$($ct.Header)New Sources ($($sd.NewSources.Count)):$r"
            foreach ($ns in $sd.NewSources) { Write-Host "  $(Get-AnsiCode '32m')+ $ns$r" }
        }
        if ($sd.DisappearedSources.Count -gt 0) {
            Write-Host "`n$($ct.Header)Disappeared Sources ($($sd.DisappearedSources.Count)):$r"
            foreach ($ds in $sd.DisappearedSources) { Write-Host "  $(Get-AnsiCode '31m')- $ds$r" }
        }
        if ($sd.TopChanges.Count -gt 0) {
            Write-Host "`n$($ct.Header)Top Source Changes:$r"
            Write-Host "$($ct.Dim)  {0,-35} {1,8} {2,8} {3,8}$r" -f "Source", "P1", "P2", "Delta"
            Write-Host "$($ct.Border)  $([string][char]0x2500 * 62)$r"
            foreach ($sc in $sd.TopChanges) {
                $name = if ($sc.Source.Length -gt 35) { $sc.Source.Substring(0, 32) + "..." } else { $sc.Source }
                $dColor = if ($sc.Delta -gt 0) { $ct.ERROR } elseif ($sc.Delta -lt 0) { $ct.INFO } else { $ct.Dim }
                Write-Host "  $($ct.INFO){0,-35}$r {1,8} {2,8} $dColor{3,+8}$r" -f $name, $sc.P1Count, $sc.P2Count, $sc.Delta
            }
        }

        # ── Fields ──
        foreach ($fieldName in $Results.FieldDiff.Keys) {
            $fd = $Results.FieldDiff[$fieldName]
            Write-Host "`n$($ct.Header)Field: $fieldName$r"
            if ($fd.NewValues.Count -gt 0) {
                $showNew = $fd.NewValues | Select-Object -First 10
                Write-Host "  $(Get-AnsiCode '32m')New values ($($fd.NewValues.Count)):$r"
                foreach ($nv in $showNew) { Write-Host "    + $nv" }
                if ($fd.NewValues.Count -gt 10) { Write-Host "    ... and $($fd.NewValues.Count - 10) more" }
            }
            if ($fd.DisappearedValues.Count -gt 0) {
                $showDis = $fd.DisappearedValues | Select-Object -First 10
                Write-Host "  $(Get-AnsiCode '31m')Disappeared values ($($fd.DisappearedValues.Count)):$r"
                foreach ($dv in $showDis) { Write-Host "    - $dv" }
                if ($fd.DisappearedValues.Count -gt 10) { Write-Host "    ... and $($fd.DisappearedValues.Count - 10) more" }
            }
            if ($fd.TopChanges.Count -gt 0) {
                Write-Host "$($ct.Dim)    {0,-30} {1,8} {2,8} {3,8}$r" -f "Value", "P1", "P2", "Delta"
                foreach ($fc in $fd.TopChanges) {
                    $val = if ($fc.Value.Length -gt 30) { $fc.Value.Substring(0, 27) + "..." } else { $fc.Value }
                    $dColor = if ($fc.Delta -gt 0) { $ct.ERROR } elseif ($fc.Delta -lt 0) { $ct.INFO } else { $ct.Dim }
                    Write-Host "    $($ct.INFO){0,-30}$r {1,8} {2,8} $dColor{3,+8}$r" -f $val, $fc.P1Count, $fc.P2Count, $fc.Delta
                }
            }
        }

        # ── Hourly ──
        $hd = $Results.HourlyDiff
        $hasHourly = $false
        for ($h = 0; $h -lt 24; $h++) { if ($hd.P1Counts[$h] -gt 0 -or $hd.P2Counts[$h] -gt 0) { $hasHourly = $true; break } }
        if ($hasHourly) {
            Write-Host "`n$($ct.Header)Hourly Distribution:$r"
            Write-Host "$($ct.Dim)  {0,-6} {1,8} {2,8} {3,8}$r" -f "Hour", $Results.Period1Label, $Results.Period2Label, "Delta"
            Write-Host "$($ct.Border)  $([string][char]0x2500 * 38)$r"
            $maxH = 1
            for ($h = 0; $h -lt 24; $h++) {
                if ($hd.P1Counts[$h] -gt $maxH) { $maxH = $hd.P1Counts[$h] }
                if ($hd.P2Counts[$h] -gt $maxH) { $maxH = $hd.P2Counts[$h] }
            }
            for ($h = 0; $h -lt 24; $h++) {
                $hourColor = if ($h -lt 7 -or $h -ge 18) { $ct.WARNING } else { $ct.INFO }
                $dColor = if ($hd.Deltas[$h] -gt 0) { $ct.ERROR } elseif ($hd.Deltas[$h] -lt 0) { $ct.INFO } else { $ct.Dim }
                $bar1Len = [Math]::Min(20, [Math]::Round(($hd.P1Counts[$h] / $maxH) * 20))
                $bar2Len = [Math]::Min(20, [Math]::Round(($hd.P2Counts[$h] / $maxH) * 20))
                $bar1 = [string][char]0x2588 * $bar1Len
                $bar2 = [string][char]0x2591 * $bar2Len
                Write-Host "  $hourColor{0:D2}:00$r  {1,8} {2,8} $dColor{3,+8}$r  $($ct.INFO){4}$($ct.Dim){5}$r" -f $h, $hd.P1Counts[$h], $hd.P2Counts[$h], $hd.Deltas[$h], $bar1, $bar2
            }
        }

        Write-Host ""

    } elseif ($DiffType -eq 'Configurations') {
        Write-Host "`n$($ct.Title)Configuration Diff: $($Results.Label1) vs $($Results.Label2)$r"
        Write-Host "$($ct.Border)$([string][char]0x2500 * 70)$r"
        Write-Host ""
        Write-Host "$($ct.Header)Summary:$r  Added: $(Get-AnsiCode '32m')$($Results.Summary.AddedCount)$r  Removed: $(Get-AnsiCode '31m')$($Results.Summary.RemovedCount)$r  Modified: $(Get-AnsiCode '33m')$($Results.Summary.ModifiedCount)$r  Policy changes: $($ct.Count)$($Results.PolicyChanges.Count)$r"

        # Added
        if ($Results.Added.Count -gt 0) {
            Write-Host "`n$($ct.Header)Added Sections/Blocks:$r"
            foreach ($a in $Results.Added) {
                Write-Host "  $(Get-AnsiCode '32m')+ [$($a.Section)] $($a.BlockId)$r"
                if ($a.Message) { Write-Host "    $($ct.Dim)$($a.Message)$r" }
            }
        }

        # Removed
        if ($Results.Removed.Count -gt 0) {
            Write-Host "`n$($ct.Header)Removed Sections/Blocks:$r"
            foreach ($rv in $Results.Removed) {
                Write-Host "  $(Get-AnsiCode '31m')- [$($rv.Section)] $($rv.BlockId)$r"
                if ($rv.Message) { Write-Host "    $($ct.Dim)$($rv.Message)$r" }
            }
        }

        # Modified — group by section+block
        if ($Results.Modified.Count -gt 0) {
            Write-Host "`n$($ct.Header)Modified Settings:$r"
            $modGroups = @{}
            foreach ($m in $Results.Modified) {
                $gKey = "$($m.Section)|$($m.BlockId)"
                if (-not $modGroups.ContainsKey($gKey)) {
                    $modGroups[$gKey] = [System.Collections.Generic.List[object]]::new()
                }
                $modGroups[$gKey].Add($m)
            }
            foreach ($gKey in $modGroups.Keys) {
                $parts = $gKey.Split('|', 2)
                Write-Host "  $($ct.INFO)[$($parts[0])] $($parts[1])$r"
                foreach ($m in $modGroups[$gKey]) {
                    Write-Host "    $(Get-AnsiCode '33m')$($m.Setting):$r"
                    Write-Host "      $(Get-AnsiCode '31m')- $($m.OldValue)$r"
                    Write-Host "      $(Get-AnsiCode '32m')+ $($m.NewValue)$r"
                }
            }
        }

        # Policy changes
        if ($Results.PolicyChanges.Count -gt 0) {
            Write-Host "`n$($ct.Header)Firewall Policy Changes:$r"
            Write-Host "$($ct.Dim)  {0,-12} {1,-20} {2,-25} {3,-25}$r" -f "Policy ID", "Setting", "Old Value", "New Value"
            Write-Host "$($ct.Border)  $([string][char]0x2500 * 85)$r"
            foreach ($pc in $Results.PolicyChanges) {
                $pcColor = if ($pc.Setting -eq 'action') { $ct.ERROR } elseif ($pc.Setting -match 'status|logtraffic') { $ct.WARNING } else { $ct.INFO }
                $oldTrunc = if ($pc.OldValue.Length -gt 25) { $pc.OldValue.Substring(0, 22) + "..." } else { $pc.OldValue }
                $newTrunc = if ($pc.NewValue.Length -gt 25) { $pc.NewValue.Substring(0, 22) + "..." } else { $pc.NewValue }
                Write-Host "  $pcColor{0,-12} {1,-20}$r $(Get-AnsiCode '31m'){2,-25}$r $(Get-AnsiCode '32m'){3,-25}$r" -f $pc.PolicyId, $pc.Setting, $oldTrunc, $newTrunc
            }
        }

        Write-Host ""
    }
}

function Compare-EntryLists {
    param(
        [System.Collections.Generic.List[object]]$List1,
        [System.Collections.Generic.List[object]]$List2,
        [string]$GroupByField
    )

    if (-not $List1) { $List1 = [System.Collections.Generic.List[object]]::new() }
    if (-not $List2) { $List2 = [System.Collections.Generic.List[object]]::new() }

    # Group List1 entries by the specified field
    $groups1 = @{}
    foreach ($entry in $List1) {
        $val = $null
        # Check Extra fields first, then top-level properties
        if ($entry.Extra -and $entry.Extra[$GroupByField]) {
            $val = [string]$entry.Extra[$GroupByField]
        } elseif ($entry.PSObject.Properties[$GroupByField]) {
            $val = [string]$entry.$GroupByField
        }
        if (-not $val) { continue }

        if (-not $groups1.ContainsKey($val)) {
            $groups1[$val] = [System.Collections.Generic.List[object]]::new()
        }
        $groups1[$val].Add($entry)
    }

    # Group List2 entries by the specified field
    $groups2 = @{}
    foreach ($entry in $List2) {
        $val = $null
        if ($entry.Extra -and $entry.Extra[$GroupByField]) {
            $val = [string]$entry.Extra[$GroupByField]
        } elseif ($entry.PSObject.Properties[$GroupByField]) {
            $val = [string]$entry.$GroupByField
        }
        if (-not $val) { continue }

        if (-not $groups2.ContainsKey($val)) {
            $groups2[$val] = [System.Collections.Generic.List[object]]::new()
        }
        $groups2[$val].Add($entry)
    }

    # Collect all unique keys
    $allKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($k in $groups1.Keys) { $allKeys.Add($k) | Out-Null }
    foreach ($k in $groups2.Keys) { $allKeys.Add($k) | Out-Null }

    $newValues = [System.Collections.Generic.List[object]]::new()
    $disappearedValues = [System.Collections.Generic.List[object]]::new()
    $changedValues = [System.Collections.Generic.List[object]]::new()

    foreach ($key in $allKeys) {
        $inL1 = $groups1.ContainsKey($key)
        $inL2 = $groups2.ContainsKey($key)
        $count1 = if ($inL1) { $groups1[$key].Count } else { 0 }
        $count2 = if ($inL2) { $groups2[$key].Count } else { 0 }

        if (-not $inL1 -and $inL2) {
            $newValues.Add(@{
                Value   = $key
                Count   = $count2
                Entries = @($groups2[$key])
            })
        } elseif ($inL1 -and -not $inL2) {
            $disappearedValues.Add(@{
                Value   = $key
                Count   = $count1
                Entries = @($groups1[$key])
            })
        } else {
            $delta = $count2 - $count1
            if ($delta -ne 0) {
                $changedValues.Add(@{
                    Value    = $key
                    L1Count  = $count1
                    L2Count  = $count2
                    Delta    = $delta
                    L1Entries = @($groups1[$key])
                    L2Entries = @($groups2[$key])
                })
            }
        }
    }

    # Sort changed values by absolute delta descending
    $sortedChanged = @($changedValues | Sort-Object { [Math]::Abs($_.Delta) } -Descending)

    return @{
        GroupByField      = $GroupByField
        NewValues         = @($newValues)
        DisappearedValues = @($disappearedValues)
        ChangedValues     = $sortedChanged
        L1UniqueCount     = $groups1.Count
        L2UniqueCount     = $groups2.Count
    }
}
