# ═══════════════════════════════════════════════════════════════════════════════
# GUI WIDGETS — GDI+ rendered data visualizations for WinForms
# ═══════════════════════════════════════════════════════════════════════════════

# ── Common Helpers ────────────────────────────────────────────────────────────

function New-DoubleBufferedPanel {
    param([int]$Width, [int]$Height)
    $panel = [System.Windows.Forms.Panel]::new()
    $panel.Size = [System.Drawing.Size]::new($Width, $Height)
    $panel.GetType().GetProperty(
        "DoubleBuffered",
        [System.Reflection.BindingFlags]::Instance -bor [System.Reflection.BindingFlags]::NonPublic
    ).SetValue($panel, $true)
    return $panel
}

function Get-SeverityColor {
    param([string]$Level)
    if ($Script:Themes -and $Script:State -and $Script:State.ActiveTheme) {
        $t = $Script:Themes[$Script:State.ActiveTheme]
        if ($t -and $t.SeverityColors -and $t.SeverityColors.ContainsKey($Level)) {
            $c = $t.SeverityColors[$Level].Back
            if ($c) { return $c }
        }
    }
    switch ($Level) {
        "CRITICAL" { return [System.Drawing.Color]::DarkRed }
        "ERROR"    { return [System.Drawing.Color]::FromArgb(255, 68, 68) }
        "WARNING"  { return [System.Drawing.Color]::FromArgb(255, 140, 0) }
        "INFO"     { return [System.Drawing.Color]::DodgerBlue }
        "DEBUG"    { return [System.Drawing.Color]::Gray }
        "TRACE"    { return [System.Drawing.Color]::DarkGray }
        default    { return [System.Drawing.Color]::LightGray }
    }
}

function Get-ThemeColor {
    param([string]$PropertyName, [System.Drawing.Color]$Fallback)
    if ($Script:Themes -and $Script:State -and $Script:State.ActiveTheme) {
        $t = $Script:Themes[$Script:State.ActiveTheme]
        if ($t -and $t.ContainsKey($PropertyName) -and $t[$PropertyName]) {
            return $t[$PropertyName]
        }
    }
    return $Fallback
}

function Get-AccentColor {
    if ($Script:Themes -and $Script:State -and $Script:State.ActiveTheme) {
        $t = $Script:Themes[$Script:State.ActiveTheme]
        if ($t) { return $t.SelectionBack }
    }
    return [System.Drawing.Color]::FromArgb(0, 120, 215)
}

function Get-ContrastTextColor {
    param([System.Drawing.Color]$Background)
    $brightness = ($Background.R * 299 + $Background.G * 587 + $Background.B * 114) / 1000
    if ($brightness -gt 128) { return [System.Drawing.Color]::FromArgb(30, 30, 30) }
    return [System.Drawing.Color]::FromArgb(240, 240, 240)
}

# ═══════════════════════════════════════════════════════════════════════════════
# WIDGET 1: Timeline Chart
# ═══════════════════════════════════════════════════════════════════════════════

function New-TimelineWidget {
    param(
        [int]$Width = 800,
        [int]$Height = 150,
        [System.Collections.Generic.List[object]]$Entries = $null
    )

    $panel = New-DoubleBufferedPanel -Width $Width -Height $Height
    $panel.Tag = @{ Entries = $Entries; HoverIndex = -1; HoverX = -1; HoverY = -1 }

    $panel.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit

        $bgColor   = Get-ThemeColor 'PanelBack' ([System.Drawing.Color]::FromArgb(35, 35, 35))
        $fgColor   = Get-ThemeColor 'FormFore'  ([System.Drawing.Color]::FromArgb(220, 220, 220))
        $gridColor = Get-ThemeColor 'GridLines' ([System.Drawing.Color]::FromArgb(70, 70, 70))
        $w = $sender.ClientSize.Width
        $h = $sender.ClientSize.Height

        # Background
        $g.Clear($bgColor)

        $data = $sender.Tag
        $entries = $data.Entries

        $labelFont = [System.Drawing.Font]::new("Segoe UI", 7.5)
        $titleFont = [System.Drawing.Font]::new("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
        $fgBrush   = [System.Drawing.SolidBrush]::new($fgColor)
        $gridPen   = [System.Drawing.Pen]::new($gridColor, 1)

        $marginL = 10; $marginR = 15; $marginT = 25; $marginB = 40
        $chartW = $w - $marginL - $marginR
        $chartH = $h - $marginT - $marginB

        # Title
        $g.DrawString("Event Timeline", $titleFont, $fgBrush, [System.Drawing.PointF]::new($marginL, 4))

        if (-not $entries -or $entries.Count -eq 0) {
            $g.DrawString("No data available", $labelFont, $fgBrush,
                [System.Drawing.PointF]::new($w / 2 - 40, $h / 2 - 6))
            $labelFont.Dispose(); $titleFont.Dispose(); $fgBrush.Dispose(); $gridPen.Dispose()
            return
        }

        # Collect valid timestamps
        $validEntries = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $entries) {
            if ($entry.Timestamp -ne [datetime]::MinValue) {
                $validEntries.Add($entry)
            }
        }

        if ($validEntries.Count -eq 0) {
            $g.DrawString("No timestamped entries", $labelFont, $fgBrush,
                [System.Drawing.PointF]::new($w / 2 - 50, $h / 2 - 6))
            $labelFont.Dispose(); $titleFont.Dispose(); $fgBrush.Dispose(); $gridPen.Dispose()
            return
        }

        # Time range
        $minTime = $validEntries[0].Timestamp
        $maxTime = $validEntries[0].Timestamp
        foreach ($entry in $validEntries) {
            if ($entry.Timestamp -lt $minTime) { $minTime = $entry.Timestamp }
            if ($entry.Timestamp -gt $maxTime) { $maxTime = $entry.Timestamp }
        }
        $totalSpan = ($maxTime - $minTime).TotalSeconds
        if ($totalSpan -lt 1) { $totalSpan = 1 }
        $pixelsPerSec = $chartW / $totalSpan

        # Density buckets for background shading
        $bucketCount = [Math]::Min(100, [Math]::Max(20, $chartW / 6))
        $buckets = [int[]]::new($bucketCount)
        $bucketSpan = $totalSpan / $bucketCount
        foreach ($entry in $validEntries) {
            $sec = ($entry.Timestamp - $minTime).TotalSeconds
            $bi = [Math]::Min($bucketCount - 1, [Math]::Max(0, [int]([Math]::Floor($sec / $bucketSpan))))
            $buckets[$bi]++
        }
        $maxBucket = 1
        foreach ($b in $buckets) { if ($b -gt $maxBucket) { $maxBucket = $b } }

        # Draw density background
        $accentColor = Get-AccentColor
        $bucketWidth = [Math]::Ceiling($chartW / $bucketCount)
        for ($bi = 0; $bi -lt $bucketCount; $bi++) {
            if ($buckets[$bi] -gt 0) {
                $intensity = [Math]::Min(80, [int](($buckets[$bi] / $maxBucket) * 80))
                $densityColor = [System.Drawing.Color]::FromArgb($intensity, $accentColor.R, $accentColor.G, $accentColor.B)
                $bx = $marginL + [int]($bi * $chartW / $bucketCount)
                $densityBrush = [System.Drawing.SolidBrush]::new($densityColor)
                $g.FillRectangle($densityBrush, $bx, $marginT, $bucketWidth, $chartH)
                $densityBrush.Dispose()
            }
        }

        # Draw chart border and axis
        $g.DrawRectangle($gridPen, $marginL, $marginT, $chartW, $chartH)

        # Time axis tick marks and labels
        $tickCount = [Math]::Min(8, [Math]::Max(3, [int]($chartW / 100)))
        for ($ti = 0; $ti -le $tickCount; $ti++) {
            $frac = $ti / $tickCount
            $tx = $marginL + [int]($frac * $chartW)
            $g.DrawLine($gridPen, $tx, $marginT + $chartH, $tx, $marginT + $chartH + 4)
            # Vertical grid line
            $dimPen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(30, $fgColor.R, $fgColor.G, $fgColor.B), 1)
            $g.DrawLine($dimPen, $tx, $marginT, $tx, $marginT + $chartH)
            $dimPen.Dispose()
            # Label
            $tickTime = $minTime.AddSeconds($frac * $totalSpan)
            $tickLabel = if ($totalSpan -gt 86400) { $tickTime.ToString("MM/dd HH:mm") }
                         elseif ($totalSpan -gt 3600) { $tickTime.ToString("HH:mm") }
                         else { $tickTime.ToString("HH:mm:ss") }
            $labelSize = $g.MeasureString($tickLabel, $labelFont)
            $lx = $tx - ($labelSize.Width / 2)
            $g.DrawString($tickLabel, $labelFont, $fgBrush,
                [System.Drawing.PointF]::new($lx, $marginT + $chartH + 6))
        }

        # Draw event markers (vertical lines colored by severity)
        $sevLevels = @("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "TRACE", "UNKNOWN")
        foreach ($entry in $validEntries) {
            $sec = ($entry.Timestamp - $minTime).TotalSeconds
            $x = $marginL + [int]($sec * $pixelsPerSec)
            $sevColor = Get-SeverityColor $entry.Level
            if (-not $sevColor -or $sevColor.A -eq 0) {
                $sevColor = Get-ThemeColor 'FormFore' ([System.Drawing.Color]::FromArgb(120, 120, 120))
            }
            $markerPen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(160, $sevColor.R, $sevColor.G, $sevColor.B), 1)
            $yTop = $marginT + 2
            $yBot = $marginT + $chartH - 2
            $g.DrawLine($markerPen, $x, $yTop, $x, $yBot)
            $markerPen.Dispose()
        }

        # Draw legend in top-right corner
        $legendX = $w - $marginR - 5
        $legendY = 5
        foreach ($lev in @("CRITICAL", "ERROR", "WARNING", "INFO")) {
            $sc = Get-SeverityColor $lev
            if (-not $sc -or $sc.A -eq 0) { continue }
            $legLabel = switch ($lev) { "CRITICAL" { "CRIT" }; "WARNING" { "WARN" }; default { $lev } }
            $legSize = $g.MeasureString($legLabel, $labelFont)
            $legendX -= ($legSize.Width + 14)
            $legBrush = [System.Drawing.SolidBrush]::new($sc)
            $g.FillRectangle($legBrush, $legendX, $legendY + 1, 8, 8)
            $legBrush.Dispose()
            $g.DrawString($legLabel, $labelFont, $fgBrush,
                [System.Drawing.PointF]::new($legendX + 10, $legendY - 1))
        }

        # Hover tooltip
        $hoverX = $data.HoverX
        if ($hoverX -ge $marginL -and $hoverX -le ($marginL + $chartW) -and $data.HoverY -ge $marginT -and $data.HoverY -le ($marginT + $chartH)) {
            $hoverFrac = ($hoverX - $marginL) / $chartW
            $hoverTime = $minTime.AddSeconds($hoverFrac * $totalSpan)
            $hoverBi = [Math]::Min($bucketCount - 1, [Math]::Max(0, [int]($hoverFrac * $bucketCount)))
            $hoverCount = $buckets[$hoverBi]
            $ttText = "$($hoverTime.ToString('yyyy-MM-dd HH:mm:ss'))  ($hoverCount events)"
            $ttSize = $g.MeasureString($ttText, $labelFont)
            $ttX = [Math]::Min($hoverX + 8, $w - $ttSize.Width - 6)
            $ttY = [Math]::Max($marginT, $data.HoverY - $ttSize.Height - 6)
            $ttBgBrush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(220, 40, 40, 40))
            $g.FillRectangle($ttBgBrush, $ttX - 2, $ttY - 1, $ttSize.Width + 4, $ttSize.Height + 2)
            $ttBgBrush.Dispose()
            $ttFgBrush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::White)
            $g.DrawString($ttText, $labelFont, $ttFgBrush, [System.Drawing.PointF]::new($ttX, $ttY))
            $ttFgBrush.Dispose()

            # Vertical indicator line
            $hoverPen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(120, 255, 255, 255), 1)
            $hoverPen.DashStyle = [System.Drawing.Drawing2D.DashStyle]::Dash
            $g.DrawLine($hoverPen, $hoverX, $marginT, $hoverX, $marginT + $chartH)
            $hoverPen.Dispose()
        }

        $labelFont.Dispose(); $titleFont.Dispose(); $fgBrush.Dispose(); $gridPen.Dispose()
    })

    $panel.Add_MouseMove({
        param($sender, $e)
        $sender.Tag.HoverX = $e.X
        $sender.Tag.HoverY = $e.Y
        $sender.Invalidate()
    })
    $panel.Add_MouseLeave({
        param($sender, $e)
        $sender.Tag.HoverX = -1
        $sender.Tag.HoverY = -1
        $sender.Invalidate()
    })

    return $panel
}

function Update-TimelineWidget {
    param(
        [System.Windows.Forms.Panel]$Widget,
        [System.Collections.Generic.List[object]]$Entries
    )
    if (-not $Widget) { return }
    $Widget.Tag.Entries = $Entries
    $Widget.Invalidate()
}

# ═══════════════════════════════════════════════════════════════════════════════
# WIDGET 2: Severity Donut Chart
# ═══════════════════════════════════════════════════════════════════════════════

function New-SeverityDonutWidget {
    param(
        [int]$Size = 200,
        [hashtable]$Counts = @{}
    )

    $panel = New-DoubleBufferedPanel -Width $Size -Height $Size
    $panel.Tag = @{ Counts = $Counts }

    $panel.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit

        $bgColor = Get-ThemeColor 'PanelBack' ([System.Drawing.Color]::FromArgb(35, 35, 35))
        $fgColor = Get-ThemeColor 'FormFore'  ([System.Drawing.Color]::FromArgb(220, 220, 220))
        $w = $sender.ClientSize.Width
        $h = $sender.ClientSize.Height
        $g.Clear($bgColor)

        $counts = $sender.Tag.Counts
        $titleFont = [System.Drawing.Font]::new("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
        $labelFont = [System.Drawing.Font]::new("Segoe UI", 7.5)
        $centerFont = [System.Drawing.Font]::new("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
        $smallFont  = [System.Drawing.Font]::new("Segoe UI", 7)
        $fgBrush   = [System.Drawing.SolidBrush]::new($fgColor)

        $g.DrawString("Severity Distribution", $titleFont, $fgBrush, [System.Drawing.PointF]::new(4, 2))

        # Calculate total
        $total = 0
        $sevOrder = @("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "TRACE", "UNKNOWN")
        foreach ($sev in $sevOrder) {
            if ($counts.ContainsKey($sev)) { $total += $counts[$sev] }
        }

        # Donut geometry
        $donutMargin = 22
        $donutSize = [Math]::Min($w, $h - 20) - ($donutMargin * 2)
        if ($donutSize -lt 40) { $donutSize = 40 }
        $cx = $w / 2
        $cy = ($h - 20) / 2 + 10
        $outerRect = [System.Drawing.RectangleF]::new($cx - $donutSize / 2, $cy - $donutSize / 2, $donutSize, $donutSize)
        $innerSize = $donutSize * 0.55
        $innerRect = [System.Drawing.RectangleF]::new($cx - $innerSize / 2, $cy - $innerSize / 2, $innerSize, $innerSize)

        if ($total -eq 0) {
            $emptyPen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(60, $fgColor.R, $fgColor.G, $fgColor.B), [float]($donutSize - $innerSize) / 2)
            $g.DrawEllipse($emptyPen, $outerRect.X + ($donutSize - $innerSize) / 4, $outerRect.Y + ($donutSize - $innerSize) / 4,
                ($donutSize + $innerSize) / 2, ($donutSize + $innerSize) / 2)
            $emptyPen.Dispose()
            $g.DrawString("0", $centerFont, $fgBrush,
                [System.Drawing.PointF]::new($cx - $g.MeasureString("0", $centerFont).Width / 2, $cy - 12))
        }
        else {
            # Draw arcs
            $startAngle = -90.0
            foreach ($sev in $sevOrder) {
                $count = 0
                if ($counts.ContainsKey($sev)) { $count = $counts[$sev] }
                if ($count -le 0) { continue }

                $sweepAngle = ($count / $total) * 360.0
                if ($sweepAngle -lt 0.5) { $sweepAngle = 0.5 }
                $sevColor = Get-SeverityColor $sev
                if (-not $sevColor -or $sevColor.A -eq 0) {
                    $sevColor = Get-ThemeColor 'GridLines' ([System.Drawing.Color]::FromArgb(100, 100, 100))
                }
                $sevBrush = [System.Drawing.SolidBrush]::new($sevColor)
                $g.FillPie($sevBrush, $outerRect.X, $outerRect.Y, $outerRect.Width, $outerRect.Height,
                    [float]$startAngle, [float]$sweepAngle)
                $sevBrush.Dispose()
                $startAngle += $sweepAngle
            }

            # Punch out center for donut effect
            $centerBrush = [System.Drawing.SolidBrush]::new($bgColor)
            $g.FillEllipse($centerBrush, $innerRect.X, $innerRect.Y, $innerRect.Width, $innerRect.Height)
            $centerBrush.Dispose()

            # Center text: total count
            $totalStr = $total.ToString("N0")
            $totalSize = $g.MeasureString($totalStr, $centerFont)
            $g.DrawString($totalStr, $centerFont, $fgBrush,
                [System.Drawing.PointF]::new($cx - $totalSize.Width / 2, $cy - $totalSize.Height / 2 - 4))
            $subtitleStr = "total"
            $subSize = $g.MeasureString($subtitleStr, $smallFont)
            $g.DrawString($subtitleStr, $smallFont, $fgBrush,
                [System.Drawing.PointF]::new($cx - $subSize.Width / 2, $cy + $totalSize.Height / 2 - 8))
        }

        # Legend below donut
        $legendY = $cy + $donutSize / 2 + 4
        $legendX = 6
        foreach ($sev in $sevOrder) {
            $count = 0
            if ($counts.ContainsKey($sev)) { $count = $counts[$sev] }
            if ($count -le 0) { continue }
            $sc = Get-SeverityColor $sev
            if (-not $sc -or $sc.A -eq 0) { continue }
            $legBrush = [System.Drawing.SolidBrush]::new($sc)
            $g.FillRectangle($legBrush, $legendX, $legendY + 1, 7, 7)
            $legBrush.Dispose()
            $legText = "$sev`: $count"
            $legMeasure = $g.MeasureString($legText, $smallFont)
            $g.DrawString($legText, $smallFont, $fgBrush,
                [System.Drawing.PointF]::new($legendX + 10, $legendY - 1))
            $legendX += $legMeasure.Width + 14
            if ($legendX -gt ($w - 40)) {
                $legendX = 6
                $legendY += 12
            }
        }

        $titleFont.Dispose(); $labelFont.Dispose(); $centerFont.Dispose()
        $smallFont.Dispose(); $fgBrush.Dispose()
    })

    return $panel
}

function Update-SeverityDonutWidget {
    param(
        [System.Windows.Forms.Panel]$Widget,
        [hashtable]$Counts
    )
    if (-not $Widget) { return }
    $Widget.Tag.Counts = $Counts
    $Widget.Invalidate()
}

# ═══════════════════════════════════════════════════════════════════════════════
# WIDGET 3: Top-N Horizontal Bar Chart
# ═══════════════════════════════════════════════════════════════════════════════

function New-BarChartWidget {
    param(
        [int]$Width = 400,
        [int]$Height = 300,
        [array]$Data = @(),
        [string]$Title = "",
        [int]$MaxBars = 10
    )

    $panel = New-DoubleBufferedPanel -Width $Width -Height $Height
    $panel.Tag = @{ Data = $Data; Title = $Title; MaxBars = $MaxBars }

    $panel.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit

        $bgColor   = Get-ThemeColor 'PanelBack' ([System.Drawing.Color]::FromArgb(35, 35, 35))
        $fgColor   = Get-ThemeColor 'FormFore'  ([System.Drawing.Color]::FromArgb(220, 220, 220))
        $accent    = Get-AccentColor
        $w = $sender.ClientSize.Width
        $h = $sender.ClientSize.Height
        $g.Clear($bgColor)

        $tagData  = $sender.Tag
        $barData  = $tagData.Data
        $title    = $tagData.Title
        $maxBars  = $tagData.MaxBars

        $titleFont = [System.Drawing.Font]::new("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
        $labelFont = [System.Drawing.Font]::new("Segoe UI", 7.5)
        $valueFont = [System.Drawing.Font]::new("Segoe UI", 7)
        $fgBrush   = [System.Drawing.SolidBrush]::new($fgColor)

        # Title
        if ($title) {
            $g.DrawString($title, $titleFont, $fgBrush, [System.Drawing.PointF]::new(4, 2))
        }

        if (-not $barData -or $barData.Count -eq 0) {
            $g.DrawString("No data available", $labelFont, $fgBrush,
                [System.Drawing.PointF]::new($w / 2 - 40, $h / 2 - 6))
            $titleFont.Dispose(); $labelFont.Dispose(); $valueFont.Dispose(); $fgBrush.Dispose()
            return
        }

        # Sort descending and take top N
        $sorted = $barData | Sort-Object { $_.Value } -Descending | Select-Object -First $maxBars

        # Layout
        $marginT = if ($title) { 22 } else { 8 }
        $marginB = 8
        $marginL = 8
        $marginR = 8

        # Measure widest label
        $maxLabelWidth = 60
        foreach ($item in $sorted) {
            $lblText = if ($item.Label.Length -gt 25) { $item.Label.Substring(0, 22) + "..." } else { $item.Label }
            $lm = $g.MeasureString($lblText, $labelFont)
            if ($lm.Width -gt $maxLabelWidth) { $maxLabelWidth = [int]$lm.Width }
        }
        $maxLabelWidth = [Math]::Min($maxLabelWidth + 4, [int]($w * 0.4))

        # Measure widest value
        $maxValWidth = 20
        $maxValue = 1
        foreach ($item in $sorted) {
            if ($item.Value -gt $maxValue) { $maxValue = $item.Value }
            $vm = $g.MeasureString($item.Value.ToString("N0"), $valueFont)
            if ($vm.Width -gt $maxValWidth) { $maxValWidth = [int]$vm.Width }
        }
        $maxValWidth += 6

        $barAreaLeft = $marginL + $maxLabelWidth + 4
        $barAreaRight = $w - $marginR - $maxValWidth - 4
        $barAreaWidth = $barAreaRight - $barAreaLeft
        if ($barAreaWidth -lt 20) { $barAreaWidth = 20 }

        $availH = $h - $marginT - $marginB
        $barCount = @($sorted).Count
        $barH = [Math]::Min(24, [Math]::Max(8, [int]($availH / $barCount) - 4))
        $barGap = [Math]::Max(2, [int](($availH - $barCount * $barH) / ($barCount + 1)))

        $by = $marginT + $barGap
        foreach ($item in $sorted) {
            $lblText = if ($item.Label.Length -gt 25) { $item.Label.Substring(0, 22) + "..." } else { $item.Label }

            # Label on left
            $lblSize = $g.MeasureString($lblText, $labelFont)
            $lblY = $by + ($barH - $lblSize.Height) / 2
            $g.DrawString($lblText, $labelFont, $fgBrush,
                [System.Drawing.PointF]::new($marginL, $lblY))

            # Bar
            $barW = [Math]::Max(2, [int](($item.Value / $maxValue) * $barAreaWidth))
            $barBrush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(200, $accent.R, $accent.G, $accent.B))
            $g.FillRectangle($barBrush, $barAreaLeft, $by, $barW, $barH)
            $barBrush.Dispose()

            # Rounded corners highlight on top of bar
            $hlColor = [System.Drawing.Color]::FromArgb(40, 255, 255, 255)
            $hlBrush = [System.Drawing.SolidBrush]::new($hlColor)
            $g.FillRectangle($hlBrush, $barAreaLeft, $by, $barW, [Math]::Max(1, $barH / 3))
            $hlBrush.Dispose()

            # Value on right
            $valText = $item.Value.ToString("N0")
            $valSize = $g.MeasureString($valText, $valueFont)
            $g.DrawString($valText, $valueFont, $fgBrush,
                [System.Drawing.PointF]::new($barAreaLeft + $barW + 4, $by + ($barH - $valSize.Height) / 2))

            $by += $barH + $barGap
        }

        $titleFont.Dispose(); $labelFont.Dispose(); $valueFont.Dispose(); $fgBrush.Dispose()
    })

    return $panel
}

function Update-BarChartWidget {
    param(
        [System.Windows.Forms.Panel]$Widget,
        [array]$Data,
        [string]$Title = $null,
        [int]$MaxBars = 0
    )
    if (-not $Widget) { return }
    $Widget.Tag.Data = $Data
    if ($Title) { $Widget.Tag.Title = $Title }
    if ($MaxBars -gt 0) { $Widget.Tag.MaxBars = $MaxBars }
    $Widget.Invalidate()
}

# ═══════════════════════════════════════════════════════════════════════════════
# WIDGET 4: Heatmap (Hour x Day)
# ═══════════════════════════════════════════════════════════════════════════════

function New-HeatmapWidget {
    param(
        [int]$Width = 500,
        [int]$Height = 200,
        [System.Collections.Generic.List[object]]$Entries = $null
    )

    $panel = New-DoubleBufferedPanel -Width $Width -Height $Height
    $panel.Tag = @{ Entries = $Entries; HoverCol = -1; HoverRow = -1 }

    $panel.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit

        $bgColor   = Get-ThemeColor 'PanelBack' ([System.Drawing.Color]::FromArgb(35, 35, 35))
        $fgColor   = Get-ThemeColor 'FormFore'  ([System.Drawing.Color]::FromArgb(220, 220, 220))
        $w = $sender.ClientSize.Width
        $h = $sender.ClientSize.Height
        $g.Clear($bgColor)

        $entries = $sender.Tag.Entries
        $hoverCol = $sender.Tag.HoverCol
        $hoverRow = $sender.Tag.HoverRow

        $titleFont = [System.Drawing.Font]::new("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
        $labelFont = [System.Drawing.Font]::new("Segoe UI", 7)
        $fgBrush   = [System.Drawing.SolidBrush]::new($fgColor)

        $g.DrawString("Activity Heatmap (Hour x Day)", $titleFont, $fgBrush, [System.Drawing.PointF]::new(4, 2))

        if (-not $entries -or $entries.Count -eq 0) {
            $g.DrawString("No data available", $labelFont, $fgBrush,
                [System.Drawing.PointF]::new($w / 2 - 40, $h / 2 - 6))
            $titleFont.Dispose(); $labelFont.Dispose(); $fgBrush.Dispose()
            return
        }

        # Build 7 x 24 grid (rows = days Mon-Sun, cols = hours 0-23)
        $grid = [int[,]]::new(7, 24)
        $hasData = $false
        foreach ($entry in $entries) {
            if ($entry.Timestamp -eq [datetime]::MinValue) { continue }
            $hasData = $true
            $dow = [int]$entry.Timestamp.DayOfWeek
            # Convert: Sunday=0 -> 6, Monday=1 -> 0, etc.
            $row = if ($dow -eq 0) { 6 } else { $dow - 1 }
            $col = $entry.Timestamp.Hour
            $grid[$row, $col]++
        }

        if (-not $hasData) {
            $g.DrawString("No timestamped entries", $labelFont, $fgBrush,
                [System.Drawing.PointF]::new($w / 2 - 50, $h / 2 - 6))
            $titleFont.Dispose(); $labelFont.Dispose(); $fgBrush.Dispose()
            return
        }

        # Find max value
        $maxVal = 1
        for ($r = 0; $r -lt 7; $r++) {
            for ($c = 0; $c -lt 24; $c++) {
                if ($grid[$r, $c] -gt $maxVal) { $maxVal = $grid[$r, $c] }
            }
        }

        # Layout
        $marginT = 20; $marginB = 22; $marginL = 35; $marginR = 10
        $gridW = $w - $marginL - $marginR
        $gridH = $h - $marginT - $marginB
        $cellW = [Math]::Floor($gridW / 24)
        $cellH = [Math]::Floor($gridH / 7)

        $dayNames = @("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
        $borderPen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(40, $fgColor.R, $fgColor.G, $fgColor.B), 1)

        # Store cell geometry for hover detection
        $sender.Tag['CellW'] = $cellW
        $sender.Tag['CellH'] = $cellH
        $sender.Tag['MarginL'] = $marginL
        $sender.Tag['MarginT'] = $marginT

        for ($r = 0; $r -lt 7; $r++) {
            # Day label
            $dayLabel = $dayNames[$r]
            $dlSize = $g.MeasureString($dayLabel, $labelFont)
            $g.DrawString($dayLabel, $labelFont, $fgBrush,
                [System.Drawing.PointF]::new($marginL - $dlSize.Width - 3, $marginT + $r * $cellH + ($cellH - $dlSize.Height) / 2))

            for ($c = 0; $c -lt 24; $c++) {
                $val = $grid[$r, $c]
                $cx = $marginL + $c * $cellW
                $cy = $marginT + $r * $cellH

                # Color: gradient from bg to intense orange/red
                if ($val -gt 0) {
                    $intensity = [Math]::Min(1.0, [Math]::Max(0.1, $val / $maxVal))
                    $rComp = [int]([Math]::Min(255, 60 + $intensity * 195))
                    $gComp = [int]([Math]::Max(20, 100 - $intensity * 80))
                    $bComp = [int]([Math]::Max(10, 40 - $intensity * 30))
                    $cellColor = [System.Drawing.Color]::FromArgb($rComp, $gComp, $bComp)
                }
                else {
                    $cellColor = [System.Drawing.Color]::FromArgb(20, $fgColor.R, $fgColor.G, $fgColor.B)
                }

                $cellBrush = [System.Drawing.SolidBrush]::new($cellColor)
                $g.FillRectangle($cellBrush, $cx + 1, $cy + 1, $cellW - 2, $cellH - 2)
                $cellBrush.Dispose()
                $g.DrawRectangle($borderPen, $cx, $cy, $cellW, $cellH)

                # Hover highlight
                if ($c -eq $hoverCol -and $r -eq $hoverRow) {
                    $highlightPen = [System.Drawing.Pen]::new([System.Drawing.Color]::White, 2)
                    $g.DrawRectangle($highlightPen, $cx, $cy, $cellW, $cellH)
                    $highlightPen.Dispose()

                    # Tooltip
                    $ttText = "$($dayNames[$r]) $($c.ToString('00')):00 - $val events"
                    $ttSize = $g.MeasureString($ttText, $labelFont)
                    $ttX = [Math]::Min($cx + $cellW + 4, $w - $ttSize.Width - 6)
                    $ttY = [Math]::Max(2, $cy - $ttSize.Height - 2)
                    $ttBg = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(220, 40, 40, 40))
                    $g.FillRectangle($ttBg, $ttX - 2, $ttY - 1, $ttSize.Width + 4, $ttSize.Height + 2)
                    $ttBg.Dispose()
                    $ttFg = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::White)
                    $g.DrawString($ttText, $labelFont, $ttFg, [System.Drawing.PointF]::new($ttX, $ttY))
                    $ttFg.Dispose()
                }
            }
        }

        # Hour labels along bottom
        for ($c = 0; $c -lt 24; $c++) {
            if ($c % 3 -eq 0) {
                $hLabel = $c.ToString("00")
                $hlSize = $g.MeasureString($hLabel, $labelFont)
                $hlx = $marginL + $c * $cellW + ($cellW - $hlSize.Width) / 2
                $g.DrawString($hLabel, $labelFont, $fgBrush,
                    [System.Drawing.PointF]::new($hlx, $marginT + 7 * $cellH + 3))
            }
        }

        $borderPen.Dispose()
        $titleFont.Dispose(); $labelFont.Dispose(); $fgBrush.Dispose()
    })

    $panel.Add_MouseMove({
        param($sender, $e)
        $tag = $sender.Tag
        $cellW = $tag['CellW']; $cellH = $tag['CellH']
        $mL = $tag['MarginL']; $mT = $tag['MarginT']
        if ($cellW -and $cellH -and $cellW -gt 0 -and $cellH -gt 0) {
            $col = [int]([Math]::Floor(($e.X - $mL) / $cellW))
            $row = [int]([Math]::Floor(($e.Y - $mT) / $cellH))
            if ($col -ge 0 -and $col -lt 24 -and $row -ge 0 -and $row -lt 7) {
                if ($col -ne $tag.HoverCol -or $row -ne $tag.HoverRow) {
                    $tag.HoverCol = $col
                    $tag.HoverRow = $row
                    $sender.Invalidate()
                }
            }
            else {
                if ($tag.HoverCol -ne -1 -or $tag.HoverRow -ne -1) {
                    $tag.HoverCol = -1; $tag.HoverRow = -1
                    $sender.Invalidate()
                }
            }
        }
    })
    $panel.Add_MouseLeave({
        param($sender, $e)
        $sender.Tag.HoverCol = -1
        $sender.Tag.HoverRow = -1
        $sender.Invalidate()
    })

    return $panel
}

function Update-HeatmapWidget {
    param(
        [System.Windows.Forms.Panel]$Widget,
        [System.Collections.Generic.List[object]]$Entries
    )
    if (-not $Widget) { return }
    $Widget.Tag.Entries = $Entries
    $Widget.Invalidate()
}

# ═══════════════════════════════════════════════════════════════════════════════
# WIDGET 5: Sparkline
# ═══════════════════════════════════════════════════════════════════════════════

function New-SparklineWidget {
    param(
        [int]$Width = 200,
        [int]$Height = 40,
        [array]$Values = @(),
        [System.Drawing.Color]$LineColor = [System.Drawing.Color]::Empty
    )

    $panel = New-DoubleBufferedPanel -Width $Width -Height $Height
    $panel.Tag = @{ Values = $Values; LineColor = $LineColor }

    $panel.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

        $bgColor = Get-ThemeColor 'PanelBack' ([System.Drawing.Color]::FromArgb(35, 35, 35))
        $w = $sender.ClientSize.Width
        $h = $sender.ClientSize.Height
        $g.Clear($bgColor)

        $values = $sender.Tag.Values
        $lineColor = $sender.Tag.LineColor
        if ($lineColor -eq [System.Drawing.Color]::Empty) {
            $lineColor = Get-AccentColor
        }

        if (-not $values -or $values.Count -lt 2) {
            $noDataFont = [System.Drawing.Font]::new("Segoe UI", 7)
            $noDataBrush = [System.Drawing.SolidBrush]::new(
                (Get-ThemeColor 'FormFore' ([System.Drawing.Color]::FromArgb(120, 120, 120))))
            $g.DrawString("--", $noDataFont, $noDataBrush,
                [System.Drawing.PointF]::new($w / 2 - 5, $h / 2 - 5))
            $noDataFont.Dispose(); $noDataBrush.Dispose()
            return
        }

        # Margins
        $mx = 3; $my = 3
        $chartW = $w - 2 * $mx
        $chartH = $h - 2 * $my

        # Normalize values
        $minV = [double]$values[0]; $maxV = [double]$values[0]
        foreach ($v in $values) {
            $dv = [double]$v
            if ($dv -lt $minV) { $minV = $dv }
            if ($dv -gt $maxV) { $maxV = $dv }
        }
        $rangeV = $maxV - $minV
        if ($rangeV -lt 0.001) { $rangeV = 1 }

        # Build point array
        $pointCount = $values.Count
        $points = [System.Drawing.PointF[]]::new($pointCount)
        for ($i = 0; $i -lt $pointCount; $i++) {
            $px = $mx + ($i / [Math]::Max(1, $pointCount - 1)) * $chartW
            $py = $my + $chartH - (([double]$values[$i] - $minV) / $rangeV) * $chartH
            $points[$i] = [System.Drawing.PointF]::new($px, $py)
        }

        # Fill area under line
        $fillPoints = [System.Drawing.PointF[]]::new($pointCount + 2)
        for ($i = 0; $i -lt $pointCount; $i++) {
            $fillPoints[$i] = $points[$i]
        }
        $fillPoints[$pointCount] = [System.Drawing.PointF]::new($mx + $chartW, $my + $chartH)
        $fillPoints[$pointCount + 1] = [System.Drawing.PointF]::new($mx, $my + $chartH)

        $fillColor = [System.Drawing.Color]::FromArgb(40, $lineColor.R, $lineColor.G, $lineColor.B)
        $fillBrush = [System.Drawing.SolidBrush]::new($fillColor)
        $g.FillPolygon($fillBrush, $fillPoints)
        $fillBrush.Dispose()

        # Draw line
        $linePen = [System.Drawing.Pen]::new($lineColor, 1.5)
        $linePen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
        if ($pointCount -gt 1) {
            $g.DrawLines($linePen, $points)
        }
        $linePen.Dispose()

        # Draw endpoint dot
        $lastPt = $points[$pointCount - 1]
        $dotBrush = [System.Drawing.SolidBrush]::new($lineColor)
        $g.FillEllipse($dotBrush, $lastPt.X - 2, $lastPt.Y - 2, 4, 4)
        $dotBrush.Dispose()
    })

    return $panel
}

function Update-SparklineWidget {
    param(
        [System.Windows.Forms.Panel]$Widget,
        [array]$Values,
        [System.Drawing.Color]$LineColor = [System.Drawing.Color]::Empty
    )
    if (-not $Widget) { return }
    $Widget.Tag.Values = $Values
    if ($LineColor -ne [System.Drawing.Color]::Empty) { $Widget.Tag.LineColor = $LineColor }
    $Widget.Invalidate()
}

# ═══════════════════════════════════════════════════════════════════════════════
# WIDGET 6: Site Map / Topology Diagram
# ═══════════════════════════════════════════════════════════════════════════════

function New-SiteMapWidget {
    param(
        [int]$Width = 600,
        [int]$Height = 400,
        [hashtable]$SiteHealth = @{}
    )

    $panel = New-DoubleBufferedPanel -Width $Width -Height $Height
    $panel.Tag = @{ SiteHealth = $SiteHealth; HoverSite = $null }

    $panel.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit

        $bgColor   = Get-ThemeColor 'PanelBack' ([System.Drawing.Color]::FromArgb(35, 35, 35))
        $fgColor   = Get-ThemeColor 'FormFore'  ([System.Drawing.Color]::FromArgb(220, 220, 220))
        $w = $sender.ClientSize.Width
        $h = $sender.ClientSize.Height
        $g.Clear($bgColor)

        $siteHealth = $sender.Tag.SiteHealth
        $hoverSite  = $sender.Tag.HoverSite

        $titleFont = [System.Drawing.Font]::new("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
        $labelFont = [System.Drawing.Font]::new("Segoe UI", 7.5)
        $smallFont = [System.Drawing.Font]::new("Segoe UI", 6.5)
        $fgBrush   = [System.Drawing.SolidBrush]::new($fgColor)

        $g.DrawString("Network Topology", $titleFont, $fgBrush, [System.Drawing.PointF]::new(4, 2))

        # Gather sites from topology or from health data
        $allSites = $null
        if ($Script:Topology) {
            $allSites = Get-AllSites
        }

        $hubs = [System.Collections.Generic.List[string]]::new()
        $drHubs = [System.Collections.Generic.List[string]]::new()
        $spokes = [System.Collections.Generic.List[string]]::new()

        if ($allSites) {
            foreach ($s in $allSites.Hubs) { $hubs.Add($s) }
            foreach ($s in $allSites.DrHubs) { $drHubs.Add($s) }
            foreach ($s in $allSites.Spokes) { $spokes.Add($s) }
        }
        elseif ($siteHealth -and $siteHealth.Count -gt 0) {
            foreach ($code in $siteHealth.Keys) {
                $sh = $siteHealth[$code]
                switch ($sh.Role) {
                    'hub'     { $hubs.Add($code) }
                    'dr_hub'  { $drHubs.Add($code) }
                    default   { $spokes.Add($code) }
                }
            }
        }

        $totalSites = $hubs.Count + $drHubs.Count + $spokes.Count
        if ($totalSites -eq 0) {
            $g.DrawString("No topology data available", $labelFont, $fgBrush,
                [System.Drawing.PointF]::new($w / 2 - 60, $h / 2 - 6))
            $titleFont.Dispose(); $labelFont.Dispose(); $smallFont.Dispose(); $fgBrush.Dispose()
            return
        }

        # Calculate node positions
        $nodeRadius = [Math]::Min(18, [Math]::Max(10, [int]([Math]::Min($w, $h) / ($totalSites + 4))))
        $cx = $w / 2
        $cy = $h / 2
        $outerRadius = [Math]::Min($w, $h) / 2 - $nodeRadius - 30

        $nodePositions = @{}
        $siteNodeList = [System.Collections.Generic.List[object]]::new()

        # Position hub(s) near center
        $hubCount = $hubs.Count + $drHubs.Count
        if ($hubCount -eq 1) {
            $hubSite = if ($hubs.Count -gt 0) { $hubs[0] } else { $drHubs[0] }
            $nodePositions[$hubSite] = @{ X = [int]$cx; Y = [int]$cy }
        }
        elseif ($hubCount -gt 1) {
            $hubRadius = $outerRadius * 0.3
            $idx = 0
            foreach ($hubSite in ($hubs + $drHubs)) {
                $angle = (2 * [Math]::PI * $idx / $hubCount) - ([Math]::PI / 2)
                $nx = [int]($cx + $hubRadius * [Math]::Cos($angle))
                $ny = [int]($cy + $hubRadius * [Math]::Sin($angle))
                $nodePositions[$hubSite] = @{ X = $nx; Y = $ny }
                $idx++
            }
        }

        # Position spokes in a circle around center
        if ($spokes.Count -gt 0) {
            for ($si = 0; $si -lt $spokes.Count; $si++) {
                $angle = (2 * [Math]::PI * $si / $spokes.Count) - ([Math]::PI / 2)
                $nx = [int]($cx + $outerRadius * [Math]::Cos($angle))
                $ny = [int]($cy + $outerRadius * [Math]::Sin($angle))
                $nodePositions[$spokes[$si]] = @{ X = $nx; Y = $ny }
            }
        }

        # Draw tunnel lines first (behind nodes)
        $tunnelLinePen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(60, $fgColor.R, $fgColor.G, $fgColor.B), 1)
        if ($Script:Topology -and $Script:Topology.tunnels) {
            foreach ($prop in $Script:Topology.tunnels.PSObject.Properties) {
                $endpoints = @($prop.Value.endpoints)
                if ($endpoints.Count -ge 2) {
                    $ep1 = $endpoints[0]; $ep2 = $endpoints[1]
                    if ($nodePositions.ContainsKey($ep1) -and $nodePositions.ContainsKey($ep2)) {
                        $p1 = $nodePositions[$ep1]; $p2 = $nodePositions[$ep2]

                        # Color tunnel line by health of connected sites
                        $tunnelColor = [System.Drawing.Color]::FromArgb(80, 100, 200, 100)
                        if ($siteHealth.ContainsKey($ep1) -or $siteHealth.ContainsKey($ep2)) {
                            $h1 = if ($siteHealth.ContainsKey($ep1)) { $siteHealth[$ep1].Health } else { "GREEN" }
                            $h2 = if ($siteHealth.ContainsKey($ep2)) { $siteHealth[$ep2].Health } else { "GREEN" }
                            if ($h1 -eq "RED" -or $h2 -eq "RED") {
                                $tunnelColor = [System.Drawing.Color]::FromArgb(120, 220, 60, 60)
                            }
                            elseif ($h1 -eq "YELLOW" -or $h2 -eq "YELLOW") {
                                $tunnelColor = [System.Drawing.Color]::FromArgb(100, 220, 180, 50)
                            }
                        }
                        $tPen = [System.Drawing.Pen]::new($tunnelColor, 1.5)
                        $g.DrawLine($tPen, $p1.X, $p1.Y, $p2.X, $p2.Y)
                        $tPen.Dispose()
                    }
                }
            }
        }
        else {
            # No topology tunnels defined -- draw lines from each spoke to first hub
            if ($hubs.Count -gt 0) {
                $hubPos = $nodePositions[$hubs[0]]
                foreach ($spoke in $spokes) {
                    if ($nodePositions.ContainsKey($spoke)) {
                        $sp = $nodePositions[$spoke]
                        $g.DrawLine($tunnelLinePen, $hubPos.X, $hubPos.Y, $sp.X, $sp.Y)
                    }
                }
            }
        }
        $tunnelLinePen.Dispose()

        # Store node positions for hit testing
        $sender.Tag['NodePositions'] = $nodePositions
        $sender.Tag['NodeRadius'] = $nodeRadius

        # Draw nodes
        $allCodes = @($hubs) + @($drHubs) + @($spokes)
        foreach ($code in $allCodes) {
            if (-not $nodePositions.ContainsKey($code)) { continue }
            $pos = $nodePositions[$code]
            $nx = $pos.X; $ny = $pos.Y

            # Determine health color
            $healthColor = [System.Drawing.Color]::FromArgb(80, 180, 80)  # green
            if ($siteHealth.ContainsKey($code)) {
                switch ($siteHealth[$code].Health) {
                    "RED"    { $healthColor = [System.Drawing.Color]::FromArgb(220, 60, 60) }
                    "YELLOW" { $healthColor = [System.Drawing.Color]::FromArgb(220, 180, 50) }
                    "GREEN"  { $healthColor = [System.Drawing.Color]::FromArgb(80, 180, 80) }
                }
            }
            else {
                # Site in topology but not in health data -- gray
                $healthColor = [System.Drawing.Color]::FromArgb(120, 120, 120)
            }

            # Node shape: hubs are slightly larger
            $isHub = $hubs.Contains($code) -or $drHubs.Contains($code)
            $drawRadius = if ($isHub) { [int]($nodeRadius * 1.3) } else { $nodeRadius }

            # Drop shadow
            $shadowBrush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(40, 0, 0, 0))
            $g.FillEllipse($shadowBrush, $nx - $drawRadius + 2, $ny - $drawRadius + 2, $drawRadius * 2, $drawRadius * 2)
            $shadowBrush.Dispose()

            # Filled circle
            $nodeBrush = [System.Drawing.SolidBrush]::new($healthColor)
            $g.FillEllipse($nodeBrush, $nx - $drawRadius, $ny - $drawRadius, $drawRadius * 2, $drawRadius * 2)
            $nodeBrush.Dispose()

            # Border
            $borderColor = if ($hoverSite -eq $code) { [System.Drawing.Color]::White } else { [System.Drawing.Color]::FromArgb(180, $fgColor.R, $fgColor.G, $fgColor.B) }
            $borderWidth = if ($hoverSite -eq $code) { 2.0 } else { 1.0 }
            $nodePen = [System.Drawing.Pen]::new($borderColor, $borderWidth)
            $g.DrawEllipse($nodePen, $nx - $drawRadius, $ny - $drawRadius, $drawRadius * 2, $drawRadius * 2)
            $nodePen.Dispose()

            # Hub icon marker (H or DR)
            if ($isHub) {
                $hubLabel = if ($drHubs.Contains($code)) { "DR" } else { "H" }
                $hlSize = $g.MeasureString($hubLabel, $smallFont)
                $textColor = Get-ContrastTextColor $healthColor
                $textBrush = [System.Drawing.SolidBrush]::new($textColor)
                $g.DrawString($hubLabel, $smallFont, $textBrush,
                    [System.Drawing.PointF]::new($nx - $hlSize.Width / 2, $ny - $hlSize.Height / 2))
                $textBrush.Dispose()
            }

            # Site label below node
            $siteLabel = $code
            $slSize = $g.MeasureString($siteLabel, $labelFont)
            $g.DrawString($siteLabel, $labelFont, $fgBrush,
                [System.Drawing.PointF]::new($nx - $slSize.Width / 2, $ny + $drawRadius + 2))
        }

        # Hover tooltip
        if ($hoverSite -and $siteHealth.ContainsKey($hoverSite) -and $nodePositions.ContainsKey($hoverSite)) {
            $sh = $siteHealth[$hoverSite]
            $hp = $nodePositions[$hoverSite]
            $ttLines = @(
                "Site: $hoverSite ($($sh.Role))"
                "Health: $($sh.Health)"
                "Events: $($sh.TotalEvents)"
                "Crit: $($sh.CriticalCount)  Err: $($sh.ErrorCount)  Warn: $($sh.WarningCount)"
                "Tunnels: $($sh.TunnelStatus)"
            )
            $ttText = $ttLines -join "`n"
            $ttSize = $g.MeasureString($ttText, $smallFont)
            $ttX = [Math]::Min($hp.X + $nodeRadius + 8, $w - $ttSize.Width - 8)
            $ttY = [Math]::Max(20, $hp.Y - $ttSize.Height / 2)
            $ttBg = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(230, 30, 30, 30))
            $g.FillRectangle($ttBg, $ttX - 4, $ttY - 2, $ttSize.Width + 8, $ttSize.Height + 4)
            $ttBg.Dispose()
            $ttBorder = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(100, 200, 200, 200), 1)
            $g.DrawRectangle($ttBorder, $ttX - 4, $ttY - 2, $ttSize.Width + 8, $ttSize.Height + 4)
            $ttBorder.Dispose()
            $ttFg = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::White)
            $g.DrawString($ttText, $smallFont, $ttFg, [System.Drawing.PointF]::new($ttX, $ttY))
            $ttFg.Dispose()
        }

        # Legend in bottom-left
        $legY = $h - 18
        $legX = 6
        foreach ($legItem in @(
            @{ Label = "Healthy"; Color = [System.Drawing.Color]::FromArgb(80, 180, 80) }
            @{ Label = "Warning"; Color = [System.Drawing.Color]::FromArgb(220, 180, 50) }
            @{ Label = "Critical"; Color = [System.Drawing.Color]::FromArgb(220, 60, 60) }
        )) {
            $lb = [System.Drawing.SolidBrush]::new($legItem.Color)
            $g.FillEllipse($lb, $legX, $legY, 8, 8)
            $lb.Dispose()
            $lm = $g.MeasureString($legItem.Label, $smallFont)
            $g.DrawString($legItem.Label, $smallFont, $fgBrush,
                [System.Drawing.PointF]::new($legX + 11, $legY - 1))
            $legX += $lm.Width + 18
        }

        $titleFont.Dispose(); $labelFont.Dispose(); $smallFont.Dispose(); $fgBrush.Dispose()
    })

    $panel.Add_MouseMove({
        param($sender, $e)
        $tag = $sender.Tag
        $positions = $tag['NodePositions']
        $radius = $tag['NodeRadius']
        if (-not $positions -or -not $radius) { return }

        $foundSite = $null
        foreach ($code in $positions.Keys) {
            $pos = $positions[$code]
            $dist = [Math]::Sqrt(($e.X - $pos.X) * ($e.X - $pos.X) + ($e.Y - $pos.Y) * ($e.Y - $pos.Y))
            if ($dist -le ($radius * 1.5)) {
                $foundSite = $code
                break
            }
        }
        if ($foundSite -ne $tag.HoverSite) {
            $tag.HoverSite = $foundSite
            $sender.Invalidate()
        }
    })
    $panel.Add_MouseLeave({
        param($sender, $e)
        if ($sender.Tag.HoverSite) {
            $sender.Tag.HoverSite = $null
            $sender.Invalidate()
        }
    })

    return $panel
}

function Update-SiteMapWidget {
    param(
        [System.Windows.Forms.Panel]$Widget,
        [hashtable]$SiteHealth
    )
    if (-not $Widget) { return }
    $Widget.Tag.SiteHealth = $SiteHealth
    $Widget.Invalidate()
}

# ═══════════════════════════════════════════════════════════════════════════════
# WIDGET 7: Anomaly Traffic Light
# ═══════════════════════════════════════════════════════════════════════════════

function New-AnomalyIndicatorWidget {
    param(
        [int]$Width = 80,
        [int]$Height = 200,
        [string]$Status = "GREEN",
        [string]$Label = ""
    )

    $panel = New-DoubleBufferedPanel -Width $Width -Height $Height
    $panel.Tag = @{ Status = $Status; Label = $Label }

    $panel.Add_Paint({
        param($sender, $e)
        $g = $e.Graphics
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::ClearTypeGridFit

        $bgColor = Get-ThemeColor 'PanelBack' ([System.Drawing.Color]::FromArgb(35, 35, 35))
        $fgColor = Get-ThemeColor 'FormFore'  ([System.Drawing.Color]::FromArgb(220, 220, 220))
        $w = $sender.ClientSize.Width
        $h = $sender.ClientSize.Height
        $g.Clear($bgColor)

        $status = $sender.Tag.Status
        $label  = $sender.Tag.Label

        $titleFont = [System.Drawing.Font]::new("Segoe UI", 7.5, [System.Drawing.FontStyle]::Bold)
        $labelFont = [System.Drawing.Font]::new("Segoe UI", 7)
        $fgBrush   = [System.Drawing.SolidBrush]::new($fgColor)

        # Housing (dark rectangle behind the lights)
        $housingMargin = 10
        $housingW = [Math]::Min(50, $w - $housingMargin * 2)
        $housingX = ($w - $housingW) / 2
        $housingTop = 4
        $housingH = $h - 30
        $housingBrush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(25, 25, 25))
        $housingPath = [System.Drawing.Drawing2D.GraphicsPath]::new()
        $cornerRadius = 8
        $housingPath.AddArc($housingX, $housingTop, $cornerRadius, $cornerRadius, 180, 90)
        $housingPath.AddArc($housingX + $housingW - $cornerRadius, $housingTop, $cornerRadius, $cornerRadius, 270, 90)
        $housingPath.AddArc($housingX + $housingW - $cornerRadius, $housingTop + $housingH - $cornerRadius, $cornerRadius, $cornerRadius, 0, 90)
        $housingPath.AddArc($housingX, $housingTop + $housingH - $cornerRadius, $cornerRadius, $cornerRadius, 90, 90)
        $housingPath.CloseFigure()
        $g.FillPath($housingBrush, $housingPath)
        $housingBrush.Dispose()

        $housingBorder = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(60, 60, 60), 1)
        $g.DrawPath($housingBorder, $housingPath)
        $housingBorder.Dispose()
        $housingPath.Dispose()

        # Three lights: Red (top), Yellow (middle), Green (bottom)
        $lightDiam = [Math]::Min([int]($housingW * 0.7), [int](($housingH - 20) / 3 - 6))
        $lightCx = $housingX + $housingW / 2
        $lightSpacing = ($housingH - 12) / 3

        $lights = @(
            @{ Color = "RED";    ActiveColor = [System.Drawing.Color]::FromArgb(220, 50, 50);  DimColor = [System.Drawing.Color]::FromArgb(60, 20, 20);  Y = $housingTop + 8 + $lightSpacing * 0 + $lightSpacing / 2 }
            @{ Color = "YELLOW"; ActiveColor = [System.Drawing.Color]::FromArgb(230, 200, 40); DimColor = [System.Drawing.Color]::FromArgb(60, 50, 15);  Y = $housingTop + 8 + $lightSpacing * 1 + $lightSpacing / 2 }
            @{ Color = "GREEN";  ActiveColor = [System.Drawing.Color]::FromArgb(50, 200, 50);  DimColor = [System.Drawing.Color]::FromArgb(15, 50, 15);  Y = $housingTop + 8 + $lightSpacing * 2 + $lightSpacing / 2 }
        )

        foreach ($light in $lights) {
            $isActive = ($status -eq $light.Color)
            $drawColor = if ($isActive) { $light.ActiveColor } else { $light.DimColor }
            $lx = $lightCx - $lightDiam / 2
            $ly = $light.Y - $lightDiam / 2

            if ($isActive) {
                # Glow effect
                $glowSize = $lightDiam + 8
                $glowBrush = [System.Drawing.SolidBrush]::new(
                    [System.Drawing.Color]::FromArgb(40, $light.ActiveColor.R, $light.ActiveColor.G, $light.ActiveColor.B))
                $g.FillEllipse($glowBrush, $lightCx - $glowSize / 2, $light.Y - $glowSize / 2, $glowSize, $glowSize)
                $glowBrush.Dispose()
            }

            # Light circle
            $lightBrush = [System.Drawing.SolidBrush]::new($drawColor)
            $g.FillEllipse($lightBrush, $lx, $ly, $lightDiam, $lightDiam)
            $lightBrush.Dispose()

            # Highlight reflection on active light
            if ($isActive) {
                $refSize = [int]($lightDiam * 0.35)
                $refBrush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(80, 255, 255, 255))
                $g.FillEllipse($refBrush, $lx + $lightDiam * 0.2, $ly + $lightDiam * 0.15, $refSize, $refSize)
                $refBrush.Dispose()
            }

            # Border
            $lightPen = [System.Drawing.Pen]::new([System.Drawing.Color]::FromArgb(80, 80, 80), 1)
            $g.DrawEllipse($lightPen, $lx, $ly, $lightDiam, $lightDiam)
            $lightPen.Dispose()
        }

        # Label below
        if ($label) {
            $lblSize = $g.MeasureString($label, $labelFont)
            $g.DrawString($label, $labelFont, $fgBrush,
                [System.Drawing.PointF]::new(($w - $lblSize.Width) / 2, $h - 20))
        }

        # Status text inside housing at top
        $statusText = switch ($status) { "RED" { "ALERT" }; "YELLOW" { "WARN" }; "GREEN" { "OK" }; default { $status } }
        $stSize = $g.MeasureString($statusText, $titleFont)
        # Place below the housing
        $g.DrawString($statusText, $titleFont, $fgBrush,
            [System.Drawing.PointF]::new(($w - $stSize.Width) / 2, $housingTop + $housingH + 2))

        $titleFont.Dispose(); $labelFont.Dispose(); $fgBrush.Dispose()
    })

    return $panel
}

function Update-AnomalyIndicatorWidget {
    param(
        [System.Windows.Forms.Panel]$Widget,
        [string]$Status,
        [string]$Label = $null
    )
    if (-not $Widget) { return }
    $Widget.Tag.Status = $Status
    if ($null -ne $Label) { $Widget.Tag.Label = $Label }
    $Widget.Invalidate()
}
