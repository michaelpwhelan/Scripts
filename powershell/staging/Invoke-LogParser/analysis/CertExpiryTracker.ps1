function Get-CertExpiryAnalysis {
    param([System.Collections.Generic.List[object]]$Entries)

    $certMap = @{}

    foreach ($entry in $Entries) {
        if (-not $entry.Extra) { continue }

        $thumbprint = $entry.Extra['Thumbprint']
        $notAfter = $entry.Extra['NotAfter']
        $daysToExpiry = $entry.Extra['DaysToExpiry']

        if (-not $thumbprint -and -not $notAfter -and $null -eq $daysToExpiry) { continue }

        $certKey = if ($thumbprint) { $thumbprint.ToUpper() } else { "$($entry.Extra['Subject'])_$notAfter" }
        if (-not $certKey) { continue }

        if (-not $certMap.ContainsKey($certKey)) {
            $certMap[$certKey] = @{
                Thumbprint  = $thumbprint
                Subject     = $entry.Extra['Subject']
                Issuer      = $entry.Extra['Issuer']
                NotAfter    = $null
                DaysToExpiry = $null
                Template    = $entry.Extra['Template']
                Status      = "Unknown"
                Source      = $entry.Extra['SourceFormat']
                Host        = $entry.Host
            }
        }

        $cert = $certMap[$certKey]

        # Update fields if better data available
        if (-not $cert.Subject -and $entry.Extra['Subject']) { $cert.Subject = $entry.Extra['Subject'] }
        if (-not $cert.Issuer -and $entry.Extra['Issuer']) { $cert.Issuer = $entry.Extra['Issuer'] }
        if (-not $cert.Template -and $entry.Extra['Template']) { $cert.Template = $entry.Extra['Template'] }
        if (-not $cert.Thumbprint -and $thumbprint) { $cert.Thumbprint = $thumbprint }

        # Parse NotAfter date
        if ($notAfter -and -not $cert.NotAfter) {
            $parsedDate = $null
            if ([datetime]::TryParse($notAfter, [ref]$parsedDate)) {
                $cert.NotAfter = $parsedDate
            }
        }

        # Parse DaysToExpiry
        if ($null -ne $daysToExpiry -and $null -eq $cert.DaysToExpiry) {
            $days = $daysToExpiry -as [int]
            if ($null -ne $days) {
                $cert.DaysToExpiry = $days
            }
        }
    }

    # Calculate DaysToExpiry from NotAfter if not already set, and assign status
    $expiredCount = 0; $criticalCount = 0; $warningCount = 0; $okCount = 0
    $certificates = [System.Collections.Generic.List[object]]::new()

    foreach ($certKey in $certMap.Keys) {
        $cert = $certMap[$certKey]

        if ($null -eq $cert.DaysToExpiry -and $cert.NotAfter) {
            $cert.DaysToExpiry = [Math]::Floor(($cert.NotAfter - [datetime]::Now).TotalDays)
        }

        if ($null -eq $cert.DaysToExpiry) {
            $cert.Status = "Unknown"
            $cert.DaysToExpiry = [int]::MaxValue
        } elseif ($cert.DaysToExpiry -le 0) {
            $cert.Status = "Expired"
            $expiredCount++
        } elseif ($cert.DaysToExpiry -le 30) {
            $cert.Status = "Critical"
            $criticalCount++
        } elseif ($cert.DaysToExpiry -le 90) {
            $cert.Status = "Warning"
            $warningCount++
        } else {
            $cert.Status = "OK"
            $okCount++
        }

        $certificates.Add($cert)
    }

    # Sort: Expired first, then Critical, Warning, OK - within each group by DaysToExpiry ascending
    $statusOrder = @{ 'Expired' = 0; 'Critical' = 1; 'Warning' = 2; 'OK' = 3; 'Unknown' = 4 }
    $sorted = $certificates | Sort-Object {
        $so = $statusOrder[$_.Status]
        if ($null -eq $so) { $so = 99 }
        $so
    }, { $_.DaysToExpiry }

    # Reset MaxValue placeholder for display
    foreach ($c in $sorted) {
        if ($c.DaysToExpiry -eq [int]::MaxValue) { $c.DaysToExpiry = $null }
    }

    return @{
        Certificates = @($sorted)
        Expired      = $expiredCount
        Critical     = $criticalCount
        Warning      = $warningCount
        OK           = $okCount
        Summary      = @{
            Total    = $certificates.Count
            Expired  = $expiredCount
            Critical = $criticalCount
            Warning  = $warningCount
            OK       = $okCount
        }
    }
}

function Show-CertExpiryDialog {
    param($Results)
    if (-not $Results -or $Results.Summary.Total -eq 0) {
        if (-not $Script:UseConsole) {
            [System.Windows.Forms.MessageBox]::Show("No certificate data found.", "Certificate Expiry Tracker")
        }
        return
    }

    if ($Script:UseConsole) {
        Write-CertExpiryTable -Results $Results
        return
    }

    $dlg = [System.Windows.Forms.Form]::new()
    $dlg.Text = "Certificate Expiry Tracker"; $dlg.Size = [System.Drawing.Size]::new(950, 600); $dlg.StartPosition = "CenterParent"
    $t = $Script:Themes[$Script:State.ActiveTheme]
    $dlg.BackColor = $t.FormBack; $dlg.ForeColor = $t.FormFore

    $grid = [System.Windows.Forms.DataGridView]::new()
    $grid.Dock = "Fill"; $grid.ReadOnly = $true; $grid.AllowUserToAddRows = $false
    $grid.BackgroundColor = $t.GridBack; $grid.DefaultCellStyle.BackColor = $t.GridBack; $grid.DefaultCellStyle.ForeColor = $t.FormFore
    $grid.ColumnHeadersDefaultCellStyle.BackColor = $t.GridBack; $grid.ColumnHeadersDefaultCellStyle.ForeColor = $t.FormFore
    $grid.EnableHeadersVisualStyles = $false
    $grid.Columns.Add("Subject", "Subject") | Out-Null
    $grid.Columns.Add("Issuer", "Issuer") | Out-Null
    $grid.Columns.Add("Expires", "Expires") | Out-Null
    $grid.Columns.Add("DaysLeft", "Days Left") | Out-Null
    $grid.Columns.Add("Template", "Template") | Out-Null
    $grid.Columns.Add("Status", "Status") | Out-Null

    foreach ($cert in $Results.Certificates) {
        $subject = if ($cert.Subject) { $cert.Subject } else { "(unknown)" }
        $issuer = if ($cert.Issuer) { $cert.Issuer } else { "" }
        $expiresStr = if ($cert.NotAfter) { $cert.NotAfter.ToString("yyyy-MM-dd") } else { "" }
        $daysLeft = if ($null -ne $cert.DaysToExpiry) { $cert.DaysToExpiry } else { "" }
        $template = if ($cert.Template) { $cert.Template } else { "" }

        $rowIdx = $grid.Rows.Add($subject, $issuer, $expiresStr, $daysLeft, $template, $cert.Status)

        switch ($cert.Status) {
            'Expired'  { $grid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Red }
            'Critical' { $grid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::OrangeRed }
            'Warning'  { $grid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Orange }
            'OK'       { $grid.Rows[$rowIdx].DefaultCellStyle.ForeColor = [System.Drawing.Color]::Green }
        }
    }
    $grid.AutoResizeColumns()

    $dlg.Controls.Add($grid)
    $dlg.ShowDialog($Script:UI.Form) | Out-Null
    $dlg.Dispose()
}

function Write-CertExpiryTable {
    param($Results)
    $r = $Script:ANSIReset
    $ct = $Script:ConsoleThemes[$Script:State.ActiveTheme]

    Write-Host "`n$($ct.Title)Certificate Expiry Tracker$r"
    Write-Host "$($ct.INFO)  Total: $($Results.Summary.Total)  |  Expired: $($Results.Summary.Expired)  |  Critical: $($Results.Summary.Critical)  |  Warning: $($Results.Summary.Warning)  |  OK: $($Results.Summary.OK)$r"
    Write-Host ""

    Write-Host "$($ct.Header){0,-40} {1,-30} {2,-12} {3,-10} {4,-20} {5}$r" -f "Subject", "Issuer", "Expires", "Days Left", "Template", "Status"
    Write-Host "$($ct.Border)$([string][char]0x2500 * 120)$r"

    foreach ($cert in $Results.Certificates) {
        $subject = if ($cert.Subject) {
            if ($cert.Subject.Length -gt 38) { $cert.Subject.Substring(0, 38) } else { $cert.Subject }
        } else { "(unknown)" }
        $issuer = if ($cert.Issuer) {
            if ($cert.Issuer.Length -gt 28) { $cert.Issuer.Substring(0, 28) } else { $cert.Issuer }
        } else { "" }
        $expiresStr = if ($cert.NotAfter) { $cert.NotAfter.ToString("yyyy-MM-dd") } else { "" }
        $daysLeft = if ($null -ne $cert.DaysToExpiry) { "$($cert.DaysToExpiry)" } else { "" }
        $template = if ($cert.Template) {
            if ($cert.Template.Length -gt 18) { $cert.Template.Substring(0, 18) } else { $cert.Template }
        } else { "" }

        $color = switch ($cert.Status) {
            'Expired'  { $ct.ERROR }
            'Critical' { $ct.ERROR }
            'Warning'  { $ct.WARNING }
            'OK'       { $ct.INFO }
            default    { $ct.INFO }
        }
        Write-Host "$color{0,-40} {1,-30} {2,-12} {3,-10} {4,-20} {5}$r" -f $subject, $issuer, $expiresStr, $daysLeft, $template, $cert.Status
    }
    Write-Host ""
}
