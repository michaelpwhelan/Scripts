# Load investigation templates from JSON
function Get-InvestigationTemplates {
    $templatePath = Join-Path $Config.ScriptRoot "data" "investigation-templates.json"
    if (-not (Test-Path $templatePath)) { return @() }
    try {
        $content = [System.IO.File]::ReadAllText($templatePath)
        return ($content | ConvertFrom-Json)
    } catch {
        Write-Log "Failed to load investigation templates: $_" -Level WARNING
        return @()
    }
}

function Get-InvestigationTemplate {
    param([string]$Name)
    $templates = Get-InvestigationTemplates
    $normalized = $Name.ToLower() -replace '\s+', '-'
    return $templates | Where-Object { ($_.id -eq $normalized) -or ($_.name -eq $Name) } | Select-Object -First 1
}

function Invoke-InvestigationTemplate {
    param($Template)
    if (-not $Template) { return }

    # Apply template to GUI filter controls
    if (-not $Script:UseConsole -and $Script:UI.TxtSearch) {
        if ($Template.regex) {
            $Script:UI.TxtSearch.Text = $Template.regex
            $Script:UI.RadRegex.Checked = $true
        }
        if ($Template.levels) {
            $levels = @($Template.levels)
            $Script:UI.ChkCritical.Checked = "CRITICAL" -in $levels
            $Script:UI.ChkError.Checked = "ERROR" -in $levels
            $Script:UI.ChkWarning.Checked = "WARNING" -in $levels
            $Script:UI.ChkInfo.Checked = "INFO" -in $levels
            $Script:UI.ChkDebug.Checked = "DEBUG" -in $levels
        }
        if ($Template.dateRelative) {
            $now = Get-Date
            if ($Template.dateRelative -match '^-(\d+)([hdm])$') {
                $val = [int]$Matches[1]
                $fromDate = switch ($Matches[2]) {
                    'h' { $now.AddHours(-$val) }
                    'd' { $now.AddDays(-$val) }
                    'm' { $now.AddMonths(-$val) }
                }
                $Script:UI.DtpFrom.Value = $fromDate
                $Script:UI.DtpFrom.Checked = $true
            }
        }
        Invoke-ApplyFilters
        Update-StatsBar
    }
}

# Populate the Investigations menu in GUI
function Initialize-InvestigationMenu {
    if ($Script:UseConsole -or -not $Script:UI.InvestigationsMenu) { return }
    $templates = Get-InvestigationTemplates
    if (-not $templates -or @($templates).Count -eq 0) { return }

    $categories = @{}
    foreach ($t in $templates) {
        $cat = if ($t.category) { $t.category } else { "Other" }
        if (-not $categories.ContainsKey($cat)) { $categories[$cat] = [System.Collections.Generic.List[object]]::new() }
        $categories[$cat].Add($t)
    }

    foreach ($cat in ($categories.Keys | Sort-Object)) {
        $catMenu = [System.Windows.Forms.ToolStripMenuItem]::new($cat)
        foreach ($tmpl in $categories[$cat]) {
            $item = [System.Windows.Forms.ToolStripMenuItem]::new($tmpl.name)
            $templateRef = $tmpl
            $item.Add_Click({ Invoke-InvestigationTemplate $templateRef }.GetNewClosure())
            $catMenu.DropDownItems.Add($item) | Out-Null
        }
        $Script:UI.InvestigationsMenu.DropDownItems.Add($catMenu) | Out-Null
    }
}
