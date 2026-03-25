# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

$Config = @{
    ScriptName       = "Invoke-LogParser"
    Version          = "5.0.0"  # Upgraded from 4.0.0
    WindowTitle      = "Universal Log Parser v5.0"
    MinWidth         = 1200
    MinHeight        = 750
    DefaultWidth     = 1400
    DefaultHeight    = 900
    FilterPanelWidth = 220
    DetailPaneHeight = 250
    TailPollMs       = 1000
    DrainTimerMs     = 100
    MaxEntries       = 500000
    TempDir          = if ($Script:IsWindowsOS -and $env:TEMP) { Join-Path $env:TEMP "LogParser" } else { Join-Path "/tmp" "LogParser" }
    ScriptRoot       = $ScriptRoot
}
