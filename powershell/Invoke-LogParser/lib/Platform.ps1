# ═══════════════════════════════════════════════════════════════════════════════
# PLATFORM DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

$Script:IsWindowsOS = $PSVersionTable.PSEdition -ne 'Core' -or $IsWindows
$Script:HasWinForms = $false
if ($Script:IsWindowsOS -and -not $Script:UseConsoleParam) {
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        [System.Windows.Forms.Application]::EnableVisualStyles()
        $Script:HasWinForms = $true
    } catch {}
}
$Script:UseConsole = $Script:UseConsoleParam -or -not $Script:HasWinForms

if ($Script:UseConsole) {
    try {
        Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    } catch {}
}
