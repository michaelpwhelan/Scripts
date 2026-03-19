# ═══════════════════════════════════════════════════════════════════════════════
# ANSI ESCAPE HELPERS (console mode)
# ═══════════════════════════════════════════════════════════════════════════════

$Script:ESC = [char]27
function Get-AnsiCode { param([string]$Code) return "$($Script:ESC)[$Code" }

$Script:ConsoleThemes = @{
    Dark = @{
        CRITICAL = Get-AnsiCode "97;41m"; ERROR = Get-AnsiCode "91m"; WARNING = Get-AnsiCode "93m"
        INFO = Get-AnsiCode "0m"; DEBUG = Get-AnsiCode "90m"; TRACE = Get-AnsiCode "90m"; UNKNOWN = Get-AnsiCode "0m"
        Header = Get-AnsiCode "1;36m"; Dim = Get-AnsiCode "2m"; Border = Get-AnsiCode "90m"
        Title = Get-AnsiCode "1;97m"; Count = Get-AnsiCode "96m"
    }
    Light = @{
        CRITICAL = Get-AnsiCode "97;41m"; ERROR = Get-AnsiCode "31m"; WARNING = Get-AnsiCode "33m"
        INFO = Get-AnsiCode "0m"; DEBUG = Get-AnsiCode "37m"; TRACE = Get-AnsiCode "37m"; UNKNOWN = Get-AnsiCode "0m"
        Header = Get-AnsiCode "1;34m"; Dim = Get-AnsiCode "2m"; Border = Get-AnsiCode "37m"
        Title = Get-AnsiCode "1;30m"; Count = Get-AnsiCode "34m"
    }
    HighContrast = @{
        CRITICAL = Get-AnsiCode "97;45m"; ERROR = Get-AnsiCode "91;1m"; WARNING = Get-AnsiCode "93;1m"
        INFO = Get-AnsiCode "97m"; DEBUG = Get-AnsiCode "92m"; TRACE = Get-AnsiCode "92m"; UNKNOWN = Get-AnsiCode "97m"
        Header = Get-AnsiCode "1;93m"; Dim = Get-AnsiCode "37m"; Border = Get-AnsiCode "97m"
        Title = Get-AnsiCode "1;97m"; Count = Get-AnsiCode "93m"
    }
    SolarizedDark = @{
        CRITICAL = Get-AnsiCode "97;41m"; ERROR = Get-AnsiCode "38;5;160m"; WARNING = Get-AnsiCode "38;5;136m"
        INFO = Get-AnsiCode "38;5;246m"; DEBUG = Get-AnsiCode "38;5;240m"; TRACE = Get-AnsiCode "38;5;240m"; UNKNOWN = Get-AnsiCode "38;5;246m"
        Header = Get-AnsiCode "1;38;5;37m"; Dim = Get-AnsiCode "38;5;240m"; Border = Get-AnsiCode "38;5;240m"
        Title = Get-AnsiCode "1;38;5;246m"; Count = Get-AnsiCode "38;5;37m"
    }
    Nord = @{
        CRITICAL = Get-AnsiCode "97;48;5;131m"; ERROR = Get-AnsiCode "38;5;131m"; WARNING = Get-AnsiCode "38;5;179m"
        INFO = Get-AnsiCode "38;5;255m"; DEBUG = Get-AnsiCode "38;5;60m"; TRACE = Get-AnsiCode "38;5;60m"; UNKNOWN = Get-AnsiCode "38;5;255m"
        Header = Get-AnsiCode "1;38;5;110m"; Dim = Get-AnsiCode "38;5;60m"; Border = Get-AnsiCode "38;5;60m"
        Title = Get-AnsiCode "1;38;5;255m"; Count = Get-AnsiCode "38;5;110m"
    }
    Monokai = @{
        CRITICAL = Get-AnsiCode "97;48;5;197m"; ERROR = Get-AnsiCode "38;5;197m"; WARNING = Get-AnsiCode "38;5;208m"
        INFO = Get-AnsiCode "38;5;231m"; DEBUG = Get-AnsiCode "38;5;242m"; TRACE = Get-AnsiCode "38;5;242m"; UNKNOWN = Get-AnsiCode "38;5;231m"
        Header = Get-AnsiCode "1;38;5;148m"; Dim = Get-AnsiCode "38;5;242m"; Border = Get-AnsiCode "38;5;242m"
        Title = Get-AnsiCode "1;38;5;231m"; Count = Get-AnsiCode "38;5;81m"
    }
}
$Script:ANSIReset = Get-AnsiCode "0m"

# ═══════════════════════════════════════════════════════════════════════════════
# THEMES (GUI — only loaded when WinForms available)
# ═══════════════════════════════════════════════════════════════════════════════

if (-not $Script:UseConsole) {
$Script:Themes = @{
    Light = @{
        FormBack       = [System.Drawing.Color]::FromArgb(245, 245, 245)
        FormFore       = [System.Drawing.Color]::FromArgb(30, 30, 30)
        GridBack       = [System.Drawing.Color]::White
        GridAltBack    = [System.Drawing.Color]::FromArgb(250, 250, 250)
        GridLines      = [System.Drawing.Color]::FromArgb(220, 220, 220)
        GridHeaderBack = [System.Drawing.Color]::FromArgb(230, 230, 230)
        GridHeaderFore = [System.Drawing.Color]::FromArgb(30, 30, 30)
        PanelBack      = [System.Drawing.Color]::FromArgb(240, 240, 240)
        DetailBack     = [System.Drawing.Color]::White
        DetailFore     = [System.Drawing.Color]::FromArgb(30, 30, 30)
        SelectionBack  = [System.Drawing.Color]::FromArgb(0, 120, 215)
        SelectionFore  = [System.Drawing.Color]::White
        ButtonBack     = [System.Drawing.Color]::FromArgb(225, 225, 225)
        ButtonFore     = [System.Drawing.Color]::FromArgb(30, 30, 30)
        TextBoxBack    = [System.Drawing.Color]::White
        TextBoxFore    = [System.Drawing.Color]::FromArgb(30, 30, 30)
        MenuBack       = [System.Drawing.Color]::FromArgb(240, 240, 240)
        MenuFore       = [System.Drawing.Color]::FromArgb(30, 30, 30)
        StatusBack     = [System.Drawing.Color]::FromArgb(230, 230, 230)
        StatusFore     = [System.Drawing.Color]::FromArgb(30, 30, 30)
        SeverityColors = @{
            CRITICAL = @{ Back = [System.Drawing.Color]::DarkRed;                                    Fore = [System.Drawing.Color]::White }
            ERROR    = @{ Back = [System.Drawing.Color]::FromArgb(255, 68, 68);                      Fore = [System.Drawing.Color]::Black }
            WARNING  = @{ Back = [System.Drawing.Color]::FromArgb(255, 140, 0);                      Fore = [System.Drawing.Color]::Black }
            INFO     = @{ Back = $null; Fore = $null }
            DEBUG    = @{ Back = [System.Drawing.Color]::FromArgb(128, 128, 128);                    Fore = [System.Drawing.Color]::White }
            TRACE    = @{ Back = [System.Drawing.Color]::DarkGray;                                   Fore = [System.Drawing.Color]::White }
            UNKNOWN  = @{ Back = $null; Fore = $null }
        }
    }
    Dark = @{
        FormBack       = [System.Drawing.Color]::FromArgb(30, 30, 30)
        FormFore       = [System.Drawing.Color]::FromArgb(220, 220, 220)
        GridBack       = [System.Drawing.Color]::FromArgb(40, 40, 40)
        GridAltBack    = [System.Drawing.Color]::FromArgb(50, 50, 50)
        GridLines      = [System.Drawing.Color]::FromArgb(70, 70, 70)
        GridHeaderBack = [System.Drawing.Color]::FromArgb(55, 55, 55)
        GridHeaderFore = [System.Drawing.Color]::FromArgb(220, 220, 220)
        PanelBack      = [System.Drawing.Color]::FromArgb(35, 35, 35)
        DetailBack     = [System.Drawing.Color]::FromArgb(45, 45, 45)
        DetailFore     = [System.Drawing.Color]::FromArgb(220, 220, 220)
        SelectionBack  = [System.Drawing.Color]::FromArgb(0, 90, 180)
        SelectionFore  = [System.Drawing.Color]::White
        ButtonBack     = [System.Drawing.Color]::FromArgb(60, 60, 60)
        ButtonFore     = [System.Drawing.Color]::FromArgb(220, 220, 220)
        TextBoxBack    = [System.Drawing.Color]::FromArgb(50, 50, 50)
        TextBoxFore    = [System.Drawing.Color]::FromArgb(220, 220, 220)
        MenuBack       = [System.Drawing.Color]::FromArgb(45, 45, 45)
        MenuFore       = [System.Drawing.Color]::FromArgb(220, 220, 220)
        StatusBack     = [System.Drawing.Color]::FromArgb(35, 35, 35)
        StatusFore     = [System.Drawing.Color]::FromArgb(200, 200, 200)
        SeverityColors = @{
            CRITICAL = @{ Back = [System.Drawing.Color]::DarkRed;                                    Fore = [System.Drawing.Color]::White }
            ERROR    = @{ Back = [System.Drawing.Color]::FromArgb(255, 68, 68);                      Fore = [System.Drawing.Color]::White }
            WARNING  = @{ Back = [System.Drawing.Color]::FromArgb(255, 140, 0);                      Fore = [System.Drawing.Color]::Black }
            INFO     = @{ Back = $null; Fore = $null }
            DEBUG    = @{ Back = [System.Drawing.Color]::FromArgb(128, 128, 128);                    Fore = [System.Drawing.Color]::White }
            TRACE    = @{ Back = [System.Drawing.Color]::DarkGray;                                   Fore = [System.Drawing.Color]::White }
            UNKNOWN  = @{ Back = $null; Fore = $null }
        }
    }
    HighContrast = @{
        FormBack       = [System.Drawing.Color]::Black
        FormFore       = [System.Drawing.Color]::White
        GridBack       = [System.Drawing.Color]::Black
        GridAltBack    = [System.Drawing.Color]::FromArgb(15, 15, 15)
        GridLines      = [System.Drawing.Color]::FromArgb(80, 80, 80)
        GridHeaderBack = [System.Drawing.Color]::FromArgb(40, 40, 40)
        GridHeaderFore = [System.Drawing.Color]::Yellow
        PanelBack      = [System.Drawing.Color]::Black
        DetailBack     = [System.Drawing.Color]::Black
        DetailFore     = [System.Drawing.Color]::White
        SelectionBack  = [System.Drawing.Color]::Yellow
        SelectionFore  = [System.Drawing.Color]::Black
        ButtonBack     = [System.Drawing.Color]::FromArgb(40, 40, 40)
        ButtonFore     = [System.Drawing.Color]::White
        TextBoxBack    = [System.Drawing.Color]::FromArgb(20, 20, 20)
        TextBoxFore    = [System.Drawing.Color]::White
        MenuBack       = [System.Drawing.Color]::Black
        MenuFore       = [System.Drawing.Color]::White
        StatusBack     = [System.Drawing.Color]::Black
        StatusFore     = [System.Drawing.Color]::Yellow
        HighlightBack  = [System.Drawing.Color]::Yellow
        SeverityColors = @{
            CRITICAL = @{ Back = [System.Drawing.Color]::Magenta;                               Fore = [System.Drawing.Color]::White }
            ERROR    = @{ Back = [System.Drawing.Color]::FromArgb(255, 0, 0);                   Fore = [System.Drawing.Color]::White }
            WARNING  = @{ Back = [System.Drawing.Color]::FromArgb(255, 255, 0);                 Fore = [System.Drawing.Color]::Black }
            INFO     = @{ Back = $null; Fore = $null }
            DEBUG    = @{ Back = [System.Drawing.Color]::FromArgb(0, 200, 0);                   Fore = [System.Drawing.Color]::Black }
            TRACE    = @{ Back = [System.Drawing.Color]::FromArgb(0, 150, 0);                   Fore = [System.Drawing.Color]::Black }
            UNKNOWN  = @{ Back = $null; Fore = $null }
        }
    }
    SolarizedDark = @{
        FormBack       = [System.Drawing.Color]::FromArgb(0, 43, 54)
        FormFore       = [System.Drawing.Color]::FromArgb(131, 148, 150)
        GridBack       = [System.Drawing.Color]::FromArgb(0, 43, 54)
        GridAltBack    = [System.Drawing.Color]::FromArgb(7, 54, 66)
        GridLines      = [System.Drawing.Color]::FromArgb(88, 110, 117)
        GridHeaderBack = [System.Drawing.Color]::FromArgb(7, 54, 66)
        GridHeaderFore = [System.Drawing.Color]::FromArgb(147, 161, 161)
        PanelBack      = [System.Drawing.Color]::FromArgb(0, 43, 54)
        DetailBack     = [System.Drawing.Color]::FromArgb(7, 54, 66)
        DetailFore     = [System.Drawing.Color]::FromArgb(131, 148, 150)
        SelectionBack  = [System.Drawing.Color]::FromArgb(38, 139, 210)
        SelectionFore  = [System.Drawing.Color]::FromArgb(253, 246, 227)
        ButtonBack     = [System.Drawing.Color]::FromArgb(7, 54, 66)
        ButtonFore     = [System.Drawing.Color]::FromArgb(131, 148, 150)
        TextBoxBack    = [System.Drawing.Color]::FromArgb(7, 54, 66)
        TextBoxFore    = [System.Drawing.Color]::FromArgb(131, 148, 150)
        MenuBack       = [System.Drawing.Color]::FromArgb(0, 43, 54)
        MenuFore       = [System.Drawing.Color]::FromArgb(131, 148, 150)
        StatusBack     = [System.Drawing.Color]::FromArgb(0, 43, 54)
        StatusFore     = [System.Drawing.Color]::FromArgb(101, 123, 131)
        HighlightBack  = [System.Drawing.Color]::FromArgb(181, 137, 0)
        SeverityColors = @{
            CRITICAL = @{ Back = [System.Drawing.Color]::FromArgb(220, 50, 47);                 Fore = [System.Drawing.Color]::FromArgb(253, 246, 227) }
            ERROR    = @{ Back = [System.Drawing.Color]::FromArgb(203, 75, 22);                 Fore = [System.Drawing.Color]::FromArgb(253, 246, 227) }
            WARNING  = @{ Back = [System.Drawing.Color]::FromArgb(181, 137, 0);                 Fore = [System.Drawing.Color]::FromArgb(0, 43, 54) }
            INFO     = @{ Back = $null; Fore = $null }
            DEBUG    = @{ Back = [System.Drawing.Color]::FromArgb(88, 110, 117);                Fore = [System.Drawing.Color]::FromArgb(253, 246, 227) }
            TRACE    = @{ Back = [System.Drawing.Color]::FromArgb(88, 110, 117);                Fore = [System.Drawing.Color]::FromArgb(147, 161, 161) }
            UNKNOWN  = @{ Back = $null; Fore = $null }
        }
    }
    Nord = @{
        FormBack       = [System.Drawing.Color]::FromArgb(46, 52, 64)
        FormFore       = [System.Drawing.Color]::FromArgb(236, 239, 244)
        GridBack       = [System.Drawing.Color]::FromArgb(46, 52, 64)
        GridAltBack    = [System.Drawing.Color]::FromArgb(59, 66, 82)
        GridLines      = [System.Drawing.Color]::FromArgb(76, 86, 106)
        GridHeaderBack = [System.Drawing.Color]::FromArgb(59, 66, 82)
        GridHeaderFore = [System.Drawing.Color]::FromArgb(236, 239, 244)
        PanelBack      = [System.Drawing.Color]::FromArgb(46, 52, 64)
        DetailBack     = [System.Drawing.Color]::FromArgb(59, 66, 82)
        DetailFore     = [System.Drawing.Color]::FromArgb(236, 239, 244)
        SelectionBack  = [System.Drawing.Color]::FromArgb(136, 192, 208)
        SelectionFore  = [System.Drawing.Color]::FromArgb(46, 52, 64)
        ButtonBack     = [System.Drawing.Color]::FromArgb(59, 66, 82)
        ButtonFore     = [System.Drawing.Color]::FromArgb(236, 239, 244)
        TextBoxBack    = [System.Drawing.Color]::FromArgb(59, 66, 82)
        TextBoxFore    = [System.Drawing.Color]::FromArgb(236, 239, 244)
        MenuBack       = [System.Drawing.Color]::FromArgb(46, 52, 64)
        MenuFore       = [System.Drawing.Color]::FromArgb(236, 239, 244)
        StatusBack     = [System.Drawing.Color]::FromArgb(46, 52, 64)
        StatusFore     = [System.Drawing.Color]::FromArgb(216, 222, 233)
        HighlightBack  = [System.Drawing.Color]::FromArgb(235, 203, 139)
        SeverityColors = @{
            CRITICAL = @{ Back = [System.Drawing.Color]::FromArgb(191, 97, 106);                Fore = [System.Drawing.Color]::White }
            ERROR    = @{ Back = [System.Drawing.Color]::FromArgb(208, 135, 112);               Fore = [System.Drawing.Color]::FromArgb(46, 52, 64) }
            WARNING  = @{ Back = [System.Drawing.Color]::FromArgb(235, 203, 139);               Fore = [System.Drawing.Color]::FromArgb(46, 52, 64) }
            INFO     = @{ Back = $null; Fore = $null }
            DEBUG    = @{ Back = [System.Drawing.Color]::FromArgb(76, 86, 106);                 Fore = [System.Drawing.Color]::FromArgb(216, 222, 233) }
            TRACE    = @{ Back = [System.Drawing.Color]::FromArgb(76, 86, 106);                 Fore = [System.Drawing.Color]::FromArgb(143, 188, 187) }
            UNKNOWN  = @{ Back = $null; Fore = $null }
        }
    }
    Monokai = @{
        FormBack       = [System.Drawing.Color]::FromArgb(39, 40, 34)
        FormFore       = [System.Drawing.Color]::FromArgb(248, 248, 242)
        GridBack       = [System.Drawing.Color]::FromArgb(39, 40, 34)
        GridAltBack    = [System.Drawing.Color]::FromArgb(49, 50, 44)
        GridLines      = [System.Drawing.Color]::FromArgb(70, 71, 65)
        GridHeaderBack = [System.Drawing.Color]::FromArgb(49, 50, 44)
        GridHeaderFore = [System.Drawing.Color]::FromArgb(248, 248, 242)
        PanelBack      = [System.Drawing.Color]::FromArgb(39, 40, 34)
        DetailBack     = [System.Drawing.Color]::FromArgb(49, 50, 44)
        DetailFore     = [System.Drawing.Color]::FromArgb(248, 248, 242)
        SelectionBack  = [System.Drawing.Color]::FromArgb(73, 72, 62)
        SelectionFore  = [System.Drawing.Color]::FromArgb(248, 248, 242)
        ButtonBack     = [System.Drawing.Color]::FromArgb(49, 50, 44)
        ButtonFore     = [System.Drawing.Color]::FromArgb(248, 248, 242)
        TextBoxBack    = [System.Drawing.Color]::FromArgb(49, 50, 44)
        TextBoxFore    = [System.Drawing.Color]::FromArgb(248, 248, 242)
        MenuBack       = [System.Drawing.Color]::FromArgb(39, 40, 34)
        MenuFore       = [System.Drawing.Color]::FromArgb(248, 248, 242)
        StatusBack     = [System.Drawing.Color]::FromArgb(39, 40, 34)
        StatusFore     = [System.Drawing.Color]::FromArgb(117, 113, 94)
        HighlightBack  = [System.Drawing.Color]::FromArgb(230, 219, 116)
        SeverityColors = @{
            CRITICAL = @{ Back = [System.Drawing.Color]::FromArgb(249, 38, 114);                Fore = [System.Drawing.Color]::White }
            ERROR    = @{ Back = [System.Drawing.Color]::FromArgb(249, 38, 114);                Fore = [System.Drawing.Color]::FromArgb(248, 248, 242) }
            WARNING  = @{ Back = [System.Drawing.Color]::FromArgb(253, 151, 31);                Fore = [System.Drawing.Color]::FromArgb(39, 40, 34) }
            INFO     = @{ Back = $null; Fore = $null }
            DEBUG    = @{ Back = [System.Drawing.Color]::FromArgb(117, 113, 94);                Fore = [System.Drawing.Color]::FromArgb(248, 248, 242) }
            TRACE    = @{ Back = [System.Drawing.Color]::FromArgb(117, 113, 94);                Fore = [System.Drawing.Color]::FromArgb(166, 226, 46) }
            UNKNOWN  = @{ Back = $null; Fore = $null }
        }
    }
}
} # end if (-not $Script:UseConsole) — GUI themes

# ═══════════════════════════════════════════════════════════════════════════════
# THEME ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

function Set-Theme {
    param([string]$ThemeName)
    $Script:State.ActiveTheme = $ThemeName
    $t = $Script:Themes[$ThemeName]
    $form = $Script:UI.Form
    if (-not $form) { return }

    $form.BackColor = $t.FormBack; $form.ForeColor = $t.FormFore

    # Recursively theme controls
    $themeControl = {
        param($control, $theme)
        if ($control -is [System.Windows.Forms.DataGridView]) {
            $control.BackgroundColor = $theme.GridBack
            $control.DefaultCellStyle.BackColor = $theme.GridBack
            $control.DefaultCellStyle.ForeColor = $theme.FormFore
            $control.DefaultCellStyle.SelectionBackColor = $theme.SelectionBack
            $control.DefaultCellStyle.SelectionForeColor = $theme.SelectionFore
            $control.AlternatingRowsDefaultCellStyle.BackColor = $theme.GridAltBack
            $control.AlternatingRowsDefaultCellStyle.ForeColor = $theme.FormFore
            $control.ColumnHeadersDefaultCellStyle.BackColor = $theme.GridHeaderBack
            $control.ColumnHeadersDefaultCellStyle.ForeColor = $theme.GridHeaderFore
            $control.GridColor = $theme.GridLines
            $control.EnableHeadersVisualStyles = $false
        }
        elseif ($control -is [System.Windows.Forms.RichTextBox]) {
            $control.BackColor = $theme.DetailBack; $control.ForeColor = $theme.DetailFore
        }
        elseif ($control -is [System.Windows.Forms.TextBox]) {
            $control.BackColor = $theme.TextBoxBack; $control.ForeColor = $theme.TextBoxFore
        }
        elseif ($control -is [System.Windows.Forms.Button]) {
            $control.BackColor = $theme.ButtonBack; $control.ForeColor = $theme.ButtonFore
            $control.FlatStyle = 'Flat'; $control.FlatAppearance.BorderColor = $theme.GridLines
        }
        elseif ($control -is [System.Windows.Forms.ComboBox]) {
            $control.BackColor = $theme.TextBoxBack; $control.ForeColor = $theme.TextBoxFore
        }
        elseif ($control -is [System.Windows.Forms.CheckBox]) {
            $control.ForeColor = $theme.FormFore
        }
        elseif ($control -is [System.Windows.Forms.RadioButton]) {
            $control.ForeColor = $theme.FormFore
        }
        elseif ($control -is [System.Windows.Forms.Label]) {
            $control.ForeColor = $theme.FormFore
        }
        elseif ($control -is [System.Windows.Forms.Panel] -or $control -is [System.Windows.Forms.FlowLayoutPanel]) {
            $control.BackColor = $theme.PanelBack
        }
        elseif ($control -is [System.Windows.Forms.SplitContainer]) {
            $control.BackColor = $theme.FormBack
        }
        elseif ($control -is [System.Windows.Forms.MenuStrip]) {
            $control.BackColor = $theme.MenuBack; $control.ForeColor = $theme.MenuFore
            foreach ($item in $control.Items) {
                $item.BackColor = $theme.MenuBack; $item.ForeColor = $theme.MenuFore
            }
        }
        elseif ($control -is [System.Windows.Forms.StatusStrip]) {
            $control.BackColor = $theme.StatusBack; $control.ForeColor = $theme.StatusFore
        }
        elseif ($control -is [System.Windows.Forms.DateTimePicker]) {
            $control.CalendarForeColor = $theme.FormFore
        }

        if ($control.Controls) {
            foreach ($child in $control.Controls) {
                & $themeControl $child $theme
            }
        }
    }
    & $themeControl $form $t
    $form.Invalidate($true)
}

function Update-StatusBar {
    param([string]$Text, [switch]$IsError)
    if ($Script:UI.StatusLabel) {
        $Script:UI.StatusLabel.Text = $Text
        if ($IsError) { $Script:UI.StatusLabel.ForeColor = [System.Drawing.Color]::Red }
        else { $Script:UI.StatusLabel.ForeColor = $Script:Themes[$Script:State.ActiveTheme].StatusFore }
    }
}
