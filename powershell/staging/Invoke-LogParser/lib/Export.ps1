# ═══════════════════════════════════════════════════════════════════════════════
# EXPORT
# ═══════════════════════════════════════════════════════════════════════════════

# --- GUI dialog wrappers ---

function Export-ToCsv {
    $sfd = [System.Windows.Forms.SaveFileDialog]::new()
    $sfd.Filter = "CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
    $sfd.FileName = "log_export_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    if ($sfd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

    try {
        $sw = [System.IO.StreamWriter]::new($sfd.FileName, $false, [System.Text.Encoding]::UTF8)
        # Collect all extra field keys
        $extraKeys = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($e in $Script:State.FilteredEntries) {
            if ($e.Extra) { foreach ($k in $e.Extra.Keys) { $extraKeys.Add($k) | Out-Null } }
        }
        $extraKeyList = $extraKeys | Sort-Object

        $headers = @("Index", "Timestamp", "Level", "Source", "Host", "Message") + $extraKeyList
        $sw.WriteLine(($headers | ForEach-Object { "`"$_`"" }) -join ",")

        foreach ($e in $Script:State.FilteredEntries) {
            $row = @(
                $e.Index
                $(if ($e.Timestamp -ne [datetime]::MinValue) { $e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss") } else { "" })
                $e.Level
                $e.Source
                $e.Host
                $e.Message -replace '[\r\n]+', ' | ' -replace '"', '""'
            )
            foreach ($k in $extraKeyList) {
                $val = if ($e.Extra -and $e.Extra.ContainsKey($k)) { [string]$e.Extra[$k] -replace '[\r\n]+', ' | ' -replace '"', '""' } else { "" }
                $row += $val
            }
            $sw.WriteLine(($row | ForEach-Object { "`"$_`"" }) -join ",")
        }
        $sw.Close()
        Update-StatusBar "Exported $($Script:State.FilteredEntries.Count) entries to CSV"
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Export failed: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

function Export-ToHtml {
    $sfd = [System.Windows.Forms.SaveFileDialog]::new()
    $sfd.Filter = "HTML Files (*.html)|*.html|All Files (*.*)|*.*"
    $sfd.FileName = "log_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    if ($sfd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

    try {
        $sw = [System.IO.StreamWriter]::new($sfd.FileName, $false, [System.Text.Encoding]::UTF8)
        $filtered = $Script:State.FilteredEntries
        $counts = @{ CRITICAL = 0; ERROR = 0; WARNING = 0; INFO = 0; DEBUG = 0 }
        foreach ($e in $filtered) { if ($counts.ContainsKey($e.Level)) { $counts[$e.Level]++ } }

        $colorMap = @{
            CRITICAL = "background:#8b0000;color:#fff"
            ERROR    = "background:#ff4444;color:#fff"
            WARNING  = "background:#ff8c00;color:#000"
            INFO     = "background:#f5f5f5;color:#000"
            DEBUG    = "background:#808080;color:#fff"
            TRACE    = "background:#a9a9a9;color:#fff"
            UNKNOWN  = "background:#f5f5f5;color:#000"
        }

        $sw.WriteLine(@"
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Log Analysis Report</title>
<style>
  body { font-family: Segoe UI, Tahoma, sans-serif; margin: 20px; background: #fff; color: #333; }
  h1 { border-bottom: 2px solid #0078d4; padding-bottom: 8px; }
  .summary { display: flex; gap: 20px; margin: 15px 0; flex-wrap: wrap; }
  .summary .card { background: #f0f0f0; border-radius: 6px; padding: 12px 20px; min-width: 120px; }
  .summary .card h3 { margin: 0 0 4px 0; font-size: 13px; color: #666; }
  .summary .card .val { font-size: 24px; font-weight: bold; }
  .crit .val { color: #8b0000; } .err .val { color: #ff4444; }
  .warn .val { color: #ff8c00; }
  table { border-collapse: collapse; width: 100%; margin-top: 20px; font-size: 13px; }
  th { background: #0078d4; color: #fff; padding: 8px 10px; text-align: left; position: sticky; top: 0; }
  td { padding: 6px 10px; border-bottom: 1px solid #ddd; max-width: 600px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  tr:hover td { background: #e8f0fe !important; }
  .meta { color: #888; font-size: 12px; margin-top: 20px; }
  @media print { th { background: #333 !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
</style></head><body>
<h1>Log Analysis Report</h1>
<p><strong>Source:</strong> $(Invoke-HtmlEncode($Script:State.OriginalPath ?? $Script:State.FilePath))<br>
<strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
<strong>Entries shown:</strong> $($filtered.Count) of $($Script:State.AllEntries.Count)</p>
<div class="summary">
  <div class="card crit"><h3>Critical</h3><div class="val">$($counts['CRITICAL'])</div></div>
  <div class="card err"><h3>Errors</h3><div class="val">$($counts['ERROR'])</div></div>
  <div class="card warn"><h3>Warnings</h3><div class="val">$($counts['WARNING'])</div></div>
  <div class="card"><h3>Info</h3><div class="val">$($counts['INFO'])</div></div>
  <div class="card"><h3>Debug</h3><div class="val">$($counts['DEBUG'])</div></div>
  <div class="card"><h3>Total</h3><div class="val">$($filtered.Count)</div></div>
</div>
<table><tr><th>#</th><th>Timestamp</th><th>Level</th><th>Source</th><th>Message</th></tr>
"@)
        $maxRows = [Math]::Min($filtered.Count, 5000)
        for ($i = 0; $i -lt $maxRows; $i++) {
            $e = $filtered[$i]
            $style = if ($colorMap.ContainsKey($e.Level)) { $colorMap[$e.Level] } else { "" }
            $tsStr = if ($e.Timestamp -ne [datetime]::MinValue) { $e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
            $encodedMsg = Invoke-HtmlEncode($e.Message)
            $msgHtml = Invoke-HtmlEncode($e.Message.Substring(0, [Math]::Min(300, $e.Message.Length)))
            $encodedSrc = Invoke-HtmlEncode($e.Source)
            $sw.WriteLine("<tr style=`"$style`"><td>$($e.Index)</td><td>$tsStr</td><td>$($e.Level)</td><td>$encodedSrc</td><td title=`"$encodedMsg`">$msgHtml</td></tr>")
        }
        if ($filtered.Count -gt $maxRows) {
            $sw.WriteLine("<tr><td colspan='5' style='text-align:center;color:#888;'>... $($filtered.Count - $maxRows) more entries truncated ...</td></tr>")
        }
        $sw.WriteLine("</table>")
        $sw.WriteLine("<p class='meta'>Generated by Universal Log Parser v$($Config.Version)</p></body></html>")
        $sw.Close()
        Update-StatusBar "Exported HTML report ($maxRows entries)"
    } catch {
        [System.Windows.Forms.MessageBox]::Show("HTML export failed: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

function Copy-SelectionToClipboard {
    if (-not $Script:UI.DataGrid -or $Script:UI.DataGrid.SelectedRows.Count -eq 0) { return }
    $sb = [System.Text.StringBuilder]::new()
    $sb.AppendLine("Index`tTimestamp`tLevel`tSource`tMessage") | Out-Null
    foreach ($row in $Script:UI.DataGrid.SelectedRows | Sort-Object { $_.Index }) {
        $entry = $Script:State.FilteredEntries[$row.Index]
        $tsStr = if ($entry.Timestamp -ne [datetime]::MinValue) { $entry.Timestamp.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
        $sb.AppendLine("$($entry.Index)`t$tsStr`t$($entry.Level)`t$($entry.Source)`t$($entry.Message)") | Out-Null
    }
    [System.Windows.Forms.Clipboard]::SetText($sb.ToString())
    Update-StatusBar "Copied $($Script:UI.DataGrid.SelectedRows.Count) rows to clipboard"
}

# --- Console core functions ---

function Export-ToCsvFile {
    param([string]$OutputPath, [System.Collections.Generic.List[object]]$Entries)
    $sw = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.Encoding]::UTF8)
    $extraKeys = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($e in $Entries) {
        if ($e.Extra) { foreach ($k in $e.Extra.Keys) { $extraKeys.Add($k) | Out-Null } }
    }
    $extraKeyList = $extraKeys | Sort-Object
    $headers = @("Index", "Timestamp", "Level", "Source", "Host", "Message") + $extraKeyList
    $sw.WriteLine(($headers | ForEach-Object { "`"$_`"" }) -join ",")
    foreach ($e in $Entries) {
        $row = @(
            $e.Index
            $(if ($e.Timestamp -ne [datetime]::MinValue) { $e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss") } else { "" })
            $e.Level
            $e.Source
            $e.Host
            $e.Message -replace '[\r\n]+', ' | ' -replace '"', '""'
        )
        foreach ($k in $extraKeyList) {
            $val = if ($e.Extra -and $e.Extra.ContainsKey($k)) { [string]$e.Extra[$k] -replace '[\r\n]+', ' | ' -replace '"', '""' } else { "" }
            $row += $val
        }
        $sw.WriteLine(($row | ForEach-Object { "`"$_`"" }) -join ",")
    }
    $sw.Close()
}

function Export-ToHtmlFile {
    param([string]$OutputPath, [System.Collections.Generic.List[object]]$Entries, [int]$TotalCount, [string]$SourcePath)
    $sw = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.Encoding]::UTF8)
    $counts = @{ CRITICAL = 0; ERROR = 0; WARNING = 0; INFO = 0; DEBUG = 0 }
    foreach ($e in $Entries) { if ($counts.ContainsKey($e.Level)) { $counts[$e.Level]++ } }
    $colorMap = @{
        CRITICAL = "background:#8b0000;color:#fff"; ERROR = "background:#ff4444;color:#fff"
        WARNING = "background:#ff8c00;color:#000"; INFO = "background:#f5f5f5;color:#000"
        DEBUG = "background:#808080;color:#fff"; TRACE = "background:#a9a9a9;color:#fff"; UNKNOWN = "background:#f5f5f5;color:#000"
    }
    $sw.WriteLine(@"
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Log Analysis Report</title>
<style>
  body { font-family: Segoe UI, Tahoma, sans-serif; margin: 20px; background: #fff; color: #333; }
  h1 { border-bottom: 2px solid #0078d4; padding-bottom: 8px; }
  .summary { display: flex; gap: 20px; margin: 15px 0; flex-wrap: wrap; }
  .summary .card { background: #f0f0f0; border-radius: 6px; padding: 12px 20px; min-width: 120px; }
  .summary .card h3 { margin: 0 0 4px 0; font-size: 13px; color: #666; }
  .summary .card .val { font-size: 24px; font-weight: bold; }
  .crit .val { color: #8b0000; } .err .val { color: #ff4444; } .warn .val { color: #ff8c00; }
  table { border-collapse: collapse; width: 100%; margin-top: 20px; font-size: 13px; }
  th { background: #0078d4; color: #fff; padding: 8px 10px; text-align: left; position: sticky; top: 0; }
  td { padding: 6px 10px; border-bottom: 1px solid #ddd; max-width: 600px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  tr:hover td { background: #e8f0fe !important; }
  .meta { color: #888; font-size: 12px; margin-top: 20px; }
</style></head><body>
<h1>Log Analysis Report</h1>
<p><strong>Source:</strong> $(Invoke-HtmlEncode $SourcePath)<br>
<strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
<strong>Entries shown:</strong> $($Entries.Count) of $TotalCount</p>
<div class="summary">
  <div class="card crit"><h3>Critical</h3><div class="val">$($counts['CRITICAL'])</div></div>
  <div class="card err"><h3>Errors</h3><div class="val">$($counts['ERROR'])</div></div>
  <div class="card warn"><h3>Warnings</h3><div class="val">$($counts['WARNING'])</div></div>
  <div class="card"><h3>Info</h3><div class="val">$($counts['INFO'])</div></div>
  <div class="card"><h3>Debug</h3><div class="val">$($counts['DEBUG'])</div></div>
  <div class="card"><h3>Total</h3><div class="val">$($Entries.Count)</div></div>
</div>
<table><tr><th>#</th><th>Timestamp</th><th>Level</th><th>Source</th><th>Message</th></tr>
"@)
    $maxRows = [Math]::Min($Entries.Count, 5000)
    for ($i = 0; $i -lt $maxRows; $i++) {
        $e = $Entries[$i]
        $style = if ($colorMap.ContainsKey($e.Level)) { $colorMap[$e.Level] } else { "" }
        $tsStr = if ($e.Timestamp -ne [datetime]::MinValue) { $e.Timestamp.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
        $encodedMsg = Invoke-HtmlEncode($e.Message)
        $msgHtml = Invoke-HtmlEncode($e.Message.Substring(0, [Math]::Min(300, $e.Message.Length)))
        $encodedSrc = Invoke-HtmlEncode($e.Source)
        $sw.WriteLine("<tr style=`"$style`"><td>$($e.Index)</td><td>$tsStr</td><td>$($e.Level)</td><td>$encodedSrc</td><td title=`"$encodedMsg`">$msgHtml</td></tr>")
    }
    if ($Entries.Count -gt $maxRows) {
        $sw.WriteLine("<tr><td colspan='5' style='text-align:center;color:#888;'>... $($Entries.Count - $maxRows) more entries truncated ...</td></tr>")
    }
    $sw.WriteLine("</table><p class='meta'>Generated by Universal Log Parser v$($Config.Version)</p></body></html>")
    $sw.Close()
}

# --- JSON Export ---

function Export-ToJson {
    $sfd = [System.Windows.Forms.SaveFileDialog]::new()
    $sfd.Filter = "JSON Files (*.json)|*.json|All Files (*.*)|*.*"
    $sfd.FileName = "log_export_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    if ($sfd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
    try {
        Export-ToJsonFile -OutputPath $sfd.FileName -Entries $Script:State.FilteredEntries
        Update-StatusBar "Exported $($Script:State.FilteredEntries.Count) entries to JSON"
    } catch {
        [System.Windows.Forms.MessageBox]::Show("JSON export failed: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

function Export-ToJsonFile {
    param([string]$OutputPath, [System.Collections.Generic.List[object]]$Entries)
    $sw = [System.IO.StreamWriter]::new($OutputPath, $false, [System.Text.Encoding]::UTF8)
    $sw.WriteLine("[")
    $count = 0
    foreach ($e in $Entries) {
        $obj = [ordered]@{
            Index = $e.Index
            Timestamp = if ($e.Timestamp -ne [datetime]::MinValue) { $e.Timestamp.ToString("yyyy-MM-ddTHH:mm:ss") } else { $null }
            Level = $e.Level
            Source = $e.Source
            Host = $e.Host
            Message = $e.Message
        }
        if ($e.Extra -and $e.Extra.Count -gt 0) {
            foreach ($k in ($e.Extra.Keys | Sort-Object)) { $obj[$k] = $e.Extra[$k] }
        }
        $json = $obj | ConvertTo-Json -Compress -Depth 3
        $comma = if ($count -lt $Entries.Count - 1) { "," } else { "" }
        $sw.WriteLine("  $json$comma")
        $count++
    }
    $sw.WriteLine("]")
    $sw.Close()
}
