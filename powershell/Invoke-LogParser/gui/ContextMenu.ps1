# ContextMenu.ps1 — Right-click context menu for the DataGridView

function New-GridContextMenu {
    param($grid)
    $ctxMenu = [System.Windows.Forms.ContextMenuStrip]::new()
    $ctxFilterBy = [System.Windows.Forms.ToolStripMenuItem]::new("Filter by this value")
    $ctxFilterBy.Add_Click({
        $cell = $grid.CurrentCell
        if ($null -eq $cell) { return }
        $val = $cell.Value
        if ($cell.ColumnIndex -eq 3) { $Script:UI.CmbLevel.SelectedItem = $val }
        elseif ($cell.ColumnIndex -eq 4) { $Script:UI.TxtSource.Text = $val }
        else { $Script:UI.TxtSearch.Text = $val }
        Invoke-ApplyFilters; Update-StatsBar
    })
    $ctxExclude = [System.Windows.Forms.ToolStripMenuItem]::new("Exclude this value")
    $ctxExclude.Add_Click({
        $cell = $grid.CurrentCell
        if ($null -eq $cell) { return }
        $val = $cell.Value
        $current = $Script:UI.TxtSearch.Text
        $exclude = if ($current) { "$current -$val" } else { "-$val" }
        $Script:UI.TxtSearch.Text = $exclude
    })
    $ctxCopyCell = [System.Windows.Forms.ToolStripMenuItem]::new("Copy cell value")
    $ctxCopyCell.Add_Click({
        $cell = $grid.CurrentCell
        if ($null -ne $cell -and $null -ne $cell.Value) {
            [System.Windows.Forms.Clipboard]::SetText([string]$cell.Value)
        }
    })
    $ctxCopyRow = [System.Windows.Forms.ToolStripMenuItem]::new("Copy row as text")
    $ctxCopyRow.Add_Click({ Copy-SelectionToClipboard })
    $ctxLookupId = [System.Windows.Forms.ToolStripMenuItem]::new("Lookup Event ID")
    $ctxLookupId.Add_Click({
        if ($grid.SelectedRows.Count -eq 0) { return }
        $entry = $Script:State.FilteredEntries[$grid.SelectedRows[0].Index]
        if ($entry.Extra -and $entry.Extra['EventID']) {
            $eid = [int]$entry.Extra['EventID']
            $desc = if ($Script:State.EventIdLookup.ContainsKey($eid)) { $Script:State.EventIdLookup[$eid] } else { "Unknown Event ID" }
            Populate-DetailPane $entry
        }
    })
    $ctxCorrelate = [System.Windows.Forms.ToolStripMenuItem]::new("Correlate this event")
    $ctxCorrelate.Add_Click({
        if ($grid.SelectedRows.Count -eq 0) { return }
        $entry = $Script:State.FilteredEntries[$grid.SelectedRows[0].Index]
        # Find correlated events within 5 minutes sharing IP or user
        $corrKey = $null
        if ($entry.Extra) {
            $corrKey = $entry.Extra['srcip'] ?? $entry.Extra['IPAddress'] ?? $entry.Extra['user'] ?? $entry.Extra['User-Name'] ?? $entry.Extra['UserPrincipalName']
        }
        if ($corrKey) {
            $Script:UI.TxtSearch.Text = $corrKey
            $Script:UI.RadText.Checked = $true
            Invoke-ApplyFilters; Update-StatsBar
        }
    })
    $ctxRelated = [System.Windows.Forms.ToolStripMenuItem]::new("Show related events (+/- 5 min)")
    $ctxRelated.Add_Click({
        if ($grid.SelectedRows.Count -eq 0) { return }
        $entry = $Script:State.FilteredEntries[$grid.SelectedRows[0].Index]
        if ($entry.Timestamp -ne [datetime]::MinValue) {
            $Script:UI.DtpFrom.Value = $entry.Timestamp.AddMinutes(-5)
            $Script:UI.DtpFrom.Checked = $true
            $Script:UI.DtpTo.Value = $entry.Timestamp.AddMinutes(5)
            $Script:UI.DtpTo.Checked = $true
            Invoke-ApplyFilters; Update-StatsBar
        }
    })
    $ctxCopyJson = [System.Windows.Forms.ToolStripMenuItem]::new("Copy as JSON")
    $ctxCopyJson.Add_Click({
        if ($grid.SelectedRows.Count -eq 0) { return }
        $jsonEntries = [System.Collections.Generic.List[object]]::new()
        foreach ($row in $grid.SelectedRows | Sort-Object { $_.Index }) {
            $entry = $Script:State.FilteredEntries[$row.Index]
            $obj = [ordered]@{
                Index = $entry.Index
                Timestamp = if ($entry.Timestamp -ne [datetime]::MinValue) { $entry.Timestamp.ToString("yyyy-MM-ddTHH:mm:ss") } else { $null }
                Level = $entry.Level; Source = $entry.Source; Host = $entry.Host; Message = $entry.Message
            }
            if ($entry.Extra) { foreach ($k in ($entry.Extra.Keys | Sort-Object)) { $obj[$k] = $entry.Extra[$k] } }
            $jsonEntries.Add($obj)
        }
        $json = $jsonEntries | ConvertTo-Json -Depth 5
        [System.Windows.Forms.Clipboard]::SetText($json)
        Update-StatusBar "Copied $($jsonEntries.Count) entries as JSON"
    })
    $ctxMenu.Items.AddRange(@($ctxFilterBy, $ctxExclude, [System.Windows.Forms.ToolStripSeparator]::new(), $ctxCopyCell, $ctxCopyRow, $ctxCopyJson, [System.Windows.Forms.ToolStripSeparator]::new(), $ctxLookupId, $ctxCorrelate, $ctxRelated))
    return $ctxMenu
}
