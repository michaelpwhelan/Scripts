# PowerShell Transcript Parser

Register-Parser -Id "powershell-transcript" -Name "PowerShell Transcript" -Extensions @(".txt", ".log") -SupportsTail $false `
    -AutoDetect {
        param($firstLines, $filePath)
        $joined = ($firstLines | Select-Object -First 5) -join "`n"
        return ($joined -match '\*{20}' -and $joined -match 'Windows PowerShell transcript')
    } `
    -Parse {
        param($filePath, $encoding)
        $entries = [System.Collections.Generic.List[object]]::new()
        $idx = 0
        $lines = [System.IO.File]::ReadAllLines($filePath, [System.Text.Encoding]::GetEncoding($encoding))
        $inHeader = $true; $currentCmd = ""; $currentOutput = ""
        $currentTs = [datetime]::MinValue; $headerInfo = @{}

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            if ($line -match '^\*{20}') {
                if ($line -match 'end') { $inHeader = $false; continue }
                if ($line -match 'start') { $inHeader = $true; continue }
                continue
            }
            if ($inHeader) {
                if ($line -match '^(\w[\w\s]+):\s*(.+)') {
                    $headerInfo[$Matches[1].Trim()] = $Matches[2].Trim()
                    if ($Matches[1].Trim() -match 'Start time') {
                        [datetime]::TryParse($Matches[2].Trim(), [ref]$currentTs) | Out-Null
                    }
                }
                continue
            }
            if ($line -match '^PS\s+[A-Z]:\\.*>\s*(.*)') {
                # Flush previous command
                if ($currentCmd) {
                    $msg = "PS> $currentCmd"
                    if ($currentOutput) { $msg += "`n$currentOutput" }
                    $entries.Add((ConvertTo-LogEntry @{
                        Index = $idx; Timestamp = $currentTs; Level = (Get-LevelFromText $currentOutput)
                        Source = $headerInfo['Username']; Host = $headerInfo['Machine']
                        Message = $msg; RawLine = "PS> $currentCmd`n$currentOutput"
                        Extra = @{ Command = $currentCmd; Output = $currentOutput; Username = $headerInfo['Username']; Machine = $headerInfo['Machine'] }
                    }))
                    $idx++; $currentOutput = ""
                }
                $currentCmd = $Matches[1]
            } else {
                if ($currentOutput) { $currentOutput += "`n$line" } else { $currentOutput = $line }
            }
        }
        # Flush last command
        if ($currentCmd) {
            $msg = "PS> $currentCmd"
            if ($currentOutput) { $msg += "`n$currentOutput" }
            $entries.Add((ConvertTo-LogEntry @{
                Index = $idx; Timestamp = $currentTs; Level = (Get-LevelFromText $currentOutput)
                Source = $headerInfo['Username']; Host = $headerInfo['Machine']
                Message = $msg; RawLine = "PS> $currentCmd`n$currentOutput"; Extra = @{ Command = $currentCmd; Output = $currentOutput }
            }))
        }
        return $entries
    }
