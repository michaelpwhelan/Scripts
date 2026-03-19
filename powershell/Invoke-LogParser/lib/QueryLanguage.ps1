# ═══════════════════════════════════════════════════════════════════════════════
# SEARCH QUERY LANGUAGE (SQL — Simple Query Language)
# ═══════════════════════════════════════════════════════════════════════════════

# --- Field Mapping Resolution ---

$Script:QueryFieldMappings = $null   # Loaded from data/field-mappings.json
$Script:SeverityAliases    = $null   # Loaded from data/field-mappings.json

function Initialize-QueryFieldMappings {
    $mapPath = Join-Path $Config.ScriptRoot "data" "field-mappings.json"
    if (Test-Path $mapPath) {
        try {
            $content = [System.IO.File]::ReadAllText($mapPath)
            $json = $content | ConvertFrom-Json

            # Convert virtualFields from JSON object to hashtable of arrays
            $Script:QueryFieldMappings = @{}
            if ($json.virtualFields) {
                foreach ($prop in $json.virtualFields.PSObject.Properties) {
                    $Script:QueryFieldMappings[$prop.Name] = @{
                        EntryFields = @($prop.Value.entryFields)
                        ExtraFields = @($prop.Value.extraFields)
                    }
                }
            }

            # Convert severityAliases
            $Script:SeverityAliases = @{}
            if ($json.severityAliases) {
                foreach ($prop in $json.severityAliases.PSObject.Properties) {
                    $Script:SeverityAliases[$prop.Name] = @($prop.Value)
                }
            }

            Write-Log "Loaded field mappings: $($Script:QueryFieldMappings.Count) virtual fields"
        } catch {
            Write-Log "Failed to load field mappings: $_" -Level WARNING
        }
    }

    if (-not $Script:QueryFieldMappings -or $Script:QueryFieldMappings.Count -eq 0) {
        # Built-in default mappings
        $Script:QueryFieldMappings = @{
            user    = @{ EntryFields = @(); ExtraFields = @("user", "User-Name", "SAM-Account-Name", "TargetUserName", "UserPrincipalName", "SubjectUserName") }
            srcip   = @{ EntryFields = @(); ExtraFields = @("srcip", "IpAddress", "IPAddress", "Client-IP-Address", "Calling-Station-Id", "SourceAddress") }
            dstip   = @{ EntryFields = @(); ExtraFields = @("dstip", "DestinationAddress", "NAS-IP-Address") }
            action  = @{ EntryFields = @(); ExtraFields = @("action", "Action", "PacketTypeName") }
            eventid = @{ EntryFields = @(); ExtraFields = @("EventID", "logid") }
            device  = @{ EntryFields = @("Host"); ExtraFields = @("devname", "DeviceName", "Computer-Name", "MachineName", "computerDnsName") }
            source  = @{ EntryFields = @("Source"); ExtraFields = @("SourceFormat", "ProviderName") }
            severity = @{ EntryFields = @("Level"); ExtraFields = @("Severity", "VulnerabilitySeverity", "ZabbixSeverity") }
            port    = @{ EntryFields = @(); ExtraFields = @("dstport", "srcport", "PortName") }
            policy  = @{ EntryFields = @(); ExtraFields = @("policyid", "PolicyName") }
            app     = @{ EntryFields = @(); ExtraFields = @("AppDisplayName", "app", "appcat", "application") }
            url     = @{ EntryFields = @(); ExtraFields = @("url", "hostname", "QueryName") }
            tunnel  = @{ EntryFields = @(); ExtraFields = @("TunnelName", "tunnelid", "vpntunnel", "tunnelip") }
            mac     = @{ EntryFields = @(); ExtraFields = @("MACAddress", "MacAddress", "Calling-Station-Id") }
            vlan    = @{ EntryFields = @(); ExtraFields = @("VlanId", "vlan") }
        }
    }

    if (-not $Script:SeverityAliases -or $Script:SeverityAliases.Count -eq 0) {
        $Script:SeverityAliases = @{
            critical = @("CRITICAL")
            high     = @("CRITICAL", "ERROR")
            medium   = @("WARNING")
            low      = @("INFO")
            info     = @("INFO", "DEBUG", "TRACE")
            debug    = @("DEBUG", "TRACE")
        }
    }

    # Initialize query history on State if not present
    if (-not $Script:State.ContainsKey('QueryHistory')) {
        $Script:State.QueryHistory = [System.Collections.Generic.List[object]]::new()
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# QUERY HISTORY
# ═══════════════════════════════════════════════════════════════════════════════

function Add-QueryHistory {
    param([string]$Query, [int]$ResultCount, [double]$ElapsedMs)

    if (-not $Script:State.ContainsKey('QueryHistory')) {
        $Script:State.QueryHistory = [System.Collections.Generic.List[object]]::new()
    }

    $entry = @{
        Query      = $Query
        Timestamp  = [datetime]::Now
        Results    = $ResultCount
        ElapsedMs  = $ElapsedMs
    }

    $Script:State.QueryHistory.Insert(0, $entry)

    # Cap at 50 entries
    while ($Script:State.QueryHistory.Count -gt 50) {
        $Script:State.QueryHistory.RemoveAt($Script:State.QueryHistory.Count - 1)
    }
}

function Get-QueryHistory {
    param([int]$Count = 10)

    if (-not $Script:State.ContainsKey('QueryHistory') -or $Script:State.QueryHistory.Count -eq 0) {
        return @()
    }

    $limit = [math]::Min($Count, $Script:State.QueryHistory.Count)
    $result = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $limit; $i++) {
        $result.Add($Script:State.QueryHistory[$i])
    }
    return $result
}

# ═══════════════════════════════════════════════════════════════════════════════
# LEXER
# ═══════════════════════════════════════════════════════════════════════════════

function Invoke-QueryLex {
    param([string]$QueryString)

    $tokens = [System.Collections.Generic.List[object]]::new()
    $len = $QueryString.Length
    $pos = 0

    # Set of pipeline/aggregation keywords (case-insensitive check)
    $keywords = @{
        'count' = $true; 'by' = $true; 'top' = $true; 'stats' = $true
        'timeline' = $true; 'table' = $true; 'sort' = $true
        'head' = $true; 'tail' = $true; 'asc' = $true; 'desc' = $true
        'sum' = $true; 'avg' = $true; 'min' = $true; 'max' = $true
    }

    while ($pos -lt $len) {
        $ch = $QueryString[$pos]

        # Skip whitespace
        if ([char]::IsWhiteSpace($ch)) {
            $pos++
            continue
        }

        # Pipe operator
        if ($ch -eq '|') {
            $tokens.Add(@{ Type = 'PIPE'; Value = '|' })
            $pos++
            continue
        }

        # Parentheses
        if ($ch -eq '(') {
            $tokens.Add(@{ Type = 'LPAREN'; Value = '(' })
            $pos++
            continue
        }
        if ($ch -eq ')') {
            $tokens.Add(@{ Type = 'RPAREN'; Value = ')' })
            $pos++
            continue
        }

        # Quoted string (standalone, not after a colon — colon-quoted handled in field match)
        if ($ch -eq '"') {
            $pos++
            $start = $pos
            while ($pos -lt $len -and $QueryString[$pos] -ne '"') {
                if ($QueryString[$pos] -eq '\' -and ($pos + 1) -lt $len) { $pos++ }
                $pos++
            }
            $val = $QueryString.Substring($start, $pos - $start)
            if ($pos -lt $len) { $pos++ }  # skip closing quote
            $tokens.Add(@{ Type = 'QUOTED_STRING'; Value = $val })
            continue
        }

        # Read a word (letters, digits, hyphens, underscores, dots, wildcards, slashes)
        if ($ch -eq '-' -or $ch -eq '_' -or $ch -eq '.' -or $ch -eq '*' -or $ch -eq '/' -or $ch -eq '\' -or [char]::IsLetterOrDigit($ch)) {
            $start = $pos
            while ($pos -lt $len) {
                $c = $QueryString[$pos]
                if ($c -eq ':' -or $c -eq '>' -or $c -eq '<' -or $c -eq '=' -or `
                    $c -eq '-' -or $c -eq '_' -or $c -eq '.' -or $c -eq '*' -or `
                    $c -eq '/' -or $c -eq '\' -or [char]::IsLetterOrDigit($c)) {
                    # Check if this is a field:value pattern (colon followed by value)
                    if ($c -eq ':') {
                        $fieldName = $QueryString.Substring($start, $pos - $start)
                        $pos++  # skip the colon

                        # Now read the value part
                        $value = ''
                        $compOp = 'eq'

                        # Check for comparison operators right after colon
                        if ($pos -lt $len) {
                            if ($QueryString[$pos] -eq '>' -and ($pos + 1) -lt $len -and $QueryString[$pos + 1] -eq '=') {
                                $compOp = 'gte'; $pos += 2
                            } elseif ($QueryString[$pos] -eq '<' -and ($pos + 1) -lt $len -and $QueryString[$pos + 1] -eq '=') {
                                $compOp = 'lte'; $pos += 2
                            } elseif ($QueryString[$pos] -eq '>') {
                                $compOp = 'gt'; $pos++
                            } elseif ($QueryString[$pos] -eq '<') {
                                $compOp = 'lt'; $pos++
                            }
                        }

                        # Read value: could be quoted or bare
                        if ($pos -lt $len -and $QueryString[$pos] -eq '"') {
                            # Quoted value
                            $pos++
                            $vstart = $pos
                            while ($pos -lt $len -and $QueryString[$pos] -ne '"') {
                                if ($QueryString[$pos] -eq '\' -and ($pos + 1) -lt $len) { $pos++ }
                                $pos++
                            }
                            $value = $QueryString.Substring($vstart, $pos - $vstart)
                            if ($pos -lt $len) { $pos++ }  # skip closing quote
                            if ($compOp -eq 'eq') { $compOp = 'phrase' }
                        } else {
                            # Bare value — read until whitespace or paren or pipe
                            $vstart = $pos
                            while ($pos -lt $len) {
                                $vc = $QueryString[$pos]
                                if ([char]::IsWhiteSpace($vc) -or $vc -eq ')' -or $vc -eq '(' -or $vc -eq '|') { break }
                                $pos++
                            }
                            $value = $QueryString.Substring($vstart, $pos - $vstart)

                            # Detect wildcards
                            if ($compOp -eq 'eq' -and $value.Contains('*')) {
                                $compOp = 'wildcard'
                            }
                        }

                        $tokens.Add(@{ Type = 'FIELD_MATCH'; Field = $fieldName; Value = $value; Operator = $compOp })
                        break  # break out of the inner while, outer while continues
                    }

                    # Comparison operators as standalone (>=, <=, >, <)
                    if ($c -eq '>' -or $c -eq '<') {
                        break
                    }

                    $pos++
                } else {
                    break
                }
            }

            # If we consumed something and did NOT produce a FIELD_MATCH, it is a word
            if ($pos -gt $start) {
                $word = $QueryString.Substring($start, $pos - $start)
                # Check if last token was FIELD_MATCH (already added)
                if ($tokens.Count -gt 0) {
                    $lastTok = $tokens[$tokens.Count - 1]
                    if ($lastTok.Type -eq 'FIELD_MATCH' -and $lastTok.Field -eq $word) {
                        # Already handled as a field match, skip
                        continue
                    }
                }

                $wordUpper = $word.ToUpper()
                if ($wordUpper -eq 'AND') {
                    $tokens.Add(@{ Type = 'AND'; Value = 'AND' })
                } elseif ($wordUpper -eq 'OR') {
                    $tokens.Add(@{ Type = 'OR'; Value = 'OR' })
                } elseif ($wordUpper -eq 'NOT') {
                    $tokens.Add(@{ Type = 'NOT'; Value = 'NOT' })
                } elseif ($keywords.ContainsKey($word.ToLower())) {
                    $tokens.Add(@{ Type = 'KEYWORD'; Value = $word.ToLower() })
                } else {
                    # Try to parse as number
                    $numVal = 0.0
                    if ([double]::TryParse($word, [ref]$numVal)) {
                        $tokens.Add(@{ Type = 'NUMBER'; Value = $numVal })
                    } else {
                        # Bare word — treat as implicit message search
                        $tokens.Add(@{ Type = 'BARE_WORD'; Value = $word })
                    }
                }
            }
            continue
        }

        # Standalone comparison operators (not attached to field:)
        if ($ch -eq '>' -or $ch -eq '<') {
            if (($pos + 1) -lt $len -and $QueryString[$pos + 1] -eq '=') {
                $op = if ($ch -eq '>') { 'gte' } else { 'lte' }
                $tokens.Add(@{ Type = 'COMPARISON_OP'; Value = $op })
                $pos += 2
            } else {
                $op = if ($ch -eq '>') { 'gt' } else { 'lt' }
                $tokens.Add(@{ Type = 'COMPARISON_OP'; Value = $op })
                $pos++
            }
            continue
        }

        # Anything else — skip
        $pos++
    }

    return ,$tokens
}

# ═══════════════════════════════════════════════════════════════════════════════
# PARSER — Recursive Descent
# ═══════════════════════════════════════════════════════════════════════════════

function Build-QueryAst {
    param([System.Collections.Generic.List[object]]$Tokens)

    # Split tokens on PIPE to separate filter expression from aggregation pipeline
    $filterTokens = [System.Collections.Generic.List[object]]::new()
    $pipelineStages = [System.Collections.Generic.List[object]]::new()
    $currentStage = $null
    $inPipeline = $false

    for ($i = 0; $i -lt $Tokens.Count; $i++) {
        $tok = $Tokens[$i]
        if ($tok.Type -eq 'PIPE') {
            if (-not $inPipeline) {
                $inPipeline = $true
            } else {
                # End current stage, start new one
                if ($currentStage) {
                    $pipelineStages.Add($currentStage)
                }
            }
            $currentStage = [System.Collections.Generic.List[object]]::new()
            continue
        }

        if ($inPipeline) {
            $currentStage.Add($tok)
        } else {
            $filterTokens.Add($tok)
        }
    }
    if ($currentStage -and $currentStage.Count -gt 0) {
        $pipelineStages.Add($currentStage)
    }

    # Parse filter expression into AST
    $ast = $null
    if ($filterTokens.Count -gt 0) {
        $parseState = @{ Tokens = $filterTokens; Pos = 0 }
        $ast = ParseOrExpr $parseState
    }

    # Parse pipeline stages
    $stages = [System.Collections.Generic.List[object]]::new()
    foreach ($stageTokens in $pipelineStages) {
        $parsed = ParsePipelineStage $stageTokens
        if ($parsed) { $stages.Add($parsed) }
    }

    return @{
        FilterAst = $ast
        Stages    = $stages
    }
}

function ParseOrExpr {
    param([hashtable]$S)

    $left = ParseAndExpr $S
    while ($S.Pos -lt $S.Tokens.Count -and $S.Tokens[$S.Pos].Type -eq 'OR') {
        $S.Pos++
        $right = ParseAndExpr $S
        $left = @{ Type = 'OR'; Left = $left; Right = $right }
    }
    return $left
}

function ParseAndExpr {
    param([hashtable]$S)

    $left = ParseNotExpr $S
    while ($S.Pos -lt $S.Tokens.Count) {
        $tok = $S.Tokens[$S.Pos]
        # Explicit AND
        if ($tok.Type -eq 'AND') {
            $S.Pos++
            $right = ParseNotExpr $S
            $left = @{ Type = 'AND'; Left = $left; Right = $right }
        }
        # Implicit AND — next token is something that can start an expression
        # (FIELD_MATCH, BARE_WORD, QUOTED_STRING, NOT, LPAREN)
        elseif ($tok.Type -eq 'FIELD_MATCH' -or $tok.Type -eq 'BARE_WORD' -or `
                $tok.Type -eq 'QUOTED_STRING' -or $tok.Type -eq 'NOT' -or `
                $tok.Type -eq 'LPAREN') {
            $right = ParseNotExpr $S
            $left = @{ Type = 'AND'; Left = $left; Right = $right }
        } else {
            break
        }
    }
    return $left
}

function ParseNotExpr {
    param([hashtable]$S)

    if ($S.Pos -lt $S.Tokens.Count -and $S.Tokens[$S.Pos].Type -eq 'NOT') {
        $S.Pos++
        $child = ParseNotExpr $S
        return @{ Type = 'NOT'; Child = $child }
    }
    return ParsePrimary $S
}

function ParsePrimary {
    param([hashtable]$S)

    if ($S.Pos -ge $S.Tokens.Count) {
        # Empty expression — match everything
        return @{ Type = 'MATCH'; Field = '_all'; Value = '*'; Operator = 'wildcard' }
    }

    $tok = $S.Tokens[$S.Pos]

    # Grouped expression
    if ($tok.Type -eq 'LPAREN') {
        $S.Pos++
        $inner = ParseOrExpr $S
        if ($S.Pos -lt $S.Tokens.Count -and $S.Tokens[$S.Pos].Type -eq 'RPAREN') {
            $S.Pos++
        }
        return $inner
    }

    # Field:value match
    if ($tok.Type -eq 'FIELD_MATCH') {
        $S.Pos++
        return @{ Type = 'MATCH'; Field = $tok.Field.ToLower(); Value = $tok.Value; Operator = $tok.Operator }
    }

    # Bare word — implicit message search
    if ($tok.Type -eq 'BARE_WORD') {
        $S.Pos++
        $val = $tok.Value
        $op = 'eq'
        if ($val.Contains('*')) { $op = 'wildcard' }
        return @{ Type = 'MATCH'; Field = '_all'; Value = $val; Operator = $op }
    }

    # Quoted string — implicit message phrase search
    if ($tok.Type -eq 'QUOTED_STRING') {
        $S.Pos++
        return @{ Type = 'MATCH'; Field = '_all'; Value = $tok.Value; Operator = 'phrase' }
    }

    # Fallback: skip unrecognized token
    $S.Pos++
    return @{ Type = 'MATCH'; Field = '_all'; Value = '*'; Operator = 'wildcard' }
}

function ParsePipelineStage {
    param([System.Collections.Generic.List[object]]$Tokens)

    if ($Tokens.Count -eq 0) { return $null }

    $first = $Tokens[0]
    if ($first.Type -ne 'KEYWORD') {
        # Not a recognized stage keyword
        return $null
    }

    $cmd = $first.Value

    switch ($cmd) {
        'count' {
            if ($Tokens.Count -ge 3 -and $Tokens[1].Type -eq 'KEYWORD' -and $Tokens[1].Value -eq 'by') {
                # count by <field>
                $fieldName = ''
                if ($Tokens[2].Type -eq 'KEYWORD' -or $Tokens[2].Type -eq 'BARE_WORD') {
                    $fieldName = $Tokens[2].Value
                } elseif ($Tokens[2].Type -eq 'FIELD_MATCH') {
                    $fieldName = $Tokens[2].Field
                }
                return @{ Stage = 'count_by'; Field = $fieldName }
            }
            return @{ Stage = 'count' }
        }
        'top' {
            $n = 10
            $fieldName = ''
            if ($Tokens.Count -ge 3) {
                if ($Tokens[1].Type -eq 'NUMBER') {
                    $n = [int]$Tokens[1].Value
                    if ($Tokens.Count -ge 3) {
                        if ($Tokens[2].Type -eq 'KEYWORD' -or $Tokens[2].Type -eq 'BARE_WORD') {
                            $fieldName = $Tokens[2].Value
                        } elseif ($Tokens[2].Type -eq 'FIELD_MATCH') {
                            $fieldName = $Tokens[2].Field
                        }
                    }
                } elseif ($Tokens[1].Type -eq 'KEYWORD' -or $Tokens[1].Type -eq 'BARE_WORD') {
                    $fieldName = $Tokens[1].Value
                }
            }
            return @{ Stage = 'top'; N = $n; Field = $fieldName }
        }
        'stats' {
            # stats <func> <field>
            $func = 'count'
            $fieldName = ''
            if ($Tokens.Count -ge 2 -and $Tokens[1].Type -eq 'KEYWORD') {
                $func = $Tokens[1].Value
            }
            if ($Tokens.Count -ge 3) {
                if ($Tokens[2].Type -eq 'KEYWORD' -or $Tokens[2].Type -eq 'BARE_WORD') {
                    $fieldName = $Tokens[2].Value
                } elseif ($Tokens[2].Type -eq 'FIELD_MATCH') {
                    $fieldName = $Tokens[2].Field
                }
            }
            return @{ Stage = 'stats'; Function = $func; Field = $fieldName }
        }
        'timeline' {
            $interval = '1h'
            if ($Tokens.Count -ge 2) {
                if ($Tokens[1].Type -eq 'BARE_WORD' -or $Tokens[1].Type -eq 'KEYWORD') {
                    $interval = $Tokens[1].Value
                }
            }
            return @{ Stage = 'timeline'; Interval = $interval }
        }
        'table' {
            # table <field1>,<field2>,...
            $fields = [System.Collections.Generic.List[string]]::new()
            for ($i = 1; $i -lt $Tokens.Count; $i++) {
                $t = $Tokens[$i]
                $raw = ''
                if ($t.Type -eq 'BARE_WORD' -or $t.Type -eq 'KEYWORD') {
                    $raw = $t.Value
                } elseif ($t.Type -eq 'FIELD_MATCH') {
                    $raw = $t.Field
                }
                if ($raw) {
                    # Split on commas for comma-separated fields
                    foreach ($f in $raw.Split(',', [System.StringSplitOptions]::RemoveEmptyEntries)) {
                        $fields.Add($f.Trim())
                    }
                }
            }
            return @{ Stage = 'table'; Fields = $fields }
        }
        'sort' {
            $fieldName = ''
            $direction = 'asc'
            if ($Tokens.Count -ge 2) {
                if ($Tokens[1].Type -eq 'KEYWORD' -or $Tokens[1].Type -eq 'BARE_WORD') {
                    $fieldName = $Tokens[1].Value
                } elseif ($Tokens[1].Type -eq 'FIELD_MATCH') {
                    $fieldName = $Tokens[1].Field
                }
            }
            if ($Tokens.Count -ge 3 -and $Tokens[2].Type -eq 'KEYWORD') {
                if ($Tokens[2].Value -eq 'desc') { $direction = 'desc' }
            }
            return @{ Stage = 'sort'; Field = $fieldName; Direction = $direction }
        }
        'head' {
            $n = 10
            if ($Tokens.Count -ge 2 -and $Tokens[1].Type -eq 'NUMBER') {
                $n = [int]$Tokens[1].Value
            }
            return @{ Stage = 'head'; N = $n }
        }
        'tail' {
            $n = 10
            if ($Tokens.Count -ge 2 -and $Tokens[1].Type -eq 'NUMBER') {
                $n = [int]$Tokens[1].Value
            }
            return @{ Stage = 'tail'; N = $n }
        }
    }

    return $null
}

# ═══════════════════════════════════════════════════════════════════════════════
# EVALUATOR
# ═══════════════════════════════════════════════════════════════════════════════

function Resolve-FieldValue {
    <#
    .SYNOPSIS
        Resolves a virtual or direct field name to its actual value from a log entry.
        Returns the first non-null value found across mapped fields.
    #>
    param(
        [string]$FieldName,
        [PSCustomObject]$Entry
    )

    $fieldLower = $FieldName.ToLower()

    # Direct entry property mapping (case-insensitive check of known properties)
    switch ($fieldLower) {
        'level'     { return $Entry.Level }
        'source'    { return $Entry.Source }
        'host'      { return $Entry.Host }
        'message'   { return $Entry.Message }
        'index'     { return $Entry.Index }
        'timestamp' { return $Entry.Timestamp }
        'time'      { return $Entry.Timestamp }
        'rawline'   { return $Entry.RawLine }
        'bookmarked' { return $Entry.Bookmarked }
    }

    # Check virtual field mappings
    if ($Script:QueryFieldMappings.ContainsKey($fieldLower)) {
        $mapping = $Script:QueryFieldMappings[$fieldLower]

        # Check entry-level fields first
        foreach ($ef in $mapping.EntryFields) {
            $val = $Entry.$ef
            if ($null -ne $val -and $val -ne '') {
                return $val
            }
        }

        # Then check Extra hashtable fields
        if ($Entry.Extra -and $Entry.Extra -is [hashtable]) {
            foreach ($xf in $mapping.ExtraFields) {
                if ($Entry.Extra.ContainsKey($xf)) {
                    $val = $Entry.Extra[$xf]
                    if ($null -ne $val -and $val -ne '') {
                        return $val
                    }
                }
            }
        }
        return $null
    }

    # Direct Extra field lookup (field name not in virtual mappings)
    if ($Entry.Extra -and $Entry.Extra -is [hashtable]) {
        if ($Entry.Extra.ContainsKey($FieldName)) {
            return $Entry.Extra[$FieldName]
        }
        # Case-insensitive fallback
        foreach ($key in $Entry.Extra.Keys) {
            if ($key -and $key.ToLower() -eq $fieldLower) {
                return $Entry.Extra[$key]
            }
        }
    }

    return $null
}

function Test-TimeMatch {
    <#
    .SYNOPSIS
        Handles relative time value shortcuts: last24h, last7d, today, last1h, lastNd, lastNh, lastNm.
        Also handles comparison operators for timestamp fields.
    #>
    param(
        [string]$Value,
        [string]$Operator,
        [datetime]$EntryTimestamp
    )

    if ($EntryTimestamp -eq [datetime]::MinValue) { return $false }

    $now = [datetime]::Now
    $valueLower = $Value.ToLower()

    # Relative time shortcuts
    switch ($valueLower) {
        'last24h'  { return $EntryTimestamp -ge $now.AddHours(-24) }
        'last1h'   { return $EntryTimestamp -ge $now.AddHours(-1) }
        'last4h'   { return $EntryTimestamp -ge $now.AddHours(-4) }
        'last12h'  { return $EntryTimestamp -ge $now.AddHours(-12) }
        'last7d'   { return $EntryTimestamp -ge $now.AddDays(-7) }
        'last30d'  { return $EntryTimestamp -ge $now.AddDays(-30) }
        'last90d'  { return $EntryTimestamp -ge $now.AddDays(-90) }
        'today'    { return $EntryTimestamp.Date -eq $now.Date }
        'yesterday' { return $EntryTimestamp.Date -eq $now.AddDays(-1).Date }
    }

    # Generic lastN[mhd] pattern
    if ($valueLower -match '^last(\d+)([mhd])$') {
        $n = [int]$Matches[1]
        $unit = $Matches[2]
        $cutoff = switch ($unit) {
            'm' { $now.AddMinutes(-$n) }
            'h' { $now.AddHours(-$n) }
            'd' { $now.AddDays(-$n) }
        }
        return $EntryTimestamp -ge $cutoff
    }

    # Comparison with explicit timestamp value
    $parsedTime = [datetime]::MinValue
    if ([datetime]::TryParse($Value, [ref]$parsedTime)) {
        switch ($Operator) {
            'gt'  { return $EntryTimestamp -gt $parsedTime }
            'gte' { return $EntryTimestamp -ge $parsedTime }
            'lt'  { return $EntryTimestamp -lt $parsedTime }
            'lte' { return $EntryTimestamp -le $parsedTime }
            default { return $EntryTimestamp.Date -eq $parsedTime.Date }
        }
    }

    return $false
}

function Test-SeverityMatch {
    <#
    .SYNOPSIS
        Matches severity aliases (critical, high, medium, low, info, debug)
        against the actual Level property.
    #>
    param(
        [string]$Value,
        [string]$ActualLevel
    )

    $valueLower = $Value.ToLower()

    # Check severity aliases
    if ($Script:SeverityAliases -and $Script:SeverityAliases.ContainsKey($valueLower)) {
        $allowedLevels = $Script:SeverityAliases[$valueLower]
        foreach ($lvl in $allowedLevels) {
            if ($lvl -eq $ActualLevel) { return $true }
        }
        return $false
    }

    # Direct level match
    return $Value -ieq $ActualLevel
}

function Test-ValueMatch {
    <#
    .SYNOPSIS
        Tests a single value against a match expression.
    #>
    param(
        [string]$ActualValue,
        [string]$ExpectedValue,
        [string]$Operator
    )

    if ($null -eq $ActualValue) { return $false }
    $actual = [string]$ActualValue

    switch ($Operator) {
        'eq' {
            return $actual -ieq $ExpectedValue
        }
        'phrase' {
            return $actual -ieq $ExpectedValue
        }
        'wildcard' {
            return $actual -ilike $ExpectedValue
        }
        'gt' {
            $a = 0.0; $b = 0.0
            if ([double]::TryParse($actual, [ref]$a) -and [double]::TryParse($ExpectedValue, [ref]$b)) {
                return $a -gt $b
            }
            return $actual -gt $ExpectedValue
        }
        'lt' {
            $a = 0.0; $b = 0.0
            if ([double]::TryParse($actual, [ref]$a) -and [double]::TryParse($ExpectedValue, [ref]$b)) {
                return $a -lt $b
            }
            return $actual -lt $ExpectedValue
        }
        'gte' {
            $a = 0.0; $b = 0.0
            if ([double]::TryParse($actual, [ref]$a) -and [double]::TryParse($ExpectedValue, [ref]$b)) {
                return $a -ge $b
            }
            return $actual -ge $ExpectedValue
        }
        'lte' {
            $a = 0.0; $b = 0.0
            if ([double]::TryParse($actual, [ref]$a) -and [double]::TryParse($ExpectedValue, [ref]$b)) {
                return $a -le $b
            }
            return $actual -le $ExpectedValue
        }
        default {
            return $actual -ieq $ExpectedValue
        }
    }
}

function Test-QueryMatch {
    <#
    .SYNOPSIS
        Evaluates an AST node against a log entry. Returns $true if the entry matches.
    #>
    param(
        [hashtable]$Node,
        [PSCustomObject]$Entry
    )

    if ($null -eq $Node) { return $true }

    switch ($Node.Type) {
        'AND' {
            if (-not (Test-QueryMatch -Node $Node.Left -Entry $Entry)) { return $false }
            return (Test-QueryMatch -Node $Node.Right -Entry $Entry)
        }
        'OR' {
            if (Test-QueryMatch -Node $Node.Left -Entry $Entry) { return $true }
            return (Test-QueryMatch -Node $Node.Right -Entry $Entry)
        }
        'NOT' {
            return -not (Test-QueryMatch -Node $Node.Child -Entry $Entry)
        }
        'MATCH' {
            $field = $Node.Field
            $value = $Node.Value
            $op = $Node.Operator

            # Special handling: time field with relative shortcuts
            if ($field -eq 'time' -or $field -eq 'timestamp') {
                return Test-TimeMatch -Value $value -Operator $op -EntryTimestamp $Entry.Timestamp
            }

            # Special handling: severity aliases
            if ($field -eq 'severity' -or $field -eq 'level') {
                return Test-SeverityMatch -Value $value -ActualLevel $Entry.Level
            }

            # All-fields search (bare word / quoted string with no field prefix)
            if ($field -eq '_all') {
                # Search across Message, RawLine, Source, Host, Level
                if ($op -eq 'wildcard') {
                    if ($Entry.Message -ilike $value) { return $true }
                    if ($Entry.RawLine -ilike $value) { return $true }
                    if ($Entry.Source -ilike $value) { return $true }
                    if ($Entry.Host -ilike $value) { return $true }
                    return $false
                }
                if ($op -eq 'phrase' -or $op -eq 'eq') {
                    $searchUpper = $value.ToUpper()
                    if ($Entry.Message -and $Entry.Message.ToUpper().Contains($searchUpper)) { return $true }
                    if ($Entry.RawLine -and $Entry.RawLine.ToUpper().Contains($searchUpper)) { return $true }
                    if ($Entry.Source -and $Entry.Source.ToUpper().Contains($searchUpper)) { return $true }
                    if ($Entry.Host -and $Entry.Host.ToUpper().Contains($searchUpper)) { return $true }
                    return $false
                }
                return $false
            }

            # Resolve the field value via virtual field mapping
            $actualValue = Resolve-FieldValue -FieldName $field -Entry $Entry
            return Test-ValueMatch -ActualValue $actualValue -ExpectedValue $value -Operator $op
        }
        default {
            return $true
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# AGGREGATION PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

function Get-FieldValueFromEntry {
    <#
    .SYNOPSIS
        Gets a field value from an entry for aggregation purposes.
        Used by pipeline stages to extract values.
    #>
    param(
        [string]$FieldName,
        [PSCustomObject]$Entry
    )

    # Direct entry properties
    $fieldLower = $FieldName.ToLower()
    switch ($fieldLower) {
        'level'     { return $Entry.Level }
        'source'    { return $Entry.Source }
        'host'      { return $Entry.Host }
        'message'   { return $Entry.Message }
        'index'     { return $Entry.Index }
        'timestamp' { return $Entry.Timestamp }
        'time'      { return $Entry.Timestamp }
    }

    # Use virtual field resolution
    $val = Resolve-FieldValue -FieldName $FieldName -Entry $Entry
    if ($null -ne $val) { return $val }

    return ''
}

function ConvertTo-TimelineBucket {
    <#
    .SYNOPSIS
        Converts a datetime to a bucket key string based on interval.
    #>
    param(
        [datetime]$Time,
        [string]$Interval
    )

    if ($Interval -match '^(\d+)([mhd])$') {
        $n = [int]$Matches[1]
        $unit = $Matches[2]

        switch ($unit) {
            'm' {
                $bucket = [math]::Floor($Time.Minute / $n) * $n
                return $Time.ToString('yyyy-MM-dd HH:') + $bucket.ToString('00')
            }
            'h' {
                $bucket = [math]::Floor($Time.Hour / $n) * $n
                return $Time.Date.AddHours($bucket).ToString('yyyy-MM-dd HH:00')
            }
            'd' {
                return $Time.Date.ToString('yyyy-MM-dd')
            }
        }
    }

    # Default: hourly buckets
    return $Time.ToString('yyyy-MM-dd HH:00')
}

function Invoke-QueryAggregate {
    <#
    .SYNOPSIS
        Processes the aggregation pipeline stages against the filtered entries.
        Each stage transforms the data for the next stage.
    #>
    param(
        [System.Collections.Generic.List[object]]$Entries,
        [System.Collections.Generic.List[object]]$Stages
    )

    if ($Stages.Count -eq 0) {
        return @{ Type = 'entries'; Data = $Entries }
    }

    # Current working data — starts as entries, may transform to aggregation results
    $currentData = $Entries
    $currentType = 'entries'  # 'entries' or 'aggregated'

    foreach ($stage in $Stages) {
        switch ($stage.Stage) {

            'count' {
                if ($currentType -eq 'entries') {
                    $currentData = @(@{ Count = $currentData.Count })
                } else {
                    $currentData = @(@{ Count = $currentData.Count })
                }
                $currentType = 'aggregated'
            }

            'count_by' {
                $fieldName = $stage.Field
                $groups = @{}
                if ($currentType -eq 'entries') {
                    foreach ($entry in $currentData) {
                        $val = [string](Get-FieldValueFromEntry -FieldName $fieldName -Entry $entry)
                        if (-not $val) { $val = '(empty)' }
                        if ($groups.ContainsKey($val)) { $groups[$val]++ }
                        else { $groups[$val] = 1 }
                    }
                } elseif ($currentType -eq 'aggregated') {
                    # Re-count from aggregated results by a field (re-grouping)
                    foreach ($row in $currentData) {
                        $val = '(unknown)'
                        if ($row -is [hashtable] -and $row.ContainsKey($fieldName)) {
                            $val = [string]$row[$fieldName]
                        }
                        if (-not $val) { $val = '(empty)' }
                        if ($groups.ContainsKey($val)) { $groups[$val]++ }
                        else { $groups[$val] = 1 }
                    }
                }

                # Sort by count descending
                $sorted = [System.Collections.Generic.List[object]]::new()
                $pairs = [System.Collections.Generic.List[object]]::new()
                foreach ($key in $groups.Keys) {
                    $pairs.Add(@{ Value = $key; Count = $groups[$key] })
                }
                # Sort descending by count using simple insertion sort (no pipeline)
                for ($i = 1; $i -lt $pairs.Count; $i++) {
                    $item = $pairs[$i]
                    $j = $i - 1
                    while ($j -ge 0 -and $pairs[$j].Count -lt $item.Count) {
                        $pairs[$j + 1] = $pairs[$j]
                        $j--
                    }
                    $pairs[$j + 1] = $item
                }
                $currentData = $pairs
                $currentType = 'aggregated'
            }

            'top' {
                $fieldName = $stage.Field
                $n = $stage.N

                $groups = @{}
                if ($currentType -eq 'entries') {
                    foreach ($entry in $currentData) {
                        $val = [string](Get-FieldValueFromEntry -FieldName $fieldName -Entry $entry)
                        if (-not $val) { $val = '(empty)' }
                        if ($groups.ContainsKey($val)) { $groups[$val]++ }
                        else { $groups[$val] = 1 }
                    }
                } elseif ($currentType -eq 'aggregated') {
                    foreach ($row in $currentData) {
                        $val = '(unknown)'
                        if ($row -is [hashtable] -and $row.ContainsKey($fieldName)) {
                            $val = [string]$row[$fieldName]
                        }
                        if (-not $val) { $val = '(empty)' }
                        if ($groups.ContainsKey($val)) { $groups[$val]++ }
                        else { $groups[$val] = 1 }
                    }
                }

                $pairs = [System.Collections.Generic.List[object]]::new()
                foreach ($key in $groups.Keys) {
                    $pairs.Add(@{ Value = $key; Count = $groups[$key] })
                }
                for ($i = 1; $i -lt $pairs.Count; $i++) {
                    $item = $pairs[$i]
                    $j = $i - 1
                    while ($j -ge 0 -and $pairs[$j].Count -lt $item.Count) {
                        $pairs[$j + 1] = $pairs[$j]
                        $j--
                    }
                    $pairs[$j + 1] = $item
                }
                $limit = [math]::Min($n, $pairs.Count)
                $currentData = [System.Collections.Generic.List[object]]::new()
                for ($i = 0; $i -lt $limit; $i++) {
                    $currentData.Add($pairs[$i])
                }
                $currentType = 'aggregated'
            }

            'stats' {
                $func = $stage.Function
                $fieldName = $stage.Field

                if ($currentType -eq 'entries') {
                    $values = [System.Collections.Generic.List[double]]::new()
                    foreach ($entry in $currentData) {
                        $raw = Get-FieldValueFromEntry -FieldName $fieldName -Entry $entry
                        $numVal = 0.0
                        if ($null -ne $raw -and [double]::TryParse([string]$raw, [ref]$numVal)) {
                            $values.Add($numVal)
                        }
                    }

                    $result = 0.0
                    switch ($func) {
                        'count' { $result = $values.Count }
                        'sum' {
                            $s = 0.0
                            foreach ($v in $values) { $s += $v }
                            $result = $s
                        }
                        'avg' {
                            if ($values.Count -gt 0) {
                                $s = 0.0
                                foreach ($v in $values) { $s += $v }
                                $result = $s / $values.Count
                            }
                        }
                        'min' {
                            if ($values.Count -gt 0) {
                                $m = $values[0]
                                for ($i = 1; $i -lt $values.Count; $i++) {
                                    if ($values[$i] -lt $m) { $m = $values[$i] }
                                }
                                $result = $m
                            }
                        }
                        'max' {
                            if ($values.Count -gt 0) {
                                $m = $values[0]
                                for ($i = 1; $i -lt $values.Count; $i++) {
                                    if ($values[$i] -gt $m) { $m = $values[$i] }
                                }
                                $result = $m
                            }
                        }
                    }

                    $currentData = @(@{
                        Function = $func
                        Field    = $fieldName
                        Result   = $result
                        Count    = $values.Count
                    })
                } else {
                    # Stats on aggregated data — operate on Count field
                    $values = [System.Collections.Generic.List[double]]::new()
                    foreach ($row in $currentData) {
                        if ($row -is [hashtable] -and $row.ContainsKey('Count')) {
                            $values.Add([double]$row.Count)
                        }
                    }
                    $result = 0.0
                    switch ($func) {
                        'count' { $result = $values.Count }
                        'sum'   { $s = 0.0; foreach ($v in $values) { $s += $v }; $result = $s }
                        'avg'   { if ($values.Count -gt 0) { $s = 0.0; foreach ($v in $values) { $s += $v }; $result = $s / $values.Count } }
                        'min'   { if ($values.Count -gt 0) { $m = $values[0]; for ($i = 1; $i -lt $values.Count; $i++) { if ($values[$i] -lt $m) { $m = $values[$i] } }; $result = $m } }
                        'max'   { if ($values.Count -gt 0) { $m = $values[0]; for ($i = 1; $i -lt $values.Count; $i++) { if ($values[$i] -gt $m) { $m = $values[$i] } }; $result = $m } }
                    }
                    $currentData = @(@{
                        Function = $func
                        Field    = $fieldName
                        Result   = $result
                        Count    = $values.Count
                    })
                }
                $currentType = 'aggregated'
            }

            'timeline' {
                $interval = $stage.Interval
                $buckets = [ordered]@{}

                if ($currentType -eq 'entries') {
                    foreach ($entry in $currentData) {
                        if ($entry.Timestamp -eq [datetime]::MinValue) { continue }
                        $bucket = ConvertTo-TimelineBucket -Time $entry.Timestamp -Interval $interval
                        if ($buckets.Contains($bucket)) { $buckets[$bucket]++ }
                        else { $buckets[$bucket] = 1 }
                    }
                }

                $result = [System.Collections.Generic.List[object]]::new()
                foreach ($key in $buckets.Keys) {
                    $result.Add(@{ Time = $key; Count = $buckets[$key] })
                }
                $currentData = $result
                $currentType = 'aggregated'
            }

            'table' {
                $fields = $stage.Fields
                if ($currentType -eq 'entries') {
                    $result = [System.Collections.Generic.List[object]]::new()
                    foreach ($entry in $currentData) {
                        $row = @{}
                        foreach ($f in $fields) {
                            $row[$f] = Get-FieldValueFromEntry -FieldName $f -Entry $entry
                        }
                        $result.Add($row)
                    }
                    $currentData = $result
                }
                # If already aggregated, just keep the relevant fields
                elseif ($currentType -eq 'aggregated') {
                    $result = [System.Collections.Generic.List[object]]::new()
                    foreach ($row in $currentData) {
                        if ($row -is [hashtable]) {
                            $newRow = @{}
                            foreach ($f in $fields) {
                                if ($row.ContainsKey($f)) {
                                    $newRow[$f] = $row[$f]
                                }
                            }
                            $result.Add($newRow)
                        }
                    }
                    $currentData = $result
                }
                $currentType = 'aggregated'
            }

            'sort' {
                $fieldName = $stage.Field
                $desc = ($stage.Direction -eq 'desc')

                if ($currentType -eq 'entries') {
                    # Sort entries by a field
                    $arr = [System.Collections.ArrayList]::new($currentData)
                    $arr.Sort({
                        param($a, $b)
                        $va = Get-FieldValueFromEntry -FieldName $fieldName -Entry $a
                        $vb = Get-FieldValueFromEntry -FieldName $fieldName -Entry $b
                        $na = 0.0; $nb = 0.0
                        $aIsNum = $null -ne $va -and [double]::TryParse([string]$va, [ref]$na)
                        $bIsNum = $null -ne $vb -and [double]::TryParse([string]$vb, [ref]$nb)
                        if ($aIsNum -and $bIsNum) {
                            $cmp = $na.CompareTo($nb)
                        } else {
                            $cmp = [string]::Compare([string]$va, [string]$vb, $true)
                        }
                        if ($desc) { return -$cmp } else { return $cmp }
                    })
                    $currentData = [System.Collections.Generic.List[object]]::new()
                    foreach ($item in $arr) { $currentData.Add($item) }
                } elseif ($currentType -eq 'aggregated') {
                    # Sort aggregated results by a key
                    $arr = [System.Collections.ArrayList]::new($currentData)
                    $arr.Sort({
                        param($a, $b)
                        $va = $null; $vb = $null
                        if ($a -is [hashtable] -and $a.ContainsKey($fieldName)) { $va = $a[$fieldName] }
                        if ($b -is [hashtable] -and $b.ContainsKey($fieldName)) { $vb = $b[$fieldName] }
                        $na = 0.0; $nb = 0.0
                        $aIsNum = $null -ne $va -and [double]::TryParse([string]$va, [ref]$na)
                        $bIsNum = $null -ne $vb -and [double]::TryParse([string]$vb, [ref]$nb)
                        if ($aIsNum -and $bIsNum) {
                            $cmp = $na.CompareTo($nb)
                        } else {
                            $cmp = [string]::Compare([string]$va, [string]$vb, $true)
                        }
                        if ($desc) { return -$cmp } else { return $cmp }
                    })
                    $currentData = [System.Collections.Generic.List[object]]::new()
                    foreach ($item in $arr) { $currentData.Add($item) }
                }
            }

            'head' {
                $n = $stage.N
                if ($currentData.Count -gt $n) {
                    $trimmed = [System.Collections.Generic.List[object]]::new()
                    $limit = [math]::Min($n, $currentData.Count)
                    for ($i = 0; $i -lt $limit; $i++) {
                        $trimmed.Add($currentData[$i])
                    }
                    $currentData = $trimmed
                }
            }

            'tail' {
                $n = $stage.N
                if ($currentData.Count -gt $n) {
                    $trimmed = [System.Collections.Generic.List[object]]::new()
                    $startIdx = $currentData.Count - $n
                    for ($i = $startIdx; $i -lt $currentData.Count; $i++) {
                        $trimmed.Add($currentData[$i])
                    }
                    $currentData = $trimmed
                }
            }
        }
    }

    return @{ Type = $currentType; Data = $currentData }
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

function Invoke-QueryFilter {
    <#
    .SYNOPSIS
        Main entry point for the Simple Query Language system.
        Parses the query, filters entries, and optionally applies aggregation.
    .PARAMETER QueryString
        The query string to parse and execute.
    .PARAMETER Entries
        The list of log entries to search. Defaults to $Script:State.AllEntries.
    .OUTPUTS
        A result object with Type ('entries' or 'aggregated') and Data.
    #>
    param(
        [string]$QueryString,
        [System.Collections.Generic.List[object]]$Entries = $null
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    if (-not $Entries) {
        $Entries = $Script:State.AllEntries
    }

    # Handle empty query — return all entries
    if ([string]::IsNullOrWhiteSpace($QueryString)) {
        $sw.Stop()
        return @{
            Type       = 'entries'
            Data       = $Entries
            Query      = ''
            ElapsedMs  = $sw.Elapsed.TotalMilliseconds
            TotalCount = $Entries.Count
            MatchCount = $Entries.Count
        }
    }

    # Initialize field mappings if needed
    if (-not $Script:QueryFieldMappings) {
        Initialize-QueryFieldMappings
    }

    # Lex
    $tokens = Invoke-QueryLex -QueryString $QueryString

    # Parse
    $parsed = Build-QueryAst -Tokens $tokens
    $ast = $parsed.FilterAst
    $stages = $parsed.Stages

    # Filter entries
    $matched = [System.Collections.Generic.List[object]]::new()

    if ($null -eq $ast) {
        # No filter expression — all entries match (pipe-only query)
        $matched = $Entries
    } else {
        # Hot loop: evaluate AST against each entry
        $entryCount = $Entries.Count
        for ($i = 0; $i -lt $entryCount; $i++) {
            $entry = $Entries[$i]
            if (Test-QueryMatch -Node $ast -Entry $entry) {
                $matched.Add($entry)
            }
        }
    }

    # Apply aggregation pipeline if any
    $result = $null
    if ($stages.Count -gt 0) {
        $result = Invoke-QueryAggregate -Entries $matched -Stages $stages
    } else {
        $result = @{ Type = 'entries'; Data = $matched }
    }

    $sw.Stop()
    $elapsedMs = $sw.Elapsed.TotalMilliseconds

    # Add to history
    $resultCount = if ($result.Data -is [System.Collections.ICollection]) { $result.Data.Count } else { 1 }
    Add-QueryHistory -Query $QueryString -ResultCount $resultCount -ElapsedMs $elapsedMs

    # Attach metadata
    $result.Query      = $QueryString
    $result.ElapsedMs  = $elapsedMs
    $result.TotalCount = $Entries.Count
    $result.MatchCount = $matched.Count

    return $result
}

# ═══════════════════════════════════════════════════════════════════════════════
# RESULT FORMATTING
# ═══════════════════════════════════════════════════════════════════════════════

function Format-QueryResults {
    <#
    .SYNOPSIS
        Formats query results for console display with ANSI coloring.
    .PARAMETER Result
        The result object from Invoke-QueryFilter.
    .PARAMETER MaxRows
        Maximum number of rows to display. Defaults to 50.
    .OUTPUTS
        Formatted string for console output.
    #>
    param(
        [hashtable]$Result,
        [int]$MaxRows = 50
    )

    $reset = $Script:ANSIReset
    $themeName = if ($Script:State.ActiveTheme) { $Script:State.ActiveTheme } else { 'Dark' }
    $theme = $Script:ConsoleThemes[$themeName]
    if (-not $theme) { $theme = $Script:ConsoleThemes['Dark'] }

    $header  = $theme['Header']
    $dim     = $theme['Dim']
    $border  = $theme['Border']
    $title   = $theme['Title']
    $count   = $theme['Count']

    $sb = [System.Text.StringBuilder]::new()

    # Query metadata line
    $null = $sb.AppendLine("${dim}Query: ${reset}${title}$($Result.Query)${reset}")
    $null = $sb.AppendLine("${dim}Matched: ${count}$($Result.MatchCount)${reset}${dim} of $($Result.TotalCount) entries in $([math]::Round($Result.ElapsedMs, 1))ms${reset}")
    $null = $sb.AppendLine("${border}$([string]::new([char]0x2500, 78))${reset}")

    $data = $Result.Data

    if ($Result.Type -eq 'entries') {
        # Format as entry table
        if ($null -eq $data -or $data.Count -eq 0) {
            $null = $sb.AppendLine("${dim}No matching entries.${reset}")
            return $sb.ToString()
        }

        $displayCount = [math]::Min($MaxRows, $data.Count)

        # Table header
        $null = $sb.AppendLine("${header}  #    Timestamp             Level     Source          Message${reset}")
        $null = $sb.AppendLine("${border}$([string]::new([char]0x2500, 78))${reset}")

        for ($i = 0; $i -lt $displayCount; $i++) {
            $entry = $data[$i]
            $levelColor = $reset
            if ($theme.ContainsKey($entry.Level)) {
                $levelColor = $theme[$entry.Level]
            }

            $ts = if ($entry.Timestamp -ne [datetime]::MinValue) { $entry.Timestamp.ToString('yyyy-MM-dd HH:mm:ss') } else { '                   ' }
            $lvl = $entry.Level.PadRight(9)
            $src = if ($entry.Source.Length -gt 14) { $entry.Source.Substring(0, 14) } else { $entry.Source.PadRight(14) }
            $msg = if ($entry.Message.Length -gt 35) { $entry.Message.Substring(0, 35) } else { $entry.Message }
            $idx = $entry.Index.ToString().PadLeft(5)

            $null = $sb.AppendLine("${dim}${idx}${reset} ${dim}${ts}${reset} ${levelColor}${lvl}${reset} ${src} ${msg}")
        }

        if ($data.Count -gt $MaxRows) {
            $null = $sb.AppendLine("${dim}... and $($data.Count - $MaxRows) more entries (use | head N or | tail N)${reset}")
        }
    }
    elseif ($Result.Type -eq 'aggregated') {
        if ($null -eq $data -or $data.Count -eq 0) {
            $null = $sb.AppendLine("${dim}No results.${reset}")
            return $sb.ToString()
        }

        # Detect result shape from first row
        $firstRow = $data[0]

        if ($firstRow -is [hashtable]) {
            # Stats result: Function/Field/Result
            if ($firstRow.ContainsKey('Function')) {
                $null = $sb.AppendLine("${header}Statistics:${reset}")
                foreach ($row in $data) {
                    $null = $sb.AppendLine("  ${count}$($row.Function.ToUpper())${reset}($($row.Field)): ${title}$($row.Result)${reset}  ${dim}(from $($row.Count) values)${reset}")
                }
                return $sb.ToString()
            }

            # Count result
            if ($firstRow.ContainsKey('Count') -and $firstRow.Keys.Count -eq 1) {
                $null = $sb.AppendLine("${header}Count:${reset} ${count}$($firstRow.Count)${reset}")
                return $sb.ToString()
            }

            # Timeline result: Time/Count
            if ($firstRow.ContainsKey('Time') -and $firstRow.ContainsKey('Count')) {
                $null = $sb.AppendLine("${header}Timeline:${reset}")
                $null = $sb.AppendLine("${header}  Time                  Count${reset}")
                $null = $sb.AppendLine("${border}$([string]::new([char]0x2500, 40))${reset}")

                $maxCount = 1
                foreach ($row in $data) {
                    if ($row.Count -gt $maxCount) { $maxCount = $row.Count }
                }

                $displayCount = [math]::Min($MaxRows, $data.Count)
                for ($i = 0; $i -lt $displayCount; $i++) {
                    $row = $data[$i]
                    $barLen = [math]::Max(1, [math]::Round(($row.Count / $maxCount) * 30))
                    $bar = [string]::new([char]0x2588, $barLen)
                    $time = $row.Time.PadRight(22)
                    $null = $sb.AppendLine("  ${dim}${time}${reset}${count}$($row.Count.ToString().PadLeft(6))${reset} ${header}${bar}${reset}")
                }
                return $sb.ToString()
            }

            # Count-by result: Value/Count
            if ($firstRow.ContainsKey('Value') -and $firstRow.ContainsKey('Count')) {
                $null = $sb.AppendLine("${header}  Value                                    Count${reset}")
                $null = $sb.AppendLine("${border}$([string]::new([char]0x2500, 54))${reset}")

                $displayCount = [math]::Min($MaxRows, $data.Count)
                for ($i = 0; $i -lt $displayCount; $i++) {
                    $row = $data[$i]
                    $val = [string]$row.Value
                    if ($val.Length -gt 40) { $val = $val.Substring(0, 40) }
                    $val = $val.PadRight(42)
                    $null = $sb.AppendLine("  ${val}${count}$($row.Count.ToString().PadLeft(8))${reset}")
                }

                if ($data.Count -gt $MaxRows) {
                    $null = $sb.AppendLine("${dim}... and $($data.Count - $MaxRows) more rows${reset}")
                }
                return $sb.ToString()
            }

            # Generic table result: display all keys
            $keys = [System.Collections.Generic.List[string]]::new()
            foreach ($k in $firstRow.Keys) { $keys.Add($k) }

            # Build header
            $headerLine = '  '
            $widths = @{}
            foreach ($k in $keys) {
                $w = [math]::Max($k.Length, 10)
                $widths[$k] = $w
                $headerLine += $k.PadRight($w + 2)
            }
            $null = $sb.AppendLine("${header}${headerLine}${reset}")
            $totalWidth = 2
            foreach ($k in $keys) { $totalWidth += $widths[$k] + 2 }
            $null = $sb.AppendLine("${border}$([string]::new([char]0x2500, $totalWidth))${reset}")

            $displayCount = [math]::Min($MaxRows, $data.Count)
            for ($i = 0; $i -lt $displayCount; $i++) {
                $row = $data[$i]
                $line = '  '
                foreach ($k in $keys) {
                    $val = ''
                    if ($row -is [hashtable] -and $row.ContainsKey($k)) { $val = [string]$row[$k] }
                    $w = $widths[$k]
                    if ($val.Length -gt $w) { $val = $val.Substring(0, $w) }
                    $line += $val.PadRight($w + 2)
                }
                $null = $sb.AppendLine($line)
            }

            if ($data.Count -gt $MaxRows) {
                $null = $sb.AppendLine("${dim}... and $($data.Count - $MaxRows) more rows${reset}")
            }
        }
    }

    return $sb.ToString()
}

# ═══════════════════════════════════════════════════════════════════════════════
# QUERY HELP / SYNTAX REFERENCE
# ═══════════════════════════════════════════════════════════════════════════════

function Get-QuerySyntaxHelp {
    <#
    .SYNOPSIS
        Returns a help string describing the query language syntax.
    #>
    $reset = $Script:ANSIReset
    $themeName = if ($Script:State.ActiveTheme) { $Script:State.ActiveTheme } else { 'Dark' }
    $theme = $Script:ConsoleThemes[$themeName]
    if (-not $theme) { $theme = $Script:ConsoleThemes['Dark'] }

    $h = $theme['Header']
    $d = $theme['Dim']
    $t = $theme['Title']
    $c = $theme['Count']

    $sb = [System.Text.StringBuilder]::new()

    $null = $sb.AppendLine("${t}Simple Query Language (SQL) Reference${reset}")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("${h}Filter Expressions:${reset}")
    $null = $sb.AppendLine("  ${c}field:value${reset}              Exact match (case-insensitive)")
    $null = $sb.AppendLine("  ${c}field:value*${reset}             Wildcard match")
    $null = $sb.AppendLine("  ${c}field:""exact phrase""${reset}     Quoted exact match")
    $null = $sb.AppendLine("  ${c}field:>N${reset} / ${c}field:<N${reset}       Numeric comparison")
    $null = $sb.AppendLine("  ${c}field:>=N${reset} / ${c}field:<=N${reset}     Numeric comparison")
    $null = $sb.AppendLine("  ${c}searchterm${reset}                Search all text fields")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("${h}Boolean Operators:${reset}")
    $null = $sb.AppendLine("  ${c}expr AND expr${reset}            Both conditions (default when space-separated)")
    $null = $sb.AppendLine("  ${c}expr OR expr${reset}             Either condition")
    $null = $sb.AppendLine("  ${c}NOT expr${reset}                 Negation")
    $null = $sb.AppendLine("  ${c}(expr) AND expr${reset}          Grouping with parentheses")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("${h}Virtual Fields:${reset}")
    $null = $sb.AppendLine("  ${d}source, severity, level, host, message, time${reset}")
    $null = $sb.AppendLine("  ${d}user, srcip, dstip, action, eventid, device${reset}")
    $null = $sb.AppendLine("  ${d}port, policy, app, url, tunnel, mac, vlan${reset}")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("${h}Time Shortcuts:${reset}")
    $null = $sb.AppendLine("  ${c}time:last24h${reset}  ${c}time:last7d${reset}  ${c}time:today${reset}  ${c}time:yesterday${reset}")
    $null = $sb.AppendLine("  ${c}time:last1h${reset}   ${c}time:last4h${reset}  ${c}time:last30d${reset}")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("${h}Severity Aliases:${reset}")
    $null = $sb.AppendLine("  ${c}severity:critical${reset}  ${c}severity:high${reset}  ${c}severity:medium${reset}")
    $null = $sb.AppendLine("  ${c}severity:low${reset}       ${c}severity:info${reset}  ${c}severity:debug${reset}")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("${h}Pipeline Stages:${reset}")
    $null = $sb.AppendLine("  ${c}| count${reset}                  Total count of matches")
    $null = $sb.AppendLine("  ${c}| count by <field>${reset}       Group and count by field")
    $null = $sb.AppendLine("  ${c}| top N <field>${reset}          Top N values by count")
    $null = $sb.AppendLine("  ${c}| stats <func> <field>${reset}   Aggregate: sum, avg, min, max, count")
    $null = $sb.AppendLine("  ${c}| timeline <interval>${reset}    Bucket by time: 1m, 5m, 1h, 1d")
    $null = $sb.AppendLine("  ${c}| table <f1>,<f2>${reset}        Select specific fields")
    $null = $sb.AppendLine("  ${c}| sort <field> asc/desc${reset}  Sort results")
    $null = $sb.AppendLine("  ${c}| head N${reset} / ${c}| tail N${reset}      Limit results")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("${h}Examples:${reset}")
    $null = $sb.AppendLine("  ${d}source:fortigate action:deny | count by dstport | sort count desc | head 20${reset}")
    $null = $sb.AppendLine("  ${d}severity:high time:last24h | timeline 1h${reset}")
    $null = $sb.AppendLine("  ${d}(srcip:10.0.* OR srcip:192.168.*) AND action:deny${reset}")
    $null = $sb.AppendLine("  ${d}user:admin* NOT action:allow | count by srcip${reset}")
    $null = $sb.AppendLine("  ${d}severity:critical | table time,source,srcip,message${reset}")

    return $sb.ToString()
}
