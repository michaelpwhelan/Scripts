# ===============================================================================
# ENRICHMENT DATA - FFIEC Control Domain Mapping to Event Patterns
# ===============================================================================

$Script:FfiecControlMap = @{
    "IS.WP.AC" = @{
        Name = "Access Controls and User Management"
        Handbook = "Information Security"
        EventPatterns = @(
            @{ Field = "EventID"; Values = @(4624,4625,4634,4647,4648,4672,4720,4722,4725,4726,4740) }
            @{ Field = "PacketTypeName"; Values = @("Access-Accept","Access-Reject") }
            @{ Field = "action"; Pattern = "login|logout|auth" }
        )
    }
    "IS.WP.AL" = @{
        Name = "Audit and Logging"
        Handbook = "Information Security"
        EventPatterns = @(
            @{ Field = "EventID"; Values = @(1102,4719,4904,4905,4906,4907,4912) }
            @{ Field = "action"; Pattern = "config_change|audit" }
            @{ Field = "type"; Pattern = "event/system" }
        )
    }
    "IS.WP.CM" = @{
        Name = "Change Management"
        Handbook = "Information Security"
        EventPatterns = @(
            @{ Field = "EventID"; Values = @(4657,4670,4697,4698,4699,4700,4701,4702,5136,7045) }
            @{ Field = "action"; Pattern = "edit_policy|add_policy|del_policy|install_policy|config_change" }
            @{ Field = "type"; Pattern = "event/system" }
        )
    }
    "IS.WP.ID" = @{
        Name = "Incident Detection and Response"
        Handbook = "Information Security"
        EventPatterns = @(
            @{ Field = "EventID"; Values = @(1116,1117,4625,4648,4719,4740,4768,4769,4771,5038) }
            @{ Field = "type"; Pattern = "utm/ips|utm/av|utm/webfilter" }
            @{ Field = "action"; Pattern = "block|deny|quarantine|alert" }
        )
    }
    "IS.WP.BC" = @{
        Name = "Business Continuity Planning"
        Handbook = "Information Security"
        EventPatterns = @(
            @{ Field = "EventID"; Values = @(41,6005,6006,6008,7034,7036,18512,18514,18516) }
            @{ Field = "action"; Pattern = "ha_failover|ha_sync|backup|restore" }
            @{ Field = "type"; Pattern = "event/ha" }
        )
    }
    "IS.WP.NS" = @{
        Name = "Network Security"
        Handbook = "Information Security"
        EventPatterns = @(
            @{ Field = "EventID"; Values = @(4946,4947,4948,4950,5152,5156,5157) }
            @{ Field = "type"; Pattern = "traffic/forward|traffic/local|utm/ips" }
            @{ Field = "action"; Pattern = "deny|block|accept|drop" }
        )
    }
    "IS.WP.AM" = @{
        Name = "Account Management and Authentication"
        Handbook = "Information Security"
        EventPatterns = @(
            @{ Field = "EventID"; Values = @(4720,4722,4723,4724,4725,4726,4738,4741,4742,4743,4767) }
            @{ Field = "PacketTypeName"; Values = @("Access-Accept","Access-Reject","Access-Challenge") }
            @{ Field = "action"; Pattern = "add_user|del_user|edit_user|password" }
        )
    }
    "IS.WP.RM" = @{
        Name = "Remote Access Management"
        Handbook = "Information Security"
        EventPatterns = @(
            @{ Field = "EventID"; Values = @(4624,4625,4648,4778,4779) }
            @{ Field = "type"; Pattern = "event/vpn|event/ipsecvpn" }
            @{ Field = "action"; Pattern = "tunnel-up|tunnel-down|sslvpn|login|logout" }
        )
    }
    "IS.WP.PM" = @{
        Name = "Privilege Management"
        Handbook = "Information Security"
        EventPatterns = @(
            @{ Field = "EventID"; Values = @(4672,4673,4728,4732,4756,4757) }
            @{ Field = "action"; Pattern = "admin|privilege|role" }
        )
    }
    "IS.WP.MV" = @{
        Name = "Malware and Vulnerability Management"
        Handbook = "Information Security"
        EventPatterns = @(
            @{ Field = "EventID"; Values = @(1006,1007,1008,1116,1117,5001,5010,5012) }
            @{ Field = "type"; Pattern = "utm/av|utm/ips" }
            @{ Field = "action"; Pattern = "block|quarantine|detect|clean" }
        )
    }
}

# Helper function to find matching FFIEC controls for a given event
function Get-FfiecControlsForEvent {
    param(
        [Parameter(Mandatory)]
        [hashtable]$EventData
    )

    $matchedControls = @()

    foreach ($controlId in $Script:FfiecControlMap.Keys) {
        $control = $Script:FfiecControlMap[$controlId]
        $matched = $false

        foreach ($pattern in $control.EventPatterns) {
            $fieldValue = $EventData[$pattern.Field]
            if ($null -eq $fieldValue) { continue }

            # Check Values-based matching (exact list)
            if ($pattern.ContainsKey('Values')) {
                if ($fieldValue -in $pattern.Values) {
                    $matched = $true
                    break
                }
            }

            # Check Pattern-based matching (regex)
            if ($pattern.ContainsKey('Pattern')) {
                if ($fieldValue -match $pattern.Pattern) {
                    $matched = $true
                    break
                }
            }
        }

        if ($matched) {
            $matchedControls += @{
                ControlId = $controlId
                Name      = $control.Name
                Handbook  = $control.Handbook
            }
        }
    }

    return $matchedControls
}
