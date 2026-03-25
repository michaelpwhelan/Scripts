# ===============================================================================
# ENRICHMENT DATA - BGP State Codes and Notification Error Codes (RFC 4271)
# ===============================================================================

$Script:BgpStateCodes = @{
    # BGP Finite State Machine States
    "Idle"        = "Not attempting to establish session; waiting for start event"
    "Connect"     = "TCP connection in progress to peer"
    "Active"      = "Actively attempting TCP connection to peer"
    "OpenSent"    = "OPEN message sent; waiting for peer OPEN"
    "OpenConfirm" = "OPEN received; waiting for KEEPALIVE or NOTIFICATION"
    "Established" = "BGP session fully established; exchanging routes"

    # BGP Notification Error Codes (RFC 4271 Section 4.5)
    # Error Code 1: Message Header Error
    "1/0"  = "Message Header Error (unspecified)"
    "1/1"  = "Message Header Error: Connection Not Synchronized"
    "1/2"  = "Message Header Error: Bad Message Length"
    "1/3"  = "Message Header Error: Bad Message Type"

    # Error Code 2: OPEN Message Error
    "2/0"  = "OPEN Message Error (unspecified)"
    "2/1"  = "OPEN Message Error: Unsupported Version Number"
    "2/2"  = "OPEN Message Error: Bad Peer AS"
    "2/3"  = "OPEN Message Error: Bad BGP Identifier"
    "2/4"  = "OPEN Message Error: Unsupported Optional Parameter"
    "2/6"  = "OPEN Message Error: Unacceptable Hold Time"
    "2/7"  = "OPEN Message Error: Unsupported Capability (RFC 5492)"

    # Error Code 3: UPDATE Message Error
    "3/0"  = "UPDATE Message Error (unspecified)"
    "3/1"  = "UPDATE Message Error: Malformed Attribute List"
    "3/2"  = "UPDATE Message Error: Unrecognized Well-known Attribute"
    "3/3"  = "UPDATE Message Error: Missing Well-known Attribute"
    "3/4"  = "UPDATE Message Error: Attribute Flags Error"
    "3/5"  = "UPDATE Message Error: Attribute Length Error"
    "3/6"  = "UPDATE Message Error: Invalid ORIGIN Attribute"
    "3/7"  = "UPDATE Message Error: AS Routing Loop (deprecated)"
    "3/8"  = "UPDATE Message Error: Invalid NEXT_HOP Attribute"
    "3/9"  = "UPDATE Message Error: Optional Attribute Error"
    "3/10" = "UPDATE Message Error: Invalid Network Field"
    "3/11" = "UPDATE Message Error: Malformed AS_PATH"

    # Error Code 4: Hold Timer Expired
    "4/0"  = "Hold Timer Expired - peer failed to send KEEPALIVE in time"

    # Error Code 5: Finite State Machine Error
    "5/0"  = "Finite State Machine Error (unspecified)"
    "5/1"  = "FSM Error: Unexpected message in OpenSent state"
    "5/2"  = "FSM Error: Unexpected message in OpenConfirm state"
    "5/3"  = "FSM Error: Unexpected message in Established state"

    # Error Code 6: Cease (RFC 4486)
    "6/0"  = "Cease (unspecified)"
    "6/1"  = "Cease: Maximum Number of Prefixes Reached"
    "6/2"  = "Cease: Administrative Shutdown"
    "6/3"  = "Cease: Peer De-configured"
    "6/4"  = "Cease: Administrative Reset"
    "6/5"  = "Cease: Connection Rejected"
    "6/6"  = "Cease: Other Configuration Change"
    "6/7"  = "Cease: Connection Collision Resolution"
    "6/8"  = "Cease: Hard Reset (RFC 8538)"
    "6/9"  = "Cease: BFD Down"
}

# Helper function to look up BGP state or notification code description
function Get-BgpStateDescription {
    param(
        [Parameter(Mandatory)]
        [string]$Code
    )

    if ($Script:BgpStateCodes.ContainsKey($Code)) {
        return $Script:BgpStateCodes[$Code]
    }

    # Try matching error/subcode format "error/subcode"
    if ($Code -match '^\d+/\d+$') {
        # Try the error code without subcode
        $errorCode = ($Code -split '/')[0]
        $baseKey = "$errorCode/0"
        if ($Script:BgpStateCodes.ContainsKey($baseKey)) {
            return $Script:BgpStateCodes[$baseKey]
        }
    }

    return $null
}
