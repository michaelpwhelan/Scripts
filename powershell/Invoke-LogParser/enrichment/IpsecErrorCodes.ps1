# ===============================================================================
# ENRICHMENT DATA - IPsec/IKE Error Codes and Notification Types (RFC 7296)
# ===============================================================================

$Script:IpsecErrorCodes = @{
    # IKEv2 Notification Types (RFC 7296)
    1     = "UNSUPPORTED_CRITICAL_PAYLOAD - Peer sent an unsupported critical payload"
    2     = "INVALID_IKE_SPI - IKE SPI does not match any known SA"
    4     = "INVALID_MAJOR_VERSION - Incompatible IKE major version"
    5     = "INVALID_SYNTAX - Malformed IKE message"
    7     = "INVALID_SYNTAX - IKE message failed parsing or validation"
    9     = "INVALID_MESSAGE_ID - Message ID out of expected window"
    11    = "INVALID_SPI - SPI value in notification does not match"
    14    = "NO_PROPOSAL_CHOSEN - No matching crypto proposal between peers"
    17    = "INVALID_KE_PAYLOAD - Key exchange payload does not match selected group"
    24    = "AUTHENTICATION_FAILED - Peer authentication failed (PSK/certificate mismatch)"
    34    = "SINGLE_PAIR_REQUIRED - Only a single traffic selector pair is supported"
    35    = "NO_ADDITIONAL_SAS - Cannot create additional SAs"
    36    = "INTERNAL_ADDRESS_FAILURE - Unable to assign internal address from pool"
    37    = "FAILED_CP_REQUIRED - Configuration payload required but not received"
    38    = "TS_UNACCEPTABLE - Traffic selectors unacceptable"
    39    = "INVALID_SELECTORS - Traffic selectors do not match SA"
    40    = "UNACCEPTABLE_ADDRESSES - Address in traffic selector not acceptable"
    41    = "UNEXPECTED_NAT_DETECTED - NAT detected but not expected"
    42    = "USE_ASSIGNED_HoA - Use assigned home address"
    43    = "INITIAL_CONTACT - Peer requests deletion of existing SAs"
    44    = "SET_WINDOW_SIZE - Peer requests window size change"
    16384 = "REKEY_SA - SA rekey requested"
    16385 = "CHILD_SA_NOT_FOUND - Referenced Child SA does not exist"
    16386 = "ADDITIONAL_TS_POSSIBLE - Additional traffic selectors possible"
    16387 = "IPCOMP_SUPPORTED - IP compression supported"
    16388 = "NAT_DETECTION_SOURCE_IP - NAT detection source IP"
    16389 = "NAT_DETECTION_DESTINATION_IP - NAT detection destination IP"
    16390 = "COOKIE - Anti-DoS cookie"
    16394 = "REKEY_SA - SA rekey in progress"

    # FortiGate-specific error strings
    "phase1 negotiate error"        = "IKE Phase 1 negotiation failed (check crypto proposals, PSK, peer ID)"
    "failed to get valid proposal"  = "No matching crypto proposal between peers"
    "DPD timeout"                   = "Dead Peer Detection timeout - peer unreachable"
    "peer not responding"           = "Remote gateway not responding to IKE packets"
    "no matching phase2"            = "No matching Phase 2 selector found for traffic"
    "invalid id"                    = "Peer identity mismatch (check local/remote ID settings)"
    "psk mismatch"                  = "Pre-shared key does not match between peers"
    "certificate verify failed"     = "Peer certificate validation failed (check CA chain)"
}

# Helper function to look up IPsec/IKE error description
function Get-IpsecErrorDescription {
    param(
        [Parameter(Mandatory)]
        $ErrorCode
    )

    if ($Script:IpsecErrorCodes.ContainsKey($ErrorCode)) {
        return $Script:IpsecErrorCodes[$ErrorCode]
    }

    # Try string match for FortiGate error messages
    if ($ErrorCode -is [string]) {
        foreach ($key in $Script:IpsecErrorCodes.Keys) {
            if ($key -is [string] -and $ErrorCode -like "*$key*") {
                return $Script:IpsecErrorCodes[$key]
            }
        }
    }

    return $null
}
