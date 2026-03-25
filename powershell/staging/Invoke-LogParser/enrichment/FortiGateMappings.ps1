# ===============================================================================
# ENRICHMENT DATA - FortiGate Log Subtype Descriptions
# ===============================================================================

$Script:FortiSubtypeLookup = @{
    "traffic/forward"  = "Forwarded traffic"
    "traffic/local"    = "Local traffic"
    "traffic/sniffer"  = "Sniffer"
    "utm/webfilter"    = "Web filter"
    "utm/av"           = "Antivirus"
    "utm/ips"          = "IPS"
    "utm/app-ctrl"     = "Application control"
    "utm/dlp"          = "DLP"
    "utm/dns"          = "DNS filter"
    "event/system"     = "System event"
    "event/vpn"        = "VPN event"
    "event/user"       = "User event"
    "event/ha"         = "HA event"
    "event/wad"        = "WAD event"
    "event/ipsecvpn"   = "IPsec VPN event"
    "event/route"      = "Routing event"
    "event/connector"  = "Security fabric connector event"
    "event/fortiextender" = "FortiExtender event"
    "utm/ssl"          = "SSL inspection"
    "utm/emailfilter"  = "Email filter"
    "utm/cifs"         = "CIFS inspection"
    "utm/ssh"          = "SSH inspection"
    "event/wireless"   = "Wireless event"
}

$Script:FortiClientModuleLookup = @{
    "sslvpn"     = "VPN"
    "vpn"        = "VPN"
    "av"         = "Antivirus"
    "malware"    = "Antivirus"
    "webfilter"  = "Web Filter"
    "ems"        = "EMS"
    "update"     = "Update"
    "endpoint"   = "Endpoint"
    "sandbox"    = "Sandbox"
    "firewall"   = "Firewall"
}

$Script:FortiGateLogIdRanges = @{
    "0001" = "Traffic: Forward"
    "0002" = "Traffic: Local"
    "0003" = "Traffic: Multicast"
    "0100" = "Event: System"
    "0101" = "Event: IPsec"
    "0102" = "Event: HA"
    "0103" = "Event: Compliance"
    "0104" = "Event: VPN"
    "0200" = "Event: User"
    "0300" = "Event: Router"
    "0400" = "Event: WAD"
    "1600" = "UTM: Virus"
    "1700" = "UTM: Web Filter"
    "1800" = "UTM: IPS"
    "1900" = "UTM: Email Filter"
    "2000" = "UTM: DLP"
    "2100" = "UTM: Application Control"
    "2200" = "UTM: VoIP"
    "2300" = "UTM: DNS"
}
