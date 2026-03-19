# MITRE ATT&CK Technique-to-EventID mapping
# Used by WindowsEvtx parser for enrichment

$Script:MitreEventIdMap = @{
    4688 = @{ TechniqueId = "T1059"; TechniqueName = "Command and Scripting Interpreter"; Tactic = "Execution" }
    4698 = @{ TechniqueId = "T1053.005"; TechniqueName = "Scheduled Task"; Tactic = "Persistence" }
    4720 = @{ TechniqueId = "T1136.001"; TechniqueName = "Create Account: Local Account"; Tactic = "Persistence" }
    4625 = @{ TechniqueId = "T1110"; TechniqueName = "Brute Force"; Tactic = "Credential Access" }
    7045 = @{ TechniqueId = "T1543.003"; TechniqueName = "Create or Modify System Process: Windows Service"; Tactic = "Persistence" }
    4648 = @{ TechniqueId = "T1550"; TechniqueName = "Use Alternate Authentication Material"; Tactic = "Lateral Movement" }
    1102 = @{ TechniqueId = "T1070.001"; TechniqueName = "Indicator Removal: Clear Windows Event Logs"; Tactic = "Defense Evasion" }
    4104 = @{ TechniqueId = "T1059.001"; TechniqueName = "Command and Scripting Interpreter: PowerShell"; Tactic = "Execution" }
    4697 = @{ TechniqueId = "T1569.002"; TechniqueName = "System Services: Service Execution"; Tactic = "Execution" }
    4672 = @{ TechniqueId = "T1078"; TechniqueName = "Valid Accounts"; Tactic = "Privilege Escalation" }
    4728 = @{ TechniqueId = "T1098"; TechniqueName = "Account Manipulation"; Tactic = "Persistence" }
    4732 = @{ TechniqueId = "T1098"; TechniqueName = "Account Manipulation"; Tactic = "Persistence" }
    4756 = @{ TechniqueId = "T1098"; TechniqueName = "Account Manipulation"; Tactic = "Persistence" }
    4768 = @{ TechniqueId = "T1558.003"; TechniqueName = "Steal or Forge Kerberos Tickets: Kerberoasting"; Tactic = "Credential Access" }
    4769 = @{ TechniqueId = "T1558.003"; TechniqueName = "Steal or Forge Kerberos Tickets: Kerberoasting"; Tactic = "Credential Access" }
    4771 = @{ TechniqueId = "T1110"; TechniqueName = "Brute Force"; Tactic = "Credential Access" }
    4776 = @{ TechniqueId = "T1110"; TechniqueName = "Brute Force"; Tactic = "Credential Access" }
    5140 = @{ TechniqueId = "T1021.002"; TechniqueName = "Remote Services: SMB/Windows Admin Shares"; Tactic = "Lateral Movement" }
    5145 = @{ TechniqueId = "T1021.002"; TechniqueName = "Remote Services: SMB/Windows Admin Shares"; Tactic = "Lateral Movement" }
    4657 = @{ TechniqueId = "T1112"; TechniqueName = "Modify Registry"; Tactic = "Defense Evasion" }
    4719 = @{ TechniqueId = "T1562.002"; TechniqueName = "Impair Defenses: Disable Windows Event Logging"; Tactic = "Defense Evasion" }
    7040 = @{ TechniqueId = "T1562.001"; TechniqueName = "Impair Defenses: Disable or Modify Tools"; Tactic = "Defense Evasion" }
    4699 = @{ TechniqueId = "T1053.005"; TechniqueName = "Scheduled Task"; Tactic = "Persistence" }
    4700 = @{ TechniqueId = "T1053.005"; TechniqueName = "Scheduled Task"; Tactic = "Persistence" }
    4701 = @{ TechniqueId = "T1053.005"; TechniqueName = "Scheduled Task"; Tactic = "Persistence" }
    4702 = @{ TechniqueId = "T1053.005"; TechniqueName = "Scheduled Task"; Tactic = "Persistence" }
    4723 = @{ TechniqueId = "T1098"; TechniqueName = "Account Manipulation"; Tactic = "Persistence" }
    4724 = @{ TechniqueId = "T1098"; TechniqueName = "Account Manipulation"; Tactic = "Persistence" }
    4725 = @{ TechniqueId = "T1531"; TechniqueName = "Account Access Removal"; Tactic = "Impact" }
    4726 = @{ TechniqueId = "T1531"; TechniqueName = "Account Access Removal"; Tactic = "Impact" }
    4740 = @{ TechniqueId = "T1110"; TechniqueName = "Brute Force"; Tactic = "Credential Access" }
    4946 = @{ TechniqueId = "T1562.004"; TechniqueName = "Impair Defenses: Disable or Modify System Firewall"; Tactic = "Defense Evasion" }
    4947 = @{ TechniqueId = "T1562.004"; TechniqueName = "Impair Defenses: Disable or Modify System Firewall"; Tactic = "Defense Evasion" }
    4948 = @{ TechniqueId = "T1562.004"; TechniqueName = "Impair Defenses: Disable or Modify System Firewall"; Tactic = "Defense Evasion" }
    1116 = @{ TechniqueId = "T1059"; TechniqueName = "Command and Scripting Interpreter"; Tactic = "Execution" }
    1117 = @{ TechniqueId = "T1059"; TechniqueName = "Command and Scripting Interpreter"; Tactic = "Execution" }
    5001 = @{ TechniqueId = "T1562.001"; TechniqueName = "Impair Defenses: Disable or Modify Tools"; Tactic = "Defense Evasion" }
    4103 = @{ TechniqueId = "T1059.001"; TechniqueName = "Command and Scripting Interpreter: PowerShell"; Tactic = "Execution" }
    4689 = @{ TechniqueId = "T1059"; TechniqueName = "Command and Scripting Interpreter"; Tactic = "Execution" }
    5038 = @{ TechniqueId = "T1553"; TechniqueName = "Subvert Trust Controls"; Tactic = "Defense Evasion" }
    4798 = @{ TechniqueId = "T1087.001"; TechniqueName = "Account Discovery: Local Account"; Tactic = "Discovery" }
    4799 = @{ TechniqueId = "T1087.001"; TechniqueName = "Account Discovery: Local Account"; Tactic = "Discovery" }
    # Hyper-V related
    12010 = @{ TechniqueId = "T1564.006"; TechniqueName = "Hide Artifacts: Run Virtual Instance"; Tactic = "Defense Evasion" }
    # Certificate related
    4886 = @{ TechniqueId = "T1553.004"; TechniqueName = "Subvert Trust Controls: Install Root Certificate"; Tactic = "Defense Evasion" }
    4887 = @{ TechniqueId = "T1649"; TechniqueName = "Steal or Forge Authentication Certificates"; Tactic = "Credential Access" }
    # Remote access
    4778 = @{ TechniqueId = "T1021.001"; TechniqueName = "Remote Services: Remote Desktop Protocol"; Tactic = "Lateral Movement" }
    4779 = @{ TechniqueId = "T1021.001"; TechniqueName = "Remote Services: Remote Desktop Protocol"; Tactic = "Lateral Movement" }
    # Service control
    7034 = @{ TechniqueId = "T1489"; TechniqueName = "Service Stop"; Tactic = "Impact" }
    7036 = @{ TechniqueId = "T1543.003"; TechniqueName = "Create or Modify System Process: Windows Service"; Tactic = "Persistence" }
    # Additional credential access
    4738 = @{ TechniqueId = "T1098"; TechniqueName = "Account Manipulation"; Tactic = "Persistence" }
    4742 = @{ TechniqueId = "T1098"; TechniqueName = "Account Manipulation"; Tactic = "Persistence" }
    4767 = @{ TechniqueId = "T1098"; TechniqueName = "Account Manipulation"; Tactic = "Persistence" }
    # AD object modification
    5136 = @{ TechniqueId = "T1484"; TechniqueName = "Domain Policy Modification"; Tactic = "Defense Evasion" }
}

# Helper function to get MITRE info for an event ID
function Get-MitreForEventId {
    param([int]$EventId)
    if ($Script:MitreEventIdMap.ContainsKey($EventId)) {
        return $Script:MitreEventIdMap[$EventId]
    }
    return $null
}

$Script:MitreFortiActionMap = @{
    "utm/ips/deny"          = @{ TechniqueId = "T1190"; TechniqueName = "Exploit Public-Facing Application"; Tactic = "Initial Access" }
    "utm/av/block"          = @{ TechniqueId = "T1204"; TechniqueName = "User Execution"; Tactic = "Execution" }
    "utm/webfilter/block"   = @{ TechniqueId = "T1071.001"; TechniqueName = "Application Layer Protocol: Web Protocols"; Tactic = "Command and Control" }
    "utm/dns/block"         = @{ TechniqueId = "T1071.004"; TechniqueName = "Application Layer Protocol: DNS"; Tactic = "Command and Control" }
    "utm/app-ctrl/block"    = @{ TechniqueId = "T1048"; TechniqueName = "Exfiltration Over Alternative Protocol"; Tactic = "Exfiltration" }
    "event/user/deny"       = @{ TechniqueId = "T1110"; TechniqueName = "Brute Force"; Tactic = "Credential Access" }
    "utm/emailfilter/block" = @{ TechniqueId = "T1566"; TechniqueName = "Phishing"; Tactic = "Initial Access" }
}
