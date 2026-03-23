#Requires -Modules Pester

<#
.SYNOPSIS
    Pester test suite for Audit-FortiGatePolicies.ps1.
.DESCRIPTION
    Tests cover pure parsing functions, helper/math functions, and
    compliance check functions using inline config snippets. The script
    is dot-sourced to load all functions without executing the main block.
#>

BeforeAll {
    # Dot-source the script.  The main block is guarded by being at the
    # end of the script and requiring $Config.ConfigFile to exist, so
    # sourcing only loads the functions and the ComplianceMap.
    . "$PSScriptRoot/Audit-FortiGatePolicies.ps1" -ConfigFile "__nonexistent__"
    $Script:FindingCounter = 0
}

# =============================================================================
# Parsing functions
# =============================================================================

Describe "ConvertTo-EditBlocks" {
    It "Parses a simple edit/next block" {
        $lines = @(
            '    edit "web-servers"',
            '        set subnet 10.0.1.0 255.255.255.0',
            '        set type ipmask',
            '    next'
        )
        $blocks = ConvertTo-EditBlocks -Lines $lines
        $blocks.Count | Should -Be 1
        $blocks[0]['_id'] | Should -Be "web-servers"
        $blocks[0]['subnet'] | Should -Be "10.0.1.0 255.255.255.0"
    }

    It "Parses multiple blocks" {
        $lines = @(
            '    edit "obj-a"',
            '        set subnet 10.0.0.0 255.0.0.0',
            '    next',
            '    edit "obj-b"',
            '        set subnet 192.168.0.0 255.255.0.0',
            '    next'
        )
        $blocks = ConvertTo-EditBlocks -Lines $lines
        $blocks.Count | Should -Be 2
        $blocks[1]['_id'] | Should -Be "obj-b"
    }

    It "Handles nested config/end blocks" {
        $lines = @(
            '    edit "snmp-community"',
            '        set name "public"',
            '        config hosts',
            '            edit 1',
            '                set ip 10.0.0.1 255.255.255.255',
            '            next',
            '        end',
            '    next'
        )
        $blocks = ConvertTo-EditBlocks -Lines $lines
        $blocks.Count | Should -Be 1
        $blocks[0]['name'] | Should -Be "public"
    }

    It "Returns empty list for empty input" {
        $blocks = ConvertTo-EditBlocks -Lines @()
        $blocks.Count | Should -Be 0
    }

    It "Parses multi-value quoted fields as array" {
        $lines = @(
            '    edit "test"',
            '        set member "obj-a" "obj-b" "obj-c"',
            '    next'
        )
        $blocks = ConvertTo-EditBlocks -Lines $lines
        $blocks[0]['member'].Count | Should -Be 3
        $blocks[0]['member'][0] | Should -Be "obj-a"
    }
}

Describe "ConvertTo-PolicyObjects" {
    It "Parses a minimal accept policy" {
        $lines = @(
            '    edit 1',
            '        set srcintf "port1"',
            '        set dstintf "wan1"',
            '        set srcaddr "all"',
            '        set dstaddr "all"',
            '        set service "ALL"',
            '        set action accept',
            '        set logtraffic all',
            '    next'
        )
        $policies = ConvertTo-PolicyObjects -Lines $lines
        $policies.Count | Should -Be 1
        $policies[0]['policyid'] | Should -Be 1
        $policies[0]['action'] | Should -Be "accept"
        $policies[0]['srcintf'] | Should -Contain "port1"
        $policies[0]['logtraffic'] | Should -Be "all"
    }

    It "Applies defaults for missing fields" {
        $lines = @(
            '    edit 99',
            '    next'
        )
        $policies = ConvertTo-PolicyObjects -Lines $lines
        $policies[0]['action'] | Should -Be "deny"
        $policies[0]['status'] | Should -Be "enable"
        $policies[0]['logtraffic'] | Should -Be "disable"
    }

    It "Returns empty list for empty input" {
        $policies = ConvertTo-PolicyObjects -Lines @()
        $policies.Count | Should -Be 0
    }
}

Describe "ConvertTo-AddressObjects" {
    It "Parses an ipmask address" {
        $lines = @(
            '    edit "LAN-Subnet"',
            '        set subnet 10.0.1.0 255.255.255.0',
            '    next'
        )
        $addrs = ConvertTo-AddressObjects -Lines $lines
        $addrs['LAN-Subnet'] | Should -Not -BeNullOrEmpty
        $addrs['LAN-Subnet']['subnet'] | Should -Be "10.0.1.0 255.255.255.0"
    }

    It "Parses an FQDN address" {
        $lines = @(
            '    edit "google-dns"',
            '        set type fqdn',
            '        set fqdn dns.google',
            '    next'
        )
        $addrs = ConvertTo-AddressObjects -Lines $lines
        $addrs['google-dns']['type'] | Should -Be "fqdn"
        $addrs['google-dns']['fqdn'] | Should -Be "dns.google"
    }

    It "Returns empty hashtable for empty input" {
        $addrs = ConvertTo-AddressObjects -Lines @()
        $addrs.Count | Should -Be 0
    }
}

# =============================================================================
# Helper / math functions
# =============================================================================

Describe "Get-SubnetPrefix" {
    It "Returns 8 for a /8 mask" {
        Get-SubnetPrefix -Subnet "10.0.0.0 255.0.0.0" | Should -Be 8
    }

    It "Returns 24 for a /24 mask" {
        Get-SubnetPrefix -Subnet "192.168.1.0 255.255.255.0" | Should -Be 24
    }

    It "Returns 32 for a /32 (host) mask" {
        Get-SubnetPrefix -Subnet "10.0.0.1 255.255.255.255" | Should -Be 32
    }

    It "Returns 0 for a /0 mask" {
        Get-SubnetPrefix -Subnet "0.0.0.0 0.0.0.0" | Should -Be 0
    }

    It "Returns -1 for invalid input" {
        Get-SubnetPrefix -Subnet "garbage" | Should -Be -1
    }
}

Describe "Test-SubnetContains" {
    It "Returns true when /8 contains /24" {
        Test-SubnetContains -SubnetA "10.0.0.0 255.0.0.0" -SubnetB "10.0.1.0 255.255.255.0" |
            Should -Be $true
    }

    It "Returns false when /24 does not contain /8" {
        Test-SubnetContains -SubnetA "10.0.1.0 255.255.255.0" -SubnetB "10.0.0.0 255.0.0.0" |
            Should -Be $false
    }

    It "Returns false for equal subnets (not strictly broader)" {
        Test-SubnetContains -SubnetA "10.0.0.0 255.255.255.0" -SubnetB "10.0.0.0 255.255.255.0" |
            Should -Be $false
    }

    It "Returns false for non-overlapping subnets" {
        Test-SubnetContains -SubnetA "10.0.0.0 255.0.0.0" -SubnetB "172.16.0.0 255.255.0.0" |
            Should -Be $false
    }

    It "Returns false for invalid input" {
        Test-SubnetContains -SubnetA "garbage" -SubnetB "10.0.0.0 255.0.0.0" |
            Should -Be $false
    }
}

Describe "Compare-FortiVersion" {
    It "Returns 0 for equal versions" {
        Compare-FortiVersion -VersionA "7.2.5" -VersionB "7.2.5" | Should -Be 0
    }

    It "Returns -1 when A is older" {
        Compare-FortiVersion -VersionA "7.0.0" -VersionB "7.2.5" | Should -Be -1
    }

    It "Returns 1 when A is newer" {
        Compare-FortiVersion -VersionA "7.4.1" -VersionB "7.2.5" | Should -Be 1
    }

    It "Handles different part counts" {
        Compare-FortiVersion -VersionA "7.2" -VersionB "7.2.0" | Should -Be 0
    }
}

Describe "Test-PolicyCovers" {
    It "Returns true when Q has 'all' in every dimension" {
        $q = @{ srcintf = @('any'); dstintf = @('any'); srcaddr = @('all'); dstaddr = @('all'); service = @('ALL') }
        $p = @{ srcintf = @('port1'); dstintf = @('wan1'); srcaddr = @('LAN'); dstaddr = @('WAN'); service = @('HTTPS') }
        Test-PolicyCovers -PolicyQ $q -PolicyP $p | Should -Be $true
    }

    It "Returns true when Q exactly matches P" {
        $q = @{ srcintf = @('port1'); dstintf = @('wan1'); srcaddr = @('LAN'); dstaddr = @('WAN'); service = @('HTTPS') }
        $p = @{ srcintf = @('port1'); dstintf = @('wan1'); srcaddr = @('LAN'); dstaddr = @('WAN'); service = @('HTTPS') }
        Test-PolicyCovers -PolicyQ $q -PolicyP $p | Should -Be $true
    }

    It "Returns false when Q is missing a dimension value" {
        $q = @{ srcintf = @('port1'); dstintf = @('wan1'); srcaddr = @('LAN'); dstaddr = @('WAN'); service = @('HTTP') }
        $p = @{ srcintf = @('port1'); dstintf = @('wan1'); srcaddr = @('LAN'); dstaddr = @('WAN'); service = @('HTTPS') }
        Test-PolicyCovers -PolicyQ $q -PolicyP $p | Should -Be $false
    }
}

Describe "New-Finding" {
    BeforeEach {
        $Script:FindingCounter = 0
    }

    It "Creates a finding with correct severity and category" {
        $f = New-Finding -Severity "HIGH" -Category "Shadow Rule" -PolicyId 5 `
             -PolicyName "test" -Detail "Rule is shadowed" -Recommendation "Delete it"
        $f.Severity | Should -Be "HIGH"
        $f.Category | Should -Be "Shadow Rule"
        $f.PolicyId | Should -Be 5
        $f.FindingId | Should -Be "F001"
    }

    It "Increments FindingId sequentially" {
        $null = New-Finding -Severity "LOW" -Category "test" -PolicyId $null `
                -PolicyName "" -Detail "a" -Recommendation "b"
        $f2 = New-Finding -Severity "LOW" -Category "test" -PolicyId $null `
              -PolicyName "" -Detail "c" -Recommendation "d"
        $f2.FindingId | Should -Be "F002"
    }

    It "Maps CIS/NIST/STIG from ComplianceMap" {
        $f = New-Finding -Severity "MEDIUM" -Category "Shadow Rule" -PolicyId 1 `
             -PolicyName "" -Detail "d" -Recommendation "r"
        $f.CisControl | Should -Be "3.1"
        $f.Nist80053 | Should -Be "AC-3"
    }
}

Describe "Get-SectionOrEmpty" {
    It "Returns section content when key exists" {
        $sections = @{ "config system global" = @("set hostname FG-TEST") }
        $result = Get-SectionOrEmpty -Sections $sections -Key "config system global"
        $result | Should -Contain "set hostname FG-TEST"
    }

    It "Returns empty array when key is missing" {
        $sections = @{}
        $result = Get-SectionOrEmpty -Sections $sections -Key "config missing"
        $result.Count | Should -Be 0
    }
}

# =============================================================================
# Compliance check functions
# =============================================================================

Describe "Find-ShadowRules" {
    It "Detects a rule fully covered by an earlier rule" {
        $policies = [System.Collections.Generic.List[hashtable]]::new()
        $policies.Add(@{
            policyid = 1; status = 'enable'; action = 'accept'
            srcintf = @('any'); dstintf = @('any'); srcaddr = @('all')
            dstaddr = @('all'); service = @('ALL')
            name = 'Allow All'
        })
        $policies.Add(@{
            policyid = 2; status = 'enable'; action = 'accept'
            srcintf = @('port1'); dstintf = @('wan1'); srcaddr = @('LAN')
            dstaddr = @('WAN'); service = @('HTTPS')
            name = 'Allow HTTPS'
        })
        $Script:FindingCounter = 0
        $findings = Find-ShadowRules -Policies $policies
        $findings.Count | Should -BeGreaterThan 0
        $findings[0].Category | Should -Be "Shadow Rule"
    }

    It "Returns no findings for non-overlapping rules" {
        $policies = [System.Collections.Generic.List[hashtable]]::new()
        $policies.Add(@{
            policyid = 1; status = 'enable'; action = 'accept'
            srcintf = @('port1'); dstintf = @('wan1'); srcaddr = @('LAN-A')
            dstaddr = @('WAN'); service = @('HTTPS')
            name = 'A to WAN'
        })
        $policies.Add(@{
            policyid = 2; status = 'enable'; action = 'accept'
            srcintf = @('port2'); dstintf = @('wan1'); srcaddr = @('LAN-B')
            dstaddr = @('WAN'); service = @('HTTP')
            name = 'B to WAN'
        })
        $Script:FindingCounter = 0
        $findings = Find-ShadowRules -Policies $policies
        $findings.Count | Should -Be 0
    }
}

Describe "Find-PermissiveRules" {
    BeforeAll {
        # Read the function to understand its signature
        $Script:FindingCounter = 0
    }

    It "Flags a policy with 'all' in srcaddr and dstaddr" {
        $policies = [System.Collections.Generic.List[hashtable]]::new()
        $policies.Add(@{
            policyid = 1; status = 'enable'; action = 'accept'
            srcintf = @('port1'); dstintf = @('wan1')
            srcaddr = @('all'); dstaddr = @('all'); service = @('ALL')
            name = 'Wide Open'
        })
        $Script:FindingCounter = 0
        $findings = Find-PermissiveRules -Policies $policies
        $findings.Count | Should -BeGreaterThan 0
        $findings[0].Severity | Should -Be "HIGH"
    }
}

Describe "Find-DisabledPolicies" {
    It "Flags disabled policies" {
        $policies = [System.Collections.Generic.List[hashtable]]::new()
        $policies.Add(@{
            policyid = 1; status = 'disable'; action = 'accept'
            srcintf = @('port1'); dstintf = @('wan1')
            srcaddr = @('all'); dstaddr = @('all'); service = @('ALL')
            name = 'Old Rule'
        })
        $Script:FindingCounter = 0
        $findings = Find-DisabledPolicies -Policies $policies
        $findings.Count | Should -BeGreaterThan 0
    }

    It "Returns nothing when all policies are enabled" {
        $policies = [System.Collections.Generic.List[hashtable]]::new()
        $policies.Add(@{
            policyid = 1; status = 'enable'; action = 'accept'
            srcintf = @('port1'); dstintf = @('wan1')
            srcaddr = @('LAN'); dstaddr = @('WAN'); service = @('HTTPS')
            name = 'Active'
        })
        $Script:FindingCounter = 0
        $findings = Find-DisabledPolicies -Policies $policies
        $findings.Count | Should -Be 0
    }
}

Describe "Find-LoggingDisabled" {
    It "Flags accept rules with logging disabled" {
        $policies = [System.Collections.Generic.List[hashtable]]::new()
        $policies.Add(@{
            policyid = 1; status = 'enable'; action = 'accept'
            srcintf = @('port1'); dstintf = @('wan1')
            srcaddr = @('LAN'); dstaddr = @('WAN'); service = @('HTTPS')
            logtraffic = 'disable'; name = 'No Logging'
        })
        $Script:FindingCounter = 0
        $findings = Find-LoggingDisabled -Policies $policies
        $findings.Count | Should -BeGreaterThan 0
    }
}
