#Requires -Modules Pester

<#
.SYNOPSIS
    Pester test suite for Rename-ManagedComputer.ps1.
.DESCRIPTION
    Tests cover pure functions (no mocks), mocked external dependencies,
    and integration-style scenarios. Dot-sources the script to load all
    functions without executing the main block.
#>

BeforeAll {
    . "$PSScriptRoot/Rename-ManagedComputer.ps1"
}

# =============================================================================
# Pure function tests
# =============================================================================

Describe "Protect-ODataValue" {
    It "Escapes single quotes by doubling them" {
        Protect-ODataValue -Value "test'name" | Should -Be "test''name"
    }

    It "Handles multiple single quotes" {
        Protect-ODataValue -Value "it's a 'test'" | Should -Be "it''s a ''test''"
    }

    It "Returns unchanged string when no quotes present" {
        Protect-ODataValue -Value "TESTPC01" | Should -Be "TESTPC01"
    }

    It "Returns empty string for empty input" {
        Protect-ODataValue -Value "" | Should -Be ""
    }
}

Describe "New-CheckResult" {
    It "Creates object with PASS status" {
        $r = New-CheckResult -Check "Test check" -Status "PASS" -Detail "All good"
        $r.Check  | Should -Be "Test check"
        $r.Status | Should -Be "PASS"
        $r.Detail | Should -Be "All good"
    }

    It "Creates object with FAIL status" {
        $r = New-CheckResult -Check "Bad check" -Status "FAIL" -Detail "Something broke"
        $r.Status | Should -Be "FAIL"
    }

    It "Creates object with WARN status" {
        $r = New-CheckResult -Check "Warn check" -Status "WARN" -Detail "Heads up"
        $r.Status | Should -Be "WARN"
    }

    It "Creates object with SKIP status" {
        $r = New-CheckResult -Check "Skip check" -Status "SKIP" -Detail "Not needed"
        $r.Status | Should -Be "SKIP"
    }
}

Describe "Test-IsRemote" {
    It "Returns false for 'localhost'" {
        Test-IsRemote -Computer "localhost" | Should -Be $false
    }

    It "Returns false for '.'" {
        Test-IsRemote -Computer "." | Should -Be $false
    }

    It "Returns false for local computer name" {
        Test-IsRemote -Computer $env:COMPUTERNAME | Should -Be $false
    }

    It "Returns true for a remote hostname" {
        Test-IsRemote -Computer "REMOTEPC01" | Should -Be $true
    }

    It "Returns true for a FQDN" {
        Test-IsRemote -Computer "server.domain.local" | Should -Be $true
    }
}

Describe "Test-SerialValid" {
    $invalidSerials = @(
        "To Be Filled By O.E.M.", "Default string",
        "System Serial Number", "None", "N/A"
    )

    It "Returns true for a valid serial number" {
        Test-SerialValid -Serial "ABC123DEF456" -InvalidSerials $invalidSerials | Should -Be $true
    }

    It "Returns false for a known placeholder" {
        Test-SerialValid -Serial "Default string" -InvalidSerials $invalidSerials | Should -Be $false
    }

    It "Returns false for 'None'" {
        Test-SerialValid -Serial "None" -InvalidSerials $invalidSerials | Should -Be $false
    }

    It "Returns false for a serial with no alphanumeric characters" {
        Test-SerialValid -Serial "---" -InvalidSerials $invalidSerials | Should -Be $false
    }

    It "Returns false for empty serial" {
        Test-SerialValid -Serial "" -InvalidSerials $invalidSerials | Should -Be $false
    }

    It "Returns true for serial with mixed valid characters" {
        Test-SerialValid -Serial "SN-1234-AB" -InvalidSerials $invalidSerials | Should -Be $true
    }
}

Describe "ConvertTo-SafeComputerName" {
    It "Converts a clean serial with prefix" {
        $result = ConvertTo-SafeComputerName -Serial "ABC123" -Prefix "PC-" -MaxLength 15
        $result.Name | Should -Be "PC-ABC123"
        $result.Truncated | Should -Be $false
    }

    It "Uppercases the result" {
        $result = ConvertTo-SafeComputerName -Serial "abc123" -Prefix "" -MaxLength 15
        $result.Name | Should -Be "ABC123"
    }

    It "Strips invalid characters" {
        $result = ConvertTo-SafeComputerName -Serial "AB C!@#12" -Prefix "" -MaxLength 15
        $result.Name | Should -Be "ABC12"
    }

    It "Truncates to MaxLength and sets Truncated flag" {
        $result = ConvertTo-SafeComputerName -Serial "ABCDEFGHIJKLMNOP" -Prefix "PRE" -MaxLength 15
        $result.Name.Length | Should -Be 15
        $result.Truncated | Should -Be $true
        $result.OrigLength | Should -BeGreaterThan 15
    }

    It "Does not truncate when within MaxLength" {
        $result = ConvertTo-SafeComputerName -Serial "SHORT" -Prefix "A" -MaxLength 15
        $result.Name | Should -Be "ASHORT"
        $result.Truncated | Should -Be $false
    }

    It "Handles serial that is only hyphens" {
        $result = ConvertTo-SafeComputerName -Serial "---" -Prefix "" -MaxLength 15
        $result.Name | Should -Be ""
    }

    It "Trims leading/trailing hyphens from cleaned serial" {
        $result = ConvertTo-SafeComputerName -Serial "-ABC-" -Prefix "" -MaxLength 15
        $result.Name | Should -Be "ABC"
    }
}

Describe "Invoke-WithRetry" {
    It "Returns result on first successful attempt" {
        $result = Invoke-WithRetry -ScriptBlock { "success" } -MaxAttempts 3 -DelaySeconds 0
        $result | Should -Be "success"
    }

    It "Retries and succeeds on later attempt" {
        $script:attempt = 0
        $result = Invoke-WithRetry -MaxAttempts 3 -DelaySeconds 0 -ScriptBlock {
            $script:attempt++
            if ($script:attempt -lt 3) { throw "transient error" }
            "recovered"
        }
        $result | Should -Be "recovered"
        $script:attempt | Should -Be 3
    }

    It "Throws after exhausting all attempts" {
        { Invoke-WithRetry -MaxAttempts 2 -DelaySeconds 0 -ScriptBlock { throw "permanent failure" } } |
            Should -Throw "permanent failure"
    }
}

# =============================================================================
# Mocked function tests
# =============================================================================

Describe "Get-GraphToken" {
    BeforeEach {
        $Script:GraphTokenCache = @{ Token = $null; ExpiresAt = [datetime]::MinValue }
    }

    It "Rejects invalid TenantId format" {
        { Get-GraphToken -TenantId "not-a-guid" -ClientId "00000000-0000-0000-0000-000000000000" -ClientSecret "secret" } |
            Should -Throw "*not a valid GUID*"
    }

    It "Acquires token and caches it" {
        Mock Invoke-RestMethod {
            return @{ access_token = "mock-token"; expires_in = 3600 }
        }
        $token = Get-GraphToken -TenantId "00000000-0000-0000-0000-000000000000" -ClientId "11111111-1111-1111-1111-111111111111" -ClientSecret "secret"
        $token | Should -Be "mock-token"
        $Script:GraphTokenCache.Token | Should -Be "mock-token"
    }

    It "Returns cached token on second call" {
        Mock Invoke-RestMethod {
            return @{ access_token = "mock-token"; expires_in = 3600 }
        }
        Get-GraphToken -TenantId "00000000-0000-0000-0000-000000000000" -ClientId "11111111-1111-1111-1111-111111111111" -ClientSecret "secret"
        $token2 = Get-GraphToken -TenantId "00000000-0000-0000-0000-000000000000" -ClientId "11111111-1111-1111-1111-111111111111" -ClientSecret "secret"
        $token2 | Should -Be "mock-token"
        Should -Invoke Invoke-RestMethod -Times 1 -Exactly
    }
}

Describe "Test-EntraNameCollision" {
    It "Returns PASS when no device found" {
        Mock Invoke-RestMethod { return @{ value = @() } }
        $result = Test-EntraNameCollision -TargetName "NEWPC01" -Token "mock-token"
        $result.Status | Should -Be "PASS"
    }

    It "Returns FAIL when device exists" {
        Mock Invoke-RestMethod { return @{ value = @(@{ displayName = "NEWPC01"; id = "123" }) } }
        $result = Test-EntraNameCollision -TargetName "NEWPC01" -Token "mock-token"
        $result.Status | Should -Be "FAIL"
    }

    It "Returns WARN when API call fails" {
        Mock Invoke-RestMethod { throw "API error" }
        $result = Test-EntraNameCollision -TargetName "NEWPC01" -Token "mock-token"
        $result.Status | Should -Be "WARN"
        $result.Detail | Should -BeLike "*API error*"
    }

    It "Passes ApiVersion parameter to URL" {
        Mock Invoke-RestMethod {
            param($Method, $Uri, $Headers)
            $Uri | Should -BeLike "*beta/devices*"
            return @{ value = @() }
        }
        Test-EntraNameCollision -TargetName "NEWPC01" -Token "mock-token" -ApiVersion "beta"
    }
}

Describe "Test-ADNameCollision" {
    It "Returns WARN when ActiveDirectory module is not available" {
        Mock Get-Module { return $null }
        $result = Test-ADNameCollision -TargetName "TESTPC"
        $result.Status | Should -Be "WARN"
        $result.Detail | Should -BeLike "*not available*"
    }
}

Describe "Get-JoinType" {
    It "Returns Hybrid when both AzureAdJoined and DomainJoined are YES" {
        Mock Invoke-OnTarget {
            return @(
                "+----------------------------------------------------------------------+",
                "| Device State                                                         |",
                "+----------------------------------------------------------------------+",
                "             AzureAdJoined : YES",
                "          DomainJoined : YES"
            )
        }
        Get-JoinType -Computer "localhost" | Should -Be "Hybrid"
    }

    It "Returns EntraJoined when only AzureAdJoined is YES" {
        Mock Invoke-OnTarget {
            return @(
                "             AzureAdJoined : YES",
                "          DomainJoined : NO"
            )
        }
        Get-JoinType -Computer "localhost" | Should -Be "EntraJoined"
    }

    It "Returns ADJoined when only DomainJoined is YES" {
        Mock Invoke-OnTarget {
            return @(
                "             AzureAdJoined : NO",
                "          DomainJoined : YES"
            )
        }
        Get-JoinType -Computer "localhost" | Should -Be "ADJoined"
    }

    It "Returns Workgroup when neither is YES" {
        Mock Invoke-OnTarget {
            return @(
                "             AzureAdJoined : NO",
                "          DomainJoined : NO"
            )
        }
        Get-JoinType -Computer "localhost" | Should -Be "Workgroup"
    }
}

Describe "Import-ScriptConfig" {
    BeforeAll {
        $testDefaults = @{
            Prefix          = ""
            MaxLength       = 15
            OldNamePattern  = ""
            InvalidSerials  = @("None", "N/A")
            GraphApiVersion = "v1.0"
            LogDir          = "/tmp/logs"
            OutputDir       = "/tmp/output"
        }
    }

    It "Returns defaults when no config file exists" {
        $config = Import-ScriptConfig -ConfigFilePath $null -ParamOverrides @{} -Defaults $testDefaults
        $config.MaxLength | Should -Be 15
        $config.Prefix | Should -Be ""
        $config.GraphApiVersion | Should -Be "v1.0"
    }

    It "Applies parameter overrides over defaults" {
        $config = Import-ScriptConfig -ConfigFilePath $null -ParamOverrides @{ Prefix = "WS-" } -Defaults $testDefaults
        $config.Prefix | Should -Be "WS-"
    }

    It "Warns on malformed JSON config file" {
        $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "bad-config-$(Get-Random).json"
        "not valid json {{{" | Set-Content -Path $tempFile
        try {
            $config = Import-ScriptConfig -ConfigFilePath $tempFile -ParamOverrides @{} -Defaults $testDefaults 3>&1
            # Should still return valid config with defaults
        } finally {
            Remove-Item $tempFile -ErrorAction SilentlyContinue
        }
    }

    It "Warns on out-of-range MaxLength" {
        $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "range-config-$(Get-Random).json"
        @{ MaxLength = 99 } | ConvertTo-Json | Set-Content -Path $tempFile
        try {
            $config = Import-ScriptConfig -ConfigFilePath $tempFile -ParamOverrides @{} -Defaults $testDefaults
            $config.MaxLength | Should -Be 15  # Should keep default
        } finally {
            Remove-Item $tempFile -ErrorAction SilentlyContinue
        }
    }

    It "Applies valid config file values" {
        $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "good-config-$(Get-Random).json"
        @{ Prefix = "LAB-"; MaxLength = 12; GraphApiVersion = "beta" } | ConvertTo-Json | Set-Content -Path $tempFile
        try {
            $config = Import-ScriptConfig -ConfigFilePath $tempFile -ParamOverrides @{} -Defaults $testDefaults
            $config.Prefix | Should -Be "LAB-"
            $config.MaxLength | Should -Be 12
            $config.GraphApiVersion | Should -Be "beta"
        } finally {
            Remove-Item $tempFile -ErrorAction SilentlyContinue
        }
    }

    It "Parameter overrides take priority over config file" {
        $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "override-config-$(Get-Random).json"
        @{ Prefix = "FILE-" } | ConvertTo-Json | Set-Content -Path $tempFile
        try {
            $config = Import-ScriptConfig -ConfigFilePath $tempFile -ParamOverrides @{ Prefix = "PARAM-" } -Defaults $testDefaults
            $config.Prefix | Should -Be "PARAM-"
        } finally {
            Remove-Item $tempFile -ErrorAction SilentlyContinue
        }
    }
}

Describe "New-TemplateConfig" {
    It "Creates a valid JSON template file" {
        $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "template-$(Get-Random).json"
        try {
            $path = New-TemplateConfig -OutputPath $tempFile
            $path | Should -Be $tempFile
            $content = Get-Content -Path $tempFile -Raw | ConvertFrom-Json
            $content.PSObject.Properties.Name | Should -Contain "Prefix" -Because "Prefix key should exist"
            $content.MaxLength | Should -Be 15
            $content.InvalidSerials | Should -Not -BeNullOrEmpty
            $content.GraphApiVersion | Should -Be "v1.0"
            $content.EntraId | Should -Not -BeNullOrEmpty -Because "EntraId section should exist"
        } finally {
            Remove-Item $tempFile -ErrorAction SilentlyContinue
        }
    }

    It "Throws when file exists and ForceOverwrite is not set" {
        $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "exists-$(Get-Random).json"
        "existing" | Set-Content -Path $tempFile
        try {
            { New-TemplateConfig -OutputPath $tempFile } | Should -Throw "*already exists*"
        } finally {
            Remove-Item $tempFile -ErrorAction SilentlyContinue
        }
    }

    It "Overwrites when ForceOverwrite is set" {
        $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "force-$(Get-Random).json"
        "existing" | Set-Content -Path $tempFile
        try {
            $path = New-TemplateConfig -OutputPath $tempFile -ForceOverwrite
            $path | Should -Be $tempFile
            $content = Get-Content -Path $tempFile -Raw | ConvertFrom-Json
            $content.MaxLength | Should -Be 15
        } finally {
            Remove-Item $tempFile -ErrorAction SilentlyContinue
        }
    }

    It "Uses values from Script:Defaults (no duplication)" {
        $tempFile = Join-Path ([System.IO.Path]::GetTempPath()) "defaults-$(Get-Random).json"
        try {
            New-TemplateConfig -OutputPath $tempFile
            $content = Get-Content -Path $tempFile -Raw | ConvertFrom-Json
            $content.InvalidSerials | Should -Contain "To Be Filled By O.E.M."
            $content.InvalidSerials | Should -Contain "Chassis Serial Number"
        } finally {
            Remove-Item $tempFile -ErrorAction SilentlyContinue
        }
    }
}

# =============================================================================
# Integration-style tests (mocked dependencies)
# =============================================================================

Describe "Invoke-Discovery" {
    BeforeAll {
        $testConfig = @{
            ScriptName      = "Rename-ManagedComputer"
            Prefix          = "PC"
            MaxLength       = 15
            OldNamePattern  = ""
            InvalidSerials  = @("None", "N/A")
            GraphApiVersion = "v1.0"
            LogDir          = "/tmp/logs"
            OutputDir       = "/tmp/output"
            TenantId        = ""
            ClientId        = ""
            ClientSecret    = ""
        }
    }

    It "Returns 9 check results for a manual name on local target" {
        Mock Invoke-OnTarget -ParameterFilter { $ScriptBlock.ToString() -match 'COMPUTERNAME' } { return "OLDPC01" }
        Mock Invoke-OnTarget -ParameterFilter { $ScriptBlock.ToString() -match 'dsregcmd' } {
            return @("AzureAdJoined : YES", "DomainJoined : NO")
        }
        Mock Get-DeviceInfo { return "Dell Latitude 5520" }
        Mock Test-IsRemote { return $false }
        Mock Get-Module { return $null }  # No AD module

        $discovery = Invoke-Discovery -Config $testConfig -ComputerName "localhost" -NewName "NEWPC01" -SkipEntraCheck
        $discovery.Results.Count | Should -Be 9
        $discovery.TargetName | Should -Be "NEWPC01"
        $discovery.ManualName | Should -Be $true
    }

    It "Blocks rename when target name already matches current name" {
        Mock Invoke-OnTarget -ParameterFilter { $ScriptBlock.ToString() -match 'COMPUTERNAME' } { return "NEWPC01" }
        Mock Invoke-OnTarget -ParameterFilter { $ScriptBlock.ToString() -match 'dsregcmd' } {
            return @("AzureAdJoined : NO", "DomainJoined : NO")
        }
        Mock Get-DeviceInfo { return "Dell Latitude 5520" }
        Mock Test-IsRemote { return $false }
        Mock Get-Module { return $null }

        $discovery = Invoke-Discovery -Config $testConfig -ComputerName "localhost" -NewName "NEWPC01" -SkipEntraCheck
        $discovery.AlreadyRenamed | Should -Be $true
    }
}

Describe "Invoke-RenamePhase" {
    It "Returns DryRun when Execute is not set" {
        $mockDiscovery = [PSCustomObject]@{
            Results        = @()
            CurrentName    = "OLDPC"
            TargetName     = "NEWPC"
            FailCount      = 0
            WarnCount      = 0
            AlreadyRenamed = $false
            JoinType       = "Workgroup"
        }
        $result = Invoke-RenamePhase -Discovery $mockDiscovery -Config @{} -ComputerName "localhost"
        $result | Should -Be "DryRun"
    }

    It "Returns Blocked when there are failures" {
        $mockDiscovery = [PSCustomObject]@{
            Results        = @()
            CurrentName    = "OLDPC"
            TargetName     = "NEWPC"
            FailCount      = 2
            WarnCount      = 0
            AlreadyRenamed = $false
            JoinType       = "Workgroup"
        }
        $result = Invoke-RenamePhase -Discovery $mockDiscovery -Config @{} -ComputerName "localhost" -Execute
        $result | Should -Be "Blocked"
    }

    It "Returns Skipped when already renamed" {
        $mockDiscovery = [PSCustomObject]@{
            Results        = @()
            CurrentName    = "NEWPC"
            TargetName     = "NEWPC"
            FailCount      = 0
            WarnCount      = 1
            AlreadyRenamed = $true
            JoinType       = "Workgroup"
        }
        $result = Invoke-RenamePhase -Discovery $mockDiscovery -Config @{} -ComputerName "localhost" -Execute
        $result | Should -Be "Skipped"
    }
}
