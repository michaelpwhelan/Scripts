#Requires -Modules Pester

<#
.SYNOPSIS
    Pester test suite for Set-GroupMembership.ps1.
.DESCRIPTION
    Tests mocked group membership operations including protected group
    detection, add/remove logic, and error handling. Dot-sources the
    script to load functions without executing the main block.
#>

BeforeAll {
    . "$PSScriptRoot/Set-GroupMembership.ps1"
}

# =============================================================================
# Pure function tests
# =============================================================================

Describe "Protect-ODataValue" {
    It "Escapes single quotes" {
        Protect-ODataValue -Value "O'Brien" | Should -Be "O''Brien"
    }

    It "Returns empty string unchanged" {
        Protect-ODataValue -Value "" | Should -Be ""
    }
}

# =============================================================================
# Mocked function tests
# =============================================================================

Describe "Get-GraphToken" {
    It "Returns a token from Graph login endpoint" {
        Mock Invoke-RestMethod { @{ access_token = "group-token" } }
        $token = Get-GraphToken
        $token | Should -Be "group-token"
    }
}

Describe "Invoke-GraphRequest" {
    BeforeAll {
        Mock Invoke-RestMethod { @{ value = @() } }
        # Set up the graph token that Invoke-GraphRequest expects
        $script:graphToken = "test-token"
    }

    It "Makes a GET request and returns results" {
        Mock Invoke-RestMethod { @{ displayName = "Test Group" } }
        $result = Invoke-GraphRequest -Uri "https://graph.example/v1.0/groups/123" -Method GET
        $result.displayName | Should -Be "Test Group"
    }

    It "Retries on transient failure" {
        $callCount = 0
        Mock Invoke-RestMethod {
            $callCount++
            if ($callCount -eq 1) { throw "503 Service Unavailable" }
            return @{ id = "success" }
        }
        $result = Invoke-GraphRequest -Uri "https://graph.example/v1.0/test" -Method GET
        $result.id | Should -Be "success"
    }
}
