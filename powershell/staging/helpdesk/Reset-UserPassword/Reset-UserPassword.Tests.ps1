#Requires -Modules Pester

<#
.SYNOPSIS
    Pester test suite for Reset-UserPassword.ps1.
.DESCRIPTION
    Tests pure functions (password generation, crypto helpers) and mocked
    external calls (Graph API token, password reset). Dot-sources the
    script to load functions without executing the main block.
#>

BeforeAll {
    . "$PSScriptRoot/Reset-UserPassword.ps1"
}

# =============================================================================
# Pure function tests
# =============================================================================

Describe "Get-SecureRandomIndex" {
    It "Returns a value within [0, MaxExclusive)" {
        $result = Get-SecureRandomIndex -MaxExclusive 10
        $result | Should -BeGreaterOrEqual 0
        $result | Should -BeLessThan 10
    }

    It "Returns 0 when MaxExclusive is 1" {
        $result = Get-SecureRandomIndex -MaxExclusive 1
        $result | Should -Be 0
    }

    It "Throws when MaxExclusive is 0" {
        { Get-SecureRandomIndex -MaxExclusive 0 } | Should -Throw
    }
}

Describe "New-RandomPassword" {
    It "Returns a password of the requested length" {
        $pw = New-RandomPassword -Length 16
        $pw.Length | Should -Be 16
    }

    It "Contains at least one uppercase letter" {
        $pw = New-RandomPassword -Length 16
        $pw | Should -Match '[A-Z]'
    }

    It "Contains at least one lowercase letter" {
        $pw = New-RandomPassword -Length 16
        $pw | Should -Match '[a-z]'
    }

    It "Contains at least one digit" {
        $pw = New-RandomPassword -Length 16
        $pw | Should -Match '\d'
    }

    It "Contains at least one symbol" {
        $pw = New-RandomPassword -Length 16
        $pw | Should -Match '[^a-zA-Z0-9]'
    }

    It "Generates unique passwords on successive calls" {
        $pw1 = New-RandomPassword -Length 32
        $pw2 = New-RandomPassword -Length 32
        $pw1 | Should -Not -Be $pw2
    }

    It "Respects minimum length of 12" {
        { New-RandomPassword -Length 8 } | Should -Throw
    }
}

# =============================================================================
# Mocked function tests
# =============================================================================

Describe "Get-GraphToken" {
    It "Returns a token from Invoke-RestMethod" {
        Mock Invoke-RestMethod { @{ access_token = "test-token-123" } }
        $token = Get-GraphToken
        $token | Should -Be "test-token-123"
    }

    It "Caches token on second call" {
        Mock Invoke-RestMethod { @{ access_token = "cached-token" } }
        $null = Get-GraphToken
        $token2 = Get-GraphToken
        $token2 | Should -Be "cached-token"
        Should -Invoke Invoke-RestMethod -Times 1  # Only one actual call
    }
}
