#Requires -Modules Pester

<#
.SYNOPSIS
    Pester test suite for Unlock-UserAccount.ps1.
.DESCRIPTION
    Tests pure display functions and mocked AD/Graph operations.
    Dot-sources the script to load functions without executing main.
#>

BeforeAll {
    . "$PSScriptRoot/Unlock-UserAccount.ps1"
}

# =============================================================================
# Pure function tests
# =============================================================================

Describe "Show-Section" {
    It "Does not throw on normal input" {
        { Show-Section -Title "Test Section" } | Should -Not -Throw
    }
}

Describe "Show-Property" {
    It "Does not throw on normal input" {
        { Show-Property -Label "Status" -Value "Locked" } | Should -Not -Throw
    }

    It "Handles empty value" {
        { Show-Property -Label "Status" -Value "" } | Should -Not -Throw
    }
}

# =============================================================================
# Mocked function tests
# =============================================================================

Describe "Get-GraphToken" {
    It "Acquires a token via Invoke-RestMethod" {
        Mock Invoke-RestMethod { @{ access_token = "unlock-token" } }
        $token = Get-GraphToken
        $token | Should -Be "unlock-token"
    }
}

Describe "Get-PagedResults" {
    It "Returns results from a single page" {
        Mock Invoke-RestMethod {
            @{ value = @(@{ id = "1" }, @{ id = "2" }) }
        }
        $results = Get-PagedResults -Uri "https://graph.example/v1.0/test" -Token "test"
        $results.Count | Should -Be 2
    }

    It "Follows @odata.nextLink for paged results" {
        $callCount = 0
        Mock Invoke-RestMethod {
            $callCount++
            if ($callCount -eq 1) {
                @{
                    value = @(@{ id = "1" })
                    '@odata.nextLink' = "https://graph.example/v1.0/test?skip=1"
                }
            } else {
                @{ value = @(@{ id = "2" }) }
            }
        }
        $results = Get-PagedResults -Uri "https://graph.example/v1.0/test" -Token "test"
        $results.Count | Should -Be 2
    }
}
