# Find-UserAccount

Unified user search across on-premises Active Directory and Entra ID (Microsoft Graph).

## What It Does

- Searches both on-prem AD and Entra ID with a single query
- Accepts UPN, SamAccountName, display name, or partial match
- Applies wildcards automatically for AD; uses `startsWith` for Entra display-name searches
- Optionally includes disabled accounts
- Deduplicates and standardizes results into PSCustomObject instances
- Exports results to a timestamped CSV

## Prerequisites

- PowerShell 5.1+
- ActiveDirectory module (optional — on-prem queries skipped if absent)
- Entra ID app registration with `User.Read.All` (application) permission

## Configuration

Set credentials via environment variables (recommended) or edit the `$Config` block:

```powershell
$env:ENTRA_TENANT_ID     = "your-tenant-id"
$env:ENTRA_CLIENT_ID     = "your-client-id"
$env:ENTRA_CLIENT_SECRET = "your-client-secret"
```

## Usage

```powershell
# Search by UPN
.\Find-UserAccount.ps1 -Identity "jane.doe@contoso.com"

# Partial name search including disabled accounts
.\Find-UserAccount.ps1 -Identity "Jane" -IncludeDisabled
```

## Output

| Output | Location |
|--------|----------|
| Console summary | Color-coded results from both directories |
| CSV | `output\Find-UserAccount_<timestamp>.csv` |
| Log | `logs\Find-UserAccount_<timestamp>.log` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Completed successfully |
| 1 | Fatal error (auth failure, no results, etc.) |
