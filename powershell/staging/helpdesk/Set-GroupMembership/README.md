# Set-GroupMembership

Adds or removes a user from security groups in on-prem Active Directory or Entra ID.

## What It Does

- Detects whether a group exists in on-prem AD, Entra ID, or both (prefers on-prem for synced groups)
- Supports single operations via parameters or bulk operations via CSV input
- Verifies membership changes after each operation
- Enforces protection on sensitive groups (Domain Admins, etc.) requiring `-Force` to modify
- Honours ShouldProcess (`-WhatIf` / `-Confirm`)
- Exports an audit CSV with all operations and results

## Prerequisites

- PowerShell 5.1+
- ActiveDirectory module (optional — Entra-only mode if absent)
- Entra ID app registration with `GroupMember.ReadWrite.All` and `User.Read.All` (application) permissions

## Configuration

Set credentials via environment variables (recommended) or edit the `$Config` block:

```powershell
$env:ENTRA_TENANT_ID     = "your-tenant-id"
$env:ENTRA_CLIENT_ID     = "your-client-id"
$env:ENTRA_CLIENT_SECRET = "your-client-secret"
```

Protected groups are defined in `$Config.ProtectedGroups`.

## Usage

```powershell
# Add a user to a group
.\Set-GroupMembership.ps1 -UserPrincipalName "jsmith@contoso.com" -GroupName "VPN Users" -Action Add

# Remove from a protected group (requires -Force)
.\Set-GroupMembership.ps1 -UPN "jsmith@contoso.com" -GroupName "Domain Admins" -Action Remove -Force

# Bulk operations from CSV
.\Set-GroupMembership.ps1 -InputCSV "C:\temp\group_changes.csv"
```

CSV format: `UserPrincipalName,GroupName,Action`

## Output

| Output | Location |
|--------|----------|
| Console summary | Operation results with success/fail counts |
| Audit CSV | `output\Set-GroupMembership_audit_<timestamp>.csv` |
| Log | `logs\Set-GroupMembership_<timestamp>.log` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All operations succeeded |
| 1 | One or more operations failed |
