# Reset-UserPassword

Resets a user's password in the appropriate directory (on-prem AD or Entra ID).

## What It Does

- Detects whether a user is synced from on-prem AD or is cloud-only in Entra ID
- Resets the password in the correct directory
- Generates a cryptographically secure temporary password
- Displays the temporary password on screen once (never written to logs or exports)
- Optionally forces password change at next logon
- Writes an audit CSV recording the timestamp, admin, UPN, directory, and change-required flag

## Prerequisites

- PowerShell 5.1+
- ActiveDirectory module (optional — on-prem operations skipped if absent)
- Entra ID app registration with `User.ReadWrite.All` (application) permission

## Configuration

Set credentials via environment variables (recommended) or edit the `$Config` block:

```powershell
$env:ENTRA_TENANT_ID     = "your-tenant-id"
$env:ENTRA_CLIENT_ID     = "your-client-id"
$env:ENTRA_CLIENT_SECRET = "your-client-secret"
```

## Usage

```powershell
# Reset with default 16-character password, force change at next logon
.\Reset-UserPassword.ps1 -UserPrincipalName "jsmith@contoso.com"

# 24-character password, no forced change
.\Reset-UserPassword.ps1 -UPN "jsmith@contoso.com" -PasswordLength 24 -NoChangeRequired
```

## Output

| Output | Location |
|--------|----------|
| Console | Temporary password displayed once |
| Audit CSV | `output\Reset-UserPassword_audit_<timestamp>.csv` |
| Log | `logs\Reset-UserPassword_<date>.log` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Completed successfully |
| 1 | Fatal error (user not found, auth failure, etc.) |
