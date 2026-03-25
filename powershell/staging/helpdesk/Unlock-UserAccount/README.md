# Unlock-UserAccount

Unlocks a locked-out user account and diagnoses the lockout cause.

## What It Does

- Checks lockout status across all domain controllers
- Unlocks the account in on-prem AD (unless `-DiagnosticOnly` is specified)
- Retrieves recent failed sign-in attempts from Entra ID sign-in logs
- Performs pattern analysis on sign-in failures (top offending apps and source IPs)
- Exports diagnostic data to a timestamped CSV
- Copies a summary block to the clipboard for ticket pasting

## Prerequisites

- PowerShell 5.1+
- ActiveDirectory module (optional — on-prem checks skipped if absent)
- Entra ID app registration with `AuditLog.Read.All` and `User.Read.All` (application) permissions (optional — sign-in diagnostics skipped if not configured)

## Configuration

Set credentials via environment variables (recommended) or edit the `$Config` block:

```powershell
$env:ENTRA_TENANT_ID     = "your-tenant-id"
$env:ENTRA_CLIENT_ID     = "your-client-id"
$env:ENTRA_CLIENT_SECRET = "your-client-secret"
```

`$Config.SignInLogsToShow` controls how many recent failures to display (default: 15).
`$Config.SignInLookbackHours` controls the query window (default: 24).

## Usage

```powershell
# Unlock and show diagnostics
.\Unlock-UserAccount.ps1 -UserPrincipalName "john.smith@contoso.com"

# Diagnostics only (no unlock)
.\Unlock-UserAccount.ps1 -UPN "john.smith@contoso.com" -DiagnosticOnly
```

## Output

| Output | Location |
|--------|----------|
| Console summary | Per-DC lockout status, sign-in failure analysis |
| Clipboard block | Plain-text summary bounded by markers |
| CSV | `output\Unlock-UserAccount_<user>_<timestamp>.csv` |
| Log | `logs\Unlock-UserAccount_<timestamp>.log` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Completed successfully |
| 1 | Fatal error (user not found, auth failure, etc.) |
