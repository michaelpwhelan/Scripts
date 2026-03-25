# Test-OffboardComplete

Verification checklist for offboarded users. Runs pass/fail/warn checks against Entra ID to confirm the user has been fully cleaned up.

## What It Does

Takes a UPN and checks:

| # | Check | Status |
|---|-------|--------|
| 1 | Entra ID account exists (must exist to verify) | PASS / FAIL |
| 2 | Account is disabled | PASS / FAIL |
| 3 | Sign-in is blocked | PASS / FAIL |
| 4 | M365 licenses removed (all) | PASS / FAIL |
| 5 | Removed from non-default groups | PASS / FAIL |
| 6 | Refresh tokens revoked | PASS / FAIL |
| 7 | Mail forwarding set | PASS / WARN (may be intentional) |
| 8 | Shared mailbox conversion | PASS / WARN |

After the colored checklist, a plain-text `--- COPY FOR TICKET ---` block is printed for pasting directly into osTicket.

## Prerequisites

- PowerShell 5.1+
- Entra ID app registration with the following API permissions (application type):
  - `User.Read.All`
  - `UserAuthenticationMethod.Read.All`
  - `AuditLog.Read.All`
  - `GroupMember.Read.All`
  - `MailboxSettings.Read`

## Configuration

Set credentials via environment variables (recommended) or edit the `$Config` block:

```powershell
$env:ENTRA_TENANT_ID     = "your-tenant-id"
$env:ENTRA_CLIENT_ID     = "your-client-id"
$env:ENTRA_CLIENT_SECRET = "your-client-secret"
```

Edit the default groups list in `$Config` to match groups that are OK to remain after offboarding:

```powershell
DefaultGroups = @("Domain Users")   # groups OK to remain after offboard
```

Any group memberships *not* in this list will trigger a FAIL.

## Usage

```powershell
# Check an offboarded user
.\Test-OffboardComplete.ps1 -UserIdentity "jsmith@contoso.com"

# Run with default config (edit $Config.UserIdentity first)
.\Test-OffboardComplete.ps1
```

## Output

| Output | Location |
|--------|----------|
| Console summary | Colored checklist with `[PASS]` / `[FAIL]` / `[WARN]` markers and totals |
| Clipboard block | Plain-text block bounded by `--- COPY FOR TICKET ---` / `--- END COPY ---` |
| CSV | `output\OffboardCheck_<user>_<timestamp>.csv` |
| Log | `logs\Test-OffboardComplete_<timestamp>.log` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed (warnings are OK) |
| 1 | One or more checks failed, or fatal error |
