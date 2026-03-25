# Test-OnboardComplete

Verification checklist for newly onboarded users. Runs pass/fail/warn checks against Entra ID to confirm provisioning is complete.

## What It Does

Takes a UPN and checks:

| # | Check | Status |
|---|-------|--------|
| 1 | Entra ID account exists | PASS / FAIL |
| 2 | Account is enabled | PASS / FAIL |
| 3 | Sign-in not blocked | PASS / FAIL |
| 4 | Required group memberships present | PASS / FAIL (per group) |
| 5 | Required M365 licenses assigned | PASS / FAIL (per license) |
| 6 | Mailbox provisioned | PASS / FAIL |
| 7 | MFA registered | PASS / WARN (grace period) |
| 8 | Has signed in at least once | PASS / WARN |

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

Edit the requirements in `$Config` to match your onboarding standards:

```powershell
RequiredGroups   = @("All Staff")           # groups the user must be in
RequiredLicenses = @("ENTERPRISEPACK")      # required SKU part numbers
```

## Usage

```powershell
# Check a newly onboarded user
.\Test-OnboardComplete.ps1 -UserIdentity "jsmith@contoso.com"

# Run with default config (edit $Config.UserIdentity first)
.\Test-OnboardComplete.ps1
```

## Output

| Output | Location |
|--------|----------|
| Console summary | Colored checklist with `[PASS]` / `[FAIL]` / `[WARN]` markers and totals |
| Clipboard block | Plain-text block bounded by `--- COPY FOR TICKET ---` / `--- END COPY ---` |
| CSV | `output\OnboardCheck_<user>_<timestamp>.csv` |
| Log | `logs\Test-OnboardComplete_<timestamp>.log` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed (warnings are OK) |
| 1 | One or more checks failed, or fatal error |
