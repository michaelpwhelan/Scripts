# Get-UserQuickStatus

Single-user, single-command lookup for helpdesk tickets. Type a UPN (or display name), get everything you need to work a ticket.

## What It Does

Queries Microsoft Graph for a single user and returns:

- **Identity** - display name, UPN, department, title, manager
- **Account status** - enabled/disabled, sign-in blocked, last interactive sign-in
- **Password** - last changed date, estimated expiry (or "never" if policy disables expiration)
- **MFA** - registered (yes/no), registered methods, default method
- **Licenses** - assigned SKUs with friendly names (e.g. "Office 365 E3" instead of "ENTERPRISEPACK")
- **Groups** - all group memberships, sorted alphabetically
- **Mailbox** - forwarding/auto-reply status

After the colored console summary, a plain-text `--- COPY FOR TICKET ---` block is printed for pasting directly into osTicket.

## Prerequisites

- PowerShell 5.1+
- Entra ID app registration with the following API permissions (application type):
  - `User.Read.All`
  - `UserAuthenticationMethod.Read.All`
  - `AuditLog.Read.All`
  - `GroupMember.Read.All`
  - `MailboxSettings.Read`

## Configuration

Set credentials via environment variables (recommended) or edit the `$Config` block in the script:

```powershell
$env:ENTRA_TENANT_ID     = "your-tenant-id"
$env:ENTRA_CLIENT_ID     = "your-client-id"
$env:ENTRA_CLIENT_SECRET = "your-client-secret"
```

The `$Config.SkuFriendlyNames` hashtable maps SKU part numbers to readable names. Add your tenant's SKUs as needed.

## Usage

```powershell
# Look up by UPN
.\Get-UserQuickStatus.ps1 -UserIdentity "jsmith@contoso.com"

# Look up by display name
.\Get-UserQuickStatus.ps1 -UserIdentity "John Smith"
```

## Output

| Output | Location |
|--------|----------|
| Console summary | Colored sections: IDENTITY, ACCOUNT STATUS, MFA, LICENSES, GROUPS, MAILBOX |
| Clipboard block | Plain-text block after the summary, bounded by `--- COPY FOR TICKET ---` / `--- END COPY ---` |
| CSV | `output\UserQuickStatus_<user>_<timestamp>.csv` |
| Log | `logs\Get-UserQuickStatus_<timestamp>.log` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Completed successfully |
| 1 | Fatal error (user not found, auth failure, etc.) |
