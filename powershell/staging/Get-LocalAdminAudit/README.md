# Get-LocalAdminAudit

Audits privileged local group membership across Windows servers. Checks multiple groups, detects unexpected members, identifies orphaned SIDs, monitors the built-in Administrator password age, and can compare against a previous baseline to track changes over time.

## Quick Start

```powershell
# Audit the local machine
.\Get-LocalAdminAudit.ps1

# Audit specific servers
.\Get-LocalAdminAudit.ps1 -Servers "SRV01","SRV02","SRV03"

# Audit from a server list with HTML report
.\Get-LocalAdminAudit.ps1 -ServerFile ".\servers.txt" -GenerateHtml

# Compare against a previous audit
.\Get-LocalAdminAudit.ps1 -BaselineCsvPath ".\output\LocalAdminAudit_20260301_090000.csv"
```

## Prerequisites

- PowerShell 5.1+
- No external modules required
- Admin access to target servers (local or via WinRM)
- WinRM enabled on remote targets (`Enable-PSRemoting` on each server, or via GPO)

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Servers` | `string[]` | One or more server names to audit. Overrides `$Config.Servers`. |
| `-ServerFile` | `string` | Path to a text file with one server per line. Lines starting with `#` are ignored. Overrides `$Config.ServerFile`. |
| `-BaselineCsvPath` | `string` | Path to a previous audit CSV for baseline comparison. Overrides `$Config.BaselineCsvPath`. |
| `-GenerateHtml` | `switch` | Produce a self-contained HTML report alongside the CSV. |

## Configuration

### Targets

Servers can be specified three ways (checked in this order):

1. **`-Servers` parameter** — highest priority
2. **`$Config.Servers` inline array** — edit in the script
3. **`$Config.ServerFile` text file** — one hostname per line, `#` comments supported

The default is `@("localhost")` so the script works out of the box against the local machine.

### Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `AuditGroups` | `@("Administrators", "Remote Desktop Users")` | Local groups to enumerate on each server. Add any group name (e.g., `"Hyper-V Administrators"`, `"Remote Management Users"`). |
| `ExpectedAdmins` | `@("Administrator", "Domain Admins")` | Short names (no domain prefix) of members that are expected. Members not in this list are flagged as unexpected. |
| `MaxAdminPwdAgeDays` | `180` | Warn if the built-in Administrator account (SID `*-500`) password is older than this. Set to `0` to skip. |
| `BaselineCsvPath` | `$null` | Path to a previous audit CSV. When set, the script diffs current results against the baseline and adds `NEW`/`REMOVED`/`UNCHANGED` status. |
| `GenerateHtml` | `$false` | Produce an HTML report alongside the CSV. |
| `LogDir` | `$PSScriptRoot\logs` | Set to `$null` to disable. |
| `OutputDir` | `$PSScriptRoot\output` | Directory for exports. |

### Expected Admins Allow-List

The `ExpectedAdmins` array is matched against the **short name** of each group member (domain prefix stripped). This means `DOMAIN\Domain Admins` matches the entry `"Domain Admins"`.

Customize for your organization:

```powershell
$Config.ExpectedAdmins = @(
    "Administrator",
    "Domain Admins",
    "IT-ServerAdmins",
    "svc_backup"
)
```

## What Gets Audited

### Per-Server Checks

The script connects to each server via `Invoke-Command` and runs all checks in a single remote session:

1. **Group membership enumeration** — for each group in `AuditGroups`, retrieves all members using `Get-LocalGroupMember`
2. **Orphaned SID detection** — members whose `Name` appears as a raw SID (e.g., `S-1-5-21-...`) indicate a deleted domain account that still has local group membership
3. **Allow-list comparison** — each member's short name is checked against `ExpectedAdmins`; non-matches are flagged as unexpected
4. **Built-in Administrator password age** — queries `Get-LocalUser` for the account with SID ending in `-500` and calculates days since `PasswordLastSet`

### Baseline Comparison

When `BaselineCsvPath` is provided, the script loads the previous CSV and diffs by the composite key `Server|Group|Name`:

| Status | Meaning |
|--------|---------|
| `NEW` | Member exists now but was not in the baseline |
| `REMOVED` | Member was in the baseline but no longer exists |
| `UNCHANGED` | Member exists in both |

Removed entries are included in the CSV output with `ChangeStatus = REMOVED` so the full picture is in one file. The console summary highlights additions and removals.

### Per-Row Output Fields

| Column | Description |
|--------|-------------|
| `Server` | Target server hostname |
| `Group` | Local group name |
| `Name` | Member name (e.g., `DOMAIN\jsmith` or a raw SID) |
| `ObjectClass` | `User`, `Group`, or `Error` |
| `PrincipalSource` | `ActiveDirectory`, `Local`, or `MicrosoftAccount` |
| `SID` | Full SID of the member |
| `IsUnexpected` | `True` if not in the allow-list |
| `IsOrphanedSID` | `True` if the name is an unresolved SID |
| `AdminPwdAgeDays` | Days since the built-in Administrator password was last changed (per-server) |
| `ChangeStatus` | `NEW`, `REMOVED`, or `UNCHANGED` (only present when baseline is used) |

## Usage Examples

```powershell
# Monthly audit of all domain controllers
.\Get-LocalAdminAudit.ps1 -ServerFile ".\dc-list.txt" -GenerateHtml

# Audit multiple groups including Hyper-V admins
# (edit $Config.AuditGroups to include "Hyper-V Administrators")
.\Get-LocalAdminAudit.ps1 -Servers "HV01","HV02"

# Compliance check: compare against last month's baseline
.\Get-LocalAdminAudit.ps1 -ServerFile ".\servers.txt" \
    -BaselineCsvPath ".\output\LocalAdminAudit_20260201_090000.csv" \
    -GenerateHtml

# Quick local check
.\Get-LocalAdminAudit.ps1
```

## Output

### CSV

`output\LocalAdminAudit_<yyyyMMdd_HHmmss>.csv`

One row per member per group per server. When baseline comparison is active, removed entries are appended with `ChangeStatus = REMOVED`.

### HTML Report

`output\LocalAdminAudit_<yyyyMMdd_HHmmss>.html`

Self-contained HTML with:
- Summary cards (servers, total members, unexpected, orphaned SIDs)
- Full results table with row highlighting (red = unexpected, yellow = orphaned, gray = error)
- Baseline change column when comparison is active

### Console Summary

Sections:
- **Unexpected members** — grouped by server/group, shown in red
- **Orphaned SIDs** — server, group, and raw SID
- **Admin password age warnings** — servers exceeding the threshold
- **Baseline changes** — `+ NEW` and `- REMOVED` entries (when baseline is used)
- **Per-server counts** — total/expected/unexpected/orphaned per server, green for clean, red for flagged
- **Totals** — aggregate counts

### Log

`logs\Get-LocalAdminAudit_<yyyyMMdd_HHmmss>.log`

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Completed successfully, no unexpected members or orphaned SIDs |
| `1` | Completed but found unexpected members or orphaned SIDs (or fatal error) |

The non-zero exit on findings is intentional — it allows the script to be used in CI/compliance pipelines where unexpected local admins should fail a check.

## Security Considerations

- The script runs `Invoke-Command` to remote servers, which requires WinRM and admin credentials
- No credentials are stored or transmitted by the script itself — WinRM handles authentication
- The `ExpectedAdmins` list should be reviewed regularly as team membership changes
- Orphaned SIDs often indicate incomplete offboarding — investigate and clean up
