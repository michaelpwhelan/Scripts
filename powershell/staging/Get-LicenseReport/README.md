# Get-LicenseReport

Microsoft 365 license consumption report via Microsoft Graph. Shows purchased vs. consumed seats for every SKU with human-readable names, flags SKUs that are low or over capacity, and optionally identifies license waste on disabled accounts.

## Quick Start

```powershell
# Set credentials (one-time, per session)
$env:ENTRA_TENANT_ID     = "your-tenant-id"
$env:ENTRA_CLIENT_ID     = "your-client-id"
$env:ENTRA_CLIENT_SECRET = "your-client-secret"

# Run the report
.\Get-LicenseReport.ps1

# Include per-user detail and waste detection
.\Get-LicenseReport.ps1 -ExportUserDetail
```

## Prerequisites

- PowerShell 5.1+
- No external modules required
- Entra ID app registration with these **application** permissions:
  - `Organization.Read.All` — required for SKU data
  - `User.Read.All` — required only when `-ExportUserDetail` is used
- Admin consent granted for the above permissions

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-ExportUserDetail` | `switch` | Also export per-user license assignments. Enables waste detection (licenses on disabled accounts). |
| `-WarnBelowPct` | `int` | Warn when available seats fall below this percentage. Default: `10`. |
| `-TenantId` | `string` | Entra ID tenant ID. Overrides `$Config.TenantId` and `$env:ENTRA_TENANT_ID`. |
| `-ClientId` | `string` | App registration client ID. Overrides config/env. |
| `-ClientSecret` | `string` | App registration client secret. Overrides config/env. |

## Configuration

### Credentials

Resolved in this order (first non-empty wins):

1. **Parameters** — `-TenantId`, `-ClientId`, `-ClientSecret`
2. **Environment variables** — `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`
3. **Config block** — edit `$Config.TenantId` etc. directly (not recommended for secrets)

### Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `WarnBelowPct` | `10` | Available seat percentage threshold. SKUs below this are flagged `LOW`. SKUs with negative availability are flagged `OVER`. |
| `ExportUserDetail` | `$false` | When enabled, queries all users and their license assignments. Required for waste detection. |
| `LogDir` | `$PSScriptRoot\logs` | Set to `$null` to disable file logging. |
| `OutputDir` | `$PSScriptRoot\output` | Directory for CSV exports. |

### SKU Friendly Names

The `$SkuFriendlyNames` hashtable maps raw `skuPartNumber` values (like `ENTERPRISEPACK`) to readable display names (like `Office 365 E3`). It ships with 35+ common SKU mappings. Unknown SKUs fall back to the raw part number.

To add your tenant's custom or uncommon SKUs, add entries to the hashtable:

```powershell
$SkuFriendlyNames["CONTOSO_CUSTOM_SKU"] = "Contoso Custom License"
```

## What Gets Reported

### SKU Summary (always)

For every subscribed SKU in the tenant:

| Field | Description |
|-------|-------------|
| `SKU` | Raw `skuPartNumber` from Graph API |
| `FriendlyName` | Human-readable name from the lookup table |
| `Status` | Capability status (`Enabled`, `Suspended`, `Warning`, etc.) |
| `Purchased` | Total enabled prepaid units |
| `Consumed` | Currently assigned units |
| `Available` | `Purchased - Consumed` (can be negative if over-assigned) |
| `PctUsed` | Consumption percentage |
| `Warning` | `LOW` if below threshold, `OVER` if negative availability, blank if healthy |

### Per-User Detail (with `-ExportUserDetail`)

For every user in the tenant:

| Field | Description |
|-------|-------------|
| `DisplayName` | User's display name |
| `UserPrincipalName` | UPN |
| `AccountEnabled` | `True` or `False` |
| `LicenseCount` | Number of assigned licenses |
| `Licenses` | Semicolon-separated list of assigned SKU part numbers |
| `IsWaste` | `True` if the account is disabled but still holds licenses |

### Waste Detection

When `-ExportUserDetail` is enabled, the script checks every user for waste: a disabled account (`accountEnabled = false`) that still has one or more licenses assigned. These licenses cost money but serve no purpose.

The console summary shows the total waste count and the per-user CSV has an `IsWaste` column for filtering.

## Usage Examples

```powershell
# Basic SKU summary
.\Get-LicenseReport.ps1

# With waste detection and a stricter warning threshold
.\Get-LicenseReport.ps1 -ExportUserDetail -WarnBelowPct 20

# Override credentials at runtime
.\Get-LicenseReport.ps1 -TenantId "abc-123" -ClientId "def-456" -ClientSecret "secret"
```

## Output

### CSV — SKU Summary

`output\LicenseReport_<yyyyMMdd_HHmmss>.csv`

One row per SKU with all fields from the table above.

### CSV — Per-User Detail

`output\LicenseDetail_Users_<yyyyMMdd_HHmmss>.csv`

One row per user. Only generated when `-ExportUserDetail` is used.

### Console Summary

The console summary includes:

- **SKU capacity table** — formatted table with purchased/consumed/available/used% per SKU, sorted with warnings first
- **Warnings** — count of `OVER` and `LOW` SKUs
- **License waste** — count of disabled accounts holding licenses (when `-ExportUserDetail` is on)
- **Totals** — aggregate purchased/consumed/available across all SKUs

Color coding: red for `OVER` capacity, yellow for `LOW`, white for healthy.

### Log

`logs\Get-LicenseReport_<yyyyMMdd_HHmmss>.log`

## Retry Logic

All Graph API calls use automatic retry with:
- 3 attempts maximum
- `Retry-After` header respected for HTTP 429 (throttling)
- Exponential backoff for HTTP 5xx (server errors)
- Non-retryable errors (401, 403, 404) fail immediately

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Completed successfully |
| `1` | Fatal error (credentials not set, auth failure, API error, etc.) |
