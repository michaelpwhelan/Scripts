# Get-UserDevices

Lists all devices associated with a user from Entra ID and optionally on-prem Active Directory.

## What It Does

- Queries Entra ID for owned and registered devices belonging to a user
- Optionally queries on-prem AD for computers with matching `ManagedBy` attribute
- Merges and deduplicates results across directories
- Shows compliance status, trust type, and device relationship context
- Flags stale devices (inactive beyond configured threshold)
- Exports all device data to a timestamped CSV

## Prerequisites

- PowerShell 5.1+
- ActiveDirectory module (optional — on-prem queries skipped if absent)
- Entra ID app registration with `Device.Read.All` and `User.Read.All` (application) permissions

## Configuration

Set credentials via environment variables (recommended) or edit the `$Config` block:

```powershell
$env:ENTRA_TENANT_ID     = "your-tenant-id"
$env:ENTRA_CLIENT_ID     = "your-client-id"
$env:ENTRA_CLIENT_SECRET = "your-client-secret"
```

`$Config.StaleDaysThreshold` controls how many days of inactivity marks a device as stale (default: 90).

## Usage

```powershell
# List active devices
.\Get-UserDevices.ps1 -UserUPN "john.smith@contoso.com"

# Include stale devices in console output
.\Get-UserDevices.ps1 -UserUPN "jane.doe@contoso.com" -IncludeStale
```

## Output

| Output | Location |
|--------|----------|
| Console summary | Color-coded device list with compliance and stale indicators |
| CSV | `output\Get-UserDevices_<user>_<timestamp>.csv` |
| Log | `logs\Get-UserDevices_<timestamp>.log` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Completed successfully |
| 1 | Fatal error (user not found, auth failure, etc.) |
