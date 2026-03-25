# Rename-ManagedComputer

A superpowered `Rename-Computer` with pre-flight safety checks. Renames managed computers using serial-number-based naming (prefix + BIOS serial) or an explicit name. Works at any organization -- configure via JSON config file, not source code.

## Quick Start

```powershell
# Generate a config file for your org (one-time setup)
.\Rename-ManagedComputer.ps1 -GenerateConfig

# Dry run (default) -- shows what would happen, no changes
.\Rename-ManagedComputer.ps1 -ComputerName "CUAPA1B2C3D4"

# Execute the rename (serial-based)
.\Rename-ManagedComputer.ps1 -ComputerName "CUAPA1B2C3D4" -Execute

# Execute with an explicit name
.\Rename-ManagedComputer.ps1 -ComputerName "OLDPC01" -NewName "NEWPC01" -Execute
```

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-ComputerName` | No | Target hostname. Defaults to localhost. Remote requires WinRM. |
| `-NewName` | No | Explicit new name -- bypasses serial lookup. Still validated and collision-checked. |
| `-Prefix` | No | Override config prefix for serial-based naming. Ignored with `-NewName`. |
| `-Execute` | No | Actually perform the rename. Without it, dry run only. |
| `-Force` | No | Skip the "Type YES" confirmation prompt. For automation. |
| `-SkipADCheck` | No | Skip the AD name collision check. |
| `-SkipEntraCheck` | No | Skip the Entra ID name collision check. |
| `-ConfigFile` | No | Path to JSON config file. Default: `config.json` in script directory. |
| `-GenerateConfig` | No | Create a template `config.json` and exit. |
| `-DomainCredential` | No | PSCredential for hybrid/AD-joined rename. Prompted if needed. |
| `-TenantId` | No | Entra ID tenant ID (overrides config/env). |
| `-ClientId` | No | Entra ID client ID (overrides config/env). |
| `-ClientSecret` | No | Entra ID client secret (overrides config/env). |
| `-LogDir` | No | Log directory (overrides config). |
| `-OutputDir` | No | CSV output directory (overrides config). |

## Pre-Flight Checks

| # | Check | PASS | FAIL | WARN | SKIP |
|---|-------|------|------|------|------|
| 1 | Running elevated | Admin (local) or remote via WinRM | Not elevated | -- | -- |
| 2 | Serial number retrieved | Got serial from BIOS | CIM query failed | -- | `-NewName` used |
| 3 | Serial number valid | Not a placeholder | Known placeholder | -- | `-NewName` used |
| 4 | Target name built/valid | Valid 1-15 char name | Empty or too long | Truncated or sanitized | -- |
| 5 | Old name pattern detected | Matches `OldNamePattern` | -- | Doesn't match | No pattern configured |
| 6 | Not already renamed | Current differs from target | No target name | Already correct | -- |
| 7 | Join type detected | Hybrid/AD/Entra recognized | -- | Workgroup | -- |
| 8 | No AD name collision | No existing object | Object exists | AD module unavailable | `-SkipADCheck` |
| 9 | No Entra ID name collision | No existing device | Device exists | Graph not configured | `-SkipEntraCheck` |

Rename is blocked if any check is FAIL. Skipped if check 6 is WARN (already correct).

## Configuration

Run `.\Rename-ManagedComputer.ps1 -GenerateConfig` to create a template `config.json`:

```json
{
    "Prefix": "",
    "MaxLength": 15,
    "OldNamePattern": "",
    "InvalidSerials": [
        "To Be Filled By O.E.M.",
        "Default string",
        "System Serial Number",
        "None", "N/A",
        "Chassis Serial Number"
    ],
    "GraphApiVersion": "v1.0",
    "EntraId": {
        "TenantId": "",
        "ClientId": "",
        "ClientSecret": ""
    },
    "LogDir": ".\\logs",
    "OutputDir": ".\\output"
}
```

### Config resolution order (highest wins):

1. **Parameters** -- one-off overrides at the command line
2. **Config file** -- JSON file for org-specific defaults
3. **Environment variables** -- for secrets (`ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`)
4. **Built-in defaults** -- script works out of the box with no config file

### Key settings

- **Prefix** -- String prepended to serial number (e.g., `CU` produces `CU5CG1234ABC`)
- **MaxLength** -- NetBIOS name limit (default: `15`)
- **OldNamePattern** -- Regex to identify machines that need renaming (e.g., `^CUAP`). Leave empty to skip this check.
- **InvalidSerials** -- BIOS strings that indicate a missing/placeholder serial
- **GraphApiVersion** -- Microsoft Graph API version (`v1.0` or `beta`). Default: `v1.0`

### Graph API (Optional)

The Entra ID collision check requires an app registration with `Device.Read.All`. Set credentials in the config file, via environment variables, or as parameters:

```powershell
$env:ENTRA_TENANT_ID     = "your-tenant-id"
$env:ENTRA_CLIENT_ID     = "your-client-id"
$env:ENTRA_CLIENT_SECRET = "your-client-secret"
```

## Hybrid AD-Joined Devices

For hybrid or AD-joined devices, the script prompts for domain credentials (via `Get-Credential`) when `-Execute` is used. Pass `-DomainCredential` to provide credentials non-interactively.

## Remote Execution

Requires WinRM enabled on the target. The script uses `Invoke-Command` for remote CIM queries, `dsregcmd`, and `Rename-Computer`. AD and Entra ID collision checks always run locally.

## Output

- **Console** -- Color-coded summary with discovery info, checklist, and clipboard block
- **Clipboard** -- Ticket text automatically copied (when `Set-Clipboard` is available)
- **Log** -- `logs\Rename-ManagedComputer_<timestamp>.log`
- **CSV** -- `output\RenameComputer_<hostname>_<timestamp>.csv`

## Reliability Features

- **Automatic retry** -- Network operations (Graph API, WinRM ping) retry up to 3 times with exponential backoff
- **Token caching** -- Graph API tokens are cached and reused until expiry (with 5-minute safety margin)
- **Config validation** -- Malformed JSON, out-of-range values, and missing config files produce warnings instead of crashes
- **Input sanitization** -- OData filter values are escaped to prevent query injection; TenantId is validated as a GUID

## Running Tests

Requires [Pester v5+](https://pester.dev/):

```powershell
Invoke-Pester ./Rename-ManagedComputer.Tests.ps1
```

## Important Notes

- **Dry run by default** -- No changes without `-Execute`
- **No auto-reboot** -- Displays a reboot warning; coordinate with the user
- **Intune sync** -- After rename + reboot, Intune picks up the new hostname within ~8 hours
- **PowerShell 5.1+** -- Compatible with Windows PowerShell and PowerShell 7
