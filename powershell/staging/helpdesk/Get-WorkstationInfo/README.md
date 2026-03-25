# Get-WorkstationInfo

Quick workstation diagnostic for "my computer is slow/broken" tickets. Gathers system, hardware, disk, network, security, and update info in one shot.

## What It Does

Queries a local or remote Windows workstation via CIM/WMI and returns:

- **System** - hostname, OS version/build, domain, last boot time, uptime
- **Hardware** - CPU model, total/used/free RAM
- **Disk** - all fixed drives with total/used/free space and percent free (flags low space)
- **Network** - IP addresses, DNS servers, default gateway, DHCP status per adapter
- **Security** - BitLocker status (C: drive), Windows Defender status and last scan date
- **Updates** - last installed update date, pending reboot check

After the colored console summary, a plain-text `--- COPY FOR TICKET ---` block is printed for pasting directly into osTicket.

## Prerequisites

- PowerShell 5.1+
- For remote computers: WinRM must be enabled on the target
- BitLocker status requires admin privileges
- No Graph API or app registration needed (CIM/WMI only)

## Configuration

Edit the `$Config` block in the script to adjust thresholds:

```powershell
DiskWarningPct = 15    # Warn when free space is below this percentage
```

## Usage

```powershell
# Local computer
.\Get-WorkstationInfo.ps1

# Remote workstation
.\Get-WorkstationInfo.ps1 -ComputerName "WS-JSMITH01"
```

If the target is unreachable, the script exits with a clear error message before attempting any queries.

## Output

| Output | Location |
|--------|----------|
| Console summary | Colored sections: SYSTEM, HARDWARE, DISK, NETWORK, SECURITY, UPDATES (with warnings) |
| Clipboard block | Plain-text block bounded by `--- COPY FOR TICKET ---` / `--- END COPY ---` |
| CSV | `output\WorkstationInfo_<hostname>_<timestamp>.csv` |
| Log | `logs\Get-WorkstationInfo_<timestamp>.log` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Completed successfully |
| 1 | Fatal error (target unreachable, WMI failure, etc.) |
