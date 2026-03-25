# Repair-Printer

Printer troubleshooting tool that diagnoses and fixes common print spooler issues. Shows before/after status so you can confirm the fix worked.

## What It Does

1. **Diagnose** - lists all printers with their status and pending print jobs
2. **Repair** - stops the Print Spooler service, clears spool files from `C:\Windows\System32\spool\PRINTERS\`, restarts the spooler
3. **Verify** - re-checks printer status and compares before/after
4. **Port test** (optional) - if `-PrinterName` is specified and the printer uses a TCP/IP port, tests network connectivity to the printer's IP

After the colored console summary, a plain-text `--- COPY FOR TICKET ---` block is printed for pasting directly into osTicket.

## Prerequisites

- PowerShell 5.1+
- Admin privileges (required to stop/start the Print Spooler and delete spool files)
- For remote computers: WinRM must be enabled on the target
- No Graph API or app registration needed (local cmdlets only)

## Usage

```powershell
# Diagnose and repair all printers on the local computer
.\Repair-Printer.ps1

# Repair printers on a remote workstation
.\Repair-Printer.ps1 -ComputerName "WS-JSMITH01"

# Repair and test connectivity to a specific printer
.\Repair-Printer.ps1 -ComputerName "WS-JSMITH01" -PrinterName "HP LaserJet 4050"
```

## What the Repair Does

| Step | Action |
|------|--------|
| 1 | `Stop-Service -Name Spooler -Force` |
| 2 | Delete all files in `C:\Windows\System32\spool\PRINTERS\` |
| 3 | `Start-Service -Name Spooler` |

All actions are logged. The before/after printer status is shown so you can confirm jobs were cleared and printers returned to normal.

## Output

| Output | Location |
|--------|----------|
| Console summary | Colored sections: PRINTER STATUS (BEFORE), REPAIR ACTIONS, PRINTER STATUS (AFTER), PORT CONNECTIVITY |
| Clipboard block | Plain-text block bounded by `--- COPY FOR TICKET ---` / `--- END COPY ---` |
| CSV | `output\PrinterRepair_<hostname>_<timestamp>.csv` |
| Log | `logs\Repair-Printer_<timestamp>.log` |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Completed successfully |
| 1 | Fatal error (target unreachable, spooler restart failed, etc.) |
