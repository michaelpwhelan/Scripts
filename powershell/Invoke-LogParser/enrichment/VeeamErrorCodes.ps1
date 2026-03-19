# ===============================================================================
# ENRICHMENT DATA - Veeam Backup & Replication Error Codes
# ===============================================================================

$Script:VeeamErrorCodes = @{
    # VSS / Snapshot Errors
    "VSS_E_WRITERERROR_TIMEOUT"         = @{ Description = "VSS writer timed out during snapshot creation"; Remediation = "Check VSS writer status with 'vssadmin list writers'. Restart the affected VSS writer service. KB: https://www.veeam.com/kb1058" }
    "VSS_E_WRITERERROR_NONRETRYABLE"    = @{ Description = "VSS writer encountered a non-retryable error"; Remediation = "Identify the failed writer with 'vssadmin list writers' and restart its service. KB: https://www.veeam.com/kb1058" }
    "VSS_E_PROVIDER_VETO"              = @{ Description = "VSS provider vetoed the shadow copy creation"; Remediation = "Check disk space on source volumes. Verify no other backup software holds VSS. KB: https://www.veeam.com/kb1058" }
    "VSS_SNAPSHOT_CREATION_FAILED"      = @{ Description = "Failed to create VSS snapshot on guest VM"; Remediation = "Verify VMware Tools or Hyper-V Integration Services are current. Check guest VSS writer health. KB: https://www.veeam.com/kb1058" }
    "VSS_SNAPSHOT_MERGE_FAILED"         = @{ Description = "VM snapshot consolidation/merge failed"; Remediation = "Manually consolidate snapshots in vSphere. Check for locked VMDK files. KB: https://www.veeam.com/kb1714" }

    # Repository / Storage Errors
    "REPO_INSUFFICIENT_SPACE"           = @{ Description = "Backup repository has insufficient free space"; Remediation = "Free space on repository, add capacity, or adjust retention policy. KB: https://www.veeam.com/kb1277" }
    "REPO_ACCESS_DENIED"               = @{ Description = "Access denied to backup repository path"; Remediation = "Verify service account permissions on repository. Check NTFS and share permissions. KB: https://www.veeam.com/kb1intl" }
    "REPO_FILE_LOCKED"                 = @{ Description = "Backup file locked by another process"; Remediation = "Check for other Veeam jobs or antivirus scanning the repository. Exclude Veeam paths from AV. KB: https://www.veeam.com/kb1999" }

    # Proxy / Transport Errors
    "PROXY_CONNECTION_FAILED"           = @{ Description = "Failed to connect to backup proxy server"; Remediation = "Verify proxy is online, check firewall rules (TCP 6160/6162), and validate credentials. KB: https://www.veeam.com/kb1855" }
    "PROXY_TIMEOUT"                    = @{ Description = "Backup proxy connection timed out"; Remediation = "Check network connectivity to proxy. Increase timeout in job advanced settings. KB: https://www.veeam.com/kb1855" }
    "TRANSPORT_MODE_FALLBACK"           = @{ Description = "Transport mode fell back from Direct SAN/HotAdd to Network (NBD)"; Remediation = "Verify SAN connectivity or HotAdd configuration on proxy. Performance may be degraded. KB: https://www.veeam.com/kb1901" }

    # VM Processing Errors
    "VM_LOCKED"                        = @{ Description = "VM locked by another task or backup process"; Remediation = "Wait for concurrent operations to finish. Check for stale snapshots or running tasks on the VM. KB: https://www.veeam.com/kb1714" }
    "CBT_ERROR"                        = @{ Description = "Changed Block Tracking error - CBT data inconsistent"; Remediation = "Reset CBT on the VM: disable/enable CBT or create and delete a snapshot. KB: https://www.veeam.com/kb1940" }
    "CBT_DISABLED"                     = @{ Description = "Changed Block Tracking is disabled on the VM"; Remediation = "Enable CBT in VM settings. Veeam requires CBT for incremental backups. KB: https://www.veeam.com/kb1940" }
    "VM_NOT_FOUND"                     = @{ Description = "VM specified in job no longer exists in inventory"; Remediation = "Update the backup job to remove or replace the missing VM reference." }

    # Network / Communication Errors
    "NETWORK_TIMEOUT"                  = @{ Description = "Network operation timed out during data transfer"; Remediation = "Check network throughput between source, proxy, and repository. Look for packet loss or high latency." }
    "AUTH_FAILURE"                     = @{ Description = "Authentication failed to target host or resource"; Remediation = "Verify credentials in Veeam credential manager. Check for expired passwords or account lockout." }
    "SSL_CERTIFICATE_ERROR"            = @{ Description = "SSL/TLS certificate validation failed"; Remediation = "Update or trust the target certificate. Check for expired or self-signed certificates." }

    # Application-Aware Processing Errors
    "SQL_LOG_TRUNCATION_FAILED"        = @{ Description = "Failed to truncate SQL Server transaction logs"; Remediation = "Verify SQL VSS writer is healthy. Check SQL permissions for the service account. KB: https://www.veeam.com/kb1885" }
    "EXCHANGE_LOG_TRUNCATION_FAILED"   = @{ Description = "Failed to truncate Exchange transaction logs"; Remediation = "Verify Exchange VSS writer is healthy. Check DAG status if applicable. KB: https://www.veeam.com/kb1885" }
    "APP_AWARE_FAILED"                = @{ Description = "Application-aware processing failed inside guest"; Remediation = "Check guest OS credentials, verify VSS writers, and ensure Veeam guest helper can deploy. KB: https://www.veeam.com/kb1885" }

    # Tape / Archive Errors
    "TAPE_DRIVE_NOT_AVAILABLE"         = @{ Description = "Tape drive is not available or offline"; Remediation = "Check physical tape drive status. Verify tape server connectivity and driver installation." }
    "TAPE_MEDIA_ERROR"                = @{ Description = "Tape media read/write error"; Remediation = "Replace the tape cartridge. Run cleaning tape if errors persist across cartridges." }

    # General / Catch-all
    "TASK_ABORTED"                    = @{ Description = "Backup task was manually aborted or terminated"; Remediation = "Job was stopped by an administrator or by a timeout policy. Review job schedule and resource allocation." }
}

# Helper function to look up Veeam error description and remediation
function Get-VeeamErrorDescription {
    param(
        [Parameter(Mandatory)]
        [string]$ErrorCode
    )

    if ($Script:VeeamErrorCodes.ContainsKey($ErrorCode)) {
        return $Script:VeeamErrorCodes[$ErrorCode]
    }

    # Try partial match against error code keys
    foreach ($key in $Script:VeeamErrorCodes.Keys) {
        if ($ErrorCode -like "*$key*") {
            return $Script:VeeamErrorCodes[$key]
        }
    }

    return $null
}
