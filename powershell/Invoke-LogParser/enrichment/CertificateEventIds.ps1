# ===============================================================================
# ENRICHMENT DATA - Windows Certificate Services Event IDs
# ===============================================================================

$Script:CertificateEventLookup = @{
    # Certificate Expiration Warnings
    1001    = "Certificate expiration warning - 90 days"
    1002    = "Certificate expiration warning - 30 days"
    1003    = "Certificate expired"

    # AD Certificate Services Events (4868-4898)
    4868    = "Certificate Services: certificate request received"
    4869    = "Certificate Services: certificate request resubmitted"
    4870    = "Certificate Services: certificate revoked"
    4871    = "Certificate Services: certificate renewal request received"
    4872    = "Certificate Services: certificate issued"
    4873    = "Certificate Services: certificate request extension processed"
    4874    = "Certificate Services: certificate request attributes updated"
    4875    = "Certificate Services: certificate request shutdown"
    4876    = "Certificate Services: backup started"
    4877    = "Certificate Services: backup completed"
    4878    = "Certificate Services: restore started"
    4879    = "Certificate Services: restore completed"
    4880    = "Certificate Services: started"
    4881    = "Certificate Services: stopped"
    4882    = "Certificate Services: security permissions changed"
    4883    = "Certificate Services: retrieved archived key"
    4884    = "Certificate Services: imported certificate to database"
    4885    = "Certificate Services: audit filter changed"
    4886    = "Certificate Services: certificate request received"
    4887    = "Certificate Services: certificate issued and approved"
    4888    = "Certificate Services: certificate request denied"

    # Additional Certificate Events
    4889    = "Certificate Services: certificate request set to pending"
    4890    = "Certificate Services: certificate manager settings changed"
    4891    = "Certificate Services: configuration entry changed"
    4892    = "Certificate Services: property changed"
    4893    = "Certificate Services: key archived"
    4894    = "Certificate Services: key imported"
    4895    = "Certificate Services: CA certificate published to Active Directory"
    4896    = "Certificate Services: rows deleted from certificate database"
    4897    = "Certificate Services: role separation enabled"
    4898    = "Certificate Services: template loaded"

    # CAPI2 / Certificate Validation Events
    11      = "CAPI2: Certificate chain built successfully"
    30      = "CAPI2: Certificate verification failure"
    40      = "CAPI2: Certificate revocation check"
    41      = "CAPI2: CRL retrieval failure"
    42      = "CAPI2: OCSP response received"
    50      = "CAPI2: Certificate trust decision made"
    53      = "CAPI2: Certificate chain policy error"
    70      = "CAPI2: Certificate auto-enrollment started"
    71      = "CAPI2: Certificate auto-enrollment completed"
    72      = "CAPI2: Certificate auto-enrollment failed"
}

# Helper function to look up certificate event description
function Get-CertEventDescription {
    param(
        [Parameter(Mandatory)]
        [int]$EventId
    )

    if ($Script:CertificateEventLookup.ContainsKey($EventId)) {
        return $Script:CertificateEventLookup[$EventId]
    }

    return $null
}
