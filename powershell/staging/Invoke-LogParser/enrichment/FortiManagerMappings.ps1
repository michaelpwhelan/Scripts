# ===============================================================================
# ENRICHMENT DATA - FortiManager Event Action Descriptions
# ===============================================================================

$Script:FortiManagerActionLookup = @{
    "add_device"          = "Device added to FortiManager"
    "del_device"          = "Device removed from FortiManager"
    "install_policy"      = "Policy package installed to device"
    "install_failed"      = "Policy installation failed"
    "login"               = "Administrator login"
    "logout"              = "Administrator logout"
    "edit_policy"         = "Firewall policy modified"
    "add_policy"          = "Firewall policy created"
    "del_policy"          = "Firewall policy deleted"
    "edit_object"         = "Address/service object modified"
    "add_object"          = "Address/service object created"
    "del_object"          = "Address/service object deleted"
    "adom_lock"           = "ADOM locked for editing"
    "adom_unlock"         = "ADOM unlocked"
    "adom_revision"       = "ADOM revision created"
    "config_change"       = "Configuration change committed"
    "ha_failover"         = "HA failover event"
    "ha_sync"             = "HA synchronization event"
    "firmware_upgrade"    = "Firmware upgrade initiated"
    "backup"              = "Configuration backup created"
    "restore"             = "Configuration restored from backup"
    "script_execute"      = "CLI script executed on managed device"
    "approve_workflow"    = "Workflow approval granted"
    "reject_workflow"     = "Workflow approval rejected"
}
