locals {
  tenant_hash   = sha256(var.tenant_id)
  tenant_suffix = substr(local.tenant_hash, 0, 12)
  name_prefix   = "${var.project_name}-${var.environment}-ota-${local.tenant_suffix}"

  artifact_bucket_name = "${local.name_prefix}-firmware"
  campaign_role_name   = "${local.name_prefix}-campaign"

  common_tags = {
    Project     = var.project_name
    Service     = "ota"
    Environment = var.environment
    ManagedBy   = "terraform"
    Owner       = var.owner
    Repository  = "ConnectedVehicle-AIoT-Enterprise"
    TenantHash  = local.tenant_hash
  }
}
