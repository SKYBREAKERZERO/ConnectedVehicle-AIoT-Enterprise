locals {
  tenant_hash = sha256(var.tenant_id)
  name_prefix = "${var.project_name}-${var.environment}"

  secret_name = "/${var.project_name}/${var.environment}/tenants/${local.tenant_hash}/ota/runtime-authority"
  policy_name = "${local.name_prefix}-ota-${local.tenant_hash}-read"

  kms_arn_parts = split(":", var.kms_key_arn)
  kms_region    = try(local.kms_arn_parts[3], "invalid")
  partition     = try(local.kms_arn_parts[1], "aws")
  dns_suffix    = local.partition == "aws-cn" ? "amazonaws.com.cn" : "amazonaws.com"

  kms_via_service = "secretsmanager.${local.kms_region}.${local.dns_suffix}"
}

