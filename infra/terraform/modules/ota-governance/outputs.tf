output "deployment_mode" {
  description = "Configured governance execution mode."
  value       = var.deployment_mode
}

output "organizations_management_enabled" {
  description = "Whether Organizations resource management is enabled; not proof of SCP enforcement."
  value       = local.organizations_enabled
}

output "scp_document_json" {
  description = "Generated deny-only SCP document, available even in offline mode."
  value       = local.scp_json

  precondition {
    condition     = length(local.scp_json) <= 5120
    error_message = "The SCP document exceeds this module's 5120-character portability cap."
  }
}

output "scp_policy_id" {
  description = "Terraform-managed SCP ID; null when Organizations management is disabled."
  value       = local.enforcement_enabled ? aws_organizations_policy.ota[0].id : null
}

output "scp_policy_arn" {
  description = "Terraform-managed SCP ARN; null when Organizations management is disabled."
  value       = local.enforcement_enabled ? aws_organizations_policy.ota[0].arn : null
}

output "configured_environment_accounts" {
  description = "Configured environment account mapping; not independently verified in offline mode."

  value = {
    for environment, config in local.environment_configs :
    environment => config.account_id
  }
}

output "configured_existing_ou_ids" {
  description = "Configured existing OU IDs; membership checks run only when management is enabled."

  value = {
    for environment, config in local.existing_ou_configs :
    environment => config.existing_ou_id
  }
}

output "managed_ou_ids" {
  description = "IDs of OUs managed by this module; creating them does not move accounts."

  value = {
    for environment, ou in aws_organizations_organizational_unit.environment :
    environment => ou.id
  }
}

output "scp_attachment_targets" {
  description = "OU or member account IDs targeted by Terraform-managed attachments; not an authorization test result."

  value = {
    for environment, attachment in aws_organizations_policy_attachment.environment :
    environment => attachment.target_id
  }
}

output "protected_resources" {
  description = "Configured resources included in the generated SCP; does not establish resource ownership or effective protection."

  value = {
    firmware_object_arns = local.protected_firmware_object_arns
    firmware_bucket_arns = local.protected_firmware_bucket_arns
    state_bucket_arns    = sort(tolist(var.protected_state_bucket_arns))
    bucket_arns          = local.protected_bucket_arns
    kms_key_arns         = local.protected_kms_key_arns
  }
}
output "governance_stage" {
  value       = var.governance_stage
  description = "Topology-only or enforcement stage; topology alone does not attach any policy."
}

output "attachment_scope" {
  value       = var.attachment_scope
  description = "OU inheritance or explicitly opted-in direct account attachment."
}
output "enforcement_enabled" {
  description = "Whether explicitly opted-in SCP enforcement is enabled."
  value       = local.enforcement_enabled
}
