output "artifact_bucket_name" {
  description = "OTA firmware bucket name."
  value       = module.artifact_bucket.bucket_name
}

output "artifact_bucket_arn" {
  description = "OTA firmware bucket ARN."
  value       = module.artifact_bucket.bucket_arn
}

output "artifact_kms_key_arn" {
  description = "KMS key used to encrypt OTA firmware."
  value       = module.artifact_kms.key_arn
}

output "authority_secret_name" {
  description = "Tenant OTA authority secret name."
  value       = module.ota_authority.secret_name
}

output "authority_secret_arn" {
  description = "Tenant OTA authority secret ARN."
  value       = module.ota_authority.secret_arn
}

output "authority_kms_key_arn" {
  description = "KMS key used to encrypt the OTA authority secret."
  value       = module.authority_kms.key_arn
}

output "campaign_runtime_role_name" {
  description = "Dedicated Campaign Dispatcher runtime role name."
  value       = module.campaign_runtime.role_name
}

output "campaign_runtime_role_arn" {
  description = "Dedicated Campaign Dispatcher runtime role ARN."
  value       = module.campaign_runtime.role_arn
}

output "api_runtime_role_name" {
  description = "Existing API runtime role receiving OTA read policies."
  value       = var.api_runtime_role_name

  depends_on = [
    aws_iam_role_policy_attachment.api_read,
  ]
}

output "runtime_read_policy_arns" {
  description = "Managed read policies for the API runtime (legacy output name)."

  value = {
    database  = module.database_read_policy.policy_arn
    authority = module.ota_authority.read_policy_arn
    artifact  = module.artifact_policy.read_policy_arn
  }
}
output "campaign_read_policy_arns" {
  description = "Campaign read policies, with an isolated database credential policy."
  value       = module.campaign_runtime.attached_policy_arns
}
