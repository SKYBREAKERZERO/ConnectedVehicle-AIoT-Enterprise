output "key_id" {
  description = "ID of the platform-managed KMS key."
  value       = aws_kms_key.this.key_id
}

output "key_arn" {
  description = "ARN of the platform-managed KMS key."
  value       = aws_kms_key.this.arn
}

output "alias_name" {
  description = "Stable alias of the platform-managed KMS key."
  value       = aws_kms_alias.this.name
}

output "alias_arn" {
  description = "ARN of the platform-managed KMS alias."
  value       = aws_kms_alias.this.arn
}

output "enable_key_rotation" {
  description = "Whether automatic key rotation is enabled."
  value       = aws_kms_key.this.enable_key_rotation
}

output "deletion_window_in_days" {
  description = "Configured waiting period before scheduled KMS key deletion."
  value       = aws_kms_key.this.deletion_window_in_days
}