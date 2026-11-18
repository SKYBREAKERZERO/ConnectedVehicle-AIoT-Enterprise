output "secret_arn" {
  description = "OTA authority secret ARN used by the secure delivery process."
  value       = aws_secretsmanager_secret.this.arn
}

output "secret_name" {
  description = "Tenant-specific OTA authority secret name."
  value       = aws_secretsmanager_secret.this.name
}

output "kms_key_arn" {
  description = "Configured KMS key ARN used to encrypt the authority secret."
  value       = var.kms_key_arn
}

output "read_policy_arn" {
  description = "IAM policy ARN to attach to authorized runtime or delivery roles."
  value       = aws_iam_policy.read.arn
}

output "read_policy_json" {
  description = "Rendered secret read policy for review and contract tests."
  value       = aws_iam_policy.read.policy
}