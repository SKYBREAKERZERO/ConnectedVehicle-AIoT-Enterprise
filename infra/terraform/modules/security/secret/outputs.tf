output "secret_id" {
  description = "ID of the platform-managed Secrets Manager secret resource."
  value       = aws_secretsmanager_secret.this.id
}

output "secret_arn" {
  description = "ARN of the platform-managed Secrets Manager secret resource."
  value       = aws_secretsmanager_secret.this.arn
}

output "secret_name" {
  description = "Name of the platform-managed Secrets Manager secret resource."
  value       = aws_secretsmanager_secret.this.name
}

output "kms_key_arn" {
  description = "ARN of the KMS key configured for secret encryption."
  value       = var.kms_key_arn
}

output "recovery_window_in_days" {
  description = "Configured secret recovery window."
  value       = aws_secretsmanager_secret.this.recovery_window_in_days
}