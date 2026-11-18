output "state_bucket_name" {
  description = "Dedicated Terraform state bucket name."
  value       = aws_s3_bucket.state.id

  depends_on = [
    aws_s3_bucket_versioning.state,
    aws_s3_bucket_public_access_block.state,
    aws_s3_bucket_ownership_controls.state,
    aws_s3_bucket_server_side_encryption_configuration.state,
    aws_s3_bucket_policy.state,
  ]
}

output "state_bucket_arn" {
  description = "Dedicated Terraform state bucket ARN."
  value       = aws_s3_bucket.state.arn
}

output "state_kms_key_arn" {
  description = "KMS key ARN required by the S3 backend configuration."
  value       = aws_kms_key.state.arn
}

output "state_kms_alias_name" {
  description = "Human-readable alias for the state encryption key."
  value       = aws_kms_alias.state.name
}

output "state_bucket_versioning_status" {
  description = "Versioning status of the Terraform state bucket."
  value       = aws_s3_bucket_versioning.state.versioning_configuration[0].status
}

output "aws_region" {
  description = "Region to configure in the LocalStack S3 backend."
  value       = var.aws_region
}

output "aws_endpoint_url" {
  description = "LocalStack endpoint to configure separately in the S3 backend."
  value       = var.aws_endpoint_url
}