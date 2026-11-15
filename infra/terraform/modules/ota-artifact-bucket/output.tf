output "bucket_name" {
  description = "OTA firmware bucket name, available after storage protections are configured."
  value       = aws_s3_bucket.this.id

  depends_on = [
    aws_s3_bucket_versioning.this,
    aws_s3_bucket_public_access_block.this,
    aws_s3_bucket_ownership_controls.this,
    aws_s3_bucket_server_side_encryption_configuration.this,
  ]
}

output "bucket_arn" {
  description = "OTA firmware bucket ARN used to construct scoped IAM policies."
  value       = aws_s3_bucket.this.arn
}

output "kms_key_arn" {
  description = "Configured KMS key ARN used for default firmware encryption."
  value       = var.kms_key_arn
}

output "versioning_status" {
  description = "Configured versioning status of the OTA firmware bucket."
  value       = aws_s3_bucket_versioning.this.versioning_configuration[0].status
}