mock_provider "aws" {}
variables {
  bucket_name = "cv-ota-contract"
  kms_key_arn = "arn:aws:kms:ap-northeast-1:000000000000:key/11111111-1111-1111-1111-111111111111"
}
run "versioned_private_encrypted_firmware" {
  command = plan
  assert {
    condition     = aws_s3_bucket_versioning.this.versioning_configuration[0].status == "Enabled" && aws_s3_bucket_public_access_block.this.block_public_acls && aws_s3_bucket_public_access_block.this.block_public_policy && aws_s3_bucket_public_access_block.this.ignore_public_acls && aws_s3_bucket_public_access_block.this.restrict_public_buckets && !one(aws_s3_bucket_server_side_encryption_configuration.this.rule).bucket_key_enabled && one(aws_s3_bucket_server_side_encryption_configuration.this.rule).apply_server_side_encryption_by_default[0].kms_master_key_id == var.kms_key_arn
    error_message = "Firmware versions must be private and use the explicit object-context KMS key."
  }
  assert {
    condition     = !aws_s3_bucket.this.force_destroy && length(one(aws_s3_bucket_lifecycle_configuration.this.rule).noncurrent_version_expiration) == 0 && length(one(aws_s3_bucket_lifecycle_configuration.this.rule).expiration) == 0
    error_message = "Lifecycle cleanup must not delete completed firmware versions."
  }
}
run "reject_wildcard_encryption" {
  command = plan
  variables { kms_key_arn = "*" }
  expect_failures = [var.kms_key_arn]
}
