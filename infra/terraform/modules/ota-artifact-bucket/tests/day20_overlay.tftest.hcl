mock_provider "aws" {}

variables {
  bucket_name = "cv-ota-firmware-contract-123"
  kms_key_arn = "arn:aws:kms:ap-northeast-1:111111111111:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
}

run "bucket_is_private_versioned_kms_encrypted_and_destroy_guarded" {
  command = plan

  assert {
    condition     = aws_s3_bucket.this.force_destroy == false
    error_message = "OTA firmware bucket must not permit force-destroy."
  }
  assert {
    condition     = aws_s3_bucket_versioning.this.versioning_configuration[0].status == "Enabled"
    error_message = "OTA firmware must have immutable version identifiers."
  }
  assert {
    condition = (
      aws_s3_bucket_public_access_block.this.block_public_acls &&
      aws_s3_bucket_public_access_block.this.ignore_public_acls &&
      aws_s3_bucket_public_access_block.this.block_public_policy &&
      aws_s3_bucket_public_access_block.this.restrict_public_buckets
    )
    error_message = "All four S3 public access protections must be enabled."
  }
  assert {
    condition     = aws_s3_bucket_ownership_controls.this.rule[0].object_ownership == "BucketOwnerEnforced"
    error_message = "ACL ownership must be disabled."
  }
  assert {
    condition = (
      one(aws_s3_bucket_server_side_encryption_configuration.this.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms" &&
      one(aws_s3_bucket_server_side_encryption_configuration.this.rule).apply_server_side_encryption_by_default[0].kms_master_key_id == var.kms_key_arn
    )
    error_message = "Default encryption must use the configured customer-managed KMS key."
  }
}

run "reject_invalid_bucket_name" {
  command = plan
  variables { bucket_name = "UPPERCASE-INVALID" }
  expect_failures = [var.bucket_name]
}

run "reject_kms_alias_instead_of_key" {
  command = plan
  variables { kms_key_arn = "alias/ota-firmware" }
  expect_failures = [var.kms_key_arn]
}
