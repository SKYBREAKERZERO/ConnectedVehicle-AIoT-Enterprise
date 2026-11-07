mock_provider "aws" {}

variables {
  state_bucket_name = "cv-local-state-contract-123"
}

run "bootstrap_protects_state_and_lock_objects" {
  command = plan

  assert {
    condition     = aws_s3_bucket.state.force_destroy == false
    error_message = "State bucket must not be force-destroyed."
  }
  assert {
    condition     = aws_s3_bucket_versioning.state.versioning_configuration[0].status == "Enabled"
    error_message = "S3 State versions must be retained."
  }
  assert {
    condition = (
      aws_s3_bucket_public_access_block.state.block_public_acls &&
      aws_s3_bucket_public_access_block.state.block_public_policy &&
      aws_s3_bucket_public_access_block.state.ignore_public_acls &&
      aws_s3_bucket_public_access_block.state.restrict_public_buckets
    )
    error_message = "S3 State must not permit public access."
  }
  assert {
    condition     = aws_kms_key.state.enable_key_rotation && aws_kms_key.state.deletion_window_in_days == 30
    error_message = "State encryption key must rotate and have safe retirement delay."
  }
}

run "reject_invalid_state_bucket_name" {
  command = plan
  variables { state_bucket_name = "UPPERCASE" }
  expect_failures = [var.state_bucket_name]
}
