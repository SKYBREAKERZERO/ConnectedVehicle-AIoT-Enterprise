mock_provider "aws" {}
variables { state_bucket_name = "cv-contract-tfstate" }
run "state_storage_controls" {
  command = plan
  assert {
    condition     = aws_kms_key.state.enable_key_rotation && !aws_s3_bucket.state.force_destroy && aws_s3_bucket_versioning.state.versioning_configuration[0].status == "Enabled" && aws_s3_bucket_public_access_block.state.restrict_public_buckets && length(one(aws_s3_bucket_lifecycle_configuration.state.rule).expiration) == 0
    error_message = "State storage must preserve encrypted private versions without expiry."
  }
}
