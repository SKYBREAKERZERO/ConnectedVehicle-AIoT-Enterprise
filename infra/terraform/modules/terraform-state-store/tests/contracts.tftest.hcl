mock_provider "aws" { override_during = plan }
override_resource {
  target          = aws_kms_key.state
  override_during = plan
  values          = { arn = "arn:aws:kms:ap-northeast-1:123456789012:key/11111111-1111-1111-1111-111111111111" }
}
variables {
  access_log_bucket_name = "cv-contract-state-access-logs"
  recovery_bucket_arn    = "arn:aws:s3:::cv-contract-state-recovery"
  replication_role_arn   = "arn:aws:iam::123456789012:role/state-replication"
  recovery_kms_key_arn   = "arn:aws:kms:us-west-2:123456789012:key/22222222-2222-2222-2222-222222222222"
  aws_account_id         = "123456789012"
  state_bucket_name      = "cv-contract-production-state"
}
run "private_encrypted_versioned_preserved_state" {
  command = plan
  assert {
    condition = (
      aws_kms_key.state.enable_key_rotation && aws_kms_key.state.deletion_window_in_days == 30 &&
      !aws_s3_bucket.state.force_destroy && aws_s3_bucket_versioning.state.versioning_configuration[0].status == "Enabled" &&
      aws_s3_bucket_public_access_block.state.block_public_acls && aws_s3_bucket_public_access_block.state.block_public_policy &&
      aws_s3_bucket_public_access_block.state.ignore_public_acls && aws_s3_bucket_public_access_block.state.restrict_public_buckets &&
      aws_s3_bucket_ownership_controls.state.rule[0].object_ownership == "BucketOwnerEnforced" &&
      one(aws_s3_bucket_server_side_encryption_configuration.state.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "aws:kms" &&
      !one(aws_s3_bucket_server_side_encryption_configuration.state.rule).bucket_key_enabled &&
      length(one(aws_s3_bucket_lifecycle_configuration.state.rule).expiration) == 0 &&
      length(one(aws_s3_bucket_lifecycle_configuration.state.rule).noncurrent_version_expiration) == 0 &&
      output.backend_contract.encrypt && output.backend_contract.use_lockfile && output.backend_contract.allowed_account_ids == ["123456789012"]
    )
    error_message = "Preserve encrypted private state versions and native S3 lockfile configuration."
  }
  assert {
    condition = (
      jsondecode(aws_s3_bucket_policy.state.policy).Statement[0].Condition.Bool["aws:SecureTransport"] == "false" &&
      jsondecode(aws_s3_bucket_policy.state.policy).Statement[0].Effect == "Deny" &&
      jsondecode(aws_s3_bucket_policy.state.policy).Statement[1].Condition.StringNotEquals["s3:x-amz-server-side-encryption"] == "aws:kms" &&
      jsondecode(aws_s3_bucket_policy.state.policy).Statement[2].Condition.ArnNotEquals["s3:x-amz-server-side-encryption-aws-kms-key-id"] == aws_kms_key.state.arn &&
      jsondecode(aws_s3_bucket_policy.state.policy).Statement[3].Condition.StringNotEquals["aws:PrincipalAccount"] == "123456789012"
    )
    error_message = "Deny cleartext transport, wrong/missing encryption and cross-account access."
  }
}
run "separate_state_and_lock_permissions" {
  command = plan
  assert {
    condition = (
      jsondecode(output.plan_state_policy_json).Statement[1].Action == ["s3:GetObject"] &&
      jsondecode(output.plan_state_policy_json).Statement[1].Resource == "arn:aws:s3:::cv-contract-production-state/ota/production/terraform.tfstate" &&
      jsondecode(output.plan_state_policy_json).Statement[2].Resource == "arn:aws:s3:::cv-contract-production-state/ota/production/terraform.tfstate.tflock" &&
      toset(jsondecode(output.plan_state_policy_json).Statement[2].Action) == toset(["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]) &&
      jsondecode(output.plan_state_policy_json).Statement[4].Effect == "Deny" &&
      jsondecode(output.apply_state_policy_json).Statement[4].Action == ["s3:PutObject"] &&
      jsondecode(output.apply_state_policy_json).Statement[5].Effect == "Deny" &&
      jsondecode(output.plan_state_policy_json).Statement[3].Condition.StringEquals["kms:ViaService"] == "s3.ap-northeast-1.amazonaws.com" &&
      jsondecode(output.plan_state_policy_json).Statement[3].Condition.StringEquals["kms:CallerAccount"] == "123456789012" &&
      length(jsondecode(output.plan_state_policy_json).Statement[3].Condition.StringEquals["kms:EncryptionContext:aws:s3:arn"]) == 2
    )
    error_message = "Plan cannot write state; lock deletion is separate; KMS is S3/account/object scoped."
  }
}
run "reject_localstack_account" {
  command = plan
  variables { aws_account_id = "000000000000" }
  expect_failures = [var.aws_account_id]
}
run "reject_wildcard_bucket" {
  command = plan
  variables { state_bucket_name = "state-*" }
  expect_failures = [var.state_bucket_name]
}
run "reject_unreviewed_state_path" {
  command = plan
  variables { state_key = "ota/staging/terraform.tfstate" }
  expect_failures = [var.state_key]
}
run "reject_unreviewed_region" {
  command = plan
  variables { aws_region = "us-east-1" }
  expect_failures = [var.aws_region]
}
