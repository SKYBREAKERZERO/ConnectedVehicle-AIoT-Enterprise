mock_provider "aws" {}
variables {
  secret_name          = "/contract/database/application"
  description          = "Database secret contract"
  kms_key_arn          = "arn:aws:kms:ap-northeast-1:000000000000:key/12345678-1234-1234-1234-123456789abc"
  resource_policy_json = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::000000000000:role/contract-runtime\"},\"Action\":\"secretsmanager:GetSecretValue\",\"Resource\":\"arn:aws:secretsmanager:ap-northeast-1:000000000000:secret:/contract/database/application-abcdef\"}]}"
}
run "customer_key_and_public_policy_guard" {
  command = plan
  assert {
    condition     = aws_secretsmanager_secret.this.kms_key_id == var.kms_key_arn && aws_secretsmanager_secret.this.recovery_window_in_days == 30 && aws_secretsmanager_secret_policy.this[0].block_public_policy
    error_message = "Secret must use the CMK, preserve recovery and reject public resource policies."
  }
}
run "reject_missing_encryption_key" {
  command = plan
  variables { kms_key_arn = "" }
  expect_failures = [var.kms_key_arn]
}
run "reject_immediate_secret_deletion" {
  command = plan
  variables { recovery_window_in_days = 0 }
  expect_failures = [var.recovery_window_in_days]
}
