mock_provider "aws" {}
variables {
  alias_name  = "alias/contract/secrets"
  description = "Encryption key contract"
}
run "rotation_and_deletion_protection" {
  command = plan
  assert {
    condition     = aws_kms_key.this.enable_key_rotation && aws_kms_key.this.deletion_window_in_days == 30 && !aws_kms_key.this.bypass_policy_lockout_safety_check && aws_kms_key.this.key_usage == "ENCRYPT_DECRYPT"
    error_message = "KMS must rotate, preserve the deletion window and prevent lockout bypass."
  }
}
run "reject_immediate_deletion" {
  command = plan
  variables { deletion_window_in_days = 0 }
  expect_failures = [var.deletion_window_in_days]
}
run "reject_reserved_alias" {
  command = plan
  variables { alias_name = "alias/aws/secretsmanager" }
  expect_failures = [var.alias_name]
}
