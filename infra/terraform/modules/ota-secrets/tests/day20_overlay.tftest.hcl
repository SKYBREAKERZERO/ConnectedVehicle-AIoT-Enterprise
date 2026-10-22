mock_provider "aws" {}

variables {
  project_name = "connected-vehicle"
  environment  = "local"
  tenant_id    = "tenant-a"
  kms_key_arn  = "arn:aws:kms:ap-northeast-1:111111111111:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
}

run "secret_is_tenant_scoped_and_kms_encrypted" {
  command = plan

  assert {
    condition = (
      aws_secretsmanager_secret.this.kms_key_id == var.kms_key_arn &&
      aws_secretsmanager_secret.this.recovery_window_in_days == 30 &&
      strcontains(aws_secretsmanager_secret.this.name, "/tenants/")
    )
    error_message = "OTA authority Secret must be tenant-scoped and protected by an explicit KMS key."
  }
}

run "reject_invalid_tenant_id" {
  command = plan
  variables { tenant_id = " tenant-a " }
  expect_failures = [var.tenant_id]
}

run "reject_invalid_secret_retention" {
  command = plan
  variables { recovery_window_in_days = 0 }
  expect_failures = [var.recovery_window_in_days]
}
