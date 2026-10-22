mock_provider "aws" {
  mock_resource "aws_secretsmanager_secret" {
    defaults = {
      arn = "arn:aws:secretsmanager:ap-northeast-1:000000000000:secret:/cv/local/authority-abcdef"
    }
  }
}

variables {
  project_name = "connected-vehicle"
  environment  = "local"
  tenant_id    = "tenant-a"
  kms_key_arn  = "arn:aws:kms:ap-northeast-1:000000000000:key/12345678-1234-1234-1234-123456789abc"
}

run "tenant_secret_and_scoped_read" {
  command = apply
  assert {
    condition = (
      aws_secretsmanager_secret.this.name == "/connected-vehicle/local/tenants/${sha256("tenant-a")}/ota/runtime-authority" &&
      aws_secretsmanager_secret.this.kms_key_id == var.kms_key_arn &&
      aws_secretsmanager_secret.this.recovery_window_in_days == 30
    )
    error_message = "A dedicated encrypted tenant secret and recovery window are required."
  }
  assert {
    condition = (
      length(jsondecode(aws_iam_policy.read.policy).Statement) == 2 &&
      toset(jsondecode(aws_iam_policy.read.policy).Statement[0].Action) == toset(["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]) &&
      jsondecode(aws_iam_policy.read.policy).Statement[0].Resource == aws_secretsmanager_secret.this.arn &&
      toset(jsondecode(aws_iam_policy.read.policy).Statement[1].Action) == toset(["kms:Decrypt"]) &&
      jsondecode(aws_iam_policy.read.policy).Statement[1].Resource == var.kms_key_arn &&
      jsondecode(aws_iam_policy.read.policy).Statement[1].Condition.StringEquals["kms:ViaService"] == "secretsmanager.ap-northeast-1.amazonaws.com" &&
      jsondecode(aws_iam_policy.read.policy).Statement[1].Condition.StringEquals["kms:EncryptionContext:SecretARN"] == aws_secretsmanager_secret.this.arn
    )
    error_message = "Authority reads must be scoped to exactly this secret and key."
  }
}

run "different_tenant_has_different_name" {
  command = plan
  variables {
    tenant_id = "tenant-b"
  }
  assert {
    condition     = aws_secretsmanager_secret.this.name != "/connected-vehicle/local/tenants/${sha256("tenant-a")}/ota/runtime-authority"
    error_message = "Different tenants cannot share the same secret name."
  }
}

run "reject_immediate_deletion" {
  command = plan
  variables {
    recovery_window_in_days = 0
  }
  expect_failures = [var.recovery_window_in_days]
}

run "reject_alias" {
  command = plan
  variables {
    kms_key_arn = "arn:aws:kms:ap-northeast-1:000000000000:alias/ota-authority"
  }
  expect_failures = [var.kms_key_arn]
}
