mock_provider "aws" { override_during = plan }
variables {
  tenant_id                        = "contract-tenant"
  api_runtime_role_name            = "contract-api"
  application_database_secret_arn  = "arn:aws:secretsmanager:ap-northeast-1:000000000000:secret:/contract/database/application-abcdef"
  application_database_kms_key_arn = "arn:aws:kms:ap-northeast-1:000000000000:key/33333333-3333-3333-3333-333333333333"
  campaign_database_secret_arn     = "arn:aws:secretsmanager:ap-northeast-1:000000000000:secret:/contract/database/campaign-abcdef"
  campaign_database_kms_key_arn    = "arn:aws:kms:ap-northeast-1:000000000000:key/44444444-4444-4444-4444-444444444444"
  artifact_keys                    = ["firmware/body.bin"]
}
override_resource {
  override_during = plan
  target          = module.artifact_kms.aws_kms_key.this
  values          = { arn = "arn:aws:kms:ap-northeast-1:000000000000:key/11111111-1111-1111-1111-111111111111" }
}
override_resource {
  override_during = plan
  target          = module.authority_kms.aws_kms_key.this
  values          = { arn = "arn:aws:kms:ap-northeast-1:000000000000:key/22222222-2222-2222-2222-222222222222" }
}
override_resource {
  override_during = plan
  target          = module.artifact_bucket.aws_s3_bucket.this
  values          = { id = "cv-ota-contract", arn = "arn:aws:s3:::cv-ota-contract" }
}
override_resource {
  override_during = plan
  target          = module.database_read_policy.aws_iam_policy.this
  values          = { arn = "arn:aws:iam::000000000000:policy/contract-database" }
}
override_resource {
  override_during = plan
  target          = module.artifact_policy.aws_iam_policy.this
  values          = { arn = "arn:aws:iam::000000000000:policy/contract-artifact" }
}
override_resource {
  override_during = plan
  target          = module.ota_authority.aws_iam_policy.read
  values          = { arn = "arn:aws:iam::000000000000:policy/contract-authority" }
}
run "runtime_credentials_and_keys_are_wired_separately" {
  command = plan
  assert {
    condition     = output.artifact_kms_key_arn != output.authority_kms_key_arn && length(aws_iam_role_policy_attachment.api_read) == 3 && output.runtime_read_policy_arns.database != output.runtime_read_policy_arns.artifact
    error_message = "The OTA root must wire distinct authority/artifact keys and three scoped runtime policies."
  }
}

override_resource {
  override_during = plan
  target          = module.campaign_database_read_policy.aws_iam_policy.this
  values          = { arn = "arn:aws:iam::000000000000:policy/contract-campaign-database" }
}

run "database_credentials_are_isolated" {
  command = plan
  assert {
    condition = (
      aws_iam_role_policy_attachment.api_read["database"].policy_arn == output.runtime_read_policy_arns.database &&
      output.campaign_read_policy_arns.database == module.campaign_database_read_policy.policy_arn &&
      length(output.campaign_read_policy_arns) == 3 &&
      output.runtime_read_policy_arns.database != output.campaign_read_policy_arns.database &&
      output.api_runtime_role_name != output.campaign_runtime_role_name &&
      jsondecode(module.database_read_policy.policy_json).Statement[0].Resource == var.application_database_secret_arn &&
      jsondecode(module.campaign_database_read_policy.policy_json).Statement[0].Resource == var.campaign_database_secret_arn
    )
    error_message = "API and Campaign must have distinct roles, database secrets and policy bindings."
  }
  assert {
    condition = alltrue([
      for policy in [jsondecode(module.database_read_policy.policy_json), jsondecode(module.campaign_database_read_policy.policy_json)] :
      length(policy.Statement) == 2 &&
      policy.Statement[1].Condition.StringEquals["kms:ViaService"] == "secretsmanager.${var.aws_region}.amazonaws.com" &&
      policy.Statement[1].Condition.StringEquals["kms:EncryptionContext:SecretARN"] == policy.Statement[0].Resource
    ])
    error_message = "Each database decrypt permission must bind Secrets Manager and its own exact Secret ARN."
  }
}

run "reject_shared_database_secret" {
  command = plan
  variables {
    campaign_database_secret_arn = "arn:aws:secretsmanager:ap-northeast-1:000000000000:secret:/contract/database/application-abcdef"
  }
  expect_failures = [var.campaign_database_secret_arn]
}

run "reject_shared_runtime_role" {
  command = plan
  variables {
    api_runtime_role_name = "connected-vehicle-local-ota-${substr(sha256("contract-tenant"), 0, 12)}-campaign"
  }
  expect_failures = [aws_iam_role_policy_attachment.api_read]
}

run "reject_nonlocal_environment" {
  command = plan
  variables { environment = "production" }
  expect_failures = [var.environment]
}

run "reject_remote_endpoint" {
  command = plan
  variables { aws_endpoint_url = "https://secretsmanager.ap-northeast-1.amazonaws.com" }
  expect_failures = [var.aws_endpoint_url]
}

run "reject_campaign_secret_wrong_account" {
  command = plan
  variables { campaign_database_secret_arn = "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:campaign" }
  expect_failures = [var.campaign_database_secret_arn]
}

run "reject_campaign_key_wrong_region" {
  command = plan
  variables { campaign_database_kms_key_arn = "arn:aws:kms:us-east-1:000000000000:key/44444444-4444-4444-4444-444444444444" }
  expect_failures = [var.campaign_database_kms_key_arn]
}

run "reject_shared_runtime_role_case_variant" {
  command = plan
  variables {
    api_runtime_role_name = upper("connected-vehicle-local-ota-${substr(sha256("contract-tenant"), 0, 12)}-campaign")
  }
  expect_failures = [aws_iam_role_policy_attachment.api_read]
}
