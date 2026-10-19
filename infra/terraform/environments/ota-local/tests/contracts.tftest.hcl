mock_provider "aws" { override_during = plan }
variables {
  tenant_id                        = "contract-tenant"
  api_runtime_role_name            = "contract-api"
  application_database_secret_arn  = "arn:aws:secretsmanager:ap-northeast-1:000000000000:secret:/contract/database/application-abcdef"
  application_database_kms_key_arn = "arn:aws:kms:ap-northeast-1:000000000000:key/33333333-3333-3333-3333-333333333333"
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
