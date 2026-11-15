mock_provider "aws" {}
variables {
  bucket_name   = "cv-ota-contract"
  kms_key_arn   = "arn:aws:kms:ap-northeast-1:000000000000:key/11111111-1111-1111-1111-111111111111"
  artifact_keys = ["firmware/body.bin"]
  environment   = "local"
}
run "fixed_version_and_object_scoped_decryption" {
  command = plan
  assert {
    condition     = jsondecode(aws_iam_policy.this.policy).Statement[0].Action == ["s3:GetObjectVersion"] && jsondecode(aws_iam_policy.this.policy).Statement[0].Resource == ["arn:aws:s3:::cv-ota-contract/firmware/body.bin"] && jsondecode(aws_iam_policy.this.policy).Statement[1].Condition.StringEquals["kms:EncryptionContext:aws:s3:arn"] == ["arn:aws:s3:::cv-ota-contract/firmware/body.bin"]
    error_message = "Runtime reads and KMS context must be restricted to approved versioned objects."
  }
}
run "aws_cannot_disable_https" {
  command = plan
  variables {
    environment = "prod"
    enforce_tls = false
  }
  expect_failures = [var.enforce_tls]
}
run "reject_wildcard_artifacts" {
  command = plan
  variables { artifact_keys = ["firmware/*"] }
  expect_failures = [var.artifact_keys]
}
