mock_provider "aws" { override_during = plan }

override_resource {
  override_during = plan
  target          = aws_iam_policy.boundary
  values          = { arn = "arn:aws:iam::123456789012:policy/contract-preview-boundary" }
}

variables {
  aws_account_id       = "123456789012"
  artifact_bucket_arns = ["arn:aws:s3:::cv-ota-production-firmware"]
}

run "exact_repository_environment_audience_and_account_trust" {
  command = plan
  assert {
    condition = (
      jsondecode(output.trust_policy_json).Statement[0].Action == "sts:AssumeRoleWithWebIdentity" &&
      jsondecode(output.trust_policy_json).Statement[0].Principal.Federated == "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" &&
      jsondecode(output.trust_policy_json).Statement[0].Condition.StringEquals == {
        "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        "token.actions.githubusercontent.com:sub" = "repo:SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise:environment:production"
      } && length(jsondecode(output.trust_policy_json).Statement) == 1
    )
    error_message = "Trust must bind the exact account, GitHub provider, audience, repository and production Environment."
  }
  assert {
    condition = (
      aws_iam_role.this.permissions_boundary == aws_iam_policy.boundary.arn &&
      aws_iam_role.this.max_session_duration == 3600 &&
      aws_iam_role_policy.preview.policy == aws_iam_policy.boundary.policy &&
      toset(jsondecode(output.preview_policy_json).Statement[0].Action) == toset([
        "s3:GetBucketLocation", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration", "s3:GetBucketPublicAccessBlock"
      ]) &&
      toset(jsondecode(output.preview_policy_json).Statement[0].Resource) == var.artifact_bucket_arns &&
      jsondecode(output.preview_policy_json).Statement[0].Condition.StringEquals["aws:ResourceAccount"] == var.aws_account_id
    )
    error_message = "Identity and boundary must grant only exact account-owned metadata reads, never Apply privileges."
  }
}

run "reject_localstack_account" {
  command = plan
  variables { aws_account_id = "000000000000" }
  expect_failures = [var.aws_account_id]
}

run "reject_invalid_account" {
  command = plan
  variables { aws_account_id = "123*" }
  expect_failures = [var.aws_account_id]
}

run "reject_wildcard_bucket" {
  command = plan
  variables { artifact_bucket_arns = ["arn:aws:s3:::cv-ota-*"] }
  expect_failures = [var.artifact_bucket_arns]
}

run "reject_object_scope" {
  command = plan
  variables { artifact_bucket_arns = ["arn:aws:s3:::cv-ota-production-firmware/secret"] }
  expect_failures = [var.artifact_bucket_arns]
}

run "reject_empty_scope" {
  command = plan
  variables { artifact_bucket_arns = [] }
  expect_failures = [var.artifact_bucket_arns]
}
