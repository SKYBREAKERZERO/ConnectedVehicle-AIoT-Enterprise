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
      jsondecode(output.preview_policy_json).Version == "2012-10-17" &&
      jsondecode(output.preview_policy_json).Statement[0].Effect == "Allow" &&
      jsondecode(aws_iam_role_policy.preview.policy).Statement[0] == jsondecode(aws_iam_policy.boundary.policy).Statement[0] &&
      toset(jsondecode(output.preview_policy_json).Statement[0].Action) == toset([
        "s3:GetBucketLocation", "s3:GetBucketVersioning", "s3:GetEncryptionConfiguration", "s3:GetBucketPublicAccessBlock"
      ]) &&
      toset(jsondecode(output.preview_policy_json).Statement[0].Resource) == var.artifact_bucket_arns &&
      jsondecode(output.preview_policy_json).Statement[0].Condition.StringEquals["aws:ResourceAccount"] == var.aws_account_id
    )
    error_message = "Identity and boundary must grant only exact account-owned metadata reads, never Apply privileges."
  }
  assert {
    condition = (
      length(jsondecode(output.boundary_policy_json).Statement) == 4 &&
      jsondecode(output.boundary_policy_json).Version == "2012-10-17" &&
      keys(jsondecode(output.boundary_policy_json).Statement[1]) == ["Effect", "NotAction", "Resource", "Sid"] &&
      keys(jsondecode(output.boundary_policy_json).Statement[2]) == ["Action", "Effect", "NotResource", "Sid"] &&
      keys(jsondecode(output.boundary_policy_json).Statement[3]) == ["Action", "Condition", "Effect", "Resource", "Sid"] &&
      jsondecode(output.boundary_policy_json).Statement[1].Effect == "Deny" &&
      toset(jsondecode(output.boundary_policy_json).Statement[1].NotAction) == toset(jsondecode(output.preview_policy_json).Statement[0].Action) &&
      jsondecode(output.boundary_policy_json).Statement[1].Resource == "*" &&
      jsondecode(output.boundary_policy_json).Statement[2].Effect == "Deny" &&
      toset(jsondecode(output.boundary_policy_json).Statement[2].NotResource) == var.artifact_bucket_arns &&
      toset(jsondecode(output.boundary_policy_json).Statement[2].Action) == toset(jsondecode(output.preview_policy_json).Statement[0].Action) &&
      jsondecode(output.boundary_policy_json).Statement[3].Effect == "Deny" &&
      jsondecode(output.boundary_policy_json).Statement[3].Resource == "*" &&
      toset(jsondecode(output.boundary_policy_json).Statement[3].Action) == toset(jsondecode(output.preview_policy_json).Statement[0].Action) &&
      jsondecode(output.boundary_policy_json).Statement[3].Condition == { StringNotEquals = { "aws:ResourceAccount" = var.aws_account_id } }
    )
    error_message = "Boundary must explicitly deny other actions, resources and accounts; implicit deny alone is insufficient for session grants."
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
