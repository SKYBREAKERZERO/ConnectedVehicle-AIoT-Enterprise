mock_provider "aws" {}

variables {
  role_name                 = "cv-ota-campaign-contract"
  database_read_policy_arn  = "arn:aws:iam::111111111111:policy/cv-db"
  authority_read_policy_arn = "arn:aws:iam::111111111111:policy/cv-authority"
  artifact_read_policy_arn  = "arn:aws:iam::111111111111:policy/cv-artifact"
}

run "campaign_has_three_distinct_managed_read_policies" {
  command = plan

  assert {
    condition     = length(aws_iam_role_policy_attachment.read) == 3
    error_message = "Campaign runtime should have exactly three distinct reviewed policies."
  }
  assert {
    condition     = jsondecode(aws_iam_role.this.assume_role_policy).Statement[0].Principal.Service == "ecs-tasks.amazonaws.com"
    error_message = "Only the intended ECS task trust service is permitted."
  }
}

run "reject_collapsed_policy_boundaries" {
  command = plan
  variables { authority_read_policy_arn = "arn:aws:iam::111111111111:policy/cv-db" }
  expect_failures = [aws_iam_role.this]
}

run "reject_aws_managed_wildcard_policy" {
  command = plan
  variables { database_read_policy_arn = "arn:aws:iam::111111111111:policy/*" }
  expect_failures = [var.database_read_policy_arn]
}
