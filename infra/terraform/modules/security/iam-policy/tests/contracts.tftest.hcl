mock_provider "aws" {}
variables {
  policy_name = "contract-scoped-policy"
  description = "Scoped policy contract"
  policy_json = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"sqs:SendMessage\"],\"Resource\":\"arn:aws:sqs:ap-northeast-1:000000000000:contract-command\"}]}"
}
run "preserves_exact_policy_scope" {
  command = apply
  assert {
    condition     = jsondecode(aws_iam_policy.this.policy).Statement[0].Action == ["sqs:SendMessage"] && jsondecode(aws_iam_policy.this.policy).Statement[0].Resource == "arn:aws:sqs:ap-northeast-1:000000000000:contract-command"
    error_message = "IAM module must preserve exact actions and resources."
  }
}
run "description_update_preserves_existing_policy" {
  command = plan
  variables { description = "Updated human-readable metadata" }
  assert {
    condition     = aws_iam_policy.this.description == "Scoped policy contract"
    error_message = "Immutable description changes must not replace the existing policy."
  }
}
run "permission_updates_are_not_ignored" {
  command = plan
  variables {
    policy_json = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":[\"sqs:ReceiveMessage\"],\"Resource\":\"arn:aws:sqs:ap-northeast-1:000000000000:contract-command\"}]}"
  }
  assert {
    condition     = jsondecode(aws_iam_policy.this.policy).Statement[0].Action == ["sqs:ReceiveMessage"]
    error_message = "Permissions changes must remain visible in the plan."
  }
}
run "reject_malformed_policy" {
  command = plan
  variables { policy_json = "invalid-json" }
  expect_failures = [var.policy_json]
}
