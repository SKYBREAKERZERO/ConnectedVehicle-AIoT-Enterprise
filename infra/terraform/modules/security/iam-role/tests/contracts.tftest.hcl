mock_provider "aws" {}
variables {
  role_name                = "contract-runtime-role"
  description              = "Runtime role contract"
  assume_role_policy_json  = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRole\",\"Principal\":{\"Service\":\"ecs-tasks.amazonaws.com\"}}]}"
  permissions_boundary_arn = "arn:aws:iam::000000000000:policy/runtime-boundary"
}
run "trust_and_boundary_are_preserved" {
  command = plan
  assert {
    condition     = jsondecode(aws_iam_role.this.assume_role_policy).Statement[0].Principal.Service == "ecs-tasks.amazonaws.com" && aws_iam_role.this.permissions_boundary == var.permissions_boundary_arn && aws_iam_role.this.max_session_duration == 3600
    error_message = "Role must preserve trust, boundary and bounded session duration."
  }
}
run "reject_invalid_boundary" {
  command = plan
  variables { permissions_boundary_arn = "*" }
  expect_failures = [var.permissions_boundary_arn]
}
run "reject_invalid_trust" {
  command = plan
  variables { assume_role_policy_json = "{}" }
  expect_failures = [var.assume_role_policy_json]
}
