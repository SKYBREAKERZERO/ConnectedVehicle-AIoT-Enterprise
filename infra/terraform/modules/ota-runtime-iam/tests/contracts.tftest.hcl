mock_provider "aws" {}

variables {
  role_name                 = "cv-local-campaign"
  database_read_policy_arn  = "arn:aws:iam::000000000000:policy/cv-local-database-read"
  authority_read_policy_arn = "arn:aws:iam::000000000000:policy/cv-local-authority-read"
  artifact_read_policy_arn  = "arn:aws:iam::000000000000:policy/cv-local-artifact-read"
}

run "dedicated_role_trust_and_bindings" {
  command = plan

  assert {
    condition = (
      length(jsondecode(aws_iam_role.this.assume_role_policy).Statement) == 1 &&
      jsondecode(aws_iam_role.this.assume_role_policy).Statement[0].Effect == "Allow" &&
      jsondecode(aws_iam_role.this.assume_role_policy).Statement[0].Principal == { Service = "ecs-tasks.amazonaws.com" } &&
      jsondecode(aws_iam_role.this.assume_role_policy).Statement[0].Action == "sts:AssumeRole"
    )
    error_message = "Only ECS task service may assume the runtime role."
  }

  assert {
    condition = (
      length(aws_iam_role_policy_attachment.read) == 3 &&
      aws_iam_role_policy_attachment.read["database"].policy_arn == var.database_read_policy_arn &&
      aws_iam_role_policy_attachment.read["authority"].policy_arn == var.authority_read_policy_arn &&
      aws_iam_role_policy_attachment.read["artifact"].policy_arn == var.artifact_read_policy_arn &&
      alltrue([for binding in aws_iam_role_policy_attachment.read : binding.role == var.role_name])
    )
    error_message = "Exactly the three supplied read policies must bind to this role."
  }
}

run "reject_duplicate_policy_bindings" {
  command = plan
  variables {
    authority_read_policy_arn = "arn:aws:iam::000000000000:policy/cv-local-database-read"
  }
  expect_failures = [aws_iam_role.this]
}

run "reject_wildcard_policy_arn" {
  command = plan
  variables {
    artifact_read_policy_arn = "arn:aws:iam::000000000000:policy/*"
  }
  expect_failures = [var.artifact_read_policy_arn]
}

run "reject_session_over_limit" {
  command = plan
  variables {
    max_session_duration_seconds = 43201
  }
  expect_failures = [var.max_session_duration_seconds]
}
