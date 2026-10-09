resource "aws_iam_role" "this" {
  name        = var.role_name
  description = var.description

  assume_role_policy = var.assume_role_policy_json

  max_session_duration = var.max_session_duration_seconds
  permissions_boundary = var.permissions_boundary_arn

  tags = var.tags
}