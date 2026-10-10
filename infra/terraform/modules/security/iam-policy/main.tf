resource "aws_iam_policy" "this" {
  name        = var.policy_name
  description = var.description
  path        = var.path
  policy      = var.policy_json

  tags = var.tags

  # AWS policy descriptions are immutable metadata. Updating only a description
  # must not replace the policy ARN and detach running task roles.
  lifecycle {
    ignore_changes = [description]
  }
}