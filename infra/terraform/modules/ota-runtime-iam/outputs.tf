output "role_arn" {
  description = "Campaign runtime role ARN, available after policy attachments."
  value       = aws_iam_role.this.arn

  depends_on = [
    aws_iam_role_policy_attachment.read
  ]
}

output "role_name" {
  description = "Name of the dedicated Campaign Dispatcher runtime role."
  value       = aws_iam_role.this.name
}

output "attached_policy_arns" {
  description = "Read policies attached to the Campaign runtime role."

  value = {
    for purpose, attachment in aws_iam_role_policy_attachment.read :
    purpose => attachment.policy_arn
  }
}

output "assume_role_policy_json" {
  description = "Rendered role trust policy for review and contract tests."
  value       = aws_iam_role.this.assume_role_policy
}