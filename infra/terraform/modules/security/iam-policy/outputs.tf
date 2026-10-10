output "policy_name" {
  description = "Name of the platform-managed IAM policy."
  value       = aws_iam_policy.this.name
}

output "policy_id" {
  description = "ID of the platform-managed IAM policy."
  value       = aws_iam_policy.this.id
}

output "policy_arn" {
  description = "ARN of the platform-managed IAM policy."
  value       = aws_iam_policy.this.arn
}

output "policy_json" {
  description = "Configured policy document for composition and contract verification."
  value       = aws_iam_policy.this.policy
}
