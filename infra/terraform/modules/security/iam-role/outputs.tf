output "role_name" {
  description = "Name of the platform-managed IAM role."
  value       = aws_iam_role.this.name
}

output "role_id" {
  description = "Stable ID of the platform-managed IAM role."
  value       = aws_iam_role.this.id
}

output "role_arn" {
  description = "ARN of the platform-managed IAM role."
  value       = aws_iam_role.this.arn
}