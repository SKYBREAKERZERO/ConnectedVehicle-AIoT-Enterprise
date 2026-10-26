output "role_arn" {
  value       = aws_iam_role.this.arn
  description = "Future account-owned preview role; module is not wired into any deployment root."
}

output "trust_policy_json" {
  value       = aws_iam_role.this.assume_role_policy
  description = "Exact GitHub Environment trust contract."
}

output "preview_policy_json" {
  value       = local.preview_policy
  description = "Read-only permissions and permissions-boundary document."
}
