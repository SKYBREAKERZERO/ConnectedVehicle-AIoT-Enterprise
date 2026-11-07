output "staging_account_id" {
  value = data.aws_caller_identity.current.account_id
}
output "ecr_repository_url" {
  value = aws_ecr_repository.api.repository_url
}
output "ecs_cluster_arn" {
  value = aws_ecs_cluster.staging.arn
}
output "ecs_task_execution_role_arn" {
  value = aws_iam_role.execution.arn
}
output "ecs_app_task_role_arn" {
  value = aws_iam_role.application.arn
}
output "ecs_security_group_id" {
  value = aws_security_group.api.id
}
output "ecs_task_definition_arn" {
  value = var.enable_service ? aws_ecs_task_definition.api[0].arn : null
}
output "ecs_service_id" {
  value = var.enable_service ? aws_ecs_service.api[0].id : null
}
output "requested_registry_image_uri" {
  value       = var.enable_service ? "${aws_ecr_repository.api.repository_url}@${var.image_digest}" : null
  description = "Requested digest URI, NOT independent supply-chain signature verification."
}
output "release_authorized" {
  value       = false
  description = "Terraform provisioning never grants OTA release or production authority."
}
