output "vpc_id" { value = aws_vpc.main.id }
output "private_subnet_ids" { value = aws_subnet.private[*].id }
output "ecs_cluster_arn" { value = aws_ecs_cluster.main.arn }
output "ecr_repository_url" { value = aws_ecr_repository.app.repository_url }
output "ecs_execution_role_arn" { value = aws_iam_role.execution.arn }
output "log_group_name" { value = aws_cloudwatch_log_group.ecs.name }
