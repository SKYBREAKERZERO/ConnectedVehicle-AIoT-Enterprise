# ECS Worker Tasks use the same immutable ECR manifest as the API, but have
# independent ECS Task Roles, private Security Groups and separate logs.
data "aws_secretsmanager_secret" "worker_database" {
  for_each = { for kind in local.worker_active : kind => local.worker_secret_arns[kind] }
  arn      = each.value
  lifecycle {
    postcondition {
      condition = (
        self.kms_key_id == var.data_kms_key_arn &&
        self.name == (each.key == "outbox" ? "/connected-vehicle/staging/database/outbox" : each.key == "remote_command" ? "/connected-vehicle/staging/database/remote-command" : "/connected-vehicle/staging/database/application")
      )
      error_message = "Worker database Secret name or KMS key mismatch"
    }
  }
}
data "aws_secretsmanager_secret_rotation" "worker_database" {
  for_each  = { for kind in local.worker_active : kind => kind if kind != "campaign" }
  secret_id = data.aws_secretsmanager_secret.worker_database[each.key].arn
  lifecycle {
    postcondition {
      condition     = self.rotation_enabled && length(self.rotation_rules) > 0
      error_message = "Worker database Secret requires active scheduled rotation"
    }
  }
}

resource "aws_ecs_task_definition" "worker" {
  for_each                 = local.worker_active
  family                   = "${local.label}-${replace(each.key, "_", "-")}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.worker_execution[each.key].arn
  task_role_arn            = aws_iam_role.worker[each.key].arn
  skip_destroy             = true

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  volume { name = "scratch" }
  container_definitions = jsonencode([{
    name                   = "worker-${replace(each.key, "_", "-")}"
    image                  = data.aws_ecr_image.candidate[0].image_uri
    essential              = true
    readonlyRootFilesystem = true
    user                   = "10001:10001"
    command                = local.worker_commands[each.key]
    stopTimeout            = 120
    mountPoints            = [{ sourceVolume = "scratch", containerPath = "/tmp", readOnly = false }]
    environment = concat([
      { name = "APP_ENV", value = "staging" },
      { name = "CLOUD_RUNTIME", value = "aws" },
      { name = "AWS_REGION", value = var.aws_region },
      { name = "AWS_ENDPOINT_URL", value = "" },
      { name = "AWS_EC2_METADATA_DISABLED", value = "true" },
      { name = "DATABASE_TENANT_ID", value = var.tenant_id },
      { name = "VEHICLE_COMMAND_QUEUE_NAME", value = aws_sqs_queue.worker_commands.name },
      { name = "REDIS_HOST", value = var.redis_host },
      { name = "REDIS_PORT", value = "6379" },
      ], each.key == "outbox" ? [
      { name = "OUTBOX_DATABASE_SECRET_ID", value = var.outbox_database_secret_arn }
      ] : each.key == "remote_command" ? [
      { name = "REMOTE_COMMAND_DATABASE_SECRET_ID", value = var.remote_command_database_secret_arn },
      { name = "AWS_IOT_DATA_ENDPOINT", value = var.aws_iot_data_endpoint }
      ] : [
      { name = "APPLICATION_DATABASE_SECRET_ID", value = var.application_database_secret_arn },
      { name = "OTA_TRUSTED_KEYS_FILE", value = var.campaign_trust_root_path }
    ])
    secrets = each.key == "remote_command" ? [
      { name = "REDIS_PASSWORD", valueFrom = var.redis_auth_secret_arn }
    ] : []
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.worker[each.key].name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = each.key
      }
    }
  }])

  lifecycle {
    precondition {
      condition     = var.enable_service && var.enable_workers && var.image_digest != null
      error_message = "Worker requires signed ECR manifest digest and approved service deployment"
    }
    precondition {
      condition = (
        each.key != "remote_command" ||
        (var.aws_iot_data_endpoint != "" && can(regex("^[a-z0-9-]+-ats\\.iot\\.ap-northeast-1\\.amazonaws\\.com$", var.aws_iot_data_endpoint)))
      )
      error_message = "Remote Command Worker requires reviewed ATS AWS IoT Core endpoint"
    }
    precondition {
      condition = (
        each.key != "campaign" ||
        (var.staging_firmware_bucket_arn != null && var.campaign_trust_root_ready && var.campaign_trust_root_path != "")
      )
      error_message = "Campaign requires pinned S3 artifact scope and independently reviewed trust roots"
    }
  }
}

resource "aws_ecs_service" "worker" {
  for_each                           = local.worker_active
  name                               = "${local.label}-${replace(each.key, "_", "-")}"
  cluster                            = aws_ecs_cluster.staging.id
  task_definition                    = aws_ecs_task_definition.worker[each.key].arn
  desired_count                      = var.worker_desired_counts[each.key]
  launch_type                        = "FARGATE"
  platform_version                   = "LATEST"
  enable_execute_command             = false
  wait_for_steady_state              = true
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  # Checkov can trace each concrete SG to this Service, while Terraform
  # selects exactly one SG for the worker; access boundaries do not change.
  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [each.key == "outbox" ? aws_security_group.worker["outbox"].id : each.key == "remote_command" ? aws_security_group.worker["remote_command"].id : aws_security_group.worker["campaign"].id]
    assign_public_ip = false
  }
  lifecycle { prevent_destroy = true }
}

output "staging_worker_services" {
  value = { for kind, service in aws_ecs_service.worker : kind => service.id }
}
output "staging_worker_task_roles" {
  value = { for kind, role in aws_iam_role.worker : kind => role.arn }
}
output "staging_sqs_queue_url" { value = aws_sqs_queue.worker_commands.url }
output "staging_dlq_arn" { value = aws_sqs_queue.worker_dlq.arn }
