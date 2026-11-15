locals {
  label = var.name_prefix
}

resource "aws_ecr_repository" "api" {
  name                 = "${local.label}/vehicle-api"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = var.data_kms_key_arn
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_ecs_cluster" "staging" {
  name = local.label

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_cloudwatch_log_group" "api" {
  name              = "/ecs/${local.label}/api"
  retention_in_days = 365
  kms_key_id        = var.data_kms_key_arn
  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_security_group" "api" {
  name_prefix = "${local.label}-api-"
  description = "Day37 staging ECS API, private ingress only"
  vpc_id      = var.vpc_id
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "from_alb" {
  security_group_id            = aws_security_group.api.id
  referenced_security_group_id = var.alb_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 8000
  to_port                      = 8000
  description                  = "Staging ALB to API only"
}

# Foundation owns DB/Redis SG definitions, while the application root owns its
# exact port-only ingress edges; these are created at the approved bootstrap Plan.
resource "aws_vpc_security_group_ingress_rule" "db_from_api" {
  security_group_id            = var.database_security_group_id
  referenced_security_group_id = aws_security_group.api.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  description                  = "Staging app_user from only the ECS API task SG"
}
resource "aws_vpc_security_group_ingress_rule" "redis_from_api" {
  security_group_id            = var.redis_security_group_id
  referenced_security_group_id = aws_security_group.api.id
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  description                  = "Staging TLS Redis from only the ECS API task SG"
}

resource "aws_vpc_security_group_egress_rule" "https" {
  security_group_id = aws_security_group.api.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "TLS for AWS endpoints and OIDC JWKS; constrain with endpoints and egress controls"
}

resource "aws_vpc_security_group_egress_rule" "database" {
  security_group_id            = aws_security_group.api.id
  referenced_security_group_id = var.database_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  description                  = "PostgreSQL only"
}

resource "aws_vpc_security_group_egress_rule" "redis" {
  security_group_id            = aws_security_group.api.id
  referenced_security_group_id = var.redis_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  description                  = "Redis only"
}

# The running app reads exactly this existing Secrets Manager record using task-role
# credentials. Terraform never reads, stores, or creates the secret VALUE.
# Only enable_service after a *separate* Day37 signed-image/evidence gate.
# This read forces the manifest digest to exist in the exact account/repository.
# It is NOT a substitute for verifying Cosign identity or provenance.
data "aws_ecr_image" "candidate" {
  count           = var.enable_service ? 1 : 0
  registry_id     = var.aws_account_id
  repository_name = aws_ecr_repository.api.name
  image_digest    = var.image_digest
}

resource "aws_ecs_task_definition" "api" {
  count                    = var.enable_service ? 1 : 0
  family                   = "${local.label}-api"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = tostring(var.cpu)
  memory                   = tostring(var.memory)
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.application.arn
  skip_destroy             = true

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([{
    name                   = "vehicle-api"
    image                  = data.aws_ecr_image.candidate[0].image_uri
    essential              = true
    readonlyRootFilesystem = true
    user                   = "10001:10001"
    portMappings           = [{ containerPort = 8000, hostPort = 8000, protocol = "tcp" }]
    environment = [
      { name = "APP_ENV", value = "staging" },
      { name = "CLOUD_RUNTIME", value = "aws" },
      { name = "AWS_REGION", value = var.aws_region },
      { name = "AWS_ENDPOINT_URL", value = "" },
      { name = "AWS_EC2_METADATA_DISABLED", value = "true" },
      { name = "APPLICATION_DATABASE_SECRET_ID", value = var.application_database_secret_arn },
      { name = "DATABASE_TENANT_ID", value = var.tenant_id },
      { name = "OIDC_ISSUER", value = var.oidc_issuer },
      { name = "OIDC_JWKS_URL", value = var.oidc_jwks_url },
      { name = "OIDC_AUDIENCE", value = var.oidc_audience },
      { name = "TRACING_ENABLED", value = "false" },
      { name = "REDIS_HOST", value = var.redis_host },
      { name = "REDIS_PORT", value = "6379" },
      { name = "REDIS_TLS_ENABLED", value = "true" }
    ]
    secrets = [{ name = "REDIS_PASSWORD", valueFrom = var.redis_auth_secret_arn }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.api.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "api"
      }
    }
    healthCheck = {
      command     = ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready',timeout=3)\""]
      interval    = 15
      timeout     = 5
      retries     = 3
      startPeriod = 60
    }
  }])

  lifecycle {
    precondition {
      condition     = var.image_digest != null && var.desired_count >= 1
      error_message = "Enabling ECS requires a verified sha256 registry manifest digest and desired_count >= 1."
    }
    precondition {
      condition     = var.alb_target_group_arn != null && can(regex(":${var.aws_account_id}:targetgroup/", var.alb_target_group_arn))
      error_message = "Existing ALB target group must belong to this staging AWS account."
    }
    precondition {
      condition     = var.redis_auth_secret_arn != null && can(regex(":${var.aws_account_id}:secret:", var.redis_auth_secret_arn))
      error_message = "ECS service requires same-account Redis auth Secret and TLS-enabled runtime."
    }
    precondition {
      condition     = can(regex(":${var.aws_account_id}:secret:", var.application_database_secret_arn))
      error_message = "Database secret must belong to the same staging account."
    }
    precondition {
      condition     = alltrue([for s in data.aws_subnet.private : s.vpc_id == var.vpc_id && !s.map_public_ip_on_launch]) && length(toset([for s in data.aws_subnet.private : s.availability_zone])) >= 2
      error_message = "Use at least two separate-AZ private staging subnets in the selected VPC."
    }
  }
}

resource "aws_ecs_service" "api" {
  count                              = var.enable_service ? 1 : 0
  name                               = "${local.label}-api"
  cluster                            = aws_ecs_cluster.staging.id
  task_definition                    = aws_ecs_task_definition.api[0].arn
  desired_count                      = var.desired_count
  launch_type                        = "FARGATE"
  platform_version                   = "1.4.0"
  enable_execute_command             = false
  health_check_grace_period_seconds  = 120
  wait_for_steady_state              = true
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.api.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = var.alb_target_group_arn
    container_name   = "vehicle-api"
    container_port   = 8000
  }

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = data.aws_lb_target_group.existing[0].target_type == "ip" && data.aws_lb_target_group.existing[0].vpc_id == var.vpc_id
      error_message = "Existing target group must be IP type in the expected staging VPC."
    }
  }
}
