locals {
  name    = "connected-vehicle-ota-staging"
  ecr_arn = "arn:aws:ecr:${var.aws_region}:${var.aws_account_id}:repository/${local.name}"
  image   = "${var.aws_account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${local.name}@${var.registry_digest}"
  task_trust = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "ecs-tasks.amazonaws.com" },
    Condition = { StringEquals = { "aws:SourceAccount" = var.aws_account_id },
    ArnLike = { "aws:SourceArn" = "arn:aws:ecs:${var.aws_region}:${var.aws_account_id}:*" } }
  }] })
}
resource "aws_ecr_repository" "api" {
  name                 = local.name
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = var.registry_kms_key_arn
  }
  lifecycle { prevent_destroy = true }
}
resource "aws_cloudwatch_log_group" "api" {
  name              = "/ecs/${local.name}"
  retention_in_days = 365
  kms_key_id        = var.logs_kms_key_arn
  lifecycle { prevent_destroy = true }
}
resource "aws_ecs_cluster" "staging" {
  name = local.name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}
resource "aws_iam_role" "execution" {
  name               = "${local.name}-execution"
  assume_role_policy = local.task_trust
  lifecycle { prevent_destroy = true }
}
resource "aws_iam_role" "application" {
  name               = "${local.name}-application"
  assume_role_policy = local.task_trust
  lifecycle { prevent_destroy = true }
}
resource "aws_iam_role_policy" "execution" {
  role = aws_iam_role.execution.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = "*",
    Condition = { StringEquals = { "aws:RequestedRegion" = var.aws_region } } },
    { Effect = "Allow", Action = ["ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage"], Resource = local.ecr_arn },
    { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"],
    Resource = "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/ecs/${local.name}:log-stream:api/*" }
  ] })
}
resource "aws_iam_role_policy" "application" {
  role = aws_iam_role.application.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = var.application_database_secret_arn },
    { Effect = "Allow", Action = ["kms:Decrypt"], Resource = var.application_database_kms_key_arn,
      Condition = { StringEquals = {
        "kms:ViaService"                  = "secretsmanager.${var.aws_region}.amazonaws.com",
        "kms:EncryptionContext:SecretARN" = var.application_database_secret_arn
    } } }
  ] })
}
resource "aws_security_group" "alb" {
  name        = "${local.name}-alb"
  vpc_id      = var.vpc_id
  description = "Internal staging TLS clients only"
  ingress {
    description = "Reviewed internal clients"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.ingress_cidrs
  }
  egress {
    description     = "API targets only"
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.api.id]
  }
}
resource "aws_security_group" "api" {
  name        = "${local.name}-api"
  vpc_id      = var.vpc_id
  description = "Private API with explicit DB/cache/AWS/JWKS egress"
  egress {
    description     = "Application DB"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.database_security_group_id]
  }
  egress {
    description     = "Tenant cache"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [var.redis_security_group_id]
  }
  egress {
    description     = "Private AWS and OIDC endpoints"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [var.aws_endpoints_security_group_id, var.oidc_proxy_security_group_id]
  }
  egress {
    description     = "ECR backing S3 gateway"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [var.s3_prefix_list_id]
  }
}
resource "aws_vpc_security_group_ingress_rule" "api" {
  description                  = "Only the internal staging ALB may reach the API"
  security_group_id            = aws_security_group.api.id
  referenced_security_group_id = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = 8000
  to_port                      = 8000
}
resource "aws_lb" "api" {
  name               = "cv-ota-staging"
  internal           = true
  load_balancer_type = "application"
  subnets            = var.private_subnet_ids
  security_groups    = [aws_security_group.alb.id]
  access_logs {
    bucket  = var.access_logs_bucket
    prefix  = "ota-staging"
    enabled = true
  }
  enable_deletion_protection = true
  drop_invalid_header_fields = true
}
resource "aws_lb_target_group" "api" {
  name        = "cv-ota-staging"
  port        = 8000
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id
  health_check {
    path                = "/health/ready"
    matcher             = "200"
    interval            = 30
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}
resource "aws_lb_listener" "api" {
  load_balancer_arn = aws_lb.api.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = var.certificate_arn
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}
resource "aws_ecs_task_definition" "api" {
  family                   = local.name
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.application.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  container_definitions = jsonencode([{
    name         = "api", image = local.image, essential = true, user = "10001:10001", readonlyRootFilesystem = true,
    portMappings = [{ containerPort = 8000, protocol = "tcp" }],
    environment = [for k, v in {
      APP_ENV                        = "staging", CLOUD_RUNTIME = "aws", AWS_REGION = var.aws_region,
      APPLICATION_DATABASE_SECRET_ID = var.application_database_secret_arn,
      DATABASE_TENANT_ID             = var.tenant_id, REDIS_HOST = var.redis_host, REDIS_PORT = "6379",
      OIDC_ISSUER                    = var.oidc_issuer, OIDC_AUDIENCE = var.oidc_audience, OIDC_JWKS_URL = var.oidc_jwks_url,
      TRACING_ENABLED                = "false"
    } : { name = k, value = v }],
    linuxParameters  = { capabilities = { drop = ["ALL"] } },
    healthCheck      = { command = ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready',timeout=3)"], interval = 30, timeout = 5, retries = 3, startPeriod = 60 },
    logConfiguration = { logDriver = "awslogs", options = { awslogs-group = aws_cloudwatch_log_group.api.name, awslogs-region = var.aws_region, awslogs-stream-prefix = "api" } }
  }])
}
resource "aws_ecs_service" "api" {
  name                               = local.name
  cluster                            = aws_ecs_cluster.staging.id
  task_definition                    = aws_ecs_task_definition.api.arn
  desired_count                      = 1
  launch_type                        = "FARGATE"
  platform_version                   = "LATEST"
  enable_execute_command             = false
  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200
  health_check_grace_period_seconds  = 90
  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }
  alarms {
    enable      = true
    rollback    = true
    alarm_names = [aws_cloudwatch_metric_alarm.errors.alarm_name]
  }
  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.api.id]
    assign_public_ip = false
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.api.arn
    container_name   = "api"
    container_port   = 8000
  }
  depends_on = [aws_lb_listener.api, aws_iam_role_policy.execution, aws_iam_role_policy.application]
  lifecycle { prevent_destroy = true }
}
resource "aws_cloudwatch_metric_alarm" "errors" {
  alarm_name          = "${local.name}-target-5xx"
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_Target_5XX_Count"
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  treat_missing_data  = "breaching"
  dimensions = {
    LoadBalancer = aws_lb.api.arn_suffix
    TargetGroup  = aws_lb_target_group.api.arn_suffix
  }
}
resource "aws_iam_role" "github_staging" {
  name                 = "${local.name}-github"
  max_session_duration = 3600
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect    = "Allow", Action = "sts:AssumeRoleWithWebIdentity",
    Principal = { Federated = "arn:aws:iam::${var.aws_account_id}:oidc-provider/token.actions.githubusercontent.com" },
    Condition = { StringEquals = {
      "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub" = "repo:SKYBREAKERZERO/ConnectedVehicle-AIoT-Enterprise:environment:aws-staging"
    } }
  }] })
  lifecycle { prevent_destroy = true }
}
# This initial identity can inspect only. Publish/UpdateService remain absent
# until signed registry artifacts, protected-main approval and AWS sandbox exist.
resource "aws_iam_role_policy" "github_staging" {
  role = aws_iam_role.github_staging.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["ecr:DescribeImages", "ecr:BatchGetImage"], Resource = local.ecr_arn },
    { Effect = "Allow", Action = ["ecs:DescribeServices"], Resource = "arn:aws:ecs:${var.aws_region}:${var.aws_account_id}:service/${local.name}/${local.name}" }
  ] })
}
output "image_uri" { value = local.image }
output "staging_role_arn" { value = aws_iam_role.github_staging.arn }
output "production_authorized" { value = false }
