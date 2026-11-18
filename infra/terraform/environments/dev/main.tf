locals {
  prefix = "${var.project_name}-dev"
  tags = {
    Project     = var.project_name
    Environment = "dev"
    ManagedBy   = "terraform"
    Repository  = "ConnectedVehicle-AIoT-Enterprise"
  }
  endpoint_services = toset(["ecr.api", "ecr.dkr", "logs", "secretsmanager", "sqs", "kms", "sts"])
}

resource "aws_vpc" "main" {
  cidr_block           = "10.74.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "${local.prefix}-vpc" }
}

resource "aws_subnet" "private" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.private_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false
  tags                    = { Name = "${local.prefix}-private-${count.index + 1}" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.prefix}-private" }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Task security groups are created when their services are defined, so that
# each group is attached to a real workload with independently scoped rules.
resource "aws_default_security_group" "locked" {
  vpc_id  = aws_vpc.main.id
  ingress = []
  egress  = []
}

resource "aws_security_group" "endpoints" {
  name        = "${local.prefix}-endpoints"
  description = "VPC interface endpoints"
  vpc_id      = aws_vpc.main.id
}
# Only the two private subnet CIDRs may reach interface endpoints over TLS.
resource "aws_vpc_security_group_ingress_rule" "endpoint_tls" {
  for_each          = toset(var.private_subnet_cidrs)
  security_group_id = aws_security_group.endpoints.id
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "Private subnet HTTPS clients only"
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = local.endpoint_services
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  tags                = { Name = "${local.prefix}-${replace(each.key, ".", "-")}" }
}
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
}
resource "aws_ecr_repository" "app" {
  name                 = "${local.prefix}-app"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false
  image_scanning_configuration { scan_on_push = true }
  encryption_configuration { encryption_type = "KMS" }
}
# Customer-managed encryption for ECS and VPC-flow CloudWatch log groups.
resource "aws_kms_key" "logging" {
  description         = "Dev ECS and network logs"
  enable_key_rotation = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableAccountKeyManagement"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.aws_account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "PermitRegionalCloudWatchLogsUse"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.aws_region}.amazonaws.com" }
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
        Condition = {
          ArnEquals = {
            "kms:EncryptionContext:aws:logs:arn" = [
              "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/ecs/${local.prefix}",
              "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/vpc/${local.prefix}/flow"
            ]
          }
        }
      }
    ]
  })
}
resource "aws_kms_alias" "logging" {
  name          = "alias/${local.prefix}-logs"
  target_key_id = aws_kms_key.logging.key_id
}

resource "aws_cloudwatch_log_group" "vpc_flow" {
  name              = "/vpc/${local.prefix}/flow"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.logging.arn
}

resource "aws_iam_role" "vpc_flow" {
  name = "${local.prefix}-vpc-flow"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.aws_account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:ec2:${var.aws_region}:${var.aws_account_id}:vpc-flow-log/*" }
      }
    }]
  })
}
resource "aws_iam_role_policy" "vpc_flow" {
  role = aws_iam_role.vpc_flow.id
  name = "${local.prefix}-vpc-flow-write"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"]
      Resource = "${aws_cloudwatch_log_group.vpc_flow.arn}:*"
    }]
  })
}
resource "aws_flow_log" "vpc" {
  vpc_id               = aws_vpc.main.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.vpc_flow.arn
  iam_role_arn         = aws_iam_role.vpc_flow.arn
  depends_on           = [aws_iam_role_policy.vpc_flow]
}

resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/${local.prefix}"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.logging.arn
}
resource "aws_ecs_cluster" "main" {
  name = "${local.prefix}-cluster"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}
resource "aws_iam_role" "execution" {
  name = "${local.prefix}-ecs-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = var.aws_account_id }
        ArnLike      = { "aws:SourceArn" = "arn:aws:ecs:${var.aws_region}:${var.aws_account_id}:*" }
      }
    }]
  })
}
resource "aws_iam_role_policy" "execution" {
  role = aws_iam_role.execution.id
  name = "${local.prefix}-ecs-execution"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = "*" },
      { Effect = "Allow", Action = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"], Resource = aws_ecr_repository.app.arn },
      { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.ecs.arn}:*" }
    ]
  })
}
