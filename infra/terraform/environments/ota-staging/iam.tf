data "aws_iam_policy_document" "ecs_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${var.name_prefix}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_trust.json
  lifecycle { prevent_destroy = true }
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "application" {
  name               = "${var.name_prefix}-app"
  assume_role_policy = data.aws_iam_policy_document.ecs_trust.json
  lifecycle { prevent_destroy = true }
}

data "aws_iam_policy_document" "application" {
  statement {
    sid       = "ReadExactlyOneApplicationDatabaseSecret"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = [var.application_database_secret_arn]
  }

  dynamic "statement" {
    for_each = var.database_kms_key_arn == null ? [] : [var.database_kms_key_arn]
    content {
      sid       = "DecryptTenantDatabaseSecretOnly"
      effect    = "Allow"
      actions   = ["kms:Decrypt"]
      resources = [statement.value]
      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["secretsmanager.${var.aws_region}.amazonaws.com"]
      }
      condition {
        test     = "StringEquals"
        variable = "kms:EncryptionContext:SecretARN"
        values   = [var.application_database_secret_arn]
      }
    }
  }
}

resource "aws_iam_role_policy" "application" {
  name   = "read-tenant-database-secret"
  role   = aws_iam_role.application.id
  policy = data.aws_iam_policy_document.application.json
}

# REDIS_PASSWORD is injected by ECS at container start, never written into TF state.
data "aws_iam_policy_document" "redis_execution" {
  statement {
    sid       = "InjectExactlyOneStagingRedisPassword"
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.redis_auth_secret_arn]
  }
}
resource "aws_iam_role_policy" "redis_execution" {
  name   = "inject-redis-secret"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.redis_execution.json
}
