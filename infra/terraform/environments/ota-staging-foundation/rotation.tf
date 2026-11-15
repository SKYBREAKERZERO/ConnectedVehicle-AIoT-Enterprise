# These published function versions are provisioned and tested by the independent
# Foundation administrator. Only the matching secret may invoke each version.
variable "application_rotation_lambda_arn" {
  type = string
  validation {
    condition     = can(regex("^arn:aws:lambda:ap-northeast-1:${var.account_id}:function:cv-ota-staging-rotate-application:[1-9][0-9]*$", var.application_rotation_lambda_arn))
    error_message = "A published version of the same-account staging application rotator is required."
  }
}

variable "redis_rotation_lambda_arn" {
  type = string
  validation {
    condition     = can(regex("^arn:aws:lambda:ap-northeast-1:${var.account_id}:function:cv-ota-staging-rotate-redis:[1-9][0-9]*$", var.redis_rotation_lambda_arn))
    error_message = "A published version of the same-account staging Redis rotator is required."
  }
}

resource "aws_lambda_permission" "application_rotation" {
  statement_id   = "AllowApplicationSecretRotation"
  action         = "lambda:InvokeFunction"
  function_name  = join(":", slice(split(":", var.application_rotation_lambda_arn), 0, 7))
  qualifier      = split(":", var.application_rotation_lambda_arn)[7]
  principal      = "secretsmanager.amazonaws.com"
  source_account = var.account_id
  source_arn     = aws_secretsmanager_secret.application.arn
}

resource "aws_lambda_permission" "redis_rotation" {
  statement_id   = "AllowRedisSecretRotation"
  action         = "lambda:InvokeFunction"
  function_name  = join(":", slice(split(":", var.redis_rotation_lambda_arn), 0, 7))
  qualifier      = split(":", var.redis_rotation_lambda_arn)[7]
  principal      = "secretsmanager.amazonaws.com"
  source_account = var.account_id
  source_arn     = aws_secretsmanager_secret.redis_auth.arn
}

resource "aws_secretsmanager_secret_rotation" "application" {
  secret_id           = aws_secretsmanager_secret.application.id
  rotation_lambda_arn = var.application_rotation_lambda_arn
  rotate_immediately  = false

  rotation_rules {
    schedule_expression = "cron(0 17 ? * SUN *)"
    duration            = "2h"
  }

  depends_on = [aws_lambda_permission.application_rotation]
  lifecycle { prevent_destroy = true }
}

resource "aws_secretsmanager_secret_rotation" "redis_auth" {
  secret_id           = aws_secretsmanager_secret.redis_auth.id
  rotation_lambda_arn = var.redis_rotation_lambda_arn
  rotate_immediately  = false

  rotation_rules {
    schedule_expression = "cron(0 17 ? * WED *)"
    duration            = "2h"
  }

  depends_on = [aws_lambda_permission.redis_rotation]
  lifecycle { prevent_destroy = true }
}
