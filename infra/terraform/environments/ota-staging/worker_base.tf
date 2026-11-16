# Day39 Staging Worker foundation: no ECS service is enabled by default.
locals {
  worker_kinds = toset(["outbox", "remote_command", "campaign"])
  worker_active = var.enable_service && var.enable_workers ? toset([for kind in local.worker_kinds : kind if var.worker_desired_counts[kind] > 0]) : toset([])
  worker_secret_arns = {
    outbox         = var.outbox_database_secret_arn
    remote_command = var.remote_command_database_secret_arn
    campaign       = var.application_database_secret_arn
  }
  worker_commands = {
    outbox         = ["python", "-m", "apps.outbox_worker.main"]
    remote_command = ["python", "-m", "apps.remote_command_worker.main"]
    campaign       = ["python", "-m", "apps.campaign"]
  }
}

resource "aws_sqs_queue" "worker_dlq" {
  name                      = "${local.label}-command-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_sqs_queue" "worker_commands" {
  name                       = "${local.label}-command"
  visibility_timeout_seconds = 120
  message_retention_seconds  = 345600
  receive_wait_time_seconds  = 10
  sqs_managed_sse_enabled    = true
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.worker_dlq.arn
    maxReceiveCount     = 5
  })
}

resource "aws_cloudwatch_log_group" "worker" {
  for_each          = local.worker_kinds
  name              = "/ecs/${local.label}/${replace(each.key, "_", "-")}"
  retention_in_days = 365
  kms_key_id        = var.data_kms_key_arn
  lifecycle { prevent_destroy = true }
}

resource "aws_security_group" "worker" {
  for_each    = local.worker_kinds
  name_prefix = "${local.label}-${replace(each.key, "_", "-")}-"
  description = "Staging ${each.key} ECS Worker without public ingress"
  vpc_id      = var.vpc_id
  lifecycle { create_before_destroy = true }
}

resource "aws_vpc_security_group_ingress_rule" "worker_postgres" {
  for_each                     = local.worker_kinds
  security_group_id            = var.database_security_group_id
  referenced_security_group_id = aws_security_group.worker[each.key].id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  description                  = "Worker tenant PostgreSQL"
}
resource "aws_vpc_security_group_egress_rule" "worker_postgres" {
  for_each                     = local.worker_kinds
  security_group_id            = aws_security_group.worker[each.key].id
  referenced_security_group_id = var.database_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  description                  = "Worker PostgreSQL only"
}
resource "aws_vpc_security_group_egress_rule" "worker_https" {
  for_each          = local.worker_kinds
  security_group_id = aws_security_group.worker[each.key].id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  description       = "HTTPS through private AWS endpoints/controlled egress"
}
resource "aws_vpc_security_group_ingress_rule" "worker_redis" {
  security_group_id            = var.redis_security_group_id
  referenced_security_group_id = aws_security_group.worker["remote_command"].id
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  description                  = "Redis TLS for remote idempotency"
}
resource "aws_vpc_security_group_egress_rule" "worker_redis" {
  security_group_id            = aws_security_group.worker["remote_command"].id
  referenced_security_group_id = var.redis_security_group_id
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  description                  = "TLS Redis"
}
