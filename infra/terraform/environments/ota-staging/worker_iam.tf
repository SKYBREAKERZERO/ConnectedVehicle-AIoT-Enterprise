# Worker task roles are distinct from ECS execution, API and GitHub deploy roles.
resource "aws_iam_role" "worker_execution" {
  for_each           = local.worker_kinds
  name               = "${local.label}-${replace(each.key, "_", "-")}-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_trust.json
  lifecycle { prevent_destroy = true }
}
resource "aws_iam_role_policy_attachment" "worker_execution" {
  for_each   = local.worker_kinds
  role       = aws_iam_role.worker_execution[each.key].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}
data "aws_iam_policy_document" "worker_redis_execution" {
  statement {
    sid       = "InjectRemoteRedisOnly"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.redis_auth_secret_arn]
  }
  statement {
    sid       = "DecryptRemoteRedisOnly"
    actions   = ["kms:Decrypt"]
    resources = [var.data_kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.aws_region}.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:SecretARN"
      values   = [var.redis_auth_secret_arn]
    }
  }
}
resource "aws_iam_role_policy" "worker_redis_execution" {
  name   = "inject-redis-token-only"
  role   = aws_iam_role.worker_execution["remote_command"].id
  policy = data.aws_iam_policy_document.worker_redis_execution.json
}

resource "aws_iam_role" "worker" {
  for_each           = local.worker_kinds
  name               = "${local.label}-${replace(each.key, "_", "-")}"
  assume_role_policy = data.aws_iam_policy_document.ecs_trust.json
  lifecycle { prevent_destroy = true }
}
data "aws_iam_policy_document" "worker" {
  for_each = local.worker_kinds
  statement {
    sid       = "ReadExactlyOneTenantDatabaseSecret"
    actions   = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"]
    resources = [local.worker_secret_arns[each.key]]
  }
  statement {
    sid       = "DecryptExactlyOneTenantDatabaseSecret"
    actions   = ["kms:Decrypt"]
    resources = [var.data_kms_key_arn]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${var.aws_region}.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:SecretARN"
      values   = [local.worker_secret_arns[each.key]]
    }
  }
  # ECS agent calls these APIs to protect this Staging cluster's in-flight
  # Worker task from ECS deployment/scale-in; no ECS service mutation allowed.
  statement {
    sid       = "ProtectOnlyStagingWorkerTasks"
    actions   = ["ecs:GetTaskProtection", "ecs:UpdateTaskProtection"]
    resources = ["arn:aws:ecs:${var.aws_region}:${var.aws_account_id}:task/${aws_ecs_cluster.staging.name}/*"]
    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = [aws_ecs_cluster.staging.arn]
    }
  }
  dynamic "statement" {
    for_each = each.key == "outbox" ? [1] : []
    content {
      sid       = "SendCommandEventsOnly"
      actions   = ["sqs:GetQueueUrl", "sqs:SendMessage"]
      resources = [aws_sqs_queue.worker_commands.arn]
    }
  }
  dynamic "statement" {
    for_each = each.key == "remote_command" ? [1] : []
    content {
      sid       = "ConsumeCommandEventsOnly"
      actions   = ["sqs:GetQueueUrl", "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility"]
      resources = [aws_sqs_queue.worker_commands.arn]
    }
  }
  dynamic "statement" {
    for_each = each.key == "remote_command" ? [1] : []
    content {
      sid       = "PublishOnlyTenantDeviceCommands"
      actions   = ["iot:Publish"]
      resources = ["arn:aws:iot:${var.aws_region}:${var.aws_account_id}:topic/tenants/${var.tenant_id}/vehicles/*/commands"]
    }
  }
  dynamic "statement" {
    for_each = each.key == "campaign" && var.staging_firmware_bucket_arn != null ? [1] : []
    content {
      sid       = "ReadPinnedStagingFirmwareVersionOnly"
      actions   = ["s3:GetObjectVersion"]
      resources = ["${var.staging_firmware_bucket_arn}/firmware/${var.tenant_id}/*"]
    }
  }
}
resource "aws_iam_role_policy" "worker" {
  for_each = local.worker_kinds
  name     = "minimum-staging-worker-access"
  role     = aws_iam_role.worker[each.key].id
  policy   = data.aws_iam_policy_document.worker[each.key].json
}
